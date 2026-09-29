import { statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const authMode = process.env.XDR_MCP_AUTH || "software-passkey";
const passkeyPath = process.env.XDR_MCP_PASSKEY_FILE;
if (!["browser", "software-passkey"].includes(authMode)) {
    console.error("live status=failed phase=setup reason=unsupported_auth_mode");
    process.exitCode = 1;
} else if (authMode === "software-passkey" && (!passkeyPath || !isAbsolute(passkeyPath))) {
    console.error("live status=failed phase=setup reason=absolute_passkey_path_required");
    process.exitCode = 1;
} else {
    let phase = "setup";
    let client;
    try {
        if (authMode === "software-passkey") {
            const metadata = statSync(passkeyPath);
            if (!metadata.isFile() || (process.platform !== "win32" && (metadata.mode & 0o077) !== 0)) {
                throw new Error("unsafe_passkey_file");
            }
        }
        const transport = new StdioClientTransport({
            command: process.execPath,
            args: [fileURLToPath(new URL("../dist/index.js", import.meta.url))],
            env: { ...process.env, XDR_MCP_AUTH: authMode, XDR_MCP_PASSKEY_FILE: authMode === "software-passkey" ? passkeyPath : "" },
            stderr: "pipe",
        });
        transport.stderr?.resume();
        client = new Client({ name: "xdr-live-read-validation", version: "0.1.0" });
        phase = "handshake";
        await client.connect(transport);
        const tools = await client.listTools();
        const expected = ["xdr_get_alert", "xdr_get_device", "xdr_get_hunting_table_schema", "xdr_get_identity", "xdr_get_incident", "xdr_hunt_recent", "xdr_list_action_history", "xdr_list_alerts", "xdr_list_cloud_policies", "xdr_list_device_alert_evidence", "xdr_list_device_timeline", "xdr_list_devices", "xdr_list_file_events", "xdr_list_identities", "xdr_list_incident_alerts", "xdr_list_incidents", "xdr_list_network_observations", "xdr_list_pending_actions", "xdr_list_user_alert_evidence", "xdr_list_user_device_logons"];
        if (JSON.stringify(tools.tools.map((tool) => tool.name).sort()) !== JSON.stringify(expected) ||
            tools.tools.some((tool) => tool.annotations?.readOnlyHint !== true)) {
            throw new Error("unexpected_tool_inventory");
        }
        console.log("live status=pass phase=handshake");

        const call = async (name, args, timeout) => {
            phase = name;
            const response = await client.callTool({ name, arguments: args }, undefined, { timeout });
            if (response.isError) {
                const code = response.content?.[0]?.text;
                throw new Error(["not_connected", "operation_failed", "invalid_response", "upstream_failed", "session_lost", "session_timed_out"].includes(code) ? code : "tool_error");
            }
            return response.structuredContent?.items;
        };

        const incidents = await call("xdr_list_incidents", { days: 7, page: 1, pageSize: 1 }, 390_000);
        if (!Array.isArray(incidents) || incidents.length > 1) throw new Error("invalid_incident_result");
        console.log(`live status=pass phase=incidents count=${incidents.length}`);
        const alerts = await call("xdr_list_alerts", { days: 7, page: 1, pageSize: 1 }, 70_000);
        if (!Array.isArray(alerts) || alerts.length > 1) throw new Error("invalid_alert_result");
        console.log(`live status=pass phase=alerts count=${alerts.length}`);
        if (alerts.length && /^[A-Za-z0-9._:-]{1,160}$/.test(alerts[0].alertId)) {
            const alert = await call("xdr_get_alert", { alertId: alerts[0].alertId }, 70_000);
            if (alert?.alertId !== alerts[0].alertId) throw new Error("invalid_alert_detail");
            console.log("live status=pass phase=alert_detail");
        } else {
            console.log("live status=skip phase=alert_detail reason=no_usable_alert");
        }
        const schema = await call("xdr_get_hunting_table_schema", { table: "DeviceEvents" }, 70_000);
        if (schema?.table !== "DeviceEvents" || !Array.isArray(schema.columns) || schema.columns.length > 50) throw new Error("invalid_schema_result");
        console.log(`live status=pass phase=hunting_schema columns=${schema.columns.length} truncated=${schema.truncated}`);
        const recent = await call("xdr_hunt_recent", { table: "DeviceEvents", pageSize: 1 }, 70_000);
        if (!Array.isArray(recent) || recent.length > 1 || recent.some((item) => item.table !== "DeviceEvents")) throw new Error("invalid_recent_hunt");
        console.log(`live status=pass phase=recent_hunt count=${recent.length}`);
        const files = await call("xdr_list_file_events", { sha256: "f".repeat(64), pageSize: 1 }, 70_000);
        if (!Array.isArray(files) || files.length > 1 || files.some((item) => item.sha256.toLowerCase() !== "f".repeat(64))) throw new Error("invalid_file_events");
        console.log(`live status=pass phase=file_events count=${files.length}`);
        for (const { kind, value } of [{ kind: "ip", value: "192.0.2.1" }, { kind: "domain", value: "example.com" }]) {
            const observations = await call("xdr_list_network_observations", { kind, value, pageSize: 1 }, 70_000);
            if (!Array.isArray(observations) || observations.length > 1) throw new Error("invalid_network_observations");
            console.log(`live status=pass phase=network_${kind} count=${observations.length}`);
        }
        const devices = await call("xdr_list_devices", { days: 7, page: 1, pageSize: 1 }, 70_000);
        if (!Array.isArray(devices) || devices.length > 1 || devices.some((item) => !/^[0-9a-f]{40}$/i.test(item.deviceId))) throw new Error("invalid_device_result");
        console.log(`live status=pass phase=devices count=${devices.length}`);
        if (devices.length) {
            const device = await call("xdr_get_device", { deviceId: devices[0].deviceId }, 70_000);
            if (device?.deviceId?.toLowerCase() !== devices[0].deviceId.toLowerCase()) throw new Error("invalid_device_detail");
            console.log("live status=pass phase=device_detail");
            const timeline = await call("xdr_list_device_timeline", { deviceId: devices[0].deviceId, minutes: 10, pageSize: 1 }, 70_000);
            if (!Array.isArray(timeline) || timeline.length > 1 || timeline.some((item) => item.deviceId !== devices[0].deviceId)) throw new Error("invalid_timeline_result");
            console.log(`live status=pass phase=device_timeline count=${timeline.length}`);
            const evidence = await call("xdr_list_device_alert_evidence", { deviceId: devices[0].deviceId, pageSize: 1 }, 70_000);
            if (!Array.isArray(evidence) || evidence.length > 1 || evidence.some((item) => item.deviceId.toLowerCase() !== devices[0].deviceId.toLowerCase())) throw new Error("invalid_device_alert_evidence");
            console.log(`live status=pass phase=device_alert_evidence count=${evidence.length}`);
        } else {
            console.log("live status=skip phase=device_detail reason=no_device");
            console.log("live status=skip phase=device_timeline reason=no_device");
            console.log("live status=skip phase=device_alert_evidence reason=no_device");
        }
        const identities = await call("xdr_list_identities", { page: 1, pageSize: 10 }, 70_000);
        if (!Array.isArray(identities) || identities.length > 10 || identities.some((item) => !item.name && !item.upn && !item.sid && !item.objectId)) {
            throw new Error("invalid_identity_result");
        }
        console.log(`live status=pass phase=identities count=${identities.length}`);
        const byUpn = identities.find((item) => /^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,189}$/.test(item.upn ?? ""));
        let pivotUpn = byUpn?.upn;
        const byObjectId = identities.find((item) => /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(item.objectId ?? ""));
        const bySid = identities.find((item) => /^S-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}$/.test(item.sid ?? ""));
        if (byUpn) {
            const identity = await call("xdr_get_identity", { upn: byUpn.upn }, 70_000);
            if (!identity || (!identity.name && !identity.objectId)) throw new Error("invalid_identity_detail");
            console.log("live status=pass phase=identity_detail");
        } else if (byObjectId) {
            const identity = await call("xdr_get_identity", { objectId: byObjectId.objectId }, 70_000);
            if (identity?.objectId?.toLowerCase() !== byObjectId.objectId.toLowerCase()) throw new Error("invalid_identity_detail");
            if (/^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,189}$/.test(identity.upn ?? "")) pivotUpn = identity.upn;
            console.log("live status=pass phase=identity_detail");
        } else if (bySid) {
            const identity = await call("xdr_get_identity", { sid: bySid.sid }, 70_000);
            if (identity?.sid !== bySid.sid) throw new Error("invalid_identity_detail");
            console.log("live status=pass phase=identity_detail");
        } else {
            console.log("live status=skip phase=identity_detail reason=no_identifier");
        }
        const userProbe = pivotUpn ?? "analyst@example.invalid";
        const userAlerts = await call("xdr_list_user_alert_evidence", { upn: userProbe, pageSize: 1 }, 70_000);
        if (!Array.isArray(userAlerts) || userAlerts.length > 1 || userAlerts.some((item) => item.upn.toLowerCase() !== userProbe.toLowerCase())) throw new Error("invalid_user_alert_evidence");
        console.log(`live status=pass phase=user_alert_evidence count=${userAlerts.length} target=${pivotUpn ? "listed" : "placeholder"}`);
        const userDevices = await call("xdr_list_user_device_logons", { upn: userProbe, pageSize: 1 }, 70_000);
        if (!Array.isArray(userDevices) || userDevices.length > 1 || userDevices.some((item) => item.upn.toLowerCase() !== userProbe.toLowerCase())) throw new Error("invalid_user_devices");
        console.log(`live status=pass phase=user_device_logons count=${userDevices.length} target=${pivotUpn ? "listed" : "placeholder"}`);
        const pending = await call("xdr_list_pending_actions", { page: 1, pageSize: 1 }, 70_000);
        if (!Array.isArray(pending) || pending.length > 1 || pending.some((item) => !item.approvalId && !item.actionType)) {
            throw new Error("invalid_pending_result");
        }
        console.log(`live status=pass phase=pending_actions count=${pending.length}`);
        const history = await call("xdr_list_action_history", { page: 1, pageSize: 1 }, 70_000);
        if (!Array.isArray(history) || history.length > 1 || history.some((item) => !item.approvalId && !item.actionType)) {
            throw new Error("invalid_history_result");
        }
        console.log(`live status=pass phase=action_history count=${history.length}`);
        const policies = await call("xdr_list_cloud_policies", { page: 1, pageSize: 1 }, 70_000);
        if (!Array.isArray(policies) || policies.length > 1 || policies.some((item) => !item.policyId && !item.name)) {
            throw new Error("invalid_policy_result");
        }
        console.log(`live status=pass phase=cloud_policies count=${policies.length}`);
        const nextIncidents = await call("xdr_list_incidents", { days: 7, page: 2, pageSize: 1 }, 70_000);
        const nextAlerts = await call("xdr_list_alerts", { days: 7, page: 2, pageSize: 1 }, 70_000);
        if (!Array.isArray(nextIncidents) || nextIncidents.length > 1 || !Array.isArray(nextAlerts) || nextAlerts.length > 1) {
            throw new Error("invalid_page_result");
        }
        console.log(`live status=pass phase=paging incident_count=${nextIncidents.length} alert_count=${nextAlerts.length}`);
        if (incidents.length && Number.isInteger(incidents[0].incidentId) && incidents[0].incidentId > 0) {
            const incident = await call("xdr_get_incident", { incidentId: incidents[0].incidentId }, 70_000);
            if (!incident || incident.incidentId !== incidents[0].incidentId) throw new Error("invalid_detail_result");
            console.log("live status=pass phase=incident_detail");
            const related = await call("xdr_list_incident_alerts", { incidentId: incident.incidentId, page: 1, pageSize: 1 }, 70_000);
            if (!Array.isArray(related) || related.length > 1 || related.some((item) => !item.alertId || item.incidentId !== incident.incidentId)) {
                throw new Error("invalid_related_alert_result");
            }
            console.log(`live status=pass phase=incident_alerts count=${related.length}`);
        } else {
            console.log("live status=skip phase=incident_detail reason=no_incident");
            console.log("live status=skip phase=incident_alerts reason=no_incident");
        }
        phase = "invalid_arguments";
        const denied = await client.callTool({ name: "xdr_list_incidents", arguments: { days: 7, page: 1, pageSize: 1, OutputPath: "/tmp/forbidden" } });
        if (!denied.isError) throw new Error("invalid_arguments_accepted");
        console.log("live status=pass phase=invalid_arguments");
    } catch (error) {
        const known = new Set(["unsafe_passkey_file", "unexpected_tool_inventory", "not_connected", "operation_failed", "invalid_response", "upstream_failed", "session_lost", "session_timed_out", "tool_error", "invalid_incident_result", "invalid_alert_result", "invalid_alert_detail", "invalid_schema_result", "invalid_recent_hunt", "invalid_file_events", "invalid_network_observations", "invalid_device_result", "invalid_device_detail", "invalid_timeline_result", "invalid_device_alert_evidence", "invalid_identity_result", "invalid_identity_detail", "invalid_user_alert_evidence", "invalid_user_devices", "invalid_pending_result", "invalid_history_result", "invalid_policy_result", "invalid_page_result", "invalid_detail_result", "invalid_related_alert_result", "invalid_arguments_accepted"]);
        const reason = known.has(error?.message) ? error.message : "connection_or_transport_failed";
        const category = ["McpError", "AbortError", "TypeError", "Error"].includes(error?.name) ? error.name : "other";
        const protocolCode = Number.isInteger(error?.code) && error.code >= -32700 && error.code <= -32000 ? error.code : "none";
        console.error(`live status=failed phase=${phase} reason=${reason} category=${category} protocol=${protocolCode}`);
        process.exitCode = 1;
    } finally {
        if (client) await client.close();
    }
}