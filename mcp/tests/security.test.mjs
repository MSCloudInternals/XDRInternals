import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../dist/index.js";
import { BridgeError, ReadOnlyBridge } from "../dist/bridge.js";

const host = fileURLToPath(new URL("../bridge/ReadOnlyHost.ps1", import.meta.url));
const fixture = fileURLToPath(new URL("./fixtures/FakeXdr.psm1", import.meta.url));

function runHost(requests, authenticated = true, env = {}) {
    const result = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-File", host, "-ModulePath", fixture], {
        input: requests.map((request) => JSON.stringify(request)).join("\n") + "\n",
        encoding: "utf8",
        env: { ...process.env, XDR_MCP_AUTH: authenticated ? "browser" : "", XDR_MCP_PASSKEY_FILE: "", ...env },
        timeout: 15_000,
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim().split("\n").map((line) => JSON.parse(line));
}

test("PowerShell denies unknown operations, extra keys and unsafe parameters", () => {
    const requests = [
        { id: "1", operation: "Get-XdrIncident", args: {} },
        { id: "2", operation: "list_incidents", args: { days: 7, page: 1, pageSize: 3, OutputPath: "/tmp/unsafe" } },
        { id: "3", operation: "get_incident", args: { incidentId: 42, Force: 1 } },
        { id: "4", operation: "list_alerts", args: { days: 7, page: 1, pageSize: 3.5 } },
        { id: "5", operation: "list_incidents", args: { days: 31, page: 1, pageSize: 3 } },
        { id: "6", operation: "list_incidents", args: { days: 7, page: 1, pageSize: 3 }, command: "Set-XdrIncident" },
        { id: "7", operation: "list_incidents", args: {} },
        { id: "8", operation: ["list_incidents", "list_alerts"], args: { days: 7, page: 1, pageSize: 3 } },
        { id: "9", operation: "get_device", args: { deviceId: "nope" } },
        { id: "10", operation: "get_device", args: { deviceId: "a".repeat(40), OutputPath: "/tmp/unsafe" } },
        { id: "11", operation: "list_identities", args: { page: 1, pageSize: 1, All: 1 } },
        { id: "12", operation: "approve_action", args: {} },
        { id: "13", operation: "get_identity", args: { upn: "analyst@example.test", Force: 1 } },
        { id: "14", operation: "get_identity", args: { upn: "analyst@example.test", objectId: "12345678-1234-1234-1234-123456789abc" } },
    ];
    const result = runHost(requests);
    assert.deepEqual(result.map((response) => response.error), [
        "operation_not_allowed", "invalid_arguments", "invalid_arguments",
        "invalid_arguments", "invalid_arguments", "invalid_request", "invalid_arguments", "invalid_request", "invalid_arguments", "invalid_arguments", "invalid_arguments", "operation_not_allowed", "invalid_arguments", "invalid_arguments",
    ]);
});

test("PowerShell requires sign-in and projects only bounded read results", () => {
    assert.equal(runHost([{ id: "1", operation: "get_incident", args: { incidentId: 42 } }], false)[0].error, "not_connected");
    const result = runHost([
        { id: "1", operation: "list_incidents", args: { days: 7, page: 2, pageSize: 3 } },
        { id: "2", operation: "get_incident", args: { incidentId: 42 } },
        { id: "3", operation: "list_alerts", args: { days: 7, page: 1, pageSize: 3 } },
        { id: "4", operation: "get_incident", args: { incidentId: 9 } },
        { id: "5", operation: "list_incidents", args: { days: 7, page: 3, pageSize: 1 } },
        { id: "6", operation: "get_incident", args: { incidentId: 10 } },
        { id: "7", operation: "get_incident", args: { incidentId: 11 } },
        { id: "8", operation: "list_devices", args: { days: 7, page: 1, pageSize: 1 } },
        { id: "9", operation: "list_identities", args: { page: 2, pageSize: 1 } },
        { id: "10", operation: "list_pending_actions", args: { page: 1, pageSize: 1 } },
        { id: "11", operation: "get_device", args: { deviceId: "a".repeat(40) } },
        { id: "12", operation: "list_action_history", args: { page: 1, pageSize: 1 } },
        { id: "13", operation: "get_device", args: { deviceId: "b".repeat(40) } },
        { id: "14", operation: "list_cloud_policies", args: { page: 2, pageSize: 1 } },
        { id: "15", operation: "list_incident_alerts", args: { incidentId: 42, page: 2, pageSize: 1 } },
        { id: "16", operation: "get_identity", args: { upn: "analyst@example.test" } },
        { id: "17", operation: "get_identity", args: { objectId: "12345678-1234-1234-1234-123456789abc" } },
        { id: "18", operation: "get_identity", args: { objectId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" } },
        { id: "19", operation: "get_identity", args: { upn: "other@example.test" } },
    ]);
    assert.equal(result[0].data.length, 1);
    assert.equal(result[0].data[0].alertCount, 3);
    assert.equal(result[0].data[0].status, 2);
    assert.equal(result[1].data.incidentId, 42);
    assert.match(result[1].data.created, /^2026-01-01T04:05:06/);
    assert.equal(result[2].data.length, 1);
    assert.equal(result[3].error, "upstream_failed");
    assert.equal(result[4].data.length, 1);
    assert.equal(result[4].data[0].incidentId, 1);
    assert.equal(result[5].error, "invalid_response");
    assert.equal(result[6].error, "invalid_response");
    assert.equal(result[7].data[0].name, "host.example");
    assert.equal(result[8].data[0].upn, "analyst@example.test");
    assert.equal(result[8].data[0].objectId, "12345678-1234-1234-1234-123456789abc");
    assert.equal(result[9].data[0].approvalId, "approval-1");
    assert.equal(result[10].data.deviceId, "a".repeat(40));
    assert.equal(result[11].data[0].approvalId, "approval-2");
    assert.equal(result[12].error, "invalid_response");
    assert.equal(result[13].data[0].severity, 2);
    assert.equal(result[14].data[0].alertId, "alert-2");
    assert.equal(result[14].data[0].incidentId, 42);
    assert.equal(result[15].data.objectId, "12345678-1234-1234-1234-123456789abc");
    assert.equal(result[16].data.objectId, "12345678-1234-1234-1234-123456789abc");
    assert.equal(result[17].error, "invalid_response");
    assert.equal(result[18].error, "invalid_response");
    assert.doesNotMatch(JSON.stringify(result), /secret-cookie-should-not-leak/);
});

test("oversized serialized pages fail without losing the session", () => {
    const result = runHost([
        { id: "1", operation: "list_incidents", args: { days: 7, page: 4, pageSize: 50 } },
        { id: "2", operation: "list_incidents", args: { days: 7, page: 4, pageSize: 1 } },
        { id: "3", operation: "get_incident", args: { incidentId: 42 } },
    ]);
    assert.equal(result[0].error, "invalid_response");
    assert.equal(result[1].ok, true);
    assert.equal(result[1].data.length, 1);
    assert.equal(result[2].ok, true);
    assert.equal(result[2].data.incidentId, 42);
});

test("device timeline requests one bounded portal page without leaking upstream fields", () => {
    const deviceId = "a".repeat(40);
    const result = runHost([
        { id: "1", operation: "list_device_timeline", args: { deviceId, minutes: 60, pageSize: 1 } },
        { id: "2", operation: "list_device_timeline", args: { deviceId, minutes: 61, pageSize: 1 } },
        { id: "3", operation: "list_device_timeline", args: { deviceId, minutes: 60, pageSize: 51 } },
        { id: "4", operation: "list_device_timeline", args: { deviceId: "b".repeat(40), minutes: 10, pageSize: 1 } },
        { id: "5", operation: "list_device_timeline", args: { deviceId: "c".repeat(40), minutes: 10, pageSize: 1 } },
        { id: "6", operation: "list_device_timeline", args: { deviceId: "e".repeat(40), minutes: 10, pageSize: 1 } },
    ]);
    assert.equal(result[0].data.length, 1);
    assert.equal(result[0].data[0].deviceId, deviceId);
    assert.deepEqual(result.slice(1).map((response) => response.error), ["invalid_arguments", "invalid_arguments", "invalid_response", "invalid_response", "invalid_response"]);
    assert.doesNotMatch(JSON.stringify(result), /secret-cookie-should-not-leak/);
});

test("device alert evidence uses one fixed single-tenant portal query", () => {
    const deviceId = "a".repeat(40);
    const result = runHost([
        { id: "1", operation: "list_device_alert_evidence", args: { deviceId, pageSize: 1 } },
        { id: "2", operation: "list_device_alert_evidence", args: { deviceId, pageSize: 51 } },
        { id: "3", operation: "list_device_alert_evidence", args: { deviceId, pageSize: 1, QueryText: "DeviceInfo | take 100" } },
    ]);
    assert.equal(result[0].data[0].alertId, "alert-2");
    assert.deepEqual(result.slice(1).map((response) => response.error), ["invalid_arguments", "invalid_arguments"]);
    assert.doesNotMatch(JSON.stringify(result), /secret-cookie-should-not-leak/);
});

test("file and network observations use fixed portal queries and reject unsafe values", () => {
    const result = runHost([
        { id: "1", operation: "list_file_events", args: { sha256: "f".repeat(64), pageSize: 1 } },
        { id: "2", operation: "list_network_observations", args: { kind: "ip", value: "192.0.2.1", pageSize: 1 } },
        { id: "3", operation: "list_network_observations", args: { kind: "domain", value: "example.com", pageSize: 1 } },
        { id: "4", operation: "list_file_events", args: { sha256: "f".repeat(63) + ";", pageSize: 1 } },
        { id: "5", operation: "list_network_observations", args: { kind: "domain", value: 'example.com" | take 100', pageSize: 1 } },
        { id: "6", operation: "list_network_observations", args: { kind: "ip", value: "192.0.2.1", pageSize: 100 } },
    ]);
    assert.equal(result[0].data[0].fileName, "sample.exe");
    assert.equal(result[1].data[0].remoteIp, "192.0.2.1");
    assert.equal(result[2].data[0].remoteUrl, "example.com");
    assert.deepEqual(result.slice(3).map((response) => response.error), ["invalid_arguments", "invalid_arguments", "invalid_arguments"]);
    assert.doesNotMatch(JSON.stringify(result), /secret-cookie-should-not-leak/);
});

test("user alert and device logon pivots verify the UPN and allow only bounded templates", () => {
    const result = runHost([
        { id: "1", operation: "list_user_alert_evidence", args: { upn: "analyst@example.test", pageSize: 1 } },
        { id: "2", operation: "list_user_device_logons", args: { upn: "analyst@example.test", pageSize: 1 } },
        { id: "3", operation: "list_user_device_logons", args: { upn: 'analyst@example.test" | take 100', pageSize: 1 } },
        { id: "4", operation: "list_user_alert_evidence", args: { upn: "analyst@example.test", pageSize: 51 } },
    ]);
    assert.equal(result[0].data[0].alertId, "alert-2");
    assert.equal(result[1].data[0].deviceName, "host.example");
    assert.deepEqual(result.slice(2).map((response) => response.error), ["invalid_arguments", "invalid_arguments"]);
    assert.doesNotMatch(JSON.stringify(result), /secret-cookie-should-not-leak/);
});

test("recent hunting accepts only predefined tables and one hour of rows", () => {
    const result = runHost([
        { id: "1", operation: "hunt_recent", args: { table: "DeviceEvents", pageSize: 1 } },
        { id: "2", operation: "hunt_recent", args: { table: "DeviceEvents | take 100", pageSize: 1 } },
        { id: "3", operation: "hunt_recent", args: { table: "DeviceEvents", pageSize: 21 } },
    ]);
    assert.equal(result[0].data[0].summary, "FileCreated");
    assert.deepEqual(result.slice(1).map((response) => response.error), ["invalid_arguments", "invalid_arguments"]);
    assert.doesNotMatch(JSON.stringify(result), /secret-cookie-should-not-leak/);
});

test("portal hunting rejects malformed or wrong-target results and revokes on 403", () => {
    const request = { id: "1", operation: "list_device_alert_evidence", args: { deviceId: "a".repeat(40), pageSize: 1 } };
    const next = { id: "2", operation: "list_incidents", args: { days: 7, page: 1, pageSize: 1 } };
    for (const key of ["XDR_MCP_TEST_HUNT_BAD_RESULTS", "XDR_MCP_TEST_HUNT_MISMATCH"]) {
        const result = runHost([request, next], true, { [key]: "1" });
        assert.equal(result[0].error, "invalid_response");
        assert.equal(result[1].ok, true);
    }
    const rejected = runHost([request, next], true, { XDR_MCP_TEST_HUNT_FORBIDDEN: "1" });
    assert.deepEqual(rejected.map((response) => response.error), ["not_connected", "not_connected"]);
});

test("MCP denies caller-supplied hunting queries and unsupported pivot values", async () => {
    const calls = [];
    const server = createServer({ invoke: async (operation, args) => { calls.push({ operation, args }); return []; } });
    const client = new Client({ name: "portal-input-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(serverTransport);
        await client.connect(clientTransport);
        for (const { name, args } of [
            { name: "xdr_hunt_recent", args: { table: "DeviceEvents", pageSize: 1, QueryText: "DeviceInfo | take 100" } },
            { name: "xdr_hunt_recent", args: { table: "OtherTable", pageSize: 1 } },
            { name: "xdr_list_device_alert_evidence", args: { deviceId: "a".repeat(40), pageSize: 1, TenantIds: ["other"] } },
            { name: "xdr_list_file_events", args: { sha256: "f".repeat(63) + ";", pageSize: 1 } },
            { name: "xdr_list_network_observations", args: { kind: "domain", value: 'example.com" | take 100', pageSize: 1 } },
            { name: "xdr_list_user_alert_evidence", args: { upn: "bad-upn", pageSize: 1 } },
            { name: "xdr_list_user_device_logons", args: { upn: "analyst@example.test", pageSize: 51 } },
        ]) {
            assert.equal((await client.callTool({ name, arguments: args })).isError, true);
        }
        assert.deepEqual(calls, []);
    } finally {
        await client.close();
        await server.close();
    }
});

test("hunting schema returns only one requested table and projected columns", () => {
    const result = runHost([
        { id: "1", operation: "get_hunting_table_schema", args: { table: "DeviceEvents" } },
        { id: "2", operation: "get_hunting_table_schema", args: { table: "NoSuchTable" } },
        { id: "3", operation: "get_hunting_table_schema", args: { table: "DeviceEvents;Remove-Item" } },
        { id: "4", operation: "get_hunting_table_schema", args: { table: "BadTable" } },
        { id: "5", operation: "get_hunting_table_schema", args: { table: "MixedTable" } },
    ]);
    assert.equal(result[0].data.columns[0].name, "Timestamp");
    assert.equal(result[0].data.truncated, false);
    assert.deepEqual(result.slice(1).map((response) => response.error), ["not_found", "invalid_arguments", "invalid_response", "not_found"]);
    const arrayRoot = runHost([{ id: "1", operation: "get_hunting_table_schema", args: { table: "DeviceEvents" } }], true, { XDR_MCP_TEST_SCHEMA_ARRAY: "1" });
    assert.equal(arrayRoot[0].error, "invalid_response");
    assert.doesNotMatch(JSON.stringify(result), /secret-cookie-should-not-leak/);
});

test("alert detail verifies its ID and projects only bounded evidence", () => {
    const result = runHost([
        { id: "1", operation: "get_alert", args: { alertId: "alert-2" } },
        { id: "2", operation: "get_alert", args: { alertId: "../secret" } },
        { id: "3", operation: "get_alert", args: { alertId: "missing" } },
    ]);
    assert.equal(result[0].data.alertId, "alert-2");
    assert.deepEqual(result.slice(1).map((response) => response.error), ["invalid_arguments", "not_found"]);
    assert.doesNotMatch(JSON.stringify(result), /secret-cookie-should-not-leak/);
});

test("new portal read revokes the session on a structured 403 but not a 404", () => {
    for (const request of [
        { operation: "get_alert", args: { alertId: "denied" } },
        { operation: "list_device_timeline", args: { deviceId: "d".repeat(40), minutes: 10, pageSize: 1 } },
    ]) {
        const result = runHost([
            { id: "1", ...request },
            { id: "2", operation: "list_incidents", args: { days: 7, page: 1, pageSize: 1 } },
        ]);
        assert.deepEqual(result.map((response) => response.error), ["not_connected", "not_connected"]);
    }
    const schemaDenied = runHost([
        { id: "1", operation: "get_hunting_table_schema", args: { table: "DeviceEvents" } },
        { id: "2", operation: "list_incidents", args: { days: 7, page: 1, pageSize: 1 } },
    ], true, { XDR_MCP_TEST_SCHEMA_FORBIDDEN: "1" });
    assert.deepEqual(schemaDenied.map((response) => response.error), ["not_connected", "not_connected"]);
    const missing = runHost([
        { id: "1", operation: "get_alert", args: { alertId: "missing" } },
        { id: "2", operation: "list_incidents", args: { days: 7, page: 1, pageSize: 1 } },
    ]);
    assert.equal(missing[0].error, "not_found");
    assert.equal(missing[1].ok, true);
});

test("identity SID lookup is bounded and verifies the resolved target", () => {
    const sid = "S-1-5-21-111-222-333-1001";
    const result = runHost([
        { id: "1", operation: "get_identity", args: { sid } },
        { id: "2", operation: "get_identity", args: { sid: "S-1-5-21-111-222-333-1002" } },
        { id: "3", operation: "get_identity", args: { sid: `${sid};Get-Content /tmp/secret` } },
        { id: "4", operation: "get_identity", args: { sid, upn: "analyst@example.test" } },
    ]);
    assert.equal(result[0].ok, true);
    assert.equal(result[0].data.sid, sid);
    assert.equal(result[0].data.objectId, null);
    assert.equal(result[0].data.upn, null);
    assert.deepEqual(result.slice(1).map((response) => response.error), ["invalid_response", "invalid_arguments", "invalid_arguments"]);
    assert.doesNotMatch(JSON.stringify(result), /secret-cookie-should-not-leak/);
});

test("MCP accepts exactly one identity identifier including SID", async () => {
    const sid = "S-1-5-21-111-222-333-1001";
    const calls = [];
    const server = createServer({
        invoke: async (operation, args) => {
            calls.push({ operation, args });
            return { sid, upn: null, objectId: null, name: "Domain analyst", firstSeen: null, lastSeen: null };
        },
    });
    const client = new Client({ name: "sid-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(serverTransport);
        await client.connect(clientTransport);
        const result = await client.callTool({ name: "xdr_get_identity", arguments: { sid } });
        assert.equal(result.isError, undefined);
        assert.equal(result.structuredContent.items.sid, sid);
        for (const args of [{}, { sid: "invalid" }, { sid, upn: "analyst@example.test" }, { sid, objectId: "12345678-1234-1234-1234-123456789abc" }]) {
            assert.equal((await client.callTool({ name: "xdr_get_identity", arguments: args })).isError, true);
        }
        assert.deepEqual(calls, [{ operation: "get_identity", args: { sid } }]);
    } finally {
        await client.close();
        await server.close();
    }
});

test("passkey startup is opt-in and authentication streams never enter stdout", () => {
    const request = [{ id: "1", operation: "get_incident", args: { incidentId: 42 } }];
    assert.equal(runHost(request, false, { XDR_MCP_AUTH: "software-passkey" })[0].error, "not_connected");
    const response = runHost(request, false, { XDR_MCP_AUTH: "software-passkey", XDR_MCP_PASSKEY_FILE: fixture });
    assert.equal(response[0].ok, true);
    assert.doesNotMatch(JSON.stringify(response), /fake-secret-must-not-leak/);
});

test("portal authorization rejection revokes the session before cached reads", () => {
    const result = runHost([
        { id: "1", operation: "list_incidents", args: { days: 7, page: 1, pageSize: 1 } },
        { id: "2", operation: "get_incident", args: { incidentId: 12 } },
        { id: "3", operation: "list_incidents", args: { days: 7, page: 1, pageSize: 1 } },
    ]);
    assert.equal(result[0].ok, true);
    assert.equal(result[1].error, "not_connected");
    assert.equal(result[2].error, "not_connected");
    const alertResult = runHost([
        { id: "1", operation: "list_alerts", args: { days: 29, page: 1, pageSize: 1 } },
        { id: "2", operation: "list_incidents", args: { days: 7, page: 1, pageSize: 1 } },
    ]);
    assert.equal(alertResult[0].error, "not_connected");
    assert.equal(alertResult[1].error, "not_connected");
});

test("missing records and authorization-like text do not revoke the session", () => {
    const result = runHost([
        { id: "1", operation: "get_incident", args: { incidentId: 401 } },
        { id: "2", operation: "get_incident", args: { incidentId: 403 } },
        { id: "3", operation: "get_incident", args: { incidentId: 13 } },
        { id: "4", operation: "get_incident", args: { incidentId: 42 } },
    ]);
    assert.deepEqual(result.slice(0, 3).map((response) => response.error), ["not_found", "not_found", "upstream_failed"]);
    assert.equal(result[3].ok, true);
});

test("MCP registers only bounded read tools and rejects invalid inputs", async () => {
    const calls = [];
    const server = createServer({
        invoke: async (operation, args) => {
            calls.push({ operation, args });
            return [{ incidentId: 42, title: "untrusted evidence", severity: "High", status: "New", lastUpdated: null, alertCount: 1 }];
        }
    });
    const client = new Client({ name: "security-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(serverTransport);
        await client.connect(clientTransport);
        const tools = await client.listTools();
        assert.deepEqual(tools.tools.map((tool) => tool.name).sort(), ["xdr_get_alert", "xdr_get_device", "xdr_get_hunting_table_schema", "xdr_get_identity", "xdr_get_incident", "xdr_hunt_recent", "xdr_list_action_history", "xdr_list_alerts", "xdr_list_cloud_policies", "xdr_list_device_alert_evidence", "xdr_list_device_timeline", "xdr_list_devices", "xdr_list_file_events", "xdr_list_identities", "xdr_list_incident_alerts", "xdr_list_incidents", "xdr_list_network_observations", "xdr_list_pending_actions", "xdr_list_user_alert_evidence", "xdr_list_user_device_logons"]);
        assert.ok(tools.tools.every((tool) => tool.annotations.readOnlyHint === true));
        await client.callTool({ name: "xdr_list_incidents", arguments: { days: 7, page: 2, pageSize: 3 } });
        assert.deepEqual(calls, [{ operation: "list_incidents", args: { days: 7, page: 2, pageSize: 3 } }]);
        for (const arguments_ of [
            { days: 7, page: 2, pageSize: 3, OutputPath: "/tmp/unsafe" },
            { days: 0, page: 1, pageSize: 3 },
        ]) {
            const response = await client.callTool({ name: "xdr_list_incidents", arguments: arguments_ });
            assert.equal(response.isError, true);
        }
        const ambiguousIdentity = await client.callTool({
            name: "xdr_get_identity", arguments: {
                upn: "analyst@example.test", objectId: "12345678-1234-1234-1234-123456789abc",
            }
        });
        assert.equal(ambiguousIdentity.isError, true);
        assert.equal(calls.length, 1);
    } finally {
        await client.close();
        await server.close();
    }
});

test("new MCP reads reject extra arguments and malformed projected results", async () => {
    const calls = [];
    const server = createServer({
        invoke: async (operation, args) => {
            calls.push({ operation, args });
            if (operation === "get_alert") return { alertId: "alert-2", title: null, severity: null, status: null, incidentId: null, generated: null, credential: "secret" };
            if (operation === "list_device_timeline") return [{ deviceId: args.deviceId, timestamp: null, eventType: null, title: null, credential: "secret" }];
            return { table: args.table, truncated: false, columns: [{ name: null, type: null, description: null, credential: "secret" }] };
        },
    });
    const client = new Client({ name: "new-reads-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(serverTransport);
        await client.connect(clientTransport);
        for (const { name, args } of [
            { name: "xdr_get_alert", args: { alertId: "alert-2" } },
            { name: "xdr_list_device_timeline", args: { deviceId: "a".repeat(40), minutes: 1, pageSize: 1 } },
            { name: "xdr_get_hunting_table_schema", args: { table: "DeviceEvents" } },
        ]) {
            assert.equal((await client.callTool({ name, arguments: { ...args, OutputPath: "/tmp/unsafe" } })).isError, true);
            const response = await client.callTool({ name, arguments: args });
            assert.equal(response.isError, true);
            assert.equal(response.content[0].text, "invalid_response");
        }
        assert.equal(calls.length, 3);
    } finally {
        await client.close();
        await server.close();
    }
});

test("MCP fails closed on malformed bridge output and unexpected error text", async () => {
    const outcomes = [null, [{ incidentId: 42, title: "x", Credential: "secret" }],
        [{ incidentId: null, title: "x", severity: null, status: null, lastUpdated: null, alertCount: null }],
        new BridgeError("raw-secret")];
    const server = createServer({
        invoke: async () => {
            const outcome = outcomes.shift();
            if (outcome instanceof Error) throw outcome;
            return outcome;
        }
    });
    const client = new Client({ name: "malformed-test", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(serverTransport);
        await client.connect(clientTransport);
        for (let index = 0; index < 4; index++) {
            const result = await client.callTool({ name: "xdr_list_incidents", arguments: { days: 1, page: 1, pageSize: 1 } });
            assert.equal(result.isError, true);
            assert.equal(result.content[0].text, index === 3 ? "operation_failed" : "invalid_response");
        }
    } finally {
        await client.close();
        await server.close();
    }
});

test("only child startup receives the authentication deadline", async (context) => {
    const deadlines = [];
    const originalSetTimeout = globalThis.setTimeout;
    context.mock.method(globalThis, "setTimeout", (callback, delay, ...args) => {
        deadlines.push(delay);
        return originalSetTimeout(callback, delay, ...args);
    });
    const bridge = new ReadOnlyBridge({ XDR_MCP_AUTH: "browser" });
    const child = {
        stdin: {
            write(line, callback) {
                const { id } = JSON.parse(line);
                const pending = bridge.pending.get(id);
                clearTimeout(pending.timer);
                bridge.pending.delete(id);
                pending.resolve({ id, ok: true, data: [] });
                callback(null);
            },
        },
        kill() { },
    };
    context.mock.method(bridge, "start", () => {
        bridge.child = child;
        return child;
    });
    try {
        await bridge.invoke("list_incidents", { days: 1, page: 1, pageSize: 1 });
        await bridge.invoke("list_incidents", { days: 1, page: 1, pageSize: 1 });
        assert.equal(deadlines.length, 2);
        assert.ok(deadlines[0] > 350_000 && deadlines[0] <= 360_000);
        assert.ok(deadlines[1] > 50_000 && deadlines[1] <= 60_000);
    } finally {
        bridge.close();
    }
});

test("closed bridge rejects both in-flight and queued calls", async () => {
    const bridge = new ReadOnlyBridge({ ...process.env, XDR_MCP_AUTH: "", XDR_MCP_PASSKEY_FILE: "" });
    const first = bridge.invoke("get_incident", { incidentId: 1 });
    const queued = bridge.invoke("get_incident", { incidentId: 1 });
    await new Promise((resolve) => setImmediate(resolve));
    bridge.close();
    await assert.rejects(first, (error) => error.code === "session_lost");
    await assert.rejects(queued, (error) => error.code === "session_lost");
    await assert.rejects(bridge.invoke("get_incident", { incidentId: 1 }), (error) => error.code === "session_lost");
});

test("bridge bounds outstanding requests and skips cancelled queued work", async () => {
    const env = { ...process.env, XDR_MCP_AUTH: "", XDR_MCP_PASSKEY_FILE: "" };
    const bridge = new ReadOnlyBridge(env);
    const calls = Array.from({ length: 8 }, () => bridge.invoke("get_incident", { incidentId: 1 }));
    await assert.rejects(bridge.invoke("get_incident", { incidentId: 1 }), (error) => error.code === "server_busy");
    bridge.close();
    const results = await Promise.allSettled(calls);
    assert.ok(results.every((result) => result.status === "rejected" && result.reason.code === "session_lost"));

    const second = new ReadOnlyBridge(env);
    const first = second.invoke("get_incident", { incidentId: 1 });
    const cancel = new AbortController();
    const queued = second.invoke("get_incident", { incidentId: 1 }, cancel.signal);
    cancel.abort();
    await assert.rejects(first, (error) => error.code === "not_connected");
    await assert.rejects(queued, (error) => error.code === "request_cancelled");
    second.close();
});

test("stdio server denies tenant reads until the operator signs in", async () => {
    const entrypoint = fileURLToPath(new URL("../dist/index.js", import.meta.url));
    const client = new Client({ name: "stdio-security-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: [entrypoint],
        env: { ...process.env, XDR_MCP_AUTH: "" },
        stderr: "pipe",
    });
    try {
        await client.connect(transport);
        const response = await client.callTool({ name: "xdr_get_incident", arguments: { incidentId: 42 } });
        assert.equal(response.isError, true);
        assert.equal(response.content[0].text, "not_connected");
    } finally {
        await client.close();
    }
});