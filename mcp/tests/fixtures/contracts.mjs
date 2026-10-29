// Synthetic projected records and caller arguments for every public read tool.
const deviceId = "a".repeat(40);
const upn = "analyst@example.test";
const page = { page: 1, pageSize: 1 };
const paged = { days: 7, ...page };
const incident = { incidentId: 42, title: null, severity: "High", status: 2, lastUpdated: null, alertCount: 1 };
const alert = { alertId: "alert-2", title: null, severity: null, status: null, incidentId: null, generated: null };
const device = { deviceId, name: null, risk: 1, health: null, lastSeen: null };
const evidence = { timestamp: null, deviceId, alertId: "alert-2", title: null, severity: null };
const action = { approvalId: null, investigationId: 1, actionType: null, asset: null, status: null, updated: null };
export const contracts = [
    ["list_incidents", paged, [incident]],
    ["get_incident", { incidentId: 42 }, { ...incident, created: null }],
    ["list_incident_alerts", { incidentId: 42, ...page }, [alert]],
    ["list_alerts", paged, [alert]],
    ["get_alert", { alertId: "alert-2" }, alert],
    ["list_devices", paged, [device]],
    ["get_device", { deviceId }, device],
    ["list_device_timeline", { deviceId, minutes: 1, pageSize: 1 }, [{ deviceId, timestamp: null, eventType: null, title: null }]],
    ["list_device_alert_evidence", { deviceId, pageSize: 1 }, [evidence]],
    ["list_file_events", { sha256: "f".repeat(64), pageSize: 1 }, [{ timestamp: null, deviceId, fileName: null, sha256: "f".repeat(64) }]],
    ["list_network_observations", { kind: "domain", value: "example.test", pageSize: 1 }, [{ timestamp: null, deviceId, remoteIp: null, remoteUrl: null }]],
    ["list_user_alert_evidence", { upn, pageSize: 1 }, [{ ...evidence, upn }]],
    ["list_user_device_logons", { upn, pageSize: 1 }, [{ timestamp: null, upn, deviceName: "host" }]],
    ["list_user_timeline", { upn, minutes: 1, pageSize: 1 }, [{ timestamp: "now", upn, eventType: "logon", deviceName: null }]],
    ["hunt_recent", { table: "DeviceEvents", pageSize: 1 }, [{ table: "DeviceEvents", timestamp: null, deviceId, summary: null, alertId: null, upn: null }]],
    ["get_hunting_table_schema", { table: "DeviceEvents" }, { table: "DeviceEvents", truncated: false, columns: [{ name: null, type: null, description: null }] }],
    ["list_identities", page, [{ name: null, upn, domain: null, sid: null, objectId: null }]],
    ["get_identity", { upn }, { upn, name: null, objectId: null, sid: null, firstSeen: null, lastSeen: null }],
    ["list_pending_actions", page, [action]],
    ["list_action_history", page, [action]],
    ["list_cloud_policies", page, [{ policyId: null, name: null, severity: 1 }]],
];
