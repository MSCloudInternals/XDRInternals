import assert from "node:assert/strict";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../dist/index.js";
import { contracts } from "./fixtures/contracts.mjs";

test("all tool contracts retain strict inputs and bounded projected output", async () => {
    let output;
    const calls = [];
    const server = createServer({ invoke: async (operation, args) => {
        calls.push({ operation, args });
        return output;
    } });
    const client = new Client({ name: "contract-test", version: "1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(st);
        await client.connect(ct);
        const tools = (await client.listTools()).tools;
        assert.equal(tools.length, contracts.length);
        const identitySchema = tools.find(tool => tool.name === "xdr_get_identity").inputSchema;
        assert.deepEqual(Object.keys(identitySchema.properties).sort(), ["objectId", "sid", "upn"]);
        assert.equal(identitySchema.additionalProperties, false);
        for (const [operation, args, valid] of contracts) {
            const name = `xdr_${operation}`;
            output = valid;
            const accepted = await client.callTool({ name, arguments: args });
            assert.ok(!accepted.isError, name);
            assert.deepEqual(accepted.structuredContent.items, valid, name);
            assert.deepEqual(calls.at(-1), { operation, args });
            for (const invalid of [{ ...args, extra: "forbidden" }, ...Object.keys(args).map(key => ({ ...args, [key]: null }))]) {
                const before = calls.length;
                assert.equal((await client.callTool({ name, arguments: invalid })).isError, true, name);
                assert.equal(calls.length, before, `${name} must reject before invoking PowerShell`);
            }
            for (const invalid of [null, Array.isArray(valid) ? [{ ...valid[0], credential: "secret" }] : { ...valid, credential: "secret" }, ...(Array.isArray(valid) ? [Array(2).fill(valid[0])] : [])]) {
                output = invalid;
                const rejected = await client.callTool({ name, arguments: args });
                assert.equal(rejected.isError, true, name);
                assert.equal(rejected.content[0].text, "invalid_response", name);
            }
        }
    } finally {
        await client.close();
        await server.close();
    }
});

test("identity GUID shape and numeric output retain the historical Zod 3 contract", async () => {
    const calls = [];
    let output = [];
    const server = createServer({ invoke: async (operation, args) => { calls.push({ operation, args }); return output; } });
    const client = new Client({ name: "boundary-test", version: "1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(st);
        await client.connect(ct);
        output = contracts.find(([operation]) => operation === "get_identity")[2];
        for (const objectId of ["12345678-1234-1234-1234-123456789abc", "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB", "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"]) {
            assert.ok(!(await client.callTool({ name: "xdr_get_identity", arguments: { objectId } })).isError);
            assert.deepEqual(calls.at(-1).args, { objectId });
        }
        for (const args of [{}, { objectId: "g".repeat(36) }, { objectId: "12345678-1234-1234-1234-123456789abc\n" }, { objectId: "12345678-1234-1234-1234-123456789abc", upn: "analyst@example.test" }]) {
            const before = calls.length;
            assert.equal((await client.callTool({ name: "xdr_get_identity", arguments: args })).isError, true);
            assert.equal(calls.length, before);
        }
        const incident = contracts[0][2][0];
        for (const value of [1, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1, 1e20]) {
            output = [{ ...incident, incidentId: value, alertCount: -value, status: value }];
            assert.ok(!(await client.callTool({ name: "xdr_list_incidents", arguments: contracts[0][1] })).isError);
        }
        for (const value of [0, -1, 1.5]) {
            output = [{ ...incident, incidentId: value }];
            assert.equal((await client.callTool({ name: "xdr_list_incidents", arguments: contracts[0][1] })).content[0].text, "invalid_response");
        }
    } finally {
        await client.close();
        await server.close();
    }
});


test("projected text limits continue to count UTF-16 units", async () => {
    let output;
    const server = createServer({ invoke: async () => output });
    const client = new Client({ name: "text-boundary-test", version: "1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(st);
        await client.connect(ct);
        for (const [operation, args, valid] of contracts) {
            const row = Array.isArray(valid) ? valid[0] : valid;
            for (const [key, value] of Object.entries(row)) {
                // Probe every free-text output field, leaving patterned IDs intact.
                if (value !== null || ["incidentId", "investigationId", "alertCount"].includes(key)) continue;
                const maximum = 500;
                for (const [text, accepted] of [["😀".repeat(maximum / 2), true], ["😀".repeat(maximum / 2 + 1), false], ["x".repeat(maximum + 1), false]]) {
                    const changed = { ...row, [key]: text };
                    output = Array.isArray(valid) ? [changed] : changed;
                    const result = await client.callTool({ name: `xdr_${operation}`, arguments: args });
                    assert.equal(!result.isError, accepted, `${operation}.${key} UTF-16 bound`);
                }
            }
        }
        for (const [operation, key, maximum] of [["get_hunting_table_schema", "table", 80], ["list_user_alert_evidence", "upn", 254]]) {
            const [, args, valid] = contracts.find(([name]) => name === operation);
            for (const [units, accepted] of [[maximum, true], [maximum + 2, false]]) {
                const row = { ...(Array.isArray(valid) ? valid[0] : valid), [key]: "😀".repeat(units / 2) };
                output = Array.isArray(valid) ? [row] : row;
                assert.equal(!(await client.callTool({ name: `xdr_${operation}`, arguments: args })).isError, accepted);
            }
        }
    } finally {
        await client.close();
        await server.close();
    }
});

test("oversized projected collections fail before validating their elements", async () => {
    let visited = 0;
    const tooMany = Array(51).fill(null);
    Object.defineProperty(tooMany, 0, { get() { visited++; return null; } });
    let output = tooMany;
    const server = createServer({ invoke: async () => output });
    const client = new Client({ name: "collection-boundary-test", version: "1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(st);
        await client.connect(ct);
        for (const [name, args] of [["xdr_list_incidents", { days: 7, page: 1, pageSize: 50 }], ["xdr_get_hunting_table_schema", { table: "DeviceEvents" }]]) {
            output = name === "xdr_list_incidents" ? tooMany : { table: "DeviceEvents", truncated: true, columns: tooMany };
            const result = await client.callTool({ name, arguments: args });
            assert.equal(result.content[0].text, "invalid_response");
            assert.equal(visited, 0, "oversized collection must stop before element parsing");
        }
    } finally {
        await client.close();
        await server.close();
    }
});
