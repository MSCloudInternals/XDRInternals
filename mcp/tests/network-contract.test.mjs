import assert from "node:assert/strict";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../dist/index.js";

const longestDomain = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
// Include historical IP-text values that are intentionally looser than real IP parsing.
const validNetworkArguments = [
    ...["127.0.0.1", "2001:db8::1", "abc", "...", ":::", "a".repeat(45)].map(value => ({ kind: "ip", value, pageSize: 1 })),
    ...["a.ab", "EXAMPLE.test", "a-b.example.test", longestDomain].map(value => ({ kind: "domain", value, pageSize: 50 })),
];
const invalidNetworkArguments = [
    ...["ab", "a".repeat(46), "example.test", "127.0.0.1/32", "[::1]", "abc\n"].map(value => ({ kind: "ip", value, pageSize: 1 })),
    ...["127.0.0.1", "localhost", "-a.example", "a-.example", "a.a", "a." + "b".repeat(64), "a".repeat(64) + ".test", longestDomain + "a", "example.test.", "https://example.test", "example.test\n", "éxample.test"].map(value => ({ kind: "domain", value, pageSize: 1 })),
    ...[0, 51, -1, 1.5, "1", null].map(pageSize => ({ kind: "ip", value: "127.0.0.1", pageSize })),
    { kind: "IP", value: "127.0.0.1", pageSize: 1 },
    { kind: "url", value: "example.test", pageSize: 1 },
    { kind: "ip", value: null, pageSize: 1 },
    { kind: "ip", value: 123, pageSize: 1 },
    { kind: "ip", value: "127.0.0.1", pageSize: 1, OutputPath: "/tmp/forbidden" },
    { value: "127.0.0.1", pageSize: 1 },
    { kind: "ip", pageSize: 1 },
    { kind: "ip", value: "127.0.0.1" },
    { Kind: "ip", value: "127.0.0.1", pageSize: 1 },
    {},
];

test("network tool discovery exposes required fields and runtime retains both branch contracts", async () => {
    const calls = [];
    const projected = [{ timestamp: null, deviceId: null, remoteIp: null, remoteUrl: null }];
    const server = createServer({ invoke: async (operation, args) => { calls.push({ operation, args }); return projected; } });
    const client = new Client({ name: "network-contract-test", version: "1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    try {
        await server.connect(st);
        await client.connect(ct);
        const tool = (await client.listTools()).tools.find(tool => tool.name === "xdr_list_network_observations");
        assert.equal(tool.inputSchema.type, "object");
        assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), ["kind", "pageSize", "value"]);
        assert.deepEqual([...tool.inputSchema.required].sort(), ["kind", "pageSize", "value"]);
        assert.equal(tool.inputSchema.additionalProperties, false);
        assert.deepEqual(tool.inputSchema.properties.kind.enum, ["ip", "domain"]);
        assert.equal(tool.inputSchema.properties.value.type, "string");
        assert.match(tool.inputSchema.properties.value.description, /253/);
        assert.deepEqual(tool.inputSchema.properties.pageSize, { type: "integer", minimum: 1, maximum: 50 });
        for (const args of validNetworkArguments) {
            const result = await client.callTool({ name: tool.name, arguments: args });
            assert.ok(!result.isError, JSON.stringify(args));
            assert.deepEqual(result.structuredContent.items, projected);
            assert.deepEqual(calls.at(-1), { operation: "list_network_observations", args });
        }
        for (const args of invalidNetworkArguments) {
            const before = calls.length;
            assert.equal((await client.callTool({ name: tool.name, arguments: args })).isError, true, JSON.stringify(args));
            assert.equal(calls.length, before, "invalid arguments must not reach the bridge");
        }
    } finally {
        await client.close();
        await server.close();
    }
});
