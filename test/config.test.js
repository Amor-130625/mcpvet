/**
 * Config normalisation tests.
 *
 * Every MCP client invents its own envelope. These tests pin down the mapping
 * so that a change which silently stops reading, say, VS Code's `servers` key
 * fails here rather than in a user's CI.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { detectDocumentKind, extractServers, extractTools, normalizeServer } from "../src/config.js";
import { parseJsonc } from "../src/jsonc.js";

/** @param {string} source */
function load(source) {
  const { value, positions } = parseJsonc(source);
  return { value, positions };
}

test("reads the Claude Desktop envelope", () => {
  const { value, positions } = load('{"mcpServers": {"demo": {"command": "npx", "args": ["-y", "pkg"]}}}');
  const { servers, warnings } = extractServers(value, { file: "c.json", positions });
  assert.equal(warnings.length, 0);
  assert.equal(servers.length, 1);
  assert.equal(servers[0].name, "demo");
  assert.equal(servers[0].transport, "stdio");
  assert.equal(servers[0].command, "npx");
  assert.deepEqual(servers[0].args, ["-y", "pkg"]);
  assert.equal(servers[0].line, 1);
});

test("reads the VS Code envelope with an explicit transport", () => {
  const { value } = load('{"servers": {"docs": {"type": "http", "url": "https://x.example/mcp"}}}');
  const { servers } = extractServers(value);
  assert.equal(servers[0].transport, "http");
  assert.equal(servers[0].url, "https://x.example/mcp");
});

test("reads a servers block nested under mcp", () => {
  const { value } = load('{"mcp": {"servers": {"demo": {"command": "node", "args": ["./s.js"]}}}}');
  const { servers } = extractServers(value);
  assert.equal(servers.length, 1);
  assert.equal(servers[0].command, "node");
});

test("reads an array-shaped server list", () => {
  const { value } = load('{"servers": [{"name": "one", "command": "npx"}, {"name": "two", "url": "https://a.example"}]}');
  const { servers } = extractServers(value);
  assert.deepEqual(servers.map((server) => server.name), ["one", "two"]);
});

test("accepts the command-as-string shorthand", () => {
  const { value } = load('{"mcpServers": {"demo": "npx -y pkg"}}');
  const { servers } = extractServers(value);
  assert.equal(servers[0].command, "npx -y pkg");
});

test("records the line of each server", () => {
  const { value, positions } = load('{\n  "mcpServers": {\n    "demo": {"command": "npx"}\n  }\n}');
  const { servers } = extractServers(value, { positions });
  assert.equal(servers[0].line, 3);
});

test("normalises every auto-approval spelling", () => {
  const variants = [
    { autoApprove: true },
    { autoApprove: ["*"] },
    { autoApprove: ["a", "b"] },
    { alwaysAllow: ["a"] },
    { always_allow: ["a"] },
    { auto_approve: ["a"] },
    { trust: ["a"] },
  ];
  for (const variant of variants) {
    const server = normalizeServer("s", { command: "npx", ...variant }, { pointer: "/s" });
    assert.equal(server.autoApprove.present, true, JSON.stringify(variant));
  }
  assert.equal(normalizeServer("s", { autoApprove: ["*"] }, { pointer: "/s" }).autoApprove.wildcard, true);
  assert.equal(normalizeServer("s", { autoApprove: true }, { pointer: "/s" }).autoApprove.wildcard, true);
  assert.equal(normalizeServer("s", { autoApprove: ["a"] }, { pointer: "/s" }).autoApprove.wildcard, false);
});

test("detects a disabled server", () => {
  assert.equal(normalizeServer("s", { command: "npx", disabled: true }, { pointer: "/s" }).disabled, true);
  assert.equal(normalizeServer("s", { command: "npx", enabled: false }, { pointer: "/s" }).disabled, true);
  assert.equal(normalizeServer("s", { command: "npx" }, { pointer: "/s" }).disabled, false);
});

test("coerces numeric env values but drops nested ones", () => {
  const server = normalizeServer(
    "s",
    { command: "npx", env: { PORT: 8080, FLAG: true, NESTED: { a: 1 }, NULLED: null } },
    { pointer: "/s" },
  );
  assert.equal(server.env.PORT, "8080");
  assert.equal(server.env.FLAG, "true");
  assert.equal(server.env.NESTED, undefined);
  assert.equal(server.env.NULLED, "");
});

test("warns about entries it cannot use, with a line", () => {
  const { value, positions } = load(`{
  "mcpServers": {
    "bad": 42,
    "numeric": {"command": 5},
    "weird": {"command": "npx", "type": "carrier-pigeon"}
  }
}`);
  const { servers, warnings } = extractServers(value, { positions, file: "c.json" });
  const codes = warnings.map((warning) => warning.code).sort();
  assert.deepEqual(codes, ["NON_OBJECT_ENTRY", "NON_STRING_COMMAND", "UNKNOWN_TRANSPORT"]);
  const bad = warnings.find((warning) => warning.code === "NON_OBJECT_ENTRY");
  assert.equal(bad.line, 3);
  assert.equal(servers.length, 3);
});

test("warns when a remote transport also declares a command", () => {
  const { value } = load('{"mcpServers": {"s": {"type": "http", "url": "https://a.example", "command": "npx"}}}');
  const { warnings } = extractServers(value);
  assert.deepEqual(warnings.map((warning) => warning.code), ["CONFLICTING_TRANSPORT"]);
});

test("infers transport from the fields that are present", () => {
  const stdio = normalizeServer("s", { command: "node" }, { pointer: "/s" });
  const remote = normalizeServer("s", { url: "https://a.example" }, { pointer: "/s" });
  const neither = normalizeServer("s", {}, { pointer: "/s" });
  assert.equal(stdio.transport, "stdio");
  assert.equal(remote.transport, "http");
  assert.equal(neither.transport, "unknown");
});

test("classifies documents", () => {
  assert.equal(detectDocumentKind({ mcpServers: {} }), "config");
  assert.equal(detectDocumentKind({ servers: {} }), "config");
  assert.equal(detectDocumentKind({ mcp: { servers: {} } }), "config");
  assert.equal(detectDocumentKind({ tools: [] }), "tools");
  assert.equal(detectDocumentKind({ result: { tools: [] } }), "tools");
  assert.equal(detectDocumentKind([]), "tools");
  assert.equal(detectDocumentKind({ version: 1 }), "unknown");
  assert.equal(detectDocumentKind(null), "unknown");
});

test("extracts tools from a raw tools/list response", () => {
  const { value, positions } = load(`{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {"name": "read_file", "description": "Read it.", "inputSchema": {"type": "object"}},
      {"name": "write_file", "description": "Write it.", "annotations": {"readOnlyHint": false}}
    ]
  }
}`);
  const tools = extractTools(value, { positions, server: "demo" });
  assert.equal(tools.length, 2);
  assert.equal(tools[0].name, "read_file");
  assert.equal(tools[0].server, "demo");
  assert.equal(tools[1].annotations.readOnlyHint, false);
  assert.equal(tools[0].line, 6);
});

test("ignores non-object tool entries", () => {
  const tools = extractTools({ tools: ["nope", { name: "ok" }] });
  assert.equal(tools.length, 1);
  assert.equal(tools[0].name, "ok");
});
