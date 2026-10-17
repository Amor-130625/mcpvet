/**
 * Audit runner tests: filtering, ordering, and the guarantees a caller can rely
 * on regardless of which rules exist.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { audit } from "../src/audit.js";
import { normalizeServer } from "../src/config.js";

const HEX_SECRET = "a8f5f167f44f4964e6c998dee827110c9c1b3e4a2d5f6071";

/** @param {any} entry @param {string} name */
function server(entry, name = "s") {
  return normalizeServer(name, entry, { file: "c.json", pointer: `/mcpServers/${name}`, positions: new Map(), warnings: [] });
}

/** @param {any[]} servers */
function run(servers, options = {}) {
  return audit({ configs: [{ file: "c.json", kind: "config", servers, warnings: [] }] }, options);
}

test("an empty input produces an empty, well-formed result", () => {
  const result = audit({});
  assert.deepEqual(result.findings, []);
  assert.equal(result.stats.files, 0);
  assert.equal(result.stats.servers, 0);
  assert.ok(result.stats.rules > 0);
});

test("findings are sorted by severity, then location", () => {
  const result = run([
    server({ command: "npx", args: ["-y", "pkg"] }, "a"),
    server({ command: "npx", args: ["-y", "pkg"], autoApprove: ["*"] }, "b"),
  ]);
  const severities = result.findings.map((finding) => finding.severity);
  const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  for (let index = 1; index < severities.length; index += 1) {
    assert.ok(rank[severities[index - 1]] >= rank[severities[index]], `misordered at ${index}`);
  }
});

test("--ignore removes a rule entirely", () => {
  const entry = { command: "npx", args: ["-y", "pkg"], autoApprove: ["*"] };
  const everything = run([server(entry)]);
  const without = run([server(entry)], { ignore: ["MCP040"] });
  assert.ok(everything.findings.some((finding) => finding.ruleId === "MCP040"));
  assert.ok(!without.findings.some((finding) => finding.ruleId === "MCP040"));
});

test("--min-severity drops low-impact findings", () => {
  const entry = { command: "npx", args: ["-y", "pkg"] }; // medium
  assert.ok(run([server(entry)], { minSeverity: "high" }).findings.length === 0);
  assert.ok(run([server(entry)], { minSeverity: "medium" }).findings.length > 0);
});

test("duplicate findings collapse onto one fingerprint", () => {
  // The same tool listed twice in one descriptor is one problem, not two: the
  // fingerprint is rule + location identity + evidence key, with no index.
  const tool = {
    name: "t",
    description: "Run a command.",
    inputSchema: { type: "object", properties: { command: { type: "string" } } },
    server: "srv",
    file: "tools.json",
    pointer: "/tools/0",
  };
  const once = audit({ descriptors: [{ file: "tools.json", kind: "tools", tools: [{ ...tool }] }] });
  const twice = audit({ descriptors: [{ file: "tools.json", kind: "tools", tools: [{ ...tool }, { ...tool, pointer: "/tools/1" }] }] });
  assert.equal(twice.findings.length, once.findings.length);
  const fingerprints = new Set(twice.findings.map((finding) => finding.fingerprint));
  assert.equal(fingerprints.size, twice.findings.length);
});

test("stats describe the scanned surface", () => {
  const result = run([server({ command: "node", args: ["./a.js"] }, "a"), server({ command: "node" }, "b")]);
  assert.equal(result.stats.files, 1);
  assert.equal(result.stats.servers, 2);
  assert.equal(result.stats.configs, 1);
  assert.equal(result.stats.descriptors, 0);
});

test("a disabled server is still audited", () => {
  // "Disabled today" is not a security boundary: the next edit can enable it.
  const result = run([server({ command: "npx", args: ["-y", "pkg"], disabled: true, autoApprove: ["*"] })]);
  assert.ok(result.findings.some((finding) => finding.ruleId === "MCP040"));
  assert.equal(result.stats.disabledServers, 1);
});

test("every finding carries the metadata formatters need", () => {
  const result = run([server({ command: "npx", args: ["-y", "pkg"], env: { K: HEX_SECRET } })]);
  assert.ok(result.findings.length > 0);
  for (const finding of result.findings) {
    assert.match(finding.ruleId, /^MCP\d{3}$/);
    assert.ok(typeof finding.title === "string" && finding.title.length > 0);
    assert.ok(typeof finding.category === "string");
    assert.ok(typeof finding.severity === "string");
    assert.ok(typeof finding.message === "string" && finding.message.length > 0);
    assert.ok(typeof finding.remediation === "string" && finding.remediation.length > 0);
    assert.ok(Array.isArray(finding.references));
    assert.match(finding.fingerprint, /^[0-9a-f]{16}$/);
  }
});

test("no finding carries a live credential in any field", () => {
  const result = run([server({ command: "npx", args: ["-y", "pkg"], env: { K: HEX_SECRET } })]);
  const serialised = JSON.stringify(result.findings);
  assert.ok(!serialised.includes(HEX_SECRET));
});
