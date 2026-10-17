/**
 * Formatter tests.
 *
 * SARIF is validated structurally — a report GitHub rejects is worse than no
 * report, because it fails the upload step and hides the findings.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { audit } from "../src/audit.js";
import { normalizeServer } from "../src/config.js";
import { format, FORMATS } from "../src/report/index.js";
import { NAME, VERSION } from "../src/version.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

const HEX_SECRET = "a8f5f167f44f4964e6c998dee827110c9c1b3e4a2d5f6071";
const JWT =
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

function sampleResult() {
  const servers = [
    normalizeServer(
      "shell",
      { command: "npx", args: ["-y", "mcp-server-shell"], autoApprove: ["*"], env: { K: HEX_SECRET } },
      { file: "config.json", pointer: "/mcpServers/shell", positions: new Map([["/mcpServers/shell", { line: 4, column: 5 }]]) },
    ),
    normalizeServer(
      "remote",
      { type: "http", url: `http://x.example/mcp?token=${JWT}` },
      { file: "config.json", pointer: "/mcpServers/remote", positions: new Map() },
    ),
  ];
  return audit({ configs: [{ file: "config.json", kind: "config", servers, warnings: [] }] }, { cwd: "/repo" });
}

test("every advertised format renders and is non-empty", () => {
  const result = sampleResult();
  for (const name of FORMATS) {
    const output = format(result, name, { color: false });
    assert.ok(typeof output === "string" && output.length > 0, `${name} produced nothing`);
  }
});

test("an unknown format is rejected with the list of valid ones", () => {
  assert.throws(() => format(sampleResult(), "yaml"), /Unknown format/);
});

test("pretty output contains no ANSI escapes when colour is off", () => {
  const output = format(sampleResult(), "pretty", { color: false });
  assert.ok(!output.includes("\u001b["));
  assert.match(output, /MCP040/);
  assert.match(output, /Summary/);
});

test("pretty output is coloured when asked", () => {
  const output = format(sampleResult(), "pretty", { color: true });
  assert.ok(output.includes("\u001b["));
});

test("pretty output says so when there is nothing to report", () => {
  const empty = audit({});
  assert.match(format(empty, "pretty", { color: false }), /No findings/);
});

test("no format leaks a credential", () => {
  const result = sampleResult();
  for (const name of FORMATS) {
    const output = format(result, name, { color: false });
    assert.ok(!output.includes(HEX_SECRET), `${name} leaked the env secret`);
    assert.ok(!output.includes(JWT), `${name} leaked the JWT`);
  }
});

test("JSON report has the documented shape", () => {
  const payload = JSON.parse(format(sampleResult(), "json"));
  assert.equal(payload.tool.name, NAME);
  assert.equal(payload.tool.version, VERSION);
  assert.ok(typeof payload.generatedAt === "string");
  assert.equal(payload.summary.findings, payload.findings.length);
  assert.equal(payload.summary.passed, payload.findings.length === 0);
  assert.equal(typeof payload.summary.score, "number");
  assert.ok(Array.isArray(payload.findings));
  const finding = payload.findings[0];
  for (const key of ["ruleId", "title", "category", "severity", "message", "file", "line", "remediation", "fingerprint"]) {
    assert.ok(key in finding, `finding is missing ${key}`);
  }
});

test("SARIF report is structurally valid", () => {
  const sarif = JSON.parse(format(sampleResult(), "sarif"));
  assert.equal(sarif.version, "2.1.0");
  assert.match(sarif.$schema, /sarif-2\.1\.0/);
  assert.equal(sarif.runs.length, 1);

  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, NAME);
  assert.equal(run.tool.driver.version, VERSION);
  assert.ok(Array.isArray(run.tool.driver.rules));
  assert.ok(run.tool.driver.rules.length > 0);
  assert.ok(Array.isArray(run.results));
  assert.ok(run.results.length > 0);

  const ruleIds = run.tool.driver.rules.map((rule) => rule.id);
  assert.equal(new Set(ruleIds).size, ruleIds.length, "duplicate rules in driver");

  for (const result of run.results) {
    assert.ok(ruleIds.includes(result.ruleId), `result references unknown rule ${result.ruleId}`);
    assert.equal(run.tool.driver.rules[result.ruleIndex].id, result.ruleId, "ruleIndex does not point at ruleId");
    assert.ok(["error", "warning", "note", "none"].includes(result.level));
    assert.ok(typeof result.message.text === "string" && result.message.text.length > 0);
    assert.ok(typeof result.partialFingerprints["mcpvet/finding/v1"] === "string");
    for (const location of result.locations) {
      assert.ok(typeof location.physicalLocation.artifactLocation.uri === "string");
      assert.ok(location.physicalLocation.region.startLine >= 1);
      assert.ok(location.physicalLocation.region.startColumn >= 1);
    }
  }
});

test("SARIF maps high and critical findings to error", () => {
  const sarif = JSON.parse(format(sampleResult(), "sarif"));
  const byId = new Map(sarif.runs[0].tool.driver.rules.map((rule) => [rule.id, rule]));
  assert.equal(byId.get("MCP040").defaultConfiguration.level, "error"); // critical
  assert.equal(byId.get("MCP020").defaultConfiguration.level, "warning"); // medium
});

test("SARIF converts Windows-style paths to URL-safe URIs", () => {
  const server = normalizeServer("s", { command: "npx", args: ["-y", "pkg"] }, { file: "C:\\repo dir\\mcp.json", pointer: "/x" });
  const result = audit({ configs: [{ file: "C:\\repo dir\\mcp.json", kind: "config", servers: [server], warnings: [] }] });
  const sarif = JSON.parse(format(result, "sarif"));
  const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  assert.ok(uri.startsWith("file:///"), uri);
  assert.ok(!uri.includes("\\"), uri);
  assert.ok(!uri.includes(" "), uri);
});

test("the JSON report matches the published schema key for key", () => {
  const schema = JSON.parse(readFileSync(join(ROOT, "schema", "report.schema.json"), "utf8"));
  const payload = JSON.parse(format(sampleResult(), "json"));

  const keysOf = (object) => Object.keys(object).sort();
  const schemaKeys = (node) => Object.keys(node.properties ?? {}).sort();

  assert.deepEqual(keysOf(payload), schemaKeys(schema));
  assert.deepEqual(keysOf(payload.summary), schemaKeys(schema.properties.summary));
  assert.deepEqual(keysOf(payload.summary.counts), schemaKeys(schema.properties.summary.properties.counts));
  assert.deepEqual(keysOf(payload.stats), schemaKeys(schema.properties.stats));
  assert.deepEqual(keysOf(payload.tool), schemaKeys(schema.properties.tool));
  for (const finding of payload.findings) {
    assert.deepEqual(keysOf(finding), schemaKeys(schema.properties.findings.items));
  }
  for (const required of schema.required) assert.ok(required in payload, `missing required ${required}`);
});

test("markdown report renders a table with one row per finding", () => {
  const result = sampleResult();
  const output = format(result, "markdown");
  assert.match(output, /## mcpvet report/);
  assert.match(output, /^\| Severity \| Rule \| Location \| Finding \|$/m);
  const rows = output.split("\n").filter((line) => line.startsWith("| ") && line.includes("`MCP"));
  assert.equal(rows.length, Math.min(result.findings.length, 50));
});

test("every markdown table row has exactly four cells", () => {
  const server = normalizeServer("s", { command: "node", args: ["a && b | c"] }, { file: "c.json", pointer: "/x" });
  const result = audit({ configs: [{ file: "c.json", kind: "config", servers: [server], warnings: [] }] });
  const output = format(result, "markdown");
  const rows = output.split("\n").filter((line) => line.startsWith("| ") && !line.startsWith("| ---") && !line.startsWith("| Severity"));
  assert.ok(rows.length > 0);
  for (const row of rows) {
    // Split on unescaped pipes only.
    const cells = row.split(/(?<!\\)\|/).slice(1, -1);
    assert.equal(cells.length, 4, `row has ${cells.length} cells: ${row}`);
  }
});
