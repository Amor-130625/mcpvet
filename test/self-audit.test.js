/**
 * Self-audit: run mcpvet over the repository's own example configs.
 *
 * This is the test that keeps the documentation honest. If a rule stops firing,
 * or starts firing on the clean example, the README and `docs/rules.md` are
 * wrong — so the build fails.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { audit } from "../src/audit.js";
import { loadFiles } from "../src/loader.js";
import { FORMATS, format } from "../src/report/index.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

const VULNERABLE_FILES = [
  "examples/vulnerable/claude_desktop_config.json",
  "examples/vulnerable/.cursor/mcp.json",
  "examples/vulnerable/tools.json",
];

/** The rule ids the vulnerable example is expected to trip. */
const EXPECTED_RULES = [
  "MCP001",
  "MCP010",
  "MCP012",
  "MCP020",
  "MCP022",
  "MCP023",
  "MCP030",
  "MCP031",
  "MCP034",
  "MCP040",
  "MCP041",
  "MCP050",
  "MCP051",
  "MCP060",
  "MCP061",
];

/**
 * @param {string[]} files
 * @returns {Promise<ReturnType<typeof audit>>}
 */
async function auditExamples(files) {
  const { configs, descriptors, errors } = await loadFiles(
    files.map((file) => ({ file: join(ROOT, file) })),
    { cwd: ROOT },
  );
  return audit({ configs, descriptors, errors }, { cwd: ROOT });
}

test("the vulnerable example trips exactly the documented rule set", async () => {
  const result = await auditExamples(VULNERABLE_FILES);
  assert.deepEqual(result.stats.errors, 0);
  const ids = [...new Set(result.findings.map((finding) => finding.ruleId))].sort();
  assert.deepEqual(ids, EXPECTED_RULES);
});

test("every finding in the example has a real line number", async () => {
  const result = await auditExamples(VULNERABLE_FILES);
  for (const finding of result.findings) {
    if (finding.file === null) continue; // scan-level rules have no single file
    assert.ok(Number.isInteger(finding.line) && finding.line >= 1, `${finding.ruleId} has no line`);
    assert.ok(Number.isInteger(finding.column) && finding.column >= 1, `${finding.ruleId} has no column`);
  }
});

test("the clean example produces no findings", async () => {
  const result = await auditExamples(["examples/safe/mcp.json"]);
  assert.deepEqual(result.findings, []);
  assert.equal(result.stats.errors, 0);
});

test("no example finding leaks the synthetic credentials", async () => {
  const result = await auditExamples(VULNERABLE_FILES);
  const source = VULNERABLE_FILES.map((file) => readFileSync(join(ROOT, file), "utf8")).join("\n");
  const secrets = [
    "a8f5f167f44f4964e6c998dee827110c9c1b3e4a2d5f6071",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  ];
  for (const secret of secrets) {
    assert.ok(source.includes(secret), "test setup: the example should contain the secret");
    for (const name of FORMATS) {
      const rendered = format(result, name, { color: false });
      assert.ok(!rendered.includes(secret), `${name} leaked a secret`);
    }
  }
});

test("the vulnerable example scores zero and the clean one scores one hundred", async () => {
  const bad = await auditExamples(VULNERABLE_FILES);
  const good = await auditExamples(["examples/safe/mcp.json"]);
  const badJson = JSON.parse(format(bad, "json"));
  const goodJson = JSON.parse(format(good, "json"));
  assert.equal(badJson.summary.score, 0);
  assert.equal(badJson.summary.grade, "F");
  assert.equal(goodJson.summary.score, 100);
  assert.equal(goodJson.summary.grade, "A");
});

test("the documented example counts stay true", async () => {
  // README quotes these numbers; keep them pinned here so a rule change cannot
  // silently make the documentation wrong.
  const result = await auditExamples(VULNERABLE_FILES);
  const json = JSON.parse(format(result, "json"));
  assert.equal(json.stats.files, 3);
  assert.equal(json.stats.servers, 6);
  assert.equal(json.stats.tools, 4);
  assert.equal(json.summary.counts.critical, 4);
  assert.ok(json.summary.counts.high >= 6);
  assert.ok(json.summary.counts.medium >= 8);
});
