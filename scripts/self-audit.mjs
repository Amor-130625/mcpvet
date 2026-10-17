#!/usr/bin/env node
/**
 * Dogfooding script: audit this repository's own example configs and assert the
 * documented outcome.
 *
 * This is what the project asks of other maintainers — "run it in CI, gate on
 * it" — so it runs on itself. Exit code 1 means the documentation and the
 * engine disagree.
 */

import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { audit } from "../src/audit.js";
import { loadFiles } from "../src/loader.js";
import { format } from "../src/report/index.js";
import { computeScore } from "../src/score.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

const VULNERABLE = [
  "examples/vulnerable/claude_desktop_config.json",
  "examples/vulnerable/.cursor/mcp.json",
  "examples/vulnerable/tools.json",
];

const EXPECTED = [
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
 */
async function run(files) {
  const { configs, descriptors, errors } = await loadFiles(
    files.map((file) => ({ file: join(ROOT, file) })),
    { cwd: ROOT },
  );
  return audit({ configs, descriptors, errors }, { cwd: ROOT });
}

const vulnerable = await run(VULNERABLE);
const safe = await run(["examples/safe/mcp.json"]);

const ids = [...new Set(vulnerable.findings.map((finding) => finding.ruleId))].sort();
const missing = EXPECTED.filter((id) => !ids.includes(id));
const unexpected = ids.filter((id) => !EXPECTED.includes(id));

process.stdout.write(format(vulnerable, "pretty", { color: process.stdout.isTTY === true }));
process.stdout.write(format(safe, "pretty", { color: process.stdout.isTTY === true }));

let failed = false;

if (missing.length > 0) {
  process.stderr.write(`self-audit: expected rules did not fire: ${missing.join(", ")}\n`);
  failed = true;
}
if (unexpected.length > 0) {
  process.stderr.write(`self-audit: unexpected rules fired: ${unexpected.join(", ")}\n`);
  failed = true;
}
if (vulnerable.stats.errors !== 0) {
  process.stderr.write(`self-audit: ${vulnerable.stats.errors} example file(s) failed to load\n`);
  failed = true;
}
if (safe.findings.length !== 0) {
  process.stderr.write(`self-audit: the clean example produced ${safe.findings.length} finding(s)\n`);
  failed = true;
}

const { score, grade } = computeScore(vulnerable.findings);
process.stdout.write(
  `\nself-audit: ${vulnerable.findings.length} findings across ${ids.length} rules on the vulnerable example ` +
    `(score ${score}/100, ${grade}); ${safe.findings.length} findings on the clean example.\n`,
);

if (failed) process.exit(1);
process.stdout.write("self-audit: OK\n");
