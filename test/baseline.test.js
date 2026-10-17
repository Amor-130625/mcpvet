/**
 * Baseline and score tests.
 *
 * The property that makes a baseline usable over time is fingerprint stability:
 * editing an unrelated line must not resurrect an accepted finding, and changing
 * the offending configuration must.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { audit } from "../src/audit.js";
import { extractServers } from "../src/config.js";
import { parseJsonc } from "../src/jsonc.js";
import {
  BASELINE_VERSION,
  applyBaseline,
  buildBaseline,
  parseBaseline,
  updateBaseline,
} from "../src/baseline.js";
import { computeScore, gradeFor, summarise } from "../src/score.js";

/** @param {string} source */
function findingsFor(source, file = "c.json") {
  const { value, positions } = parseJsonc(source);
  const { servers } = extractServers(value, { file, positions });
  return audit({ configs: [{ file, kind: "config", servers, warnings: [] }] }).findings;
}

const CONFIG = '{"mcpServers": {"s": {"command": "npx", "args": ["-y", "pkg"]}}}';
const CONFIG_SHIFTED = '{\n  // a comment added above the finding\n  "mcpServers": {"s": {"command": "npx", "args": ["-y", "pkg"]}}}';
const CONFIG_CHANGED = '{"mcpServers": {"s": {"command": "npx", "args": ["-y", "other-pkg"]}}}';

test("fingerprints survive a line shift", () => {
  const first = findingsFor(CONFIG);
  const shifted = findingsFor(CONFIG_SHIFTED);

  assert.ok(first.length > 0);
  assert.notEqual(first[0].line, shifted[0].line, "test setup: lines should differ");
  assert.deepEqual(
    first.map((finding) => finding.fingerprint).sort(),
    shifted.map((finding) => finding.fingerprint).sort(),
  );
});

test("fingerprints change when the offending configuration changes", () => {
  const first = findingsFor(CONFIG);
  const changed = findingsFor(CONFIG_CHANGED);
  const before = new Set(first.map((finding) => finding.fingerprint));
  const after = changed.map((finding) => finding.fingerprint);
  assert.ok(after.some((fingerprint) => !before.has(fingerprint)));
});

test("a baseline records every finding once", () => {
  const findings = findingsFor(CONFIG);
  const baseline = buildBaseline(findings, { generatedAt: "2026-01-01T00:00:00.000Z" });
  assert.equal(baseline.version, BASELINE_VERSION);
  assert.equal(baseline.count, findings.length);
  assert.equal(new Set(baseline.entries.map((entry) => entry.fingerprint)).size, findings.length);
  assert.equal(baseline.generatedAt, "2026-01-01T00:00:00.000Z");
});

test("applying a baseline separates new findings from accepted ones", () => {
  const findings = findingsFor(CONFIG);
  const baseline = buildBaseline(findings);
  const applied = applyBaseline(findings, baseline);
  assert.equal(applied.newFindings.length, 0);
  assert.equal(applied.suppressed.length, findings.length);
});

test("a finding absent from the baseline is reported as new", () => {
  const findings = findingsFor(CONFIG_CHANGED);
  const baseline = buildBaseline(findingsFor(CONFIG));
  const applied = applyBaseline(findings, baseline);
  assert.ok(applied.newFindings.length > 0);
});

test("an empty or missing baseline accepts nothing", () => {
  const findings = findingsFor(CONFIG);
  assert.equal(applyBaseline(findings, null).newFindings.length, findings.length);
  assert.equal(applyBaseline(findings, { entries: [] }).newFindings.length, findings.length);
});

test("updating a baseline reports additions and removals", () => {
  const first = findingsFor(CONFIG);
  const second = findingsFor(CONFIG_CHANGED);
  const { baseline, added, removed } = updateBaseline(second, buildBaseline(first));
  assert.ok(added > 0, "the changed package is a new fingerprint");
  assert.ok(removed > 0, "the old package fingerprint is gone");
  assert.equal(baseline.count, second.length);
});

test("parseBaseline rejects malformed baselines with a reason", () => {
  assert.equal(parseBaseline("not json").ok, false);
  assert.equal(parseBaseline('{"version": 999, "entries": []}').ok, false);
  assert.equal(parseBaseline('{"version": 1}').ok, false);
  assert.equal(parseBaseline('{"version": 1, "entries": [{}]}').ok, false);
  assert.equal(parseBaseline('{"version": 1, "entries": []}').ok, true);
});

test("the score follows the documented formula", () => {
  assert.deepEqual(computeScore([]), { score: 100, grade: "A", penalty: 0, counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } });
  assert.equal(computeScore([{ severity: "critical" }]).score, 75);
  assert.equal(computeScore([{ severity: "high" }]).score, 88);
  assert.equal(computeScore([{ severity: "medium" }]).score, 95);
  assert.equal(computeScore([{ severity: "low" }]).score, 98);
  assert.equal(computeScore([{ severity: "info" }]).score, 100);
});

test("the score never goes below zero", () => {
  const findings = Array.from({ length: 20 }, () => ({ severity: "critical" }));
  assert.equal(computeScore(findings).score, 0);
  assert.equal(computeScore(findings).grade, "F");
});

test("grades map to the documented bands", () => {
  assert.equal(gradeFor(90), "A");
  assert.equal(gradeFor(89), "B");
  assert.equal(gradeFor(80), "B");
  assert.equal(gradeFor(79), "C");
  assert.equal(gradeFor(70), "C");
  assert.equal(gradeFor(60), "D");
  assert.equal(gradeFor(59), "F");
});

test("summarise describes an empty and a non-empty result", () => {
  assert.match(summarise([]), /No findings/);
  const text = summarise([{ severity: "critical" }, { severity: "medium" }]);
  assert.match(text, /2 findings/);
  assert.match(text, /Trust score 70\/100 \(C\)/);
});
