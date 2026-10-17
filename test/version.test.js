/**
 * Registry integrity.
 *
 * A security tool that silently drops a rule is dangerous in a way an ordinary
 * library is not: the report says "clean" and the human believes it. These
 * tests make the rule set's consistency part of the build.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { RULES, RULES_BY_ID, getRule, listRules, validateRules } from "../src/rules/index.js";
import { NAME, VERSION, HOMEPAGE } from "../src/version.js";
import { SEVERITY_ORDER } from "../src/severity.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

test("VERSION matches package.json", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.equal(VERSION, pkg.version);
  assert.equal(NAME, pkg.name);
  assert.equal(pkg.dependencies && Object.keys(pkg.dependencies).length, 0, "runtime dependencies must stay empty");
  assert.equal(
    pkg.devDependencies && Object.keys(pkg.devDependencies).length,
    0,
    "devDependencies must stay empty",
  );
});

test("the rule set validates", () => {
  assert.deepEqual(validateRules(RULES), []);
});

test("rule ids are unique and well formed", () => {
  const ids = RULES.map((rule) => rule.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const id of ids) assert.match(id, /^MCP\d{3}$/);
});

test("every rule declares a severity from the vocabulary", () => {
  for (const rule of RULES) {
    assert.ok(SEVERITY_ORDER.includes(rule.severity), `${rule.id} has severity ${rule.severity}`);
  }
});

test("every rule documents why it exists and how to fix it", () => {
  for (const rule of RULES) {
    assert.ok(rule.why.length > 80, `${rule.id} needs a real rationale`);
    assert.ok(rule.remediation.length > 20, `${rule.id} needs a real remediation`);
    assert.ok(rule.summary.length > 10, `${rule.id} needs a summary`);
  }
});

test("validateRules catches the mistakes it claims to catch", () => {
  const broken = [
    { ...RULES[0], id: "NOPE" },
    { ...RULES[1], severity: "apocalyptic" },
    { ...RULES[2], target: "moon" },
    { ...RULES[3], check: "not a function" },
    { ...RULES[4], why: "" },
  ];
  const problems = validateRules(broken);
  assert.ok(problems.some((problem) => problem.includes("not of the form")));
  assert.ok(problems.some((problem) => problem.includes("invalid severity")));
  assert.ok(problems.some((problem) => problem.includes("invalid target")));
  assert.ok(problems.some((problem) => problem.includes("no check()")));
  assert.ok(problems.some((problem) => problem.includes('missing "why"')));
});

test("validateRules catches duplicate ids", () => {
  const problems = validateRules([RULES[0], RULES[0]]);
  assert.ok(problems.some((problem) => problem.includes("Duplicate")));
});

test("lookups work and are case insensitive", () => {
  assert.equal(getRule("MCP001").id, "MCP001");
  assert.equal(getRule("mcp001").id, "MCP001");
  assert.equal(getRule("MCP999"), undefined);
  assert.equal(RULES_BY_ID.size, RULES.length);
});

test("listRules is sorted by id and returns a copy", () => {
  const rules = listRules();
  const ids = rules.map((rule) => rule.id);
  assert.deepEqual(ids, [...ids].sort());
  rules.pop();
  assert.equal(RULES.length > 0 && listRules().length, RULES.length);
});

test("the homepage is a real URL", () => {
  assert.match(HOMEPAGE, /^https:\/\//);
});
