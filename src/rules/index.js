/**
 * The rule registry.
 *
 * Importing this module validates the rule set once, at load time. A duplicate
 * id, a missing `why`, or an unrecognised severity becomes an immediate crash
 * instead of a report that silently omits a check — which is the failure mode
 * that matters for a security tool.
 *
 * @module rules
 */

import { supplyChainRules } from "./supply-chain.js";
import { credentialRules } from "./credentials.js";
import { transportRules } from "./transport.js";
import { capabilityRules } from "./capability.js";
import { postureRules } from "./posture.js";
import { injectionRules } from "./injection.js";
import { schemaRules } from "./schema.js";
import { configShapeRules } from "./config-shape.js";
import { SEVERITY_ORDER } from "../severity.js";

/** @type {import("./types.js").Rule[]} */
export const RULES = [
  ...supplyChainRules,
  ...credentialRules,
  ...transportRules,
  ...capabilityRules,
  ...postureRules,
  ...injectionRules,
  ...schemaRules,
  ...configShapeRules,
];

const VALID_TARGETS = new Set(["server", "tool", "scan", "warning", "error"]);
const VALID_CATEGORIES = new Set([
  "supply-chain",
  "credentials",
  "transport",
  "capability",
  "posture",
  "injection",
  "schema",
  "configuration",
]);

/**
 * @param {import("./types.js").Rule[]} rules
 * @returns {string[]} problems found in the rule set (empty when valid)
 */
export function validateRules(rules) {
  /** @type {string[]} */
  const problems = [];
  /** @type {Set<string>} */
  const seen = new Set();

  for (const rule of rules) {
    if (!/^MCP\d{3}$/.test(rule.id ?? "")) problems.push(`Rule id ${JSON.stringify(rule.id)} is not of the form MCPnnn.`);
    if (seen.has(rule.id)) problems.push(`Duplicate rule id ${rule.id}.`);
    seen.add(rule.id);
    for (const field of ["title", "summary", "why", "remediation"]) {
      if (typeof rule[field] !== "string" || rule[field].trim() === "") {
        problems.push(`Rule ${rule.id} is missing "${field}".`);
      }
    }
    if (!SEVERITY_ORDER.includes(rule.severity)) problems.push(`Rule ${rule.id} has invalid severity ${JSON.stringify(rule.severity)}.`);
    if (!VALID_TARGETS.has(rule.target)) problems.push(`Rule ${rule.id} has invalid target ${JSON.stringify(rule.target)}.`);
    if (!VALID_CATEGORIES.has(rule.category)) problems.push(`Rule ${rule.id} has invalid category ${JSON.stringify(rule.category)}.`);
    if (typeof rule.check !== "function") problems.push(`Rule ${rule.id} has no check().`);
    if (rule.references !== undefined && !Array.isArray(rule.references)) {
      problems.push(`Rule ${rule.id} references must be an array.`);
    }
  }
  return problems;
}

const problems = validateRules(RULES);
if (problems.length > 0) {
  throw new Error(`Invalid rule set:\n  - ${problems.join("\n  - ")}`);
}

/** @type {Map<string, import("./types.js").Rule>} */
export const RULES_BY_ID = new Map(RULES.map((rule) => [rule.id, rule]));

/**
 * @param {string} id
 * @returns {import("./types.js").Rule|undefined}
 */
export function getRule(id) {
  return RULES_BY_ID.get(String(id).toUpperCase());
}

/** All rules, sorted by id (which groups them by category automatically). */
export function listRules() {
  return [...RULES].sort((a, b) => (a.id < b.id ? -1 : 1));
}

/** Risk score a rule contributes when it fires, used by the trust score. */
export function ruleWeight(rule, severity) {
  return ruleWeightBySeverity(severity ?? rule.severity);
}

/** @param {import("../severity.js").Severity} severity */
export function ruleWeightBySeverity(severity) {
  /** @type {Record<string, number>} */
  const weights = { critical: 25, high: 12, medium: 5, low: 2, info: 0 };
  return weights[severity] ?? 0;
}
