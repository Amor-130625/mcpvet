/**
 * Finding construction and stable fingerprinting.
 *
 * The fingerprint is the load-bearing piece for CI adoption. It has to stay
 * identical when a developer adds a comment above the offending line (line
 * numbers move) but differ when the offending configuration itself changes
 * (a second unpinned package is a genuinely new risk). So it is derived from
 * rule id + location identity + a normalised evidence key, and never from line
 * numbers.
 *
 * @module findings
 */

import { createHash } from "node:crypto";
import { truncate } from "./util.js";
import { redact } from "./secrets.js";

/**
 * @typedef {object} Finding
 * @property {string} ruleId
 * @property {string} title
 * @property {string} category
 * @property {import("./severity.js").Severity} severity
 * @property {string} message
 * @property {string|null} file
 * @property {number|null} line
 * @property {number|null} column
 * @property {string|null} server
 * @property {string|null} tool
 * @property {string|null} evidence
 * @property {string|null} detail
 * @property {string} remediation
 * @property {string[]} references
 * @property {string} fingerprint
 */

/**
 * Normalise an evidence string before hashing so cosmetic edits (redaction
 * markers, whitespace, truncation) do not churn the baseline.
 *
 * @param {string} text
 */
function normaliseEvidence(text) {
  return String(text ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

/**
 * @param {{ruleId: string, file?: string|null, server?: string|null, tool?: string|null, key?: string}} input
 * @returns {string} 16 hex characters
 */
export function fingerprintFor({ ruleId, file = null, server = null, tool = null, key = "" }) {
  const material = [ruleId, file ?? "", server ?? "", tool ?? "", normaliseEvidence(key)].join("\u0000");
  return createHash("sha256").update(material).digest("hex").slice(0, 16);
}

/**
 * Build a complete finding from a rule and a rule's partial result.
 *
 * @param {import("./rules/types.js").Rule} rule
 * @param {import("./rules/types.js").RuleHit} hit
 * @param {{file?: string|null, server?: string|null, tool?: string|null, line?: number|null, column?: number|null}} location
 * @returns {Finding}
 */
export function createFinding(rule, hit, location) {
  const file = location.file ?? null;
  const server = location.server ?? null;
  const tool = location.tool ?? null;
  const line = hit.line ?? location.line ?? null;
  const column = hit.column ?? location.column ?? null;
  const evidence = hit.evidence === undefined || hit.evidence === null ? null : truncate(redact(String(hit.evidence)), 240);

  return {
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: hit.severity ?? rule.severity,
    message: truncate(redact(hit.message), 400),
    file,
    line,
    column,
    server,
    tool,
    evidence,
    detail: hit.detail ? truncate(redact(hit.detail), 600) : null,
    remediation: rule.remediation,
    references: rule.references ?? [],
    fingerprint: fingerprintFor({
      ruleId: rule.id,
      file,
      server,
      tool,
      key: hit.fingerprintKey ?? evidence ?? hit.message,
    }),
  };
}
