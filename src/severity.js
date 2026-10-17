/**
 * Severity vocabulary shared by every rule, formatter, and CI gate.
 *
 * The scale is deliberately short. A maintainer triaging a red CI run needs to
 * know "does this block the merge" in under a second, and a five-step scale
 * maps cleanly onto SARIF levels (error / warning / note).
 */

/** @typedef {"critical"|"high"|"medium"|"low"|"info"} Severity */

/** @type {Severity[]} ascending order of impact */
export const SEVERITY_ORDER = /** @type {Severity[]} */ (["info", "low", "medium", "high", "critical"]);

/** Points removed from the 100-point trust score per finding. */
export const SEVERITY_WEIGHT = Object.freeze({
  critical: 25,
  high: 12,
  medium: 5,
  low: 2,
  info: 0,
});

/** SARIF / GitHub Code Scanning level for each severity. */
export const SARIF_LEVEL = Object.freeze({
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
});

/** Short fixed-width labels used by the pretty formatter. */
export const SEVERITY_LABEL = Object.freeze({
  critical: "CRIT",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
  info: "INFO",
});

/** @param {string} severity @returns {number} -1 when unknown */
export function severityRank(severity) {
  return SEVERITY_ORDER.indexOf(/** @type {Severity} */ (severity));
}

/**
 * True when `severity` is at least as severe as `minimum`.
 * Unknown severities never satisfy a threshold, so a typo in a rule cannot
 * silently fail a build.
 */
export function isAtLeast(severity, minimum) {
  const a = severityRank(severity);
  const b = severityRank(minimum);
  if (a < 0 || b < 0) return false;
  return a >= b;
}

/** Greatest severity present in a finding list, or `null` when empty. */
export function worstSeverity(findings) {
  let worst = null;
  for (const finding of findings) {
    if (worst === null || severityRank(finding.severity) > severityRank(worst)) {
      worst = finding.severity;
    }
  }
  return worst;
}

/** Count findings per severity, always returning every key. */
export function countBySeverity(findings) {
  /** @type {Record<Severity, number>} */
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    if (finding.severity in counts) counts[finding.severity] += 1;
  }
  return counts;
}

/** Deterministic ordering: severity first, then location, then rule id. */
export function compareFindings(a, b) {
  const bySeverity = severityRank(b.severity) - severityRank(a.severity);
  if (bySeverity !== 0) return bySeverity;
  const fileA = a.file ?? "";
  const fileB = b.file ?? "";
  if (fileA !== fileB) return fileA < fileB ? -1 : 1;
  const lineA = a.line ?? 0;
  const lineB = b.line ?? 0;
  if (lineA !== lineB) return lineA - lineB;
  if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
  return 0;
}
