/**
 * Machine-readable report. The shape is documented in
 * `schema/report.schema.json` and treated as a public API: bumping a field name
 * is a breaking change.
 *
 * @module report/json
 */

import { countBySeverity } from "../severity.js";
import { computeScore } from "../score.js";
import { NAME, VERSION, HOMEPAGE } from "../version.js";

/**
 * @param {{findings: import("../findings.js").Finding[], stats: any}} result
 * @param {{generatedAt?: string}} [options]
 * @returns {string}
 */
export function formatJson(result, options = {}) {
  const { findings, stats } = result;
  const counts = countBySeverity(findings);
  const { score, grade, penalty } = computeScore(findings);

  const payload = {
    tool: {
      name: NAME,
      version: VERSION,
      homepage: HOMEPAGE,
    },
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    summary: {
      findings: findings.length,
      counts,
      penalty,
      score,
      grade,
      passed: findings.length === 0,
    },
    stats,
    findings: findings.map((finding) => ({
      ruleId: finding.ruleId,
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      message: finding.message,
      file: finding.file,
      line: finding.line,
      column: finding.column,
      server: finding.server,
      tool: finding.tool,
      evidence: finding.evidence,
      detail: finding.detail,
      remediation: finding.remediation,
      references: finding.references,
      fingerprint: finding.fingerprint,
    })),
  };

  return `${JSON.stringify(payload, null, 2)}\n`;
}
