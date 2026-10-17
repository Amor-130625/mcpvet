/**
 * The 0-100 trust score.
 *
 * A count of findings answers "is CI red". It does not answer "is this config
 * getting better or worse", which is the question a maintainer asks week to
 * week. The score is a deliberately simple linear penalty so that a reader can
 * reproduce it by hand:
 *
 *     score = 100 - (25*critical + 12*high + 5*medium + 2*low), floored at 0
 *
 * It is not a risk model. It is a monotone summary with a documented formula,
 * and the plan is to keep the formula stable across minor versions so the
 * number is comparable over time.
 *
 * @module score
 */

import { countBySeverity, SEVERITY_WEIGHT } from "./severity.js";

/**
 * @param {import("./findings.js").Finding[]} findings
 * @returns {{score: number, grade: string, penalty: number, counts: Record<string, number>}}
 */
export function computeScore(findings) {
  const counts = countBySeverity(findings);
  let penalty = 0;
  for (const [severity, count] of Object.entries(counts)) {
    penalty += count * (SEVERITY_WEIGHT[severity] ?? 0);
  }
  const score = Math.max(0, Math.min(100, 100 - penalty));
  return { score, grade: gradeFor(score), penalty, counts };
}

/**
 * @param {number} score
 * @returns {"A"|"B"|"C"|"D"|"F"}
 */
export function gradeFor(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * One-line summary, used by every formatter so the wording never drifts.
 *
 * @param {import("./findings.js").Finding[]} findings
 * @returns {string}
 */
export function summarise(findings) {
  const { score, grade } = computeScore(findings);
  if (findings.length === 0) return `No findings. Trust score 100/100 (A).`;
  const counts = countBySeverity(findings);
  const parts = Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => `${count} ${severity}`)
    .join(", ");
  return `${findings.length} finding${findings.length === 1 ? "" : "s"} (${parts}). Trust score ${score}/100 (${grade}).`;
}
