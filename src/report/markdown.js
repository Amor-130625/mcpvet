/**
 * Markdown formatter, aimed at pull-request comments and job summaries.
 *
 * GitHub renders a `<details>` block collapsed by default, which is what keeps
 * a 20-finding report readable in a comment thread.
 *
 * @module report/markdown
 */

import { SEVERITY_LABEL, countBySeverity } from "../severity.js";
import { computeScore } from "../score.js";
import { NAME, VERSION } from "../version.js";

/**
 * @param {{findings: import("../findings.js").Finding[], stats: any}} result
 * @param {{maxFindings?: number}} [options]
 * @returns {string}
 */
export function formatMarkdown(result, options = {}) {
  const { findings, stats } = result;
  const maxFindings = options.maxFindings ?? 50;
  const counts = countBySeverity(findings);
  const { score, grade } = computeScore(findings);
  const lines = [];

  lines.push(`## ${NAME} report`);
  lines.push("");

  if (findings.length === 0) {
    lines.push(`**No findings.** ${stats.files} file(s), ${stats.servers} server(s) checked. Trust score 100/100 (A).`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `**${findings.length} finding${findings.length === 1 ? "" : "s"}** — ` +
      Object.entries(counts)
        .filter(([, count]) => count > 0)
        .map(([severity, count]) => `${count} ${severity}`)
        .join(", ") +
      ` · trust score **${score}/100 (${grade})**`,
  );
  lines.push("");
  lines.push("| Severity | Rule | Location | Finding |");
  lines.push("| --- | --- | --- | --- |");

  const shown = findings.slice(0, maxFindings);
  for (const finding of shown) {
    const location = finding.file
      ? `\`${finding.file}${finding.line ? `:${finding.line}` : ""}\``
      : "—";
    const target = finding.server ? `${finding.message} _(${finding.server})_` : finding.message;
    lines.push(
      `| ${SEVERITY_LABEL[finding.severity]} | \`${finding.ruleId}\` | ${location} | ${escapeCell(target)} |`,
    );
  }

  if (findings.length > shown.length) {
    lines.push("");
    lines.push(`_… and ${findings.length - shown.length} more. See the SARIF artifact for the full list._`);
  }

  lines.push("");
  lines.push("<details>");
  lines.push("<summary>How to fix</summary>");
  lines.push("");
  const seen = new Set();
  for (const finding of shown) {
    if (seen.has(finding.ruleId)) continue;
    seen.add(finding.ruleId);
    lines.push(`- **${finding.ruleId}** — ${finding.remediation}`);
  }
  lines.push("");
  lines.push("</details>");
  lines.push("");
  lines.push(`<sub>${NAME} ${VERSION} · ${stats.files} file(s) · ${stats.servers} server(s)</sub>`);
  lines.push("");

  return lines.join("\n");
}

/** Markdown table cells cannot contain raw pipes or newlines. */
function escapeCell(text) {
  return String(text).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}
