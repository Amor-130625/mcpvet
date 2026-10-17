/**
 * Terminal formatter.
 *
 * Design constraint: the output has to be readable in a 100-column terminal
 * during a code review, and it must never print a live credential. Evidence
 * strings arrive already redacted by `src/findings.js`, so this module only
 * formats.
 *
 * @module report/pretty
 */

import { SEVERITY_LABEL, countBySeverity } from "../severity.js";
import { computeScore } from "../score.js";
import { NAME, VERSION } from "../version.js";

const ANSI = {
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  dim: "\u001b[2m",
  red: "\u001b[31m",
  green: "\u001b[32m",
  yellow: "\u001b[33m",
  blue: "\u001b[34m",
  magenta: "\u001b[35m",
  cyan: "\u001b[36m",
  gray: "\u001b[90m",
};

const SEVERITY_COLOR = {
  critical: ANSI.magenta,
  high: ANSI.red,
  medium: ANSI.yellow,
  low: ANSI.cyan,
  info: ANSI.gray,
};

/**
 * @param {boolean} enabled
 * @returns {(code: string, text: string) => string}
 */
function painter(enabled) {
  return (code, text) => (enabled ? `${code}${text}${ANSI.reset}` : text);
}

/**
 * @param {{findings: import("../findings.js").Finding[], stats: any}} result
 * @param {{color?: boolean, verbose?: boolean}} [options]
 * @returns {string}
 */
export function formatPretty(result, options = {}) {
  const { color = true, verbose = false } = options;
  const paint = painter(color);
  const { findings, stats } = result;
  const lines = [];

  lines.push("");
  lines.push(`  ${paint(ANSI.bold, `${NAME} ${VERSION}`)}${paint(ANSI.gray, "  —  MCP server security audit")}`);

  const scope = [
    `${stats.files} file${stats.files === 1 ? "" : "s"}`,
    `${stats.servers} server${stats.servers === 1 ? "" : "s"}`,
  ];
  if (stats.tools > 0) scope.push(`${stats.tools} tool${stats.tools === 1 ? "" : "s"}`);
  lines.push(`  ${paint(ANSI.gray, scope.join("  \u00b7  "))}`);
  lines.push("");

  if (findings.length === 0) {
    lines.push(`  ${paint(ANSI.green, "\u2713 No findings.")} ${paint(ANSI.gray, "Every configured server passed the current rule set.")}`);
    lines.push("");
    return lines.join("\n");
  }

  for (const finding of findings) {
    const colorCode = SEVERITY_COLOR[finding.severity] ?? ANSI.gray;
    const label = SEVERITY_LABEL[finding.severity] ?? "????";
    lines.push(`  ${paint(colorCode, label.padEnd(5))}${paint(ANSI.bold, finding.ruleId)}  ${finding.title}`);

    const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "(scan)";
    const context = [finding.server ? `server ${finding.server}` : null, finding.tool ? `tool ${finding.tool}` : null]
      .filter(Boolean)
      .join(" \u00b7 ");
    lines.push(`        ${paint(ANSI.gray, location)}${context ? paint(ANSI.gray, `  ${context}`) : ""}`);
    lines.push(`        ${finding.message}`);
    if (finding.evidence) lines.push(`        ${paint(ANSI.gray, `evidence: ${finding.evidence}`)}`);
    if (verbose && finding.detail) {
      for (const chunk of wrap(finding.detail, 88)) lines.push(`        ${paint(ANSI.gray, chunk)}`);
    }
    if (verbose && finding.remediation) {
      for (const chunk of wrap(`fix: ${finding.remediation}`, 88)) lines.push(`        ${paint(ANSI.blue, chunk)}`);
    }
    lines.push("");
  }

  const counts = countBySeverity(findings);
  const { score, grade } = computeScore(findings);
  const breakdown = Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => paint(SEVERITY_COLOR[severity] ?? ANSI.gray, `${count} ${severity}`))
    .join(paint(ANSI.gray, ", "));

  lines.push(
    `  ${paint(ANSI.bold, "Summary")}  ${findings.length} finding${findings.length === 1 ? "" : "s"} (${breakdown})  ` +
      `${paint(ANSI.gray, "\u00b7")}  trust score ${paint(ANSI.bold, `${score}/100`)} (${grade})`,
  );
  lines.push("");

  return lines.join("\n");
}

/**
 * Greedy word wrap that does not break words.
 * @param {string} text
 * @param {number} width
 * @returns {string[]}
 */
function wrap(text, width) {
  const words = String(text).split(/\s+/).filter(Boolean);
  /** @type {string[]} */
  const lines = [];
  let current = "";
  for (const word of words) {
    if (current === "") {
      current = word;
    } else if (`${current} ${word}`.length <= width) {
      current = `${current} ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines;
}
