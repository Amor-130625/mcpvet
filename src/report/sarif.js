/**
 * SARIF 2.1.0 output for GitHub Code Scanning.
 *
 * The whole point of SARIF here is that a security finding should appear as an
 * annotation on the pull request that introduced it, not as a line in a log
 * nobody reads. That requires three things this module is careful about:
 *
 *  - `level` mapped from our severity scale, so `high` fails the check;
 *  - a `partialFingerprints` value, so GitHub tracks the alert across commits
 *    instead of re-opening it every push;
 *  - a `locations[].physicalLocation.region.startLine`, which is why the
 *    JSONC parser tracks positions at all.
 *
 * @module report/sarif
 */

import { SARIF_LEVEL } from "../severity.js";
import { NAME, VERSION, HOMEPAGE } from "../version.js";
import { getRule } from "../rules/index.js";

/**
 * Percent-encode a path for use inside a URI, keeping the separators and the
 * Windows drive colon readable (`file:///C:/repo%20dir/mcp.json`).
 *
 * @param {string} path
 */
function encodePath(path) {
  return encodeURI(path).replace(/\?/g, "%3F").replace(/#/g, "%23");
}

/**
 * Convert a path into something SARIF consumers accept as an artifact URI.
 * Relative paths stay relative (they are repo-relative, which is what GitHub
 * wants); absolute paths become `file://` URIs.
 *
 * @param {string} file
 */
function toArtifactUri(file) {
  const normalised = String(file).replace(/\\/g, "/");
  if (/^[a-zA-Z]:\//.test(normalised)) {
    return `file:///${encodePath(normalised)}`;
  }
  if (normalised.startsWith("/")) {
    return `file://${encodePath(normalised)}`;
  }
  return encodePath(normalised);
}

/**
 * @param {{findings: import("../findings.js").Finding[], stats: any}} result
 * @returns {string}
 */
export function formatSarif(result) {
  const { findings } = result;

  /** @type {Map<string, number>} */
  const ruleIndex = new Map();
  /** @type {any[]} */
  const sarifRules = [];

  for (const finding of findings) {
    if (ruleIndex.has(finding.ruleId)) continue;
    const rule = getRule(finding.ruleId);
    ruleIndex.set(finding.ruleId, sarifRules.length);
    sarifRules.push({
      id: finding.ruleId,
      name: finding.ruleId,
      shortDescription: { text: finding.title },
      fullDescription: { text: rule?.summary ?? finding.title },
      help: {
        text: [rule?.why, rule?.remediation ? `Remediation: ${rule.remediation}` : null].filter(Boolean).join("\n\n"),
        markdown: [
          rule?.why ?? "",
          "",
          rule?.remediation ? `**Remediation:** ${rule.remediation}` : "",
        ].join("\n"),
      },
      helpUri: `${HOMEPAGE}/blob/main/docs/rules.md#${finding.ruleId.toLowerCase()}`,
      defaultConfiguration: { level: SARIF_LEVEL[finding.severity] ?? "warning" },
      properties: {
        tags: [finding.category, "security", "mcp"],
        precision: "high",
        "security-severity": securitySeverity(finding.severity),
      },
    });
  }

  const results = findings.map((finding) => {
    const physicalLocation = finding.file
      ? {
          artifactLocation: { uri: toArtifactUri(finding.file) },
          region: {
            startLine: Math.max(1, finding.line ?? 1),
            startColumn: Math.max(1, finding.column ?? 1),
          },
        }
      : null;

    return {
      ruleId: finding.ruleId,
      ruleIndex: ruleIndex.get(finding.ruleId) ?? 0,
      level: SARIF_LEVEL[finding.severity] ?? "warning",
      message: { text: `${finding.message}${finding.evidence ? ` [evidence: ${finding.evidence}]` : ""}` },
      locations: physicalLocation ? [{ physicalLocation }] : [],
      partialFingerprints: { "mcpvet/finding/v1": finding.fingerprint },
      properties: {
        severity: finding.severity,
        category: finding.category,
        server: finding.server,
        tool: finding.tool,
        remediation: finding.remediation,
      },
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: NAME,
            version: VERSION,
            informationUri: HOMEPAGE,
            rules: sarifRules,
          },
        },
        results,
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

/**
 * GitHub Code Scanning sorts by a CVSS-like score. These are intentionally
 * coarse bands, documented so the mapping is not a mystery.
 *
 * @param {string} severity
 */
function securitySeverity(severity) {
  const map = { critical: "9.0", high: "7.5", medium: "5.5", low: "3.0", info: "0.0" };
  return map[severity] ?? "5.0";
}
