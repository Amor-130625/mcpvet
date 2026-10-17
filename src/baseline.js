/**
 * Baselines: accept today's findings so that CI fails only on *new* risk.
 *
 * Without this, nobody adopts a linter on an existing codebase: the first run
 * is red, the threshold gets deleted, and the tool stops mattering. With it,
 * the team can commit the current state, fix it gradually, and still block a
 * regression on the next pull request.
 *
 * A baseline is therefore a reviewed security decision and belongs in version
 * control. Fingerprints are stable across line moves (see `src/findings.js`),
 * so unrelated edits do not invalidate it.
 *
 * @module baseline
 */

import { NAME, VERSION } from "./version.js";

export const BASELINE_VERSION = 1;
export const DEFAULT_BASELINE_FILENAME = ".mcpvet-baseline.json";

/**
 * @param {import("./findings.js").Finding[]} findings
 * @param {{generatedAt?: string}} [options]
 * @returns {object}
 */
export function buildBaseline(findings, options = {}) {
  const entries = findings
    .map((finding) => ({
      fingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      severity: finding.severity,
      file: finding.file,
      server: finding.server,
      message: finding.message,
    }))
    .sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1));

  return {
    version: BASELINE_VERSION,
    tool: { name: NAME, version: VERSION },
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    note: "Accepted findings. CI fails only on findings that are not listed here. Review this file like any other security change.",
    count: entries.length,
    entries,
  };
}

/**
 * @param {string} text
 * @returns {{ok: true, baseline: any}|{ok: false, error: string}}
 */
export function parseBaseline(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return { ok: false, error: `baseline is not valid JSON: ${error.message}` };
  }
  if (!parsed || typeof parsed !== "object") return { ok: false, error: "baseline must be a JSON object" };
  if (parsed.version !== BASELINE_VERSION) {
    return { ok: false, error: `unsupported baseline version ${JSON.stringify(parsed.version)}` };
  }
  if (!Array.isArray(parsed.entries)) return { ok: false, error: "baseline.entries must be an array" };
  for (const entry of parsed.entries) {
    if (!entry || typeof entry.fingerprint !== "string") {
      return { ok: false, error: "every baseline entry needs a string fingerprint" };
    }
  }
  return { ok: true, baseline: parsed };
}

/**
 * Split findings into new and previously accepted.
 *
 * @param {import("./findings.js").Finding[]} findings
 * @param {any} baseline
 * @returns {{newFindings: import("./findings.js").Finding[], suppressed: import("./findings.js").Finding[]}}
 */
export function applyBaseline(findings, baseline) {
  const known = new Set((baseline?.entries ?? []).map((entry) => entry.fingerprint));
  /** @type {import("./findings.js").Finding[]} */
  const newFindings = [];
  /** @type {import("./findings.js").Finding[]} */
  const suppressed = [];
  for (const finding of findings) {
    if (known.has(finding.fingerprint)) suppressed.push(finding);
    else newFindings.push(finding);
  }
  return { newFindings, suppressed };
}

/**
 * Re-baseline the current state, dropping entries for findings that no longer
 * exist. Keeping stale entries would make the file grow forever and hide the
 * fact that a rule stopped firing.
 *
 * @param {import("./findings.js").Finding[]} findings
 * @param {any} [previousBaseline]
 * @returns {{baseline: object, added: number, removed: number}}
 */
export function updateBaseline(findings, previousBaseline = null) {
  const next = buildBaseline(findings);
  const previous = new Set((previousBaseline?.entries ?? []).map((entry) => entry.fingerprint));
  const current = new Set(next.entries.map((entry) => entry.fingerprint));
  let added = 0;
  for (const fingerprint of current) if (!previous.has(fingerprint)) added += 1;
  let removed = 0;
  for (const fingerprint of previous) if (!current.has(fingerprint)) removed += 1;
  return { baseline: next, added, removed };
}
