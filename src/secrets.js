/**
 * Secret detection and — more importantly — secret *redaction*.
 *
 * mcpvet reads files that are supposed to contain credentials, so it has a hard
 * invariant: a secret found in a config must never leave the process. Every
 * piece of evidence that reaches a terminal, a JSON report, a SARIF file, or a
 * GitHub issue is passed through {@link redact} first. `test/secrets.test.js`
 * asserts this for every pattern we know about.
 *
 * @module secrets
 */

/**
 * @typedef {object} SecretMatch
 * @property {string} kind   stable identifier used in redaction markers
 * @property {string} match  the raw matched text (never printed)
 * @property {number} index
 */

/** Vendor-prefixed token formats. High precision, near-zero false positives. */
const KNOWN_PATTERNS = [
  { kind: "openai-key", re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g },
  { kind: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { kind: "github-token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
  { kind: "github-pat", re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  { kind: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { kind: "aws-access-key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{30,}\b/g },
  { kind: "npm-token", re: /\bnpm_[A-Za-z0-9]{30,}\b/g },
  { kind: "stripe-key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { kind: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { kind: "private-key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
];

/**
 * `name: value` / `name=value` assignments. The value must be long and
 * mixed-alphabet to avoid flagging `"token": "expires"` style prose.
 */
const ASSIGNMENT_PATTERN =
  /(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer|password|passwd|pwd|secret|token|credential)\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{20,})/gi;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Values that look like credentials but are obviously not one. */
const PLACEHOLDER_PATTERNS = [
  /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/, // ${VAR}
  /^\$[A-Za-z_][A-Za-z0-9_]*$/, // $VAR
  /^%[A-Za-z_][A-Za-z0-9_]*%$/, // %VAR%
  /^\{[A-Za-z0-9_.\-]+\}$/, // {VAR}
  /^(?:process\.env|os\.environ|env:|secrets\.)/i, // process.env.X
  /^<[^>]*>$/, // <YOUR_TOKEN>
  /^(?:your|my|example|sample|dummy|test|fake|placeholder)[-_ .]/i,
  /(?:placeholder|changeme|change_me|replace_me|insert_here|redacted|todo|fixme)/i,
  /^x{4,}$/i,
  /^\.{3,}$/,
  /^(?:none|null|undefined|true|false|empty|n\/?a)$/i,
];

/**
 * @param {unknown} value
 * @returns {boolean} true when the value cannot plausibly be a live credential
 */
export function looksLikePlaceholder(value) {
  const text = typeof value === "string" ? value.trim() : "";
  if (text.length === 0) return true;
  if (/\s/.test(text)) return false; // real secrets do not contain spaces
  if (PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(text))) return true;
  if (UUID_PATTERN.test(text)) return true;
  // A single repeated character, e.g. "aaaaaaaaaaaa".
  if (/^(.)\1*$/.test(text)) return true;
  return false;
}

/**
 * Shannon entropy in bits per character.
 * @param {string} text
 * @returns {number}
 */
export function shannonEntropy(text) {
  if (!text) return 0;
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Find every credential-looking substring in `text`.
 *
 * @param {string} text
 * @returns {SecretMatch[]}
 */
export function findSecrets(text) {
  const input = typeof text === "string" ? text : "";
  if (!input) return [];

  /** @type {SecretMatch[]} */
  const found = [];
  /** @type {Set<string>} */
  const seen = new Set();

  const push = (kind, match, index) => {
    if (!match || seen.has(match)) return;
    seen.add(match);
    found.push({ kind, match, index });
  };

  for (const { kind, re } of KNOWN_PATTERNS) {
    // `String.match` with a /g regex is stateless, unlike `re.exec` loops.
    const matches = input.match(re);
    if (!matches) continue;
    for (const match of matches) push(kind, match, input.indexOf(match));
  }

  if (!looksLikePlaceholder(input)) {
    const re = new RegExp(ASSIGNMENT_PATTERN.source, "gi");
    let assignment;
    while ((assignment = re.exec(input)) !== null) {
      const value = assignment[1];
      if (looksLikePlaceholder(value)) continue;
      push("assigned-secret", value, assignment.index);
    }

    for (const token of tokenizeCandidates(input)) {
      if (token.length < 24) continue;
      if (UUID_PATTERN.test(token)) continue;
      // Paths and package specs are long, mixed-alphabet strings that are not
      // secrets. Real base64 credentials still reach the report through the
      // assignment rule above, which has the surrounding key as context.
      if (/[/\\]/.test(token)) continue;
      if (token.startsWith("@")) continue;
      if (!/[a-z]/.test(token) || !/[A-Z0-9]/.test(token)) continue;
      if (!/[0-9]/.test(token)) continue;
      if (!/^[A-Za-z0-9_\-+/=.]+$/.test(token)) continue;
      if (looksLikePlaceholder(token)) continue;
      if (shannonEntropy(token) < 3.5) continue;
      push("high-entropy", token, input.indexOf(token));
    }
  }

  return found.sort((a, b) => a.index - b.index);
}

/**
 * Split a string into candidate opaque tokens, dropping natural-language words.
 * @param {string} text
 * @returns {string[]}
 */
function tokenizeCandidates(text) {
  return text.split(/[\s"',;()[\]{}<>]+/).filter((token) => token.length >= 24);
}

/**
 * @param {unknown} value
 * @returns {SecretMatch|null} the first credential-looking value, if any
 */
export function detectSecret(value) {
  if (typeof value !== "string") return null;
  const matches = findSecrets(value);
  return matches.length > 0 ? matches[0] : null;
}

/**
 * Replace every credential-shaped substring with a stable marker.
 *
 * The marker keeps the *kind* and the length bucket, so a reviewer can tell
 * "this is probably an OpenAI key, and it is long" without ever seeing the
 * value. Length is bucketed to 8 characters so the marker cannot be used to
 * fingerprint a specific secret across reports.
 *
 * @param {string} text
 * @param {number} [maxLength] hard cap applied after redaction
 * @returns {string}
 */
export function redact(text, maxLength = 400) {
  let output = String(text ?? "");
  if (!output) return "";

  const matches = findSecrets(output).sort((a, b) => b.match.length - a.match.length);
  for (const { kind, match } of matches) {
    const bucket = Math.ceil(match.length / 8) * 8;
    output = output.split(match).join(`<redacted:${kind}:~${bucket}ch>`);
  }

  if (output.length > maxLength) output = `${output.slice(0, maxLength - 1)}\u2026`;
  return output;
}

/**
 * Redact a mapping without exposing keys' values, e.g. for env evidence.
 * @param {Record<string, string>} map
 * @param {string[]} keys
 * @returns {string}
 */
export function describeKeys(map, keys) {
  return keys.map((key) => `${key}=${detectSecret(map[key]) ? "<redacted>" : JSON.stringify(map[key])}`).join(" ");
}
