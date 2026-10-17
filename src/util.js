/**
 * Small shared helpers. Kept dependency-free on purpose: every function here is
 * something the audit report relies on, so it has to be trivially reviewable.
 */

/** @returns {boolean} true for plain `{}` objects (not arrays, not null). */
export function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Coerce a value to a trimmed string; non-primitives become "". */
export function asString(value) {
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

/** Coerce a JSON-ish env/headers object into a flat `Record<string,string>`. */
export function toStringMap(value) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!isPlainObject(value)) return out;
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw === "string") out[key] = raw;
    else if (typeof raw === "number" || typeof raw === "boolean") out[key] = String(raw);
    else if (raw === null) out[key] = "";
    // Nested objects/arrays are not valid env values in any MCP client we
    // know of; they are reported by the config-normalisation rules instead of
    // being silently stringified into "[object Object]".
  }
  return out;
}

/** Truncate on a word boundary-free cut, appending an ellipsis marker. */
export function truncate(text, max = 240) {
  const value = String(text ?? "");
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}\u2026`;
}

/** Basename of a command without a Windows executable suffix. */
export function commandBasename(command) {
  const raw = asString(command);
  if (!raw) return "";
  const normalised = raw.replace(/\\/g, "/");
  const base = normalised.slice(normalised.lastIndexOf("/") + 1);
  return base.replace(/\.(exe|cmd|bat|ps1|mjs|cjs|js)$/i, "").toLowerCase();
}

/** Sort helper: stable, locale-independent. */
export function compareStrings(a, b) {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** Deduplicate an array while preserving first-seen order. */
export function unique(items) {
  return [...new Set(items)];
}

/**
 * Normalise a file path into a repo-style relative path with forward slashes.
 * Absolute paths outside the working directory stay absolute so reports remain
 * unambiguous about which machine-local file they refer to.
 */
export function toDisplayPath(file, cwd = process.cwd()) {
  if (!file) return null;
  const absolute = file;
  const base = cwd.replace(/\\/g, "/").replace(/\/$/, "");
  const normalised = absolute.replace(/\\/g, "/");
  if (normalised === base) return ".";
  if (normalised.startsWith(`${base}/`)) return normalised.slice(base.length + 1);
  return normalised;
}
