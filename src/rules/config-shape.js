/**
 * Rules that report structural problems found while loading config files.
 *
 * These are not checks against the *content* of a server; they are checks
 * against the file itself. They still belong in the same report, because "this
 * config will not load" and "this config is dangerous" arrive through the same
 * channel for a maintainer.
 *
 * @module rules/config-shape
 */

const WARNING_SEVERITY = {
  NON_OBJECT_ENTRY: "medium",
  NON_STRING_COMMAND: "medium",
  NON_ARRAY_ARGS: "low",
  UNKNOWN_TRANSPORT: "low",
  CONFLICTING_TRANSPORT: "medium",
};

/** @type {import("./types.js").Rule[]} */
export const configShapeRules = [
  {
    id: "MCP070",
    title: "Server entry has an unusable shape",
    category: "configuration",
    severity: "low",
    target: "warning",
    summary: "A server entry is missing a required field or has a field of the wrong type.",
    why:
      "Clients disagree about how strict they are: some reject the whole file, others drop the server silently. " +
      "Either way the developer believes a capability exists that does not, or gets an error with no location.",
    remediation: "Fix the entry shape; the message names the field the loader could not use.",
    check({ warning }) {
      return {
        message: warning.message,
        severity: WARNING_SEVERITY[warning.code] ?? "low",
        fingerprintKey: `${warning.code}:${warning.pointer}`,
      };
    },
  },

  {
    id: "MCP072",
    title: "Config file could not be parsed",
    category: "configuration",
    severity: "medium",
    target: "error",
    summary: "A config or descriptor file is unreadable or is not valid JSON/JSONC.",
    why:
      "An unparsable config is unaudited: this tool could not inspect it, and the client will either refuse to start " +
      "or fall back to defaults. Silence here would look like a clean scan, which is the one outcome a security " +
      "report must never fabricate.",
    remediation: "Fix the syntax error. mcpvet accepts comments and trailing commas, so a failure is a real defect.",
    check({ error }) {
      return {
        message: error.message,
        fingerprintKey: `${error.code ?? "PARSE"}:${error.file ?? ""}`,
      };
    },
  },
];
