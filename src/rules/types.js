/**
 * @module rules/types
 */

/**
 * @typedef {"server"|"tool"|"scan"|"warning"} RuleTarget
 */

/**
 * @typedef {object} RuleHit
 * @property {string} message      one sentence a reviewer can act on
 * @property {string} [evidence]   machine-relevant excerpt; redacted before output
 * @property {string} [detail]     longer explanation shown by --verbose / explain
 * @property {import("./severity.js").Severity} [severity] per-occurrence override
 * @property {number} [line]       overrides the location's line
 * @property {number} [column]
 * @property {string} [fingerprintKey] stable identity for this hit, defaults to evidence
 */

/**
 * @typedef {object} Rule
 * @property {string} id           stable rule identifier, e.g. "MCP001"
 * @property {string} title        short human title
 * @property {string} category     one of the documented categories
 * @property {import("./severity.js").Severity} severity default severity
 * @property {RuleTarget} target   which input shape the rule receives
 * @property {string} summary      what the rule checks, one line
 * @property {string} why          why it matters (shown by `mcpvet explain`)
 * @property {string} remediation  what to do instead
 * @property {string[]} [references] external documentation links
 * @property {(context: any) => RuleHit|RuleHit[]|null|undefined} check
 */

export {};
