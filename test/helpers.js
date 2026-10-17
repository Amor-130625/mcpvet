/**
 * Shared test helpers.
 *
 * Tests drive rules through the same `normalizeServer` / `audit` pipeline the
 * CLI uses, so a rule cannot pass in isolation and fail on a real config.
 */

import { audit } from "../src/audit.js";
import { normalizeServer } from "../src/config.js";
import { getRule } from "../src/rules/index.js";

/**
 * @param {any} entry raw config entry
 * @param {{name?: string, file?: string|null}} [options]
 */
export function normalized(entry, options = {}) {
  const { name = "test", file = "test.json" } = options;
  return normalizeServer(name, entry, {
    file,
    pointer: `/mcpServers/${name}`,
    positions: new Map(),
    warnings: [],
  });
}

/** @param {any} entry */
export function serverContext(entry, options = {}) {
  return {
    server: normalized(entry, options),
    scan: makeScan({ servers: [], tools: [], home: options.home ?? "/home/dev" }),
  };
}

/**
 * @param {{servers?: any[], tools?: any[], home?: string}} [input]
 */
export function makeScan({ servers = [], tools = [], home = "/home/dev" } = {}) {
  return {
    servers,
    tools,
    configs: [],
    descriptors: [],
    errors: [],
    files: [],
    home,
    cwd: "/repo",
  };
}

/**
 * Run a single rule and return its hits (always an array).
 *
 * @param {string} ruleId
 * @param {any} context
 */
export function checkRule(ruleId, context) {
  const rule = getRule(ruleId);
  if (!rule) throw new Error(`Unknown rule ${ruleId}`);
  const result = rule.check(context);
  if (!result) return [];
  return Array.isArray(result) ? result : [result];
}

/**
 * Rule ids that fire for a whole entry, through the real audit pipeline.
 *
 * @param {any} entry
 * @param {{name?: string, home?: string}} [options]
 */
export function firedRules(entry, options = {}) {
  const server = normalized(entry, { name: options.name ?? "test" });
  const result = audit(
    { configs: [{ file: "test.json", kind: "config", servers: [server], warnings: [] }] },
    { cwd: "/repo", home: options.home ?? "/home/dev" },
  );
  return [...new Set(result.findings.map((finding) => finding.ruleId))].sort();
}

/**
 * Findings for a single entry, through the real audit pipeline. Use this when
 * the assertion is about what a *report* contains (redaction, fingerprints),
 * rather than about what a rule returns.
 *
 * @param {any} entry
 * @param {{name?: string, home?: string}} [options]
 */
export function findingsFor(entry, options = {}) {
  const server = normalized(entry, { name: options.name ?? "test" });
  return audit(
    { configs: [{ file: "test.json", kind: "config", servers: [server], warnings: [] }] },
    { cwd: "/repo", home: options.home ?? "/home/dev" },
  ).findings;
}

/**
 * A normalised tool for tool-target rules.
 *
 * @param {any} overrides
 */
export function normalizedTool(overrides = {}) {
  return {
    name: "demo_tool",
    description: "Does a thing.",
    inputSchema: { type: "object", properties: {} },
    annotations: null,
    server: "srv",
    file: "tools.json",
    pointer: "/tools/0",
    line: 1,
    column: 1,
    ...overrides,
  };
}
