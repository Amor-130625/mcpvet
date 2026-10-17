/**
 * The audit runner: apply every rule to every relevant input.
 *
 * @module audit
 */

import { homedir } from "node:os";
import { listRules } from "./rules/index.js";
import { createFinding } from "./findings.js";
import { compareFindings, isAtLeast } from "./severity.js";

/**
 * @typedef {object} AuditInput
 * @property {import("./loader.js").LoadedDocument[]} [configs]
 * @property {import("./loader.js").LoadedDocument[]} [descriptors]
 * @property {import("./loader.js").LoadError[]} [errors]
 */

/**
 * @typedef {object} AuditOptions
 * @property {string} [cwd]
 * @property {string} [home]
 * @property {string[]} [ignore]          rule ids to skip
 * @property {import("./severity.js").Severity|null} [minSeverity] drop findings below this severity
 */

/**
 * @typedef {object} AuditResult
 * @property {import("./findings.js").Finding[]} findings
 * @property {object} stats
 * @property {object} scan   the normalised input, exposed for formatters/tests
 */

/**
 * @param {AuditInput} input
 * @param {AuditOptions} [options]
 * @returns {AuditResult}
 */
export function audit(input, options = {}) {
  const {
    cwd = process.cwd(),
    home = homedir(),
    ignore = [],
    minSeverity = null,
  } = options;

  const configs = input.configs ?? [];
  const descriptors = input.descriptors ?? [];
  const errors = input.errors ?? [];

  const scan = {
    cwd,
    home,
    configs,
    descriptors,
    errors,
    servers: configs.flatMap((config) => config.servers ?? []),
    tools: descriptors.flatMap((descriptor) => descriptor.tools ?? []),
    files: [...configs, ...descriptors].map((document) => document.file),
  };

  const ignored = new Set(ignore.map((id) => String(id).toUpperCase()));
  const rules = listRules();

  /** @type {import("./findings.js").Finding[]} */
  let findings = [];

  for (const rule of rules) {
    if (ignored.has(rule.id)) continue;

    try {
      switch (rule.target) {
        case "server": {
          for (const server of scan.servers) {
            emit(findings, rule, rule.check({ server, scan }), {
              file: server.file,
              server: server.name,
              line: server.line,
              column: server.column,
            });
          }
          break;
        }
        case "tool": {
          for (const tool of scan.tools) {
            emit(findings, rule, rule.check({ tool, server: tool.server, scan }), {
              file: tool.file,
              server: tool.server,
              tool: tool.name,
              line: tool.line,
              column: tool.column,
            });
          }
          break;
        }
        case "scan": {
          emit(findings, rule, rule.check({ scan }), { file: null });
          break;
        }
        case "warning": {
          for (const config of scan.configs) {
            for (const warning of config.warnings ?? []) {
              emit(findings, rule, rule.check({ warning, config, scan }), {
                file: config.file,
                line: warning.line ?? null,
              });
            }
          }
          break;
        }
        case "error": {
          for (const error of scan.errors) {
            emit(findings, rule, rule.check({ error, scan }), {
              file: error.file,
              line: error.line ?? null,
              column: error.column ?? null,
            });
          }
          break;
        }
        default:
          throw new Error(`Unknown rule target "${rule.target}"`);
      }
    } catch (cause) {
      // A broken check must never masquerade as "no problems found".
      const error = new Error(`Rule ${rule.id} crashed while auditing: ${cause?.message ?? cause}`);
      error.cause = cause;
      throw error;
    }
  }

  // Two rules can describe the same underlying issue (e.g. secrets in both URL
  // and argv); deduplicate on the stable fingerprint.
  const seen = new Set();
  findings = findings.filter((finding) => {
    if (seen.has(finding.fingerprint)) return false;
    seen.add(finding.fingerprint);
    return true;
  });

  if (minSeverity) findings = findings.filter((finding) => isAtLeast(finding.severity, minSeverity));

  findings.sort(compareFindings);

  return {
    findings,
    stats: {
      files: scan.files.length,
      configs: configs.length,
      descriptors: descriptors.length,
      servers: scan.servers.length,
      tools: scan.tools.length,
      rules: rules.length,
      errors: errors.length,
      disabledServers: scan.servers.filter((server) => server.disabled).length,
    },
    scan,
  };
}

/**
 * @param {import("./findings.js").Finding[]} sink
 * @param {import("./rules/types.js").Rule} rule
 * @param {import("./rules/types.js").RuleHit|import("./rules/types.js").RuleHit[]|null|undefined} result
 * @param {object} location
 */
function emit(sink, rule, result, location) {
  if (!result) return;
  const hits = Array.isArray(result) ? result : [result];
  for (const hit of hits) {
    if (!hit || typeof hit.message !== "string") continue;
    sink.push(createFinding(rule, hit, location));
  }
}
