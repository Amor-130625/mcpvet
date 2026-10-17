/**
 * Public programmatic API.
 *
 *     import { audit, loadFiles, format } from "mcpvet";
 *
 * The CLI is a thin wrapper over these functions, and the test suite exercises
 * the same entry points — there is no second code path that only the CLI uses.
 *
 * @module mcpvet
 */

export { audit } from "./audit.js";
export { loadFile, loadFiles } from "./loader.js";
export { discoverConfigFiles, candidateLocations, projectCandidates, PROJECT_CONFIG_FILES } from "./discovery.js";
export { format, FORMATS, formatJson, formatMarkdown, formatPretty, formatSarif } from "./report/index.js";
export { computeScore, gradeFor, summarise } from "./score.js";
export {
  BASELINE_VERSION,
  DEFAULT_BASELINE_FILENAME,
  applyBaseline,
  buildBaseline,
  parseBaseline,
  updateBaseline,
} from "./baseline.js";
export { RULES, RULES_BY_ID, getRule, listRules, validateRules } from "./rules/index.js";
export {
  SEVERITY_ORDER,
  SEVERITY_WEIGHT,
  SARIF_LEVEL,
  compareFindings,
  countBySeverity,
  isAtLeast,
  severityRank,
  worstSeverity,
} from "./severity.js";
export { detectSecret, findSecrets, looksLikePlaceholder, redact, shannonEntropy } from "./secrets.js";
export { parseJsonc, tryParseJsonc, getPosition, resolvePointer, JsoncError } from "./jsonc.js";
export { detectDocumentKind, extractServers, extractTools, normalizeServer } from "./config.js";
export { NAME, VERSION, HOMEPAGE } from "./version.js";
