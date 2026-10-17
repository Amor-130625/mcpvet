/**
 * Formatter dispatch. One place decides what `--format` means, so the CLI and
 * the programmatic API cannot drift apart.
 *
 * @module report
 */

import { formatPretty } from "./pretty.js";
import { formatJson } from "./json.js";
import { formatSarif } from "./sarif.js";
import { formatMarkdown } from "./markdown.js";

export const FORMATS = ["pretty", "json", "sarif", "markdown"];

/**
 * @param {{findings: import("../findings.js").Finding[], stats: any}} result
 * @param {string} format
 * @param {{color?: boolean, verbose?: boolean, generatedAt?: string}} [options]
 * @returns {string}
 */
export function format(result, formatName = "pretty", options = {}) {
  switch (String(formatName).toLowerCase()) {
    case "pretty":
    case "text":
      return formatPretty(result, options);
    case "json":
      return formatJson(result, options);
    case "sarif":
      return formatSarif(result);
    case "markdown":
    case "md":
      return formatMarkdown(result, options);
    default:
      throw new Error(`Unknown format "${formatName}". Expected one of: ${FORMATS.join(", ")}.`);
  }
}

export { formatPretty, formatJson, formatSarif, formatMarkdown };
