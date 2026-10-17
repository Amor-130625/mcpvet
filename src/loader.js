/**
 * File loading: read, parse, classify, normalise.
 *
 * Every failure path becomes data (`errors[]`) rather than an exception. A
 * security scan that throws on the first bad file tells you nothing about the
 * other twelve.
 *
 * @module loader
 */

import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { tryParseJsonc } from "./jsonc.js";
import { detectDocumentKind, extractServers, extractTools } from "./config.js";
import { toDisplayPath } from "./util.js";

/**
 * @typedef {object} LoadedDocument
 * @property {string} file            display path (relative when inside cwd)
 * @property {"config"|"tools"|"unknown"} kind
 * @property {any} [document]
 * @property {Map<string, {line: number, column: number}>} [positions]
 * @property {import("./config.js").NormalizedServer[]} [servers]
 * @property {import("./config.js").ConfigWarning[]} [warnings]
 * @property {import("./config.js").NormalizedTool[]} [tools]
 */

/**
 * @typedef {object} LoadError
 * @property {string} code
 * @property {string} file
 * @property {string} message
 * @property {number|null} line
 * @property {number|null} column
 */

/**
 * @param {string} file absolute path
 * @param {{cwd?: string, server?: string|null, kind?: "config"|"tools"}} [options]
 * @returns {Promise<{loaded: LoadedDocument|null, error: LoadError|null}>}
 */
export async function loadFile(file, options = {}) {
  const { cwd = process.cwd(), server = null, kind } = options;
  const display = toDisplayPath(file, cwd);

  let text;
  try {
    text = await readFile(file, "utf8");
  } catch (error) {
    return {
      loaded: null,
      error: {
        code: "UNREADABLE",
        file: display,
        message: `Could not read ${basename(display)}: ${error.code ?? error.message}.`,
        line: null,
        column: null,
      },
    };
  }

  const parsed = tryParseJsonc(text);
  if (!parsed.ok) {
    return {
      loaded: null,
      error: {
        code: "PARSE_ERROR",
        file: display,
        message: `Could not parse ${basename(display)}: ${parsed.error.message}.`,
        line: parsed.error.line ?? null,
        column: parsed.error.column ?? null,
      },
    };
  }

  const detected = kind ?? detectDocumentKind(parsed.value);
  if (detected === "unknown") {
    return {
      loaded: null,
      error: {
        code: "UNKNOWN_DOCUMENT",
        file: display,
        message: `${basename(display)} is not an MCP config or a tool descriptor; nothing to audit.`,
        line: null,
        column: null,
      },
    };
  }

  if (detected === "tools") {
    return {
      loaded: {
        file: display,
        kind: "tools",
        document: parsed.value,
        positions: parsed.positions,
        tools: extractTools(parsed.value, { file: display, positions: parsed.positions, server }),
      },
      error: null,
    };
  }

  const { servers, warnings } = extractServers(parsed.value, { file: display, positions: parsed.positions });
  return {
    loaded: {
      file: display,
      kind: "config",
      document: parsed.value,
      positions: parsed.positions,
      servers,
      warnings,
    },
    error: null,
  };
}

/**
 * Load many files, separating successful loads from errors.
 *
 * @param {{file: string, kind?: "config"|"tools", server?: string|null}[]} entries
 * @param {{cwd?: string}} [options]
 * @returns {Promise<{configs: LoadedDocument[], descriptors: LoadedDocument[], errors: LoadError[]}>}
 */
export async function loadFiles(entries, options = {}) {
  const { cwd = process.cwd() } = options;
  /** @type {LoadedDocument[]} */
  const configs = [];
  /** @type {LoadedDocument[]} */
  const descriptors = [];
  /** @type {LoadError[]} */
  const errors = [];

  for (const entry of entries) {
    const { loaded, error } = await loadFile(entry.file, { cwd, kind: entry.kind, server: entry.server });
    if (error) errors.push(error);
    if (!loaded) continue;
    if (loaded.kind === "tools") descriptors.push(loaded);
    else configs.push(loaded);
  }

  return { configs, descriptors, errors };
}
