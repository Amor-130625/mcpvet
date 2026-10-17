/**
 * Normalisation layer between "whatever JSON the client wrote" and "the shape
 * the rules reason about".
 *
 * MCP clients disagree about the config envelope: Claude Desktop and Cursor use
 * `mcpServers`, VS Code uses `servers` (sometimes nested under `mcp`), and
 * third-party launchers invent their own. They also disagree about field names
 * inside a server entry (`type` vs `transport`, `alwaysAllow` vs `autoApprove`).
 * Every rule would otherwise need to know all of that, so the mess is
 * concentrated here and rules get one vocabulary.
 *
 * @module config
 */

import { asString, commandBasename, isPlainObject, toStringMap } from "./util.js";
import { getPosition } from "./jsonc.js";

/** @typedef {"stdio"|"http"|"sse"|"unknown"} Transport */

/**
 * @typedef {object} NormalizedServer
 * @property {string} name
 * @property {string|null} file
 * @property {string} pointer
 * @property {number|null} line
 * @property {number|null} column
 * @property {any} raw
 * @property {Transport} transport
 * @property {string|null} command
 * @property {string} launcher     basename of `command`, without extension
 * @property {string[]} args
 * @property {Record<string, string>} env
 * @property {string|null} cwd
 * @property {string|null} url
 * @property {Record<string, string>} headers
 * @property {{present: boolean, values: string[], wildcard: boolean}} autoApprove
 * @property {boolean} disabled
 */

/**
 * @typedef {object} NormalizedTool
 * @property {string} name
 * @property {string} description
 * @property {any} inputSchema
 * @property {{readOnlyHint?: boolean, destructiveHint?: boolean, idempotentHint?: boolean, openWorldHint?: boolean}|null} annotations
 * @property {string|null} server
 * @property {string|null} file
 * @property {string} pointer
 * @property {number|null} line
 * @property {number|null} column
 */

/**
 * @typedef {object} ConfigWarning
 * @property {string} code
 * @property {string} message
 * @property {string} pointer
 * @property {number|null} line
 */

const AUTO_APPROVE_KEYS = ["autoApprove", "auto_approve", "alwaysAllow", "always_allow", "trust"];
const HTTP_TRANSPORTS = new Set(["http", "streamable-http", "streamablehttp", "streamable_http"]);
const SSE_TRANSPORTS = new Set(["sse", "http+sse", "httpsse"]);
const STDIO_TRANSPORTS = new Set(["stdio", "process", "child_process", "command"]);

/**
 * Decide what a parsed document represents.
 *
 * @param {any} document
 * @returns {"config"|"tools"|"unknown"}
 */
export function detectDocumentKind(document) {
  if (Array.isArray(document)) {
    return document.length === 0 || isPlainObject(document[0]) ? "tools" : "unknown";
  }
  if (!isPlainObject(document)) return "unknown";
  if (Array.isArray(document.tools) || Array.isArray(document.result?.tools)) return "tools";
  if (isPlainObject(document.mcpServers)) return "config";
  if (isPlainObject(document.servers)) return "config";
  if (isPlainObject(document.mcp?.servers)) return "config";
  if (isPlainObject(document.mcp?.mcpServers)) return "config";
  if (Array.isArray(document.servers)) return "config";
  return "unknown";
}

/**
 * Collect every `{ name -> entry }` container a document might use.
 *
 * @param {any} document
 * @returns {{label: string, pointer: string, value: Record<string, any>|any[]}[]}
 */
function findServerContainers(document) {
  /** @type {{label: string, pointer: string, value: Record<string, any>|any[]}[]} */
  const containers = [];
  if (!isPlainObject(document)) return containers;
  const push = (label, pointer, value) => {
    if (isPlainObject(value) || Array.isArray(value)) containers.push({ label, pointer, value });
  };
  push("mcpServers", "/mcpServers", document.mcpServers);
  push("mcp.servers", "/mcp/servers", document.mcp?.servers);
  push("mcp.mcpServers", "/mcp/mcpServers", document.mcp?.mcpServers);
  push("servers", "/servers", document.servers);
  return containers;
}

/**
 * Turn a single raw server entry into the shape rules consume.
 *
 * @param {string} name
 * @param {any} entry
 * @param {{file?: string|null, pointer: string, positions?: Map<string, {line: number, column: number}>|null, warnings?: ConfigWarning[]}} options
 * @returns {NormalizedServer}
 */
export function normalizeServer(name, entry, options) {
  const { file = null, pointer, positions = null, warnings = [] } = options;
  const position = getPosition(positions, pointer);

  /** @type {NormalizedServer} */
  const server = {
    name: String(name),
    file,
    pointer,
    line: position?.line ?? null,
    column: position?.column ?? null,
    raw: entry,
    transport: "unknown",
    command: null,
    launcher: "",
    args: [],
    env: {},
    cwd: null,
    url: null,
    headers: {},
    autoApprove: { present: false, values: [], wildcard: false },
    disabled: false,
  };

  // Some launchers allow the shorthand `"server": "npx -y pkg"`.
  let record = entry;
  if (typeof entry === "string") {
    record = { command: entry };
  } else if (!isPlainObject(entry)) {
    warnings.push({
      code: "NON_OBJECT_ENTRY",
      message: `Server "${name}" is not an object; the client will ignore it.`,
      pointer,
      line: position?.line ?? null,
    });
    return server;
  }

  const declaredType = asString(record.type ?? record.transport ?? record.protocol).toLowerCase();

  if (typeof record.command === "string" && record.command.trim() !== "") {
    server.command = record.command.trim();
    server.launcher = commandBasename(server.command);
  } else if (record.command !== undefined) {
    warnings.push({
      code: "NON_STRING_COMMAND",
      message: `Server "${name}" has a non-string "command"; it cannot be launched.`,
      pointer: `${pointer}/command`,
      line: getPosition(positions, `${pointer}/command`)?.line ?? null,
    });
  }

  const rawArgs = record.args;
  if (Array.isArray(rawArgs)) {
    server.args = rawArgs.map((arg) => (typeof arg === "string" ? arg : asString(arg)));
  } else if (typeof rawArgs === "string") {
    // Tolerated by a few clients; audited as the single argv element it is.
    server.args = [rawArgs];
  } else if (rawArgs !== undefined) {
    warnings.push({
      code: "NON_ARRAY_ARGS",
      message: `Server "${name}" has a non-array "args"; the client may reject the config.`,
      pointer: `${pointer}/args`,
      line: getPosition(positions, `${pointer}/args`)?.line ?? null,
    });
  }

  server.env = toStringMap(record.env ?? record.environment);
  server.headers = toStringMap(record.headers);

  const url = asString(record.url ?? record.endpoint ?? record.serverUrl ?? record.server_url);
  server.url = url === "" ? null : url;
  const cwd = asString(record.cwd ?? record.cwdPath);
  server.cwd = cwd === "" ? null : cwd;

  if (declaredType !== "") {
    if (HTTP_TRANSPORTS.has(declaredType)) server.transport = "http";
    else if (SSE_TRANSPORTS.has(declaredType)) server.transport = "sse";
    else if (STDIO_TRANSPORTS.has(declaredType)) server.transport = "stdio";
    else {
      warnings.push({
        code: "UNKNOWN_TRANSPORT",
        message: `Server "${name}" declares an unrecognised transport "${declaredType}".`,
        pointer: `${pointer}/type`,
        line: getPosition(positions, `${pointer}/type`)?.line ?? null,
      });
    }
    if ((server.transport === "http" || server.transport === "sse") && server.command) {
      warnings.push({
        code: "CONFLICTING_TRANSPORT",
        message: `Server "${name}" declares a remote transport but also a local command; behaviour depends on the client.`,
        pointer,
        line: position?.line ?? null,
      });
    }
  }

  if (server.transport === "unknown") {
    if (server.command) server.transport = "stdio";
    else if (server.url) server.transport = "http";
  }

  for (const key of AUTO_APPROVE_KEYS) {
    const value = record[key];
    if (value === undefined) continue;
    if (value === true) {
      server.autoApprove = { present: true, values: [], wildcard: true };
      break;
    }
    if (Array.isArray(value)) {
      const values = value.map((item) => (typeof item === "string" ? item : JSON.stringify(item)));
      server.autoApprove = {
        present: true,
        values,
        wildcard: values.includes("*"),
      };
      break;
    }
    if (isPlainObject(value) && Object.keys(value).length > 0) {
      server.autoApprove = { present: true, values: Object.keys(value), wildcard: false };
      break;
    }
  }

  if (record.disabled === true || record.enabled === false) server.disabled = true;

  return server;
}

/**
 * Extract every server declared by a config document.
 *
 * @param {any} document
 * @param {{file?: string|null, positions?: Map<string, {line: number, column: number}>|null}} [options]
 * @returns {{servers: NormalizedServer[], warnings: ConfigWarning[]}}
 */
export function extractServers(document, options = {}) {
  const { file = null, positions = null } = options;
  /** @type {NormalizedServer[]} */
  const servers = [];
  /** @type {ConfigWarning[]} */
  const warnings = [];

  for (const container of findServerContainers(document)) {
    if (Array.isArray(container.value)) {
      container.value.forEach((entry, index) => {
        const pointer = `${container.pointer}/${index}`;
        const name = asString(entry?.name) || `server-${index}`;
        servers.push(normalizeServer(name, entry, { file, pointer, positions, warnings }));
      });
      continue;
    }
    for (const [name, entry] of Object.entries(container.value)) {
      const pointer = `${container.pointer}/${name.replace(/~/g, "~0").replace(/\//g, "~1")}`;
      servers.push(normalizeServer(name, entry, { file, pointer, positions, warnings }));
    }
  }

  return { servers, warnings };
}

/**
 * Extract tool descriptors from a `tools/list` payload (raw response or the
 * unwrapped result) or a bare array of tools.
 *
 * @param {any} document
 * @param {{file?: string|null, positions?: Map<string, {line: number, column: number}>|null, server?: string|null}} [options]
 * @returns {NormalizedTool[]}
 */
export function extractTools(document, options = {}) {
  const { file = null, positions = null, server = null } = options;
  let list = null;
  let pointer = "";

  if (Array.isArray(document)) {
    list = document;
  } else if (isPlainObject(document) && Array.isArray(document.tools)) {
    list = document.tools;
    pointer = "/tools";
  } else if (isPlainObject(document) && Array.isArray(document.result?.tools)) {
    list = document.result.tools;
    pointer = "/result/tools";
  }
  if (!list) return [];

  /** @type {NormalizedTool[]} */
  const tools = [];
  list.forEach((raw, index) => {
    if (!isPlainObject(raw)) return;
    const itemPointer = `${pointer}/${index}`;
    const position = getPosition(positions, itemPointer);
    const annotations = isPlainObject(raw.annotations) ? raw.annotations : null;
    tools.push({
      name: asString(raw.name),
      description: asString(raw.description),
      inputSchema: raw.inputSchema ?? raw.input_schema ?? null,
      annotations,
      server,
      file,
      pointer: itemPointer,
      line: position?.line ?? null,
      column: position?.column ?? null,
    });
  });
  return tools;
}
