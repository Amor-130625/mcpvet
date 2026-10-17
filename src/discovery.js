/**
 * Where MCP clients keep their configuration.
 *
 * Discovery is deliberately pure and injectable: `candidateLocations()` takes
 * the platform, home directory, and environment as arguments. That makes the
 * Windows paths testable on Linux CI, and it means a test can never touch the
 * real `~/.cursor/mcp.json` of whoever runs the suite.
 *
 * @module discovery
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { toDisplayPath } from "./util.js";

/**
 * Filenames that a project may use for its MCP servers, relative to the
 * project root.
 */
export const PROJECT_CONFIG_FILES = [
  ".mcp.json",
  "mcp.json",
  ".mcp/servers.json",
  ".vscode/mcp.json",
  ".cursor/mcp.json",
  ".github/mcp.json",
];

/**
 * @typedef {object} Candidate
 * @property {string} file    absolute path
 * @property {string} source  human description of the owning client
 */

/**
 * Build the list of per-user config locations for a platform.
 *
 * @param {{platform?: NodeJS.Platform, home?: string, env?: Record<string, string|undefined>}} [options]
 * @returns {Candidate[]}
 */
export function candidateLocations(options = {}) {
  const {
    platform = process.platform,
    home = homedir(),
    env = process.env,
  } = options;

  /** @type {Candidate[]} */
  const candidates = [];

  if (platform === "win32") {
    const appData = env.APPDATA ?? join(home, "AppData", "Roaming");
    const localAppData = env.LOCALAPPDATA ?? join(home, "AppData", "Local");
    candidates.push(
      { file: join(appData, "Claude", "claude_desktop_config.json"), source: "Claude Desktop" },
      { file: join(appData, "Code", "User", "mcp.json"), source: "VS Code (user)" },
      { file: join(appData, "Cursor", "User", "mcp.json"), source: "Cursor (user)" },
      { file: join(home, ".cursor", "mcp.json"), source: "Cursor" },
      { file: join(home, ".codeium", "windsurf", "mcp_config.json"), source: "Windsurf" },
      { file: join(localAppData, "Claude", "claude_desktop_config.json"), source: "Claude Desktop (local)" },
    );
  } else if (platform === "darwin") {
    candidates.push(
      { file: join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), source: "Claude Desktop" },
      { file: join(home, "Library", "Application Support", "Code", "User", "mcp.json"), source: "VS Code (user)" },
      { file: join(home, "Library", "Application Support", "Cursor", "User", "mcp.json"), source: "Cursor (user)" },
      { file: join(home, ".cursor", "mcp.json"), source: "Cursor" },
      { file: join(home, ".codeium", "windsurf", "mcp_config.json"), source: "Windsurf" },
    );
  } else {
    const configHome = env.XDG_CONFIG_HOME ?? join(home, ".config");
    candidates.push(
      { file: join(configHome, "Claude", "claude_desktop_config.json"), source: "Claude Desktop" },
      { file: join(configHome, "Code", "User", "mcp.json"), source: "VS Code (user)" },
      { file: join(configHome, "Cursor", "User", "mcp.json"), source: "Cursor (user)" },
      { file: join(home, ".cursor", "mcp.json"), source: "Cursor" },
      { file: join(home, ".codeium", "windsurf", "mcp_config.json"), source: "Windsurf" },
    );
  }

  return candidates;
}

/**
 * Project-local configs, in the order a client would prefer them.
 *
 * @param {string} cwd
 * @returns {Candidate[]}
 */
export function projectCandidates(cwd) {
  return PROJECT_CONFIG_FILES.map((relative) => ({
    file: resolve(cwd, relative),
    source: "project",
  }));
}

/**
 * Discover config files that actually exist.
 *
 * @param {{cwd?: string, includeUser?: boolean, platform?: NodeJS.Platform, home?: string, env?: Record<string, string|undefined>, exists?: (file: string) => boolean}} [options]
 * @returns {Candidate[]}
 */
export function discoverConfigFiles(options = {}) {
  const {
    cwd = process.cwd(),
    includeUser = true,
    platform = process.platform,
    home = homedir(),
    env = process.env,
    exists = existsSync,
  } = options;

  const candidates = [...projectCandidates(cwd), ...(includeUser ? candidateLocations({ platform, home, env }) : [])];
  /** @type {Map<string, Candidate>} */
  const seen = new Map();
  for (const candidate of candidates) {
    const key = candidate.file.toLowerCase().replace(/\\/g, "/");
    if (seen.has(key)) continue;
    if (!exists(candidate.file)) continue;
    seen.set(key, candidate);
  }
  return [...seen.values()];
}

/**
 * Attach display paths to candidates.
 * @param {Candidate[]} candidates
 * @param {string} cwd
 */
export function toDisplayCandidates(candidates, cwd = process.cwd()) {
  return candidates.map((candidate) => ({ ...candidate, display: toDisplayPath(candidate.file, cwd) }));
}
