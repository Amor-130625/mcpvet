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
import { posix, resolve, win32 } from "node:path";
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

  // Build paths in the syntax of the *requested* platform, not the host's. A
  // caller that asks for Windows locations on Linux should get `C:\…`, and the
  // test suite depends on this to be able to check every platform anywhere.
  const path = platform === "win32" ? win32 : posix;
  const pathJoin = (...segments) => path.join(...segments);

  /** @type {Candidate[]} */
  const candidates = [];

  if (platform === "win32") {
    const appData = env.APPDATA ?? pathJoin(home, "AppData", "Roaming");
    const localAppData = env.LOCALAPPDATA ?? pathJoin(home, "AppData", "Local");
    candidates.push(
      { file: pathJoin(appData, "Claude", "claude_desktop_config.json"), source: "Claude Desktop" },
      { file: pathJoin(appData, "Code", "User", "mcp.json"), source: "VS Code (user)" },
      { file: pathJoin(appData, "Cursor", "User", "mcp.json"), source: "Cursor (user)" },
      { file: pathJoin(home, ".cursor", "mcp.json"), source: "Cursor" },
      { file: pathJoin(home, ".codeium", "windsurf", "mcp_config.json"), source: "Windsurf" },
      { file: pathJoin(localAppData, "Claude", "claude_desktop_config.json"), source: "Claude Desktop (local)" },
    );
  } else if (platform === "darwin") {
    candidates.push(
      { file: pathJoin(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), source: "Claude Desktop" },
      { file: pathJoin(home, "Library", "Application Support", "Code", "User", "mcp.json"), source: "VS Code (user)" },
      { file: pathJoin(home, "Library", "Application Support", "Cursor", "User", "mcp.json"), source: "Cursor (user)" },
      { file: pathJoin(home, ".cursor", "mcp.json"), source: "Cursor" },
      { file: pathJoin(home, ".codeium", "windsurf", "mcp_config.json"), source: "Windsurf" },
    );
  } else {
    const configHome = env.XDG_CONFIG_HOME ?? pathJoin(home, ".config");
    candidates.push(
      { file: pathJoin(configHome, "Claude", "claude_desktop_config.json"), source: "Claude Desktop" },
      { file: pathJoin(configHome, "Code", "User", "mcp.json"), source: "VS Code (user)" },
      { file: pathJoin(configHome, "Cursor", "User", "mcp.json"), source: "Cursor (user)" },
      { file: pathJoin(home, ".cursor", "mcp.json"), source: "Cursor" },
      { file: pathJoin(home, ".codeium", "windsurf", "mcp_config.json"), source: "Windsurf" },
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
