/**
 * Discovery tests.
 *
 * Discovery is injectable, so Windows paths can be checked on any OS and no test
 * ever reads the real `~/.cursor/mcp.json` of whoever runs the suite.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { join, resolve } from "node:path";
import {
  PROJECT_CONFIG_FILES,
  candidateLocations,
  discoverConfigFiles,
  projectCandidates,
} from "../src/discovery.js";

test("projects are searched for the documented filenames", () => {
  assert.deepEqual(PROJECT_CONFIG_FILES, [
    ".mcp.json",
    "mcp.json",
    ".mcp/servers.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".github/mcp.json",
  ]);
  const candidates = projectCandidates("/work/repo");
  assert.equal(candidates.length, PROJECT_CONFIG_FILES.length);
  assert.ok(candidates.every((candidate) => candidate.source === "project"));
});

test("Windows locations use APPDATA and the home directory", () => {
  const candidates = candidateLocations({
    platform: "win32",
    home: "C:\\Users\\dev",
    env: { APPDATA: "C:\\Users\\dev\\AppData\\Roaming", LOCALAPPDATA: "C:\\Users\\dev\\AppData\\Local" },
  });
  const files = candidates.map((candidate) => candidate.file);
  assert.ok(files.includes(join("C:\\Users\\dev\\AppData\\Roaming", "Claude", "claude_desktop_config.json")));
  assert.ok(files.includes(join("C:\\Users\\dev\\.cursor", "mcp.json")));
  assert.ok(files.includes(join("C:\\Users\\dev\\AppData\\Local", "Claude", "claude_desktop_config.json")));
});

test("Windows falls back to a derived APPDATA when the variable is missing", () => {
  const files = candidateLocations({ platform: "win32", home: "C:\\Users\\dev", env: {} }).map((entry) => entry.file);
  assert.ok(files.some((file) => file.includes("AppData")));
});

test("macOS locations use Application Support", () => {
  const files = candidateLocations({ platform: "darwin", home: "/Users/dev", env: {} }).map((entry) => entry.file);
  assert.ok(files.includes(join("/Users/dev", "Library", "Application Support", "Claude", "claude_desktop_config.json")));
  assert.ok(files.includes(join("/Users/dev", "Library", "Application Support", "Code", "User", "mcp.json")));
});

test("Linux locations honour XDG_CONFIG_HOME", () => {
  const files = candidateLocations({
    platform: "linux",
    home: "/home/dev",
    env: { XDG_CONFIG_HOME: "/home/dev/.config2" },
  }).map((entry) => entry.file);
  assert.ok(files.includes(join("/home/dev/.config2", "Claude", "claude_desktop_config.json")));
});

test("discovery keeps only files that exist", () => {
  const cwd = resolve("/work/repo");
  const expected = resolve(cwd, ".mcp.json");
  const exists = (file) => file === expected;
  const found = discoverConfigFiles({ cwd, includeUser: false, exists });
  assert.equal(found.length, 1);
  assert.equal(found[0].file, expected);
});

test("discovery deduplicates the same path found twice", () => {
  const cwd = "/work/repo";
  const found = discoverConfigFiles({ cwd, includeUser: false, exists: () => true });
  const keys = found.map((candidate) => candidate.file.toLowerCase());
  assert.equal(new Set(keys).size, keys.length);
});

test("discovery can skip per-user configs", () => {
  const withUser = discoverConfigFiles({
    cwd: "/work/repo",
    includeUser: true,
    platform: "linux",
    home: "/home/dev",
    env: {},
    exists: () => true,
  });
  const withoutUser = discoverConfigFiles({ cwd: "/work/repo", includeUser: false, exists: () => true });
  assert.ok(withUser.length > withoutUser.length);
  assert.ok(withUser.some((candidate) => candidate.source === "Claude Desktop"));
});
