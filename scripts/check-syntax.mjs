#!/usr/bin/env node
/**
 * Syntax-check every JavaScript file without executing it.
 *
 * `node --check` is used instead of importing because some modules (the CLI)
 * read `process.argv` at import time, and a syntax check should be free of
 * side effects. Child stdio is discarded rather than piped: piped stdio is
 * unavailable in some locked-down environments, and this check does not need
 * the child's output.
 */

import { spawnSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const ROOTS = ["bin", "src", "test", "scripts"];
const SKIP = new Set(["node_modules", ".git"]);

/** @param {string} dir @returns {string[]} */
function collect(dir) {
  /** @type {string[]} */
  const files = [];
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) files.push(...collect(full));
    else if (/\.(?:m?js)$/.test(entry)) files.push(full);
  }
  return files;
}

const files = ROOTS.flatMap((name) => {
  try {
    return collect(join(ROOT, name));
  } catch {
    return [];
  }
});

let failures = 0;
for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { stdio: "ignore" });
  if (result.status !== 0) {
    failures += 1;
    process.stderr.write(`syntax check failed: ${relative(ROOT, file)}\n`);
  }
}

if (failures > 0) {
  process.stderr.write(`${failures} file(s) failed the syntax check\n`);
  process.exit(1);
}
process.stdout.write(`syntax check passed for ${files.length} file(s)\n`);
