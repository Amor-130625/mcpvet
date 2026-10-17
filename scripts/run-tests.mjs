#!/usr/bin/env node
/**
 * Run the test suite deterministically across Node versions and platforms.
 *
 * `node --test test/` is not portable: newer Node versions treat a positional
 * argument as something to execute, so a directory becomes `require('test')` and
 * fails with MODULE_NOT_FOUND. Passing a bare glob is also not portable, because
 * only some shells expand it and Node itself only gained glob support in v22.
 *
 * So the file list is built here and passed explicitly. That also keeps
 * `test/helpers.js` out of the run — it is a shared module, not a test, and
 * letting the runner pick it up inflates the reported test count.
 *
 * Usage:
 *   node scripts/run-tests.mjs                 # one process per file (default)
 *   node scripts/run-tests.mjs --in-process    # every file in one process
 *   node scripts/run-tests.mjs --coverage      # with the experimental coverage report
 */

import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const TEST_DIR = join(ROOT, "test");

const files = readdirSync(TEST_DIR)
  .filter((name) => name.endsWith(".test.js"))
  .sort()
  .map((name) => join(TEST_DIR, name));

if (files.length === 0) {
  process.stderr.write(`no *.test.js files found in ${TEST_DIR}\n`);
  process.exit(1);
}

const args = ["--test"];
if (process.argv.includes("--in-process")) args.push("--test-isolation=none");
if (process.argv.includes("--coverage")) args.push("--experimental-test-coverage");
args.push(...files);

const result = spawnSync(process.execPath, args, { stdio: "inherit" });
if (result.error) {
  process.stderr.write(`could not start the test runner: ${result.error.message}\n`);
  process.exit(1);
}
process.exit(result.status ?? 1);
