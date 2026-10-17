#!/usr/bin/env node
/**
 * Executable entry point.
 *
 * Deliberately thin: everything testable lives in `src/`, so the test suite can
 * exercise the same code paths the process runs. The only thing this file does
 * is wire `process` to `main()` and translate the returned code into an exit
 * status.
 */

import { main, defaultIO } from "../src/cli.js";

try {
  const code = await main(process.argv.slice(2), defaultIO());
  process.exitCode = code;
} catch (error) {
  // `main` handles its own errors; reaching this means something escaped.
  process.stderr.write(`mcpvet: fatal: ${error?.stack ?? error}\n`);
  process.exitCode = 3;
}
