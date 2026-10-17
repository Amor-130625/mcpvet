/**
 * Single source of truth for the tool name and version.
 *
 * `test/version.test.js` asserts that VERSION stays in sync with package.json,
 * so a release can never ship a SARIF report or a `--version` line that lies
 * about which build produced it.
 */
export const NAME = "mcpvet";
export const VERSION = "0.1.0";
export const HOMEPAGE = "https://github.com/Amor-130625/mcpvet";
