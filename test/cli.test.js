/**
 * End-to-end CLI tests.
 *
 * These spawn the real executable, so argument parsing, exit codes, file
 * writing, and process wiring are all covered — the parts a unit test on `run`
 * would silently skip.
 */

import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { VERSION } from "../src/version.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const BIN = join(ROOT, "bin", "mcpvet.js");
const VULNERABLE = join("examples", "vulnerable");
const SAFE = join("examples", "safe");

/**
 * Child output is captured through *files*, not pipes.
 *
 * On Windows under a restrictive sandbox, `spawn` with piped stdio fails with
 * EPERM because pipes are named objects. Writing child stdout/stderr to real
 * files works everywhere, keeps the test end-to-end, and avoids a pipe buffer
 * deadlock on large SARIF reports.
 */
const OUTPUT_DIR = mkdtempSync(join(tmpdir(), "mcpvet-cli-output-"));
after(() => rmSync(OUTPUT_DIR, { recursive: true, force: true }));

let cliRun = 0;

/**
 * @param {string[]} args
 * @param {{cwd?: string}} [options]
 */
function cli(args, options = {}) {
  cliRun += 1;
  const stdoutFile = join(OUTPUT_DIR, `stdout-${cliRun}.txt`);
  const stderrFile = join(OUTPUT_DIR, `stderr-${cliRun}.txt`);
  const stdoutFd = openSync(stdoutFile, "w");
  const stderrFd = openSync(stderrFile, "w");
  let status;
  try {
    const result = spawnSync(process.execPath, [BIN, ...args], {
      cwd: options.cwd ?? ROOT,
      env: { ...process.env, NO_COLOR: "1" },
      stdio: ["ignore", stdoutFd, stderrFd],
      timeout: 60_000,
    });
    status = result.status;
  } finally {
    closeSync(stdoutFd);
    closeSync(stderrFd);
  }
  return {
    code: status,
    stdout: readFileSync(stdoutFile, "utf8"),
    stderr: readFileSync(stderrFile, "utf8"),
  };
}

test("--version prints the package version", () => {
  const { code, stdout } = cli(["--version"]);
  assert.equal(code, 0);
  assert.match(stdout, new RegExp(`mcpvet ${VERSION.replace(/\./g, "\\.")}`));
});

test("help is printed and exits zero", () => {
  const { code, stdout } = cli(["help"]);
  assert.equal(code, 0);
  assert.match(stdout, /Usage:/);
  assert.match(stdout, /Exit codes:/);
});

test("an unknown option is a usage error", () => {
  const { code, stderr } = cli(["scan", "--nope"]);
  assert.equal(code, 2);
  assert.match(stderr, /Unknown option/);
});

test("an unknown command is a usage error", () => {
  const { code, stderr } = cli(["frobnicate"]);
  assert.equal(code, 2);
  assert.match(stderr, /Unknown command/);
});

test("an invalid enum value is rejected", () => {
  const { code, stderr } = cli(["scan", "--format", "yaml"]);
  assert.equal(code, 2);
  assert.match(stderr, /Invalid value/);
});

test("a missing path is a usage error", () => {
  const { code, stderr } = cli(["scan", "does/not/exist.json"]);
  assert.equal(code, 2);
  assert.match(stderr, /No such file or directory/);
});

test("rules lists every rule", () => {
  const { code, stdout } = cli(["rules"]);
  assert.equal(code, 0);
  assert.match(stdout, /MCP001/);
  assert.match(stdout, /MCP060/);
});

test("rules --format json is machine readable", () => {
  const { code, stdout } = cli(["rules", "--format", "json"]);
  assert.equal(code, 0);
  const parsed = JSON.parse(stdout);
  assert.ok(Array.isArray(parsed));
  assert.ok(parsed.every((rule) => /^MCP\d{3}$/.test(rule.id)));
  assert.ok(parsed.every((rule) => typeof rule.why === "undefined"));
});

test("explain prints the rationale and the fix", () => {
  const { code, stdout } = cli(["explain", "MCP001"]);
  assert.equal(code, 0);
  assert.match(stdout, /MCP001/);
  assert.match(stdout, /Fix/);
});

test("explain with an unknown rule is a usage error", () => {
  const { code, stderr } = cli(["explain", "MCP999"]);
  assert.equal(code, 2);
  assert.match(stderr, /Unknown rule/);
});

test("a clean config exits zero", () => {
  const { code, stdout } = cli(["scan", SAFE, "--no-user"]);
  assert.equal(code, 0, stdout);
  assert.match(stdout, /No findings/);
});

test("a risky config exits one at the default threshold", () => {
  const { code, stderr } = cli(["scan", VULNERABLE, "--no-user"]);
  assert.equal(code, 1);
  assert.match(stderr, /failing/);
});

test("--fail-on none always exits zero", () => {
  const { code } = cli(["scan", VULNERABLE, "--no-user", "--fail-on", "none"]);
  assert.equal(code, 0);
});

test("--fail-on critical only fails on critical findings", () => {
  const { code } = cli(["scan", SAFE, "--no-user", "--fail-on", "critical"]);
  assert.equal(code, 0);
});

test("--format json emits a parseable report", () => {
  const { code, stdout } = cli(["scan", VULNERABLE, "--no-user", "--format", "json", "--fail-on", "none"]);
  assert.equal(code, 0);
  const payload = JSON.parse(stdout);
  assert.ok(payload.findings.length > 0);
  assert.equal(payload.tool.name, "mcpvet");
});

test("--format sarif emits valid SARIF", () => {
  const { code, stdout } = cli(["scan", VULNERABLE, "--no-user", "--format", "sarif", "--fail-on", "none"]);
  assert.equal(code, 0);
  const sarif = JSON.parse(stdout);
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].results.length > 0);
});

test("--format markdown emits a report comment", () => {
  const { code, stdout } = cli(["scan", VULNERABLE, "--no-user", "--format", "markdown", "--fail-on", "none"]);
  assert.equal(code, 0);
  assert.match(stdout, /## mcpvet report/);
});

test("--ignore removes a rule from the report", () => {
  const { stdout } = cli(["scan", VULNERABLE, "--no-user", "--format", "json", "--fail-on", "none", "--ignore", "MCP040,MCP050"]);
  const payload = JSON.parse(stdout);
  assert.ok(!payload.findings.some((finding) => finding.ruleId === "MCP040"));
  assert.ok(!payload.findings.some((finding) => finding.ruleId === "MCP050"));
});

test("--output writes the report to a file and keeps stdout quiet", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcpvet-cli-"));
  try {
    const output = join(dir, "report.sarif");
    const { code, stdout, stderr } = cli([
      "scan",
      VULNERABLE,
      "--no-user",
      "--format",
      "sarif",
      "--output",
      output,
      "--fail-on",
      "none",
    ]);
    assert.equal(code, 0);
    assert.equal(stdout.trim(), "");
    assert.match(stderr, /written to/);
    const sarif = JSON.parse(await readFile(output, "utf8"));
    assert.equal(sarif.version, "2.1.0");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("check audits a command that is not in any file", () => {
  const { code, stdout } = cli(["check", "--command", "npx -y unpinned-server", "--fail-on", "none"]);
  assert.equal(code, 0);
  assert.match(stdout, /MCP001/);
});

test("check exits one when the spec is risky", () => {
  const { code, stdout } = cli(["check", "--command", "npx -y unpinned-server", "--auto-approve", "*"]);
  assert.equal(code, 1);
  assert.match(stdout, /MCP040/);
});

test("check requires --command or --url", () => {
  const { code, stderr } = cli(["check"]);
  assert.equal(code, 2);
  assert.match(stderr, /needs --command or --url/);
});

test("baseline write then scan suppresses the accepted findings", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcpvet-baseline-"));
  try {
    await writeFile(
      join(dir, "mcp.json"),
      JSON.stringify({ mcpServers: { s: { command: "npx", args: ["-y", "pkg"] } } }, null, 2),
      "utf8",
    );

    const write = cli(["baseline", "write"], { cwd: dir });
    assert.equal(write.code, 0, write.stderr);
    const baseline = JSON.parse(await readFile(join(dir, ".mcpvet-baseline.json"), "utf8"));
    assert.ok(baseline.count > 0);

    const scan = cli(["scan", ".", "--no-user"], { cwd: dir });
    assert.equal(scan.code, 0, scan.stderr);
    assert.match(scan.stderr, /suppressed by/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an invalid .mcpvetrc.json is a usage error", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcpvet-rc-"));
  try {
    await writeFile(join(dir, ".mcpvetrc.json"), "{ not json", "utf8");
    const { code, stderr } = cli(["scan", SAFE, "--no-user"], { cwd: dir });
    assert.equal(code, 2);
    assert.match(stderr, /is invalid/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a directory walk ignores unrelated JSON files", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcpvet-walk-"));
  try {
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }), "utf8");
    await writeFile(join(dir, "notes.json"), JSON.stringify({ hello: "world" }), "utf8");
    const { code, stdout } = cli(["scan", ".", "--no-user", "--format", "json"], { cwd: dir });
    assert.equal(code, 0, stdout);
    assert.match(stdout, /no MCP configuration found|"findings": \[\]/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("init creates a config file and a workflow", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcpvet-init-"));
  try {
    const { code, stdout } = cli(["init"], { cwd: dir });
    assert.equal(code, 0);
    assert.match(stdout, /created/);
    const rc = JSON.parse(await readFile(join(dir, ".mcpvetrc.json"), "utf8"));
    assert.equal(rc.failOn, "high");
    const workflow = await readFile(join(dir, ".github", "workflows", "mcpvet.yml"), "utf8");
    assert.match(workflow, /upload-sarif/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
