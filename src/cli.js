/**
 * Command-line interface.
 *
 * Hand-rolled argument parsing, because a security tool with zero dependencies
 * still needs to behave predictably: `--flag=value` and `--flag value` both
 * work, an unknown flag is a usage error (never silently ignored), and `--`
 * ends option parsing so a path may start with a dash.
 *
 * Side effects are injected (`io`), so every branch — including the exit codes —
 * is reachable from the test suite.
 *
 * @module cli
 */

import { readFile, writeFile, stat, readdir, mkdir } from "node:fs/promises";
import { join, resolve, basename, dirname } from "node:path";
import { audit } from "./audit.js";
import { loadFiles } from "./loader.js";
import { discoverConfigFiles } from "./discovery.js";
import { format, FORMATS } from "./report/index.js";
import { SEVERITY_ORDER, isAtLeast, worstSeverity } from "./severity.js";
import { computeScore } from "./score.js";
import { listRules, getRule } from "./rules/index.js";
import {
  DEFAULT_BASELINE_FILENAME,
  applyBaseline,
  parseBaseline,
  updateBaseline,
  buildBaseline,
} from "./baseline.js";
import { tryParseJsonc } from "./jsonc.js";
import { normalizeServer } from "./config.js";
import { splitShellWords } from "./shellwords.js";
import { NAME, VERSION, HOMEPAGE } from "./version.js";
import { toDisplayPath } from "./util.js";

export const EXIT = Object.freeze({ OK: 0, FINDINGS: 1, USAGE: 2, INTERNAL: 3 });
export const FAIL_ON_VALUES = ["none", ...SEVERITY_ORDER];

/** Filenames that are always treated as an MCP config, even in a directory walk. */
const KNOWN_CONFIG_NAMES = new Set([
  "claude_desktop_config.json",
  "mcp.json",
  ".mcp.json",
  "servers.json",
  "mcp_config.json",
  "mcp.tools.json",
]);

/** Raised for user mistakes; mapped to exit code 2 with a hint. */
export class UsageError extends Error {
  constructor(message, hint) {
    super(message);
    this.name = "UsageError";
    this.hint = hint;
  }
}

/**
 * @typedef {object} OptionSpec
 * @property {"string"|"boolean"|"number"} type
 * @property {string} [alias]
 * @property {boolean} [array]
 * @property {string[]} [values]
 */

/** @type {Record<string, OptionSpec>} */
export const OPTION_SPEC = {
  format: { type: "string", alias: "f", values: FORMATS },
  output: { type: "string", alias: "o" },
  "fail-on": { type: "string", values: FAIL_ON_VALUES },
  "min-severity": { type: "string", values: SEVERITY_ORDER },
  ignore: { type: "string", array: true },
  baseline: { type: "string" },
  "no-baseline": { type: "boolean" },
  descriptor: { type: "string", array: true },
  "no-user": { type: "boolean" },
  color: { type: "boolean" },
  "no-color": { type: "boolean" },
  verbose: { type: "boolean", alias: "v" },
  quiet: { type: "boolean", alias: "q" },
  config: { type: "string" },
  help: { type: "boolean", alias: "h" },
  version: { type: "boolean", alias: "V" },
  name: { type: "string" },
  command: { type: "string" },
  url: { type: "string" },
  type: { type: "string" },
  env: { type: "string", array: true },
  arg: { type: "string", array: true },
  header: { type: "string", array: true },
  "auto-approve": { type: "string", array: true },
  "max-findings": { type: "number" },
};

const ALIASES = new Map(
  Object.entries(OPTION_SPEC)
    .filter(([, spec]) => spec.alias)
    .map(([name, spec]) => [spec.alias, name]),
);

/**
 * @param {string[]} argv
 * @returns {{options: Record<string, any>, positionals: string[]}}
 */
export function parseArgs(argv) {
  /** @type {Record<string, any>} */
  const options = {};
  /** @type {string[]} */
  const positionals = [];
  let endOfOptions = false;

  const assign = (name, value) => {
    const spec = OPTION_SPEC[name];
    if (!spec) throw new UsageError(`Unknown option --${name}.`, "Run `mcpvet help` to see the options.");
    if (spec.array) {
      options[name] = options[name] ?? [];
      options[name].push(value);
      return;
    }
    options[name] = value;
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (endOfOptions) {
      positionals.push(arg);
      continue;
    }
    if (arg === "--") {
      endOfOptions = true;
      continue;
    }
    if (!arg.startsWith("-") || arg === "-") {
      positionals.push(arg);
      continue;
    }

    let name;
    let inlineValue;
    if (arg.startsWith("--")) {
      const withoutPrefix = arg.slice(2);
      const equals = withoutPrefix.indexOf("=");
      name = equals === -1 ? withoutPrefix : withoutPrefix.slice(0, equals);
      inlineValue = equals === -1 ? undefined : withoutPrefix.slice(equals + 1);
    } else {
      const short = arg.slice(1);
      if (short.length !== 1) throw new UsageError(`Unknown option ${arg}.`, "Short options are single letters.");
      name = ALIASES.get(short);
      if (!name) throw new UsageError(`Unknown option ${arg}.`, "Run `mcpvet help` to see the options.");
    }

    const spec = OPTION_SPEC[name];
    if (!spec) throw new UsageError(`Unknown option --${name}.`, "Run `mcpvet help` to see the options.");

    if (spec.type === "boolean") {
      if (inlineValue !== undefined) {
        throw new UsageError(`--${name} does not take a value.`);
      }
      assign(name, true);
      continue;
    }

    let value = inlineValue;
    if (value === undefined) {
      const next = argv[index + 1];
      if (next === undefined || (next.startsWith("-") && next !== "-")) {
        throw new UsageError(`--${name} requires a value.`);
      }
      value = next;
      index += 1;
    }

    if (spec.values && !spec.values.includes(value)) {
      throw new UsageError(`Invalid value "${value}" for --${name}.`, `Expected one of: ${spec.values.join(", ")}.`);
    }
    if (spec.type === "number") {
      const parsed = Number(value);
      if (!Number.isInteger(parsed) || parsed < 0) throw new UsageError(`--${name} expects a non-negative integer.`);
      assign(name, parsed);
      continue;
    }
    assign(name, value);
  }

  return { options, positionals };
}

/**
 * @typedef {object} IO
 * @property {string} cwd
 * @property {Record<string, string|undefined>} env
 * @property {(text: string) => void} out
 * @property {(text: string) => void} err
 * @property {boolean} isTTY
 */

/** @returns {IO} */
export function defaultIO() {
  return {
    cwd: process.cwd(),
    env: process.env,
    out: (text) => process.stdout.write(text),
    err: (text) => process.stderr.write(text),
    isTTY: Boolean(process.stdout.isTTY),
  };
}

/**
 * Entry point. Never throws for user input; returns the process exit code.
 *
 * @param {string[]} argv
 * @param {IO} [io]
 * @returns {Promise<number>}
 */
export async function main(argv, io = defaultIO()) {
  try {
    return await run(argv, io);
  } catch (error) {
    if (error instanceof UsageError) {
      io.err(`${NAME}: ${error.message}\n`);
      if (error.hint) io.err(`${error.hint}\n`);
      return EXIT.USAGE;
    }
    io.err(`${NAME}: internal error: ${error?.stack ?? error}\n`);
    io.err(`${NAME}: this is a bug in ${NAME}, not in your config. Please report it at ${HOMEPAGE}/issues\n`);
    return EXIT.INTERNAL;
  }
}

/**
 * @param {string[]} argv
 * @param {IO} io
 * @returns {Promise<number>}
 */
async function run(argv, io) {
  const { options, positionals } = parseArgs(argv);
  const [command, ...rest] = positionals;

  if (options.help) {
    io.out(helpText(command));
    return EXIT.OK;
  }
  if (options.version) {
    io.out(`${NAME} ${VERSION}\n`);
    return EXIT.OK;
  }

  switch (command) {
    case undefined:
    case "scan":
      return runScan(rest, options, io);
    case "check":
      return runCheck(options, io);
    case "rules":
      return runRules(options, io);
    case "explain":
      return runExplain(rest, io);
    case "baseline":
      return runBaseline(rest, options, io);
    case "init":
      return runInit(options, io);
    case "help":
      io.out(helpText(rest[0]));
      return EXIT.OK;
    case "version":
      io.out(`${NAME} ${VERSION}\n`);
      return EXIT.OK;
    default:
      throw new UsageError(`Unknown command "${command}".`, `Run \`${NAME} help\` for the list of commands.`);
  }
}

/**
 * Merge `.mcpvetrc.json` with CLI options. CLI always wins.
 *
 * @param {string|undefined} configPath
 * @param {string} cwd
 * @param {any} options
 */
async function resolveSettings(configPath, cwd, options, env = process.env) {
  const path = configPath ? resolve(cwd, configPath) : resolve(cwd, ".mcpvetrc.json");
  /** @type {any} */
  let fileSettings = {};
  let raw = null;

  try {
    raw = await readFile(path, "utf8");
  } catch (error) {
    if (configPath) {
      throw new UsageError(`Could not read config file ${configPath}: ${error.code ?? error.message}.`);
    }
    raw = null;
  }

  if (raw !== null) {
    const parsed = tryParseJsonc(raw);
    if (!parsed.ok) {
      throw new UsageError(`Config file ${toDisplayPath(path, cwd)} is invalid: ${parsed.error.message}.`);
    }
    if (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
      throw new UsageError(`Config file ${toDisplayPath(path, cwd)} must contain a JSON object.`);
    }
    fileSettings = parsed.value;
  }

  const ignore = [...(fileSettings.ignore ?? []), ...(options.ignore ?? [])].flatMap((entry) =>
    String(entry)
      .split(",")
      .map((part) => part.trim().toUpperCase())
      .filter(Boolean),
  );

  const failOn = options["fail-on"] ?? fileSettings.failOn ?? "high";
  if (!FAIL_ON_VALUES.includes(failOn)) {
    throw new UsageError(`Invalid failOn "${failOn}" in ${toDisplayPath(path, cwd)}.`, `Expected one of: ${FAIL_ON_VALUES.join(", ")}.`);
  }

  return {
    ignore,
    failOn,
    minSeverity: options["min-severity"] ?? fileSettings.minSeverity ?? null,
    format: options.format ?? fileSettings.format ?? "pretty",
    descriptors: [...(fileSettings.descriptors ?? []), ...(options.descriptor ?? [])],
    baselinePath: options["no-baseline"] ? null : (options.baseline ?? fileSettings.baseline ?? DEFAULT_BASELINE_FILENAME),
    color: resolveColor(options, env),
  };
}

function resolveColor(options, env) {
  if (options["no-color"]) return false;
  if (options.color) return true;
  if (env.NO_COLOR) return false;
  return true;
}

/** Files in a directory walk that are never MCP configs. */
const IGNORED_FILENAMES = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "tsconfig.json",
  "jsconfig.json",
  "composer.json",
  "deno.json",
  "renovate.json",
  ".mcpvetrc.json",
]);

/**
 * @param {string} dir
 * @returns {Promise<string[]>} candidate files, absolute
 */
async function collectFromDirectory(dir) {
  /** @type {string[]} */
  const files = [];
  const walk = async (current, level) => {
    if (level > 2) return;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "dist") continue;
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(full, level + 1);
      } else if (/\.(?:json|jsonc)$/i.test(entry.name) && !IGNORED_FILENAMES.has(entry.name) && !/\.schema\.json$/i.test(entry.name)) {
        files.push(full);
      }
    }
  };
  await walk(dir, 0);
  return files;
}

/**
 * Resolve positional paths into loadable entries, marking which ones the user
 * named explicitly (an explicit path that fails to parse is an error, a random
 * JSON file found in a directory walk is not).
 *
 * @param {string[]} paths
 * @param {string} cwd
 * @returns {Promise<import("./loader.js").LoadError[]|{entries: {file: string, explicit: boolean}[]}>}
 */
async function resolveInputs(paths, cwd) {
  /** @type {{file: string, explicit: boolean}[]} */
  const entries = [];

  for (const path of paths) {
    const absolute = resolve(cwd, path);
    let info;
    try {
      info = await stat(absolute);
    } catch {
      throw new UsageError(`No such file or directory: ${path}`);
    }
    if (info.isDirectory()) {
      for (const file of await collectFromDirectory(absolute)) entries.push({ file, explicit: false });
    } else {
      entries.push({ file: absolute, explicit: true });
    }
  }

  return entries;
}

/**
 * @param {string[]} positionals
 * @param {any} options
 * @param {IO} io
 */
async function runScan(positionals, options, io) {
  const settings = await resolveSettings(options.config, io.cwd, options, io.env);

  /** @type {{file: string, kind?: "config"|"tools", explicit: boolean}[]} */
  let entries = [];

  if (positionals.length === 0) {
    const discovered = discoverConfigFiles({ cwd: io.cwd, includeUser: options["no-user"] !== true });
    if (discovered.length === 0) {
      io.err(
        `${NAME}: no MCP configuration found in ${io.cwd} or in the known per-user locations.\n` +
          `Pass a path explicitly, for example: ${NAME} scan path/to/claude_desktop_config.json\n`,
      );
      return EXIT.OK;
    }
    entries = discovered.map((candidate) => ({ file: candidate.file, explicit: false }));
  } else {
    entries = await resolveInputs(positionals, io.cwd);
  }

  for (const descriptor of settings.descriptors) {
    entries.push({ file: resolve(io.cwd, descriptor), kind: "tools", explicit: true });
  }

  const { configs, descriptors, errors } = await loadFiles(
    entries.map((entry) => ({ file: entry.file, kind: entry.kind })),
    { cwd: io.cwd },
  );

  // Only report load failures for files the user pointed at, or for filenames
  // that can only be MCP configs.
  const explicitFiles = new Set(entries.filter((entry) => entry.explicit).map((entry) => entry.file));
  const relevantErrors = errors.filter((error) => {
    const absolute = resolve(io.cwd, error.file);
    if (explicitFiles.has(absolute)) return true;
    return KNOWN_CONFIG_NAMES.has(basename(error.file));
  });

  const result = audit(
    { configs, descriptors, errors: relevantErrors },
    {
      cwd: io.cwd,
      ignore: settings.ignore,
      minSeverity: settings.minSeverity,
    },
  );

  let findings = result.findings;
  /** @type {import("./findings.js").Finding[]} */
  let suppressed = [];

  if (settings.baselinePath) {
    const baselineFile = resolve(io.cwd, settings.baselinePath);
    let baselineText = null;
    try {
      baselineText = await readFile(baselineFile, "utf8");
    } catch {
      baselineText = null;
    }
    if (baselineText !== null) {
      const parsed = parseBaseline(baselineText);
      if (!parsed.ok) {
        throw new UsageError(`Baseline ${settings.baselinePath} is invalid: ${parsed.error}.`);
      }
      const applied = applyBaseline(findings, parsed.baseline);
      findings = applied.newFindings;
      suppressed = applied.suppressed;
    }
  }

  const filtered = { ...result, findings };
  const rendered = format(filtered, settings.format, {
    color: settings.color && io.isTTY,
    verbose: Boolean(options.verbose),
  });

  if (options.output) {
    await writeReport(resolve(io.cwd, options.output), rendered);
    if (!options.quiet) {
      const { score, grade } = computeScore(findings);
      io.err(
        `${NAME}: ${findings.length} finding(s) written to ${options.output} (trust score ${score}/100, ${grade})${
          suppressed.length > 0 ? `; ${suppressed.length} suppressed by baseline` : ""
        }.\n`,
      );
    }
  } else {
    io.out(rendered);
  }

  if (!options.quiet && suppressed.length > 0 && !options.output) {
    io.err(`${NAME}: ${suppressed.length} finding(s) suppressed by ${settings.baselinePath}.\n`);
  }

  return exitCodeFor(findings, settings.failOn, io, options);
}

/**
 * @param {import("./findings.js").Finding[]} findings
 * @param {string} failOn
 * @param {IO} io
 * @param {any} options
 */
function exitCodeFor(findings, failOn, io, options) {
  if (failOn === "none") return EXIT.OK;
  if (findings.length === 0) return EXIT.OK;
  const worst = worstSeverity(findings) ?? "info";
  if (!isAtLeast(worst, failOn)) {
    if (!options.quiet) {
      io.err(`${NAME}: worst finding is ${worst}, below --fail-on ${failOn}; exiting 0.\n`);
    }
    return EXIT.OK;
  }
  if (!options.quiet) {
    io.err(`${NAME}: failing because ${worst} findings are at or above --fail-on ${failOn}.\n`);
  }
  return EXIT.FINDINGS;
}

/**
 * Audit a server spec that is not in any file yet — the "should I install this?"
 * case.
 *
 * @param {any} options
 * @param {IO} io
 */
async function runCheck(options, io) {
  if (!options.command && !options.url) {
    throw new UsageError("check needs --command or --url.", `Example: ${NAME} check --command "npx -y some-mcp-server"`);
  }

  /** @type {Record<string, any>} */
  const entry = {};
  if (options.command) {
    if (options.arg && options.arg.length > 0) {
      entry.command = options.command;
      entry.args = options.arg;
    } else {
      const [head, ...tail] = splitShellWords(options.command);
      if (!head) throw new UsageError("--command is empty.");
      entry.command = head;
      entry.args = tail;
    }
  }
  if (options.url) entry.url = options.url;
  if (options.type) entry.type = options.type;
  if (options.env) {
    entry.env = {};
    for (const pair of options.env) {
      const split = pair.indexOf("=");
      if (split <= 0) throw new UsageError(`--env expects KEY=VALUE, got "${pair}".`);
      entry.env[pair.slice(0, split)] = pair.slice(split + 1);
    }
  }
  if (options.header) {
    entry.headers = {};
    for (const pair of options.header) {
      const split = pair.indexOf(":");
      if (split <= 0) throw new UsageError(`--header expects "Name: value", got "${pair}".`);
      entry.headers[pair.slice(0, split).trim()] = pair.slice(split + 1).trim();
    }
  }
  if (options["auto-approve"]) entry.autoApprove = options["auto-approve"];

  const name = options.name ?? "ad-hoc";
  const server = normalizeServer(name, entry, { file: null, pointer: "", positions: null, warnings: [] });

  const result = audit(
    { configs: [{ file: null, kind: "config", servers: [server], warnings: [] }] },
    { cwd: io.cwd, ignore: (options.ignore ?? []).flatMap((entry) => String(entry).split(",")) },
  );

  const formatName = options.format ?? "pretty";
  const rendered = format(result, formatName, { color: resolveColor(options, io.env) && io.isTTY, verbose: Boolean(options.verbose) });
  if (options.output) {
    await writeReport(resolve(io.cwd, options.output), rendered);
  } else {
    io.out(rendered);
  }

  return exitCodeFor(result.findings, options["fail-on"] ?? "high", io, options);
}

/**
 * @param {any} options
 * @param {IO} io
 */
async function runRules(options, io) {
  const rules = listRules();
  if (options.format === "json") {
    const payload = rules.map((rule) => ({
      id: rule.id,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      target: rule.target,
      summary: rule.summary,
      remediation: rule.remediation,
      references: rule.references ?? [],
    }));
    io.out(`${JSON.stringify(payload, null, 2)}\n`);
    return EXIT.OK;
  }

  const lines = [""];
  lines.push(`  ${NAME} ${VERSION} — ${rules.length} rules`);
  lines.push("");
  let category = null;
  for (const rule of rules) {
    if (rule.category !== category) {
      category = rule.category;
      lines.push(`  ${category.toUpperCase()}`);
    }
    lines.push(`    ${rule.id}  ${rule.severity.padEnd(8)}  ${rule.title}`);
  }
  lines.push("");
  lines.push(`  Run \`${NAME} explain <id>\` for the rationale and the fix.`);
  lines.push("");
  io.out(lines.join("\n"));
  return EXIT.OK;
}

/**
 * @param {string[]} rest
 * @param {IO} io
 */
async function runExplain(rest, io) {
  const id = rest[0];
  if (!id) throw new UsageError("explain needs a rule id.", `Example: ${NAME} explain MCP001`);
  const rule = getRule(id);
  if (!rule) throw new UsageError(`Unknown rule "${id}".`, `Run \`${NAME} rules\` to list them.`);

  const lines = [""];
  lines.push(`  ${rule.id}  ${rule.title}`);
  lines.push(`  ${rule.category} · severity ${rule.severity} · applies to ${rule.target}`);
  lines.push("");
  for (const line of wrap(rule.summary, 92)) lines.push(`  ${line}`);
  lines.push("");
  for (const line of wrap(rule.why, 92)) lines.push(`  ${line}`);
  lines.push("");
  lines.push("  Fix");
  for (const line of wrap(rule.remediation, 92)) lines.push(`    ${line}`);
  if (rule.references?.length) {
    lines.push("");
    lines.push("  References");
    for (const reference of rule.references) lines.push(`    ${reference}`);
  }
  lines.push("");
  io.out(lines.join("\n"));
  return EXIT.OK;
}

/**
 * @param {string[]} rest
 * @param {any} options
 * @param {IO} io
 */
async function runBaseline(rest, options, io) {
  const action = rest[0] ?? "write";
  if (!["write", "update"].includes(action)) {
    throw new UsageError(`baseline expects "write" or "update", got "${action}".`);
  }
  const target = resolve(io.cwd, options.output ?? DEFAULT_BASELINE_FILENAME);

  const settings = await resolveSettings(options.config, io.cwd, { ...options, baseline: options.baseline });
  const input = await collectForBaseline(io.cwd, options);

  let previous = null;
  if (action === "update") {
    try {
      const text = await readFile(target, "utf8");
      const parsed = parseBaseline(text);
      if (!parsed.ok) throw new UsageError(`Existing baseline is invalid: ${parsed.error}.`);
      previous = parsed.baseline;
    } catch (error) {
      if (error instanceof UsageError) throw error;
      previous = null;
    }
  }

  const { baseline, added, removed } =
    action === "update" ? updateBaseline(input.findings, previous) : { baseline: buildBaseline(input.findings), added: input.findings.length, removed: 0 };

  await writeReport(target, `${JSON.stringify(baseline, null, 2)}\n`);
  io.out(
    `${NAME}: baseline written to ${toDisplayPath(target, io.cwd)} — ${baseline.count} finding(s) accepted` +
      `${action === "update" ? ` (${added} added, ${removed} removed)` : ""}.\n` +
      `${NAME}: commit this file so CI can distinguish new findings from accepted ones.\n`,
  );
  void settings;
  return EXIT.OK;
}

/**
 * @param {string} cwd
 * @param {any} options
 */
async function collectForBaseline(cwd, options) {
  const discovered = discoverConfigFiles({ cwd, includeUser: false });
  const { configs, descriptors, errors } = await loadFiles(
    discovered.map((candidate) => ({ file: candidate.file })),
    { cwd },
  );
  return audit({ configs, descriptors, errors }, { cwd, ignore: options.ignore ?? [] });
}

/**
 * @param {any} options
 * @param {IO} io
 */
async function runInit(options, io) {
  const created = [];

  const rcPath = resolve(io.cwd, ".mcpvetrc.json");
  let exists = true;
  try {
    await stat(rcPath);
  } catch {
    exists = false;
  }
  if (!exists) {
    const rc = {
      $schema: `${HOMEPAGE}/blob/main/schema/mcpvetrc.schema.json`,
      failOn: "high",
      ignore: [],
      minSeverity: null,
      baseline: DEFAULT_BASELINE_FILENAME,
      descriptors: [],
    };
    await writeReport(rcPath, `${JSON.stringify(rc, null, 2)}\n`);
    created.push(toDisplayPath(rcPath, io.cwd));
  }

  const workflowPath = resolve(io.cwd, ".github", "workflows", "mcpvet.yml");
  let workflowExists = true;
  try {
    await stat(workflowPath);
  } catch {
    workflowExists = false;
  }
  if (!workflowExists) {
    await mkdir(dirname(workflowPath), { recursive: true });
    await writeReport(workflowPath, workflowTemplate());
    created.push(toDisplayPath(workflowPath, io.cwd));
  }

  if (created.length === 0) {
    io.out(`${NAME}: nothing to do, .mcpvetrc.json and the workflow already exist.\n`);
    return EXIT.OK;
  }

  io.out(`${NAME}: created\n${created.map((file) => `  - ${file}`).join("\n")}\n\n`);
  io.out(`Next:\n  1. ${NAME} scan .\n  2. ${NAME} baseline write     # accept today's findings\n  3. commit the workflow and the baseline\n`);
  void options;
  return EXIT.OK;
}

function workflowTemplate() {
  return `name: mcpvet

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 6 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    name: Audit MCP server configs
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Install mcpvet
        run: npm install --global mcpvet

      - name: Scan
        run: mcpvet scan . --format sarif --output mcpvet.sarif --fail-on high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcpvet.sarif
`;
}

/**
 * @param {string} path
 * @param {string} contents
 */
async function writeReport(path, contents) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, contents, "utf8");
}

/**
 * @param {string|null} text
 * @param {number} width
 */
function wrap(text, width) {
  const words = String(text ?? "").split(/\s+/).filter(Boolean);
  /** @type {string[]} */
  const lines = [];
  let current = "";
  for (const word of words) {
    if (current === "") current = word;
    else if (`${current} ${word}`.length <= width) current = `${current} ${word}`;
    else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines.length > 0 ? lines : [""];
}

/**
 * @param {string} [command]
 */
export function helpText(command) {
  if (command === "check") {
    return `${NAME} check — audit a server spec before you install it

Usage:
  ${NAME} check --command "npx -y some-mcp-server" [options]
  ${NAME} check --url https://example.com/mcp [--header "Authorization: Bearer ..."]

Options:
  --name <name>            name to use in the report (default: ad-hoc)
  --command <string>       command line to launch the server
  --arg <value>            one argument (repeatable; skips shell splitting)
  --url <url>              remote endpoint
  --type <transport>       stdio | http | sse
  --env KEY=VALUE          environment entry (repeatable)
  --header "Name: value"   header (repeatable)
  --auto-approve <tool>    tool that is pre-approved (repeatable)
  -f, --format <format>    pretty | json | sarif | markdown
  --fail-on <severity>     none | info | low | medium | high | critical (default: high)
`;
  }

  return `${NAME} ${VERSION} — vet MCP servers before your agent does

Usage:
  ${NAME} [scan] [paths...] [options]
  ${NAME} check --command "..." | --url <url>
  ${NAME} rules [--format json]
  ${NAME} explain <ruleId>
  ${NAME} baseline [write|update]
  ${NAME} init

Scan options:
  -f, --format <format>     pretty (default) | json | sarif | markdown
  -o, --output <file>       write the report to a file instead of stdout
  --fail-on <severity>      none | info | low | medium | high | critical (default: high)
  --min-severity <sev>      drop findings below this severity
  --ignore <ids>            comma-separated rule ids to skip (repeatable)
  --baseline <file>         accepted-findings file (default: ${DEFAULT_BASELINE_FILENAME})
  --no-baseline             ignore any baseline file
  --descriptor <file>       tools/list JSON to audit (repeatable)
  --no-user                 do not read per-user client configs
  --config <file>           settings file (default: .mcpvetrc.json)
  --color / --no-color      force or disable ANSI colour
  -v, --verbose             include rationale and fix for each finding
  -q, --quiet               suppress the summary on stderr
  -h, --help                show this help
  -V, --version             print the version

Exit codes:
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  usage error
  3  internal error

Docs: ${HOMEPAGE}
`;
}
