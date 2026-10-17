/**
 * Helpers shared by rules that reason about how a server will be launched.
 *
 * Auditing an MCP server is mostly auditing argv: the difference between
 * `npx -y pkg` and `npx -y pkg@1.4.2` is the difference between "runs whatever
 * the registry serves today" and "runs the code that was reviewed".
 *
 * @module rules/helpers
 */

import { asString } from "../util.js";

/** Flags that consume the following argv element as their value. */
export const FLAGS_WITH_VALUES = new Set([
  "--registry",
  "--package",
  "-p",
  "--cache",
  "--prefix",
  "--userconfig",
  "--workspace",
  "-w",
  "--cwd",
  "--config",
  "--from",
  "--with",
  "--python",
  "--index-url",
  "--extra-index-url",
  "--tag",
  "--target",
]);

/** Package runners that fetch and execute code at launch time. */
export const NODE_RUNNERS = new Set(["npx", "bunx", "pnpx", "npm", "bun", "yarn", "deno"]);
export const PYTHON_RUNNERS = new Set(["uvx", "pipx", "uv", "poetry", "pip", "pip3"]);
export const CONTAINER_RUNNERS = new Set(["docker", "podman", "nerdctl"]);
export const SHELLS = new Set(["sh", "bash", "zsh", "fish", "dash", "ksh", "cmd", "powershell", "pwsh", "tmux", "screen"]);

/**
 * First argv element that is not a flag, skipping values of known
 * value-taking flags.
 *
 * @param {string[]} args
 * @returns {{value: string, index: number}|null}
 */
export function firstPositional(args) {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (typeof arg !== "string") continue;
    if (arg.startsWith("-")) {
      if (FLAGS_WITH_VALUES.has(arg)) index += 1;
      continue;
    }
    return { value: arg, index };
  }
  return null;
}

/**
 * The package spec a runner will install, e.g. `@scope/server@1.2.3`.
 *
 * @param {string} launcher basename of the command
 * @param {string[]} args
 * @returns {string|null}
 */
export function packageSpecFor(launcher, args) {
  if (launcher === "npm" || launcher === "yarn" || launcher === "pnpm") {
    // `npm exec pkg@1` / `yarn dlx pkg@1` put the spec after the subcommand.
    const sub = firstPositional(args);
    if (!sub) return null;
    const rest = args.slice(sub.index + 1);
    const spec = firstPositional(rest);
    return spec?.value ?? null;
  }
  const spec = firstPositional(args);
  return spec?.value ?? null;
}

/**
 * True when a package spec is pinned to an exact, non-floating version.
 *
 * @param {string|null} spec
 * @param {"node"|"python"} ecosystem
 */
export function isPinnedSpec(spec, ecosystem) {
  if (!spec) return false;
  if (ecosystem === "python") {
    return /===?/.test(spec) || /~=/.test(spec);
  }
  const atIndex = spec.lastIndexOf("@");
  if (atIndex <= 0) return false; // unscoped without version, or scoped without version
  const version = spec.slice(atIndex + 1);
  if (version === "" || version === "latest" || version === "*" || version === "next" || version === "beta") {
    return false;
  }
  // Accept 1.2.3, ^1.2.3, ~1.2.3, >=1.2.3, 1.2.3-beta.1.
  return /^[~^<>=]*\d/.test(version);
}

/**
 * Human-readable command line for evidence. Redaction happens downstream, so
 * secrets in argv cannot leak through this string.
 *
 * @param {{command: string|null, args: string[]}} server
 */
export function commandLine(server) {
  const command = asString(server.command);
  if (!command) return "(no command)";
  const args = (server.args ?? []).map((arg) => (/\s/.test(arg) ? JSON.stringify(arg) : arg));
  return [command, ...args].join(" ");
}

/**
 * Container image reference from `docker run [flags] IMAGE`.
 *
 * @param {string[]} args
 * @returns {string|null}
 */
export function containerImage(args) {
  const runIndex = args.findIndex((arg) => arg === "run" || arg === "create");
  const rest = runIndex >= 0 ? args.slice(runIndex + 1) : args;
  return firstPositional(rest)?.value ?? null;
}

/** True when a container image reference is pinned to a digest or exact tag. */
export function isPinnedImage(image) {
  if (!image) return false;
  if (image.includes("@sha256:")) return true;
  const withoutRegistryPort = image.replace(/^[^/]*:\d+\//, "");
  const lastSegment = withoutRegistryPort.slice(withoutRegistryPort.lastIndexOf("/") + 1);
  if (!lastSegment.includes(":")) return false;
  const tag = lastSegment.slice(lastSegment.lastIndexOf(":") + 1);
  return tag !== "" && tag !== "latest";
}

/** Loopback hosts are not exposed to the network, so they are not a finding. */
export function isLoopbackHost(host) {
  const value = String(host ?? "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!value) return false;
  return (
    value === "localhost" ||
    value === "127.0.0.1" ||
    value === "::1" ||
    value.endsWith(".localhost") ||
    value.startsWith("127.")
  );
}

/**
 * Parse a URL without throwing.
 * @param {string} value
 * @returns {URL|null}
 */
export function safeUrl(value) {
  try {
    return new URL(String(value));
  } catch {
    return null;
  }
}

/**
 * Positional arguments that look like filesystem paths (used to check whether a
 * filesystem server was given an explicit root).
 *
 * Relative paths count. `./docs` is exactly the confinement we want to
 * recognise, and treating it as "no path at all" would produce a false positive
 * on the safest possible configuration.
 *
 * @param {string[]} args
 * @returns {string[]}
 */
export function pathLikeArgs(args) {
  const result = [];
  for (const arg of args) {
    if (typeof arg !== "string" || arg === "") continue;
    if (arg.startsWith("-")) continue;
    if (arg.startsWith("@") && !arg.startsWith("@/")) continue; // package spec
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(arg)) continue; // URL, not a path
    const looksLikePath =
      /^[a-zA-Z]:[\\/]/.test(arg) ||
      arg.startsWith("/") ||
      arg.startsWith("\\\\") ||
      arg.startsWith("./") ||
      arg.startsWith("../") ||
      arg.startsWith("~") ||
      /[/\\]/.test(arg);
    if (looksLikePath) result.push(arg);
  }
  return result;
}

/**
 * True when a path argument grants access to an entire filesystem or home dir.
 *
 * @param {string} value
 * @param {{home?: string}} [options]
 */
export function isBroadRoot(value, options = {}) {
  const home = options.home ?? "";
  const normalised = String(value).replace(/\\/g, "/").replace(/\/+$/, "");
  if (normalised === "" || normalised === "/") return true;
  if (/^[a-zA-Z]:$/.test(normalised)) return true; // C:
  if (normalised === "~") return true;
  if (home && normalised.toLowerCase() === home.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase()) return true;
  if (normalised === "/home" || normalised === "/Users" || normalised === "/root") return true;
  return false;
}
