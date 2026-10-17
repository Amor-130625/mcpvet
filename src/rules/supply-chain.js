/**
 * Supply-chain rules: what code will actually run when the agent starts.
 *
 * @module rules/supply-chain
 */

import {
  CONTAINER_RUNNERS,
  NODE_RUNNERS,
  PYTHON_RUNNERS,
  commandLine,
  containerImage,
  isPinnedImage,
  isPinnedSpec,
  packageSpecFor,
} from "./helpers.js";

/** @type {import("./types.js").Rule[]} */
export const supplyChainRules = [
  {
    id: "MCP001",
    title: "Server launcher is not pinned to a version",
    category: "supply-chain",
    severity: "medium",
    target: "server",
    summary: "Package runners such as npx/uvx install and execute the newest published code on every launch.",
    why:
      "An unpinned launcher turns every agent start into a fresh install of whatever the registry serves right now. " +
      "A single compromised or malicious publish becomes code execution on the developer machine, with the same " +
      "access the agent has — and it can happen weeks after the config was reviewed and approved.",
    remediation:
      "Pin the version the review was performed against: `npx -y pkg@1.4.2` or `uvx pkg==1.4.2`. For containers use a " +
      "digest (`image@sha256:...`) or an exact tag. Renovate/Dependabot can keep the pin current.",
    references: [
      "https://modelcontextprotocol.io/docs/concepts/transports",
      "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
    ],
    check({ server }) {
      if (server.transport !== "stdio" || !server.command) return null;
      const launcher = server.launcher;

      if (NODE_RUNNERS.has(launcher)) {
        const spec = packageSpecFor(launcher, server.args);
        if (!spec) return null;
        if (isPinnedSpec(spec, "node")) return null;
        const floating = /@(?:latest|next|beta|\*)$/.test(spec);
        return {
          message: `"${spec}" is installed from the registry at launch without a pinned version.`,
          evidence: commandLine(server),
          severity: floating ? "high" : "medium",
          detail: floating
            ? "The spec explicitly targets a floating tag, so the executed code changes on every publish."
            : "A version range or a bare package name resolves to the newest release at launch time.",
        };
      }

      if (PYTHON_RUNNERS.has(launcher)) {
        const spec = packageSpecFor(launcher, server.args);
        if (!spec) return null;
        if (isPinnedSpec(spec, "python")) return null;
        return {
          message: `"${spec}" is installed from PyPI at launch without an exact version.`,
          evidence: commandLine(server),
          detail: "uvx/pipx resolve the newest compatible release unless the spec uses `==`.",
        };
      }

      if (CONTAINER_RUNNERS.has(launcher)) {
        const image = containerImage(server.args);
        if (!image) return null;
        if (isPinnedImage(image)) return null;
        return {
          message: `Container image "${image}" is not pinned by digest or exact tag.`,
          evidence: commandLine(server),
          detail: "Tags are mutable; `:latest` and untagged images silently change underneath the agent.",
        };
      }

      return null;
    },
  },

  {
    id: "MCP002",
    title: "Package is fetched from an untrusted or plaintext source",
    category: "supply-chain",
    severity: "medium",
    target: "server",
    summary: "Launcher arguments point the package manager at a non-default registry or an http:// artifact.",
    why:
      "Overriding the registry is a legitimate corporate mirror pattern and a convenient attack pattern. If the " +
      "override is http:// the artifact can be swapped in transit, and a non-default registry has none of the " +
      "popularity, provenance, or revocation signals of the public one.",
    remediation:
      "Remove the override and mirror packages through a private registry configured in the developer environment, " +
      "over https, with lockfile or digest verification.",
    references: ["https://docs.npmjs.com/cli/v10/using-npm/registry"],
    check({ server }) {
      const argv = [server.command ?? "", ...server.args];
      for (const arg of argv) {
        if (typeof arg !== "string") continue;
        if (/^--registry=?(http:|http$)/i.test(arg) || arg === "--registry") {
          return {
            message: "Launcher overrides the package registry.",
            evidence: commandLine(server),
            detail: "Any packages installed through the override bypass the default registry's integrity metadata.",
          };
        }
        if (/^git\+http:\/\//i.test(arg) || (/^http:\/\//i.test(arg) && /\.(?:tgz|tar\.gz|whl)$/i.test(arg))) {
          return {
            message: "Launcher downloads an artifact over plaintext http.",
            evidence: commandLine(server),
            severity: "high",
            detail: "Plaintext artifact downloads can be replaced in transit by anyone on the network path.",
          };
        }
      }
      return null;
    },
  },

  {
    id: "MCP003",
    title: "Command is passed through a shell",
    category: "supply-chain",
    severity: "high",
    target: "server",
    summary: "The command or its arguments contain shell syntax, so a shell metacharacter becomes command execution.",
    why:
      "MCP servers are declared by copying snippets from README files and issues. When a config contains `&&`, " +
      "`$(...)`, backticks, or a shell wrapper, everything after it runs too — including in CI, where the config " +
      "may be committed and the credentials are higher value.",
    remediation:
      "Invoke the executable directly and pass arguments as an array, with no shell wrapper. If a wrapper is " +
      "unavoidable, quote the untrusted part and use `--` before positional arguments.",
    references: ["https://owasp.org/www-community/attacks/Command_Injection"],
    check({ server }) {
      if (!server.command) return null;
      const command = server.command;
      // A path such as `C:\Program Files\nodejs\node.exe` legitimately contains
      // spaces; a bare `npx some-package` does not mean the same thing.
      const looksLikePath = /[\\/]/.test(command);
      if (/\s/.test(command) && !looksLikePath) {
        return {
          message: "The server command is a shell string rather than an executable plus arguments.",
          evidence: commandLine(server),
          detail: "Clients that concatenate command and args will re-split this string, so quoting differs per client.",
        };
      }
      for (const arg of server.args) {
        if (typeof arg !== "string") continue;
        if (/\$\(|`|\$\{/.test(arg) || /[;&|]\s*\w/.test(arg) || /^\s*(?:sh|bash|cmd|powershell|pwsh)\s+-c\b/.test(arg)) {
          return {
            message: "An argument contains shell metacharacters or a shell invocation.",
            evidence: commandLine(server),
            detail: "Arguments are normally passed verbatim; shell syntax implies something in the chain expands them.",
          };
        }
      }
      return null;
    },
  },
];
