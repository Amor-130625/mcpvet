/**
 * Posture rules: how much the human is kept in the loop.
 *
 * @module rules/posture
 */

import { commandLine } from "./helpers.js";

const DANGEROUS_FLAGS = [
  "--dangerously-skip-permissions",
  "--dangerously-bypass-approvals-and-sandbox",
  "--yolo",
  "--auto-approve",
  "--always-allow",
  "--no-confirm",
  "--skip-confirmations",
];

/** @type {import("./types.js").Rule[]} */
export const postureRules = [
  {
    id: "MCP040",
    title: "Server bypasses tool-call confirmation",
    category: "posture",
    severity: "high",
    target: "server",
    summary: "The config pre-approves tool execution, or the launcher runs with a confirmation-bypass flag.",
    why:
      "Human confirmation is the last control that stops a prompt-injected tool call from doing damage. " +
      "`autoApprove`/`alwaysAllow` removes it for whole tools, and a wildcard removes it for everything the server " +
      "exposes — including tools the server adds in a later release, after the config was reviewed.",
    remediation:
      "Remove the auto-approval entry. If a read-only tool is genuinely noisy, approve that single tool rather than " +
      "using a wildcard, and pin the server version so its tool list cannot grow.",
    references: [
      "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
      "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ],
    check({ server }) {
      const flag = server.args.find((arg) => typeof arg === "string" && DANGEROUS_FLAGS.includes(arg));
      if (flag) {
        return {
          message: `Launcher runs with ${flag}.`,
          evidence: commandLine(server),
          severity: "critical",
          detail: "A confirmation-bypass flag removes the only control between a poisoned tool result and execution.",
        };
      }

      const { present, values, wildcard } = server.autoApprove;
      if (!present) return null;
      if (wildcard) {
        return {
          message: "All tools from this server are auto-approved, including tools added in future releases.",
          evidence: values.length > 0 ? `autoApprove: ${JSON.stringify(values)}` : "autoApprove: true",
          severity: "critical",
        };
      }
      if (values.length === 0) return null;
      return {
        message: `${values.length} tool(s) are pre-approved without confirmation: ${values.slice(0, 6).join(", ")}${values.length > 6 ? ", …" : ""}.`,
        evidence: values.join(", "),
        detail: "Pre-approval is per tool name; a server that later redefines the tool inherits the approval.",
      };
    },
  },

  {
    id: "MCP041",
    title: "Server is declared with conflicting definitions",
    category: "posture",
    severity: "medium",
    target: "scan",
    summary: "The same server name is declared in more than one config with a different command or URL.",
    why:
      "Two configs that disagree mean the agent's capabilities depend on which client the developer happened to " +
      "start. It is also how a reviewed, pinned definition quietly gets replaced by an unpinned one in a second file " +
      "that nobody reviews.",
    remediation: "Keep one definition per server name, and generate per-client configs from that single source.",
    check({ scan }) {
      /** @type {Map<string, import("../config.js").NormalizedServer[]>} */
      const byName = new Map();
      for (const server of scan.servers) {
        if (!server.file) continue;
        const list = byName.get(server.name) ?? [];
        list.push(server);
        byName.set(server.name, list);
      }

      /** @type {import("./types.js").RuleHit[]} */
      const hits = [];
      for (const [name, servers] of byName) {
        const files = new Set(servers.map((server) => server.file));
        if (files.size < 2) continue;
        const signatures = new Set(
          servers.map((server) => `${server.command ?? ""} ${server.args.join(" ")} ${server.url ?? ""}`.trim()),
        );
        if (signatures.size < 2) continue;
        const locations = [...files].sort().join(", ");
        hits.push({
          message: `Server "${name}" is defined differently in ${files.size} config files.`,
          evidence: `${name} -> ${locations}`,
          fingerprintKey: `${name}:${[...signatures].sort().join("|")}`,
          detail: `Definitions differ across: ${locations}.`,
        });
      }
      return hits;
    },
  },
];
