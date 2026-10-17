/**
 * Capability rules: what a server is allowed to touch once it is running.
 *
 * @module rules/capability
 */

import { SHELLS, isBroadRoot, commandLine, pathLikeArgs, packageSpecFor } from "./helpers.js";

const FILESYSTEM_SERVERS = /filesystem|file[-_]?system|server[-_]?fs\b/i;
const DATABASE_SERVERS = /(postgres|postgresql|mysql|mariadb|mongo|mongodb|sqlite|redis|mssql|clickhouse|duckdb)/i;
const READ_ONLY_MARKERS = /(--read-?only|\bread-?only\b|mode=ro\b|readonly=true)/i;
const TEMP_LOCATIONS = /(?:\/tmp\b|\/var\/tmp|%TEMP%|\\Temp\\|\/Downloads\/|\\Downloads\\|\/Desktop\/|\\Desktop\\|\/Downloads$|\\Downloads$)/i;

/** @type {import("./types.js").Rule[]} */
export const capabilityRules = [
  {
    id: "MCP030",
    title: "Filesystem server has an unbounded or missing root",
    category: "capability",
    severity: "high",
    target: "server",
    summary: "A filesystem MCP server is granted a whole drive, the home directory, or no explicit directory.",
    why:
      "A filesystem server is the agent's hands. Pointed at `/`, `C:\\`, or the home directory, every later mistake " +
      "by the model — or by a malicious tool result it just read — becomes a write to a real file. Scoping the root " +
      "to one project directory is the difference between a bad suggestion and a bad commit to your dotfiles.",
    remediation:
      "Pass exactly the directories the server needs, e.g. `npx -y @modelcontextprotocol/server-filesystem@1.2.3 ./docs`.",
    references: ["https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem"],
    check({ server, scan }) {
      const identity = `${server.launcher} ${packageSpecFor(server.launcher, server.args) ?? ""} ${server.command ?? ""}`;
      if (!FILESYSTEM_SERVERS.test(identity) && !FILESYSTEM_SERVERS.test(server.name)) return null;

      const paths = pathLikeArgs(server.args);
      const broad = paths.filter((candidate) => isBroadRoot(candidate, { home: scan?.home }));
      if (broad.length > 0) {
        return {
          message: `Filesystem server is rooted at a broad location: ${broad.join(", ")}.`,
          evidence: commandLine(server),
          detail: "A broad root makes every path reachable by the agent, including SSH keys and credential files.",
        };
      }
      if (paths.length === 0) {
        return {
          message: "Filesystem server has no explicit allowed directory.",
          evidence: commandLine(server),
          severity: "medium",
          detail: "Behaviour depends on the implementation: it either refuses to start or falls back to a permissive default.",
        };
      }
      return null;
    },
  },

  {
    id: "MCP031",
    title: "Server exposes shell or command execution",
    category: "capability",
    severity: "high",
    target: "server",
    summary: "The server runs a shell, or its package is a shell/exec/terminal bridge.",
    why:
      "A shell bridge converts every future model mistake into arbitrary code execution, and it is the standard " +
      "first step in MCP-focused prompt-injection chains: a poisoned tool result asks the agent to run one command, " +
      "and the bridge is what makes that possible.",
    remediation:
      "Replace the shell server with the narrowest server that does the job (filesystem, git, fetch), and require " +
      "human confirmation for anything that executes code.",
    references: [
      "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
      "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ],
    check({ server }) {
      if (server.transport !== "stdio") return null;
      if (SHELLS.has(server.launcher)) {
        return {
          message: `Server launches a shell (${server.launcher}).`,
          evidence: commandLine(server),
        };
      }
      const spec = packageSpecFor(server.launcher, server.args) ?? "";
      // Match each component separately: a name like `mcp-server-shell` puts
      // "shell" at the end of a hyphenated token, which a boundary class
      // without a space separator would miss when the components are joined.
      const components = [spec, server.command ?? "", server.name];
      const bridge = components.find((component) =>
        /(?:^|[/@_.\- ])(?:shell|bash|powershell|terminal|exec)(?:[/@_.\- ]|$)/i.test(component),
      );
      if (bridge !== undefined) {
        return {
          message: `Server appears to be a shell/terminal bridge (${bridge || spec || server.command}).`,
          evidence: commandLine(server),
        };
      }
      return null;
    },
  },

  {
    id: "MCP032",
    title: "Database server is not restricted to read-only access",
    category: "capability",
    severity: "medium",
    target: "server",
    summary: "A database MCP server connects with write credentials and no read-only switch.",
    why:
      "An agent that can write to a database can corrupt data during an ordinary reasoning error, not just under " +
      "attack. Read-only connections keep the useful part (schema introspection, SELECT) and remove the part that " +
      "needs a human in the loop.",
    remediation:
      "Connect with a read-only role, and pass the server's read-only flag or `?mode=ro` connection parameter.",
    references: ["https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices"],
    check({ server }) {
      const identity = `${server.launcher} ${packageSpecFor(server.launcher, server.args) ?? ""} ${server.command ?? ""} ${server.name}`;
      const engine = DATABASE_SERVERS.exec(identity)?.[1];
      if (!engine) return null;
      const haystack = [commandLine(server), ...Object.values(server.env)].join(" ");
      if (READ_ONLY_MARKERS.test(haystack)) return null;
      return {
        message: `Database server (${engine}) has no read-only restriction.`,
        evidence: commandLine(server),
        detail: "Schema introspection and SELECT are what agents need most; write access is what needs review.",
      };
    },
  },

  {
    id: "MCP033",
    title: "Server executes a script from a temporary or download directory",
    category: "capability",
    severity: "medium",
    target: "server",
    summary: "The launch path points into Temp, Downloads, or Desktop.",
    why:
      "Files in those directories arrive from elsewhere — an installer, a browser download, an archive extraction. " +
      "They are not tracked by version control, not reviewed, and can be replaced by any process on the machine.",
    remediation: "Install the server properly (pinned package, project-local directory) and launch it from a reviewed path.",
    check({ server }) {
      const haystack = [server.command ?? "", ...server.args].join(" ");
      if (!TEMP_LOCATIONS.test(haystack)) return null;
      return {
        message: "Server is launched from a temporary or download location.",
        evidence: commandLine(server),
      };
    },
  },

  {
    id: "MCP034",
    title: "Tool can execute arbitrary commands",
    category: "capability",
    severity: "high",
    target: "tool",
    summary: "A tool name or description advertises shell/command execution.",
    why:
      "Tool descriptions are instructions the model reads. A tool that promises to run any command will eventually " +
      "be asked to run one that arrived from a web page, an issue comment, or a repository file. This is the most " +
      "direct path from untrusted text to code execution.",
    remediation: "Split the tool into the specific operations needed, and gate execution behind explicit human approval.",
    references: ["https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices"],
    check({ tool }) {
      const text = `${tool.name} ${tool.description}`;
      if (!/(?:^|\W)(?:run|exec(?:ute)?|shell|bash|powershell|terminal|command|eval|spawn)(?:\W|$)/i.test(text)) return null;
      if (/(?:run|execute|exec|shell|terminal|command|eval)/i.test(tool.name)) {
        return {
          message: `Tool "${tool.name}" advertises command execution in its name.`,
          evidence: tool.name,
        };
      }
      return {
        message: `Tool "${tool.name}" advertises command execution in its description.`,
        evidence: tool.description,
      };
    },
  },
];
