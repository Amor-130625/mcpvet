/**
 * Credential-handling rules.
 *
 * The findings never contain the secret: evidence is redacted by
 * `src/secrets.js` before it reaches any formatter, and these rules go further
 * by naming the *key* rather than the value.
 *
 * @module rules/credentials
 */

import { detectSecret, looksLikePlaceholder } from "../secrets.js";
import { commandLine, safeUrl } from "./helpers.js";

/** @type {import("./types.js").Rule[]} */
export const credentialRules = [
  {
    id: "MCP010",
    title: "Credential is written directly into the config",
    category: "credentials",
    severity: "high",
    target: "server",
    summary: "An env or header value in the MCP config is a live-looking secret instead of an environment reference.",
    why:
      "MCP configs are plain files that get synced to cloud drives, committed by accident, pasted into issues, and " +
      "shared in screenshots. A literal token in `env` has none of the rotation or scoping of a secret manager and " +
      "is readable by every process running as that user.",
    remediation:
      "Reference the environment instead of the value (`\"API_KEY\": \"${API_KEY}\"`), and keep the real value in a " +
      "secret store or a gitignored .env that the client loads at startup.",
    references: ["https://12factor.net/config"],
    check({ server }) {
      /** @type {import("./types.js").RuleHit[]} */
      const hits = [];
      const examine = (map, label) => {
        for (const [key, value] of Object.entries(map)) {
          if (typeof value !== "string" || value.trim() === "") continue;
          if (looksLikePlaceholder(value)) continue;
          const match = detectSecret(value);
          if (!match) continue;
          hits.push({
            message: `${label}.${key} contains what looks like a live credential (${match.kind}).`,
            evidence: `${label}.${key}=<redacted>`,
            fingerprintKey: `${label}.${key}:${match.kind}`,
          });
        }
      };
      examine(server.env, "env");
      examine(server.headers, "headers");
      return hits;
    },
  },

  {
    id: "MCP011",
    title: "Credential is passed as a command-line argument",
    category: "credentials",
    severity: "high",
    target: "server",
    summary: "A secret appears in argv, where other processes can read it.",
    why:
      "Arguments are visible to every user on the machine through `ps`, /proc, and the Windows process list, and are " +
      "usually logged in full by crash reporters and CI runners. It is the least private way to hand a token to a " +
      "child process.",
    remediation: "Pass the credential through the environment (`env`) instead of `args`, or point the server at a credentials file.",
    references: ["https://owasp.org/www-project-top-ten/"],
    check({ server }) {
      /** @type {import("./types.js").RuleHit[]} */
      const hits = [];
      server.args.forEach((arg, index) => {
        if (typeof arg !== "string" || arg.trim() === "") return;
        if (looksLikePlaceholder(arg)) return;
        const match = detectSecret(arg);
        if (!match) return;
        hits.push({
          message: `args[${index}] contains what looks like a live ${match.kind}.`,
          evidence: `args[${index}]=<redacted>`,
          fingerprintKey: `args[${index}]:${match.kind}`,
        });
      });
      return hits;
    },
  },

  {
    id: "MCP012",
    title: "Credential is embedded in the server URL",
    category: "credentials",
    severity: "high",
    target: "server",
    summary: "The MCP endpoint URL carries a token in the query string or in the userinfo section.",
    why:
      "URLs are the most-logged string in any system: proxies, CDNs, shell history, error trackers, and the client's " +
      "own debug output all record them. A token in the query string is effectively published to every layer in the path.",
    remediation:
      "Send credentials in an `Authorization` header instead of the URL, and rotate any token that has already been " +
      "used in one.",
    references: ["https://datatracker.ietf.org/doc/html/rfc6750"],
    check({ server }) {
      if (!server.url) return null;
      const url = safeUrl(server.url);
      const hasUserInfo = Boolean(url?.username || url?.password);
      const hasTokenParam = /[?&](?:token|access_token|api_?key|key|sig|signature|password|secret)=/i.test(server.url);
      const match = detectSecret(server.url);
      if (!hasUserInfo && !hasTokenParam && !match) return null;
      const parameter = /[?&]([A-Za-z_]+)=/.exec(server.url)?.[1];
      return {
        message: hasUserInfo
          ? "The server URL embeds credentials in the userinfo section."
          : `The server URL carries a credential in the query string${parameter ? ` (${parameter})` : ""}.`,
        evidence: server.url,
        detail: "Headers are not logged with the same regularity as URLs, which is why RFC 6750 puts tokens there.",
      };
    },
  },

  {
    id: "MCP013",
    title: "Environment is inherited wholesale by the server",
    category: "credentials",
    severity: "medium",
    target: "server",
    summary: "The launcher loads a .env file or forwards the whole host environment into the server process.",
    why:
      "A server that inherits everything in the parent environment receives unrelated credentials — cloud keys, " +
      "package registry tokens, SSH agent sockets — that it was never meant to see. Combined with an unpinned " +
      "package, a single malicious publish harvests the developer's whole environment.",
    remediation:
      "Enumerate the specific variables the server needs in `env` and pass nothing else.",
    references: ["https://12factor.net/config"],
    check({ server }) {
      const argv = server.args;
      for (const arg of argv) {
        if (typeof arg !== "string") continue;
        if (/^--env-file(=|\b)/.test(arg) || /^dotenv/i.test(arg)) {
          return {
            message: "The server is started with a full .env file.",
            evidence: commandLine(server),
            detail: "Every variable in the file becomes available to the server, not just the one it needs.",
          };
        }
      }
      const envKeys = Object.keys(server.env);
      const broad = envKeys.filter((key) => /^(?:\*|ALL|INHERIT|PASSTHROUGH)$/i.test(key));
      if (broad.length > 0) {
        return {
          message: `Environment requests full passthrough (${broad.join(", ")}).`,
          evidence: broad.join(", "),
        };
      }
      return null;
    },
  },
];
