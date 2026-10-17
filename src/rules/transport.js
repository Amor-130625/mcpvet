/**
 * Transport rules: how bytes get from the agent to the server.
 *
 * @module rules/transport
 */

import { commandLine, isLoopbackHost, safeUrl } from "./helpers.js";

/** @type {import("./types.js").Rule[]} */
export const transportRules = [
  {
    id: "MCP020",
    title: "Remote MCP server is reached over plaintext HTTP",
    category: "transport",
    severity: "medium",
    target: "server",
    summary: "A non-loopback server URL uses http:// instead of https://.",
    why:
      "The MCP stream carries tool results and often the user's own data to the model. Over plaintext http, anyone " +
      "on the path can read those results and rewrite them — turning a trusted tool into an attacker-controlled " +
      "input channel for the model.",
    remediation: "Use an https:// endpoint, or terminate TLS on a local proxy you control.",
    references: ["https://modelcontextprotocol.io/docs/concepts/transports"],
    check({ server }) {
      if (!server.url) return null;
      const url = safeUrl(server.url);
      if (!url || url.protocol !== "http:") return null;
      if (isLoopbackHost(url.hostname)) return null;
      return {
        message: `Server is reached over plaintext http (${url.host}).`,
        evidence: server.url,
        detail: "Tool output is model input: an on-path attacker gains a prompt-injection primitive, not just a read.",
      };
    },
  },

  {
    id: "MCP021",
    title: "Server is bound to or reached at a wildcard address",
    category: "transport",
    severity: "high",
    target: "server",
    summary: "The endpoint uses 0.0.0.0 or [::], exposing the server to the whole network.",
    why:
      "Binding to a wildcard address publishes the MCP endpoint on every interface, including public ones on a " +
      "laptop connected to a café network. Most MCP servers have no authentication at all, so reachability is the " +
      "only access control there is.",
    remediation: "Bind to 127.0.0.1 (or ::1) and put an authenticated proxy in front if remote access is required.",
    references: ["https://modelcontextprotocol.io/docs/concepts/transports"],
    check({ server }) {
      if (server.url) {
        const url = safeUrl(server.url);
        const host = (url?.hostname ?? "").replace(/^\[|\]$/g, "");
        if (host === "0.0.0.0" || host === "::" || host === "[::]") {
          return {
            message: `Server URL points at the wildcard address ${host}.`,
            evidence: server.url,
          };
        }
      }
      const needle = server.args.find((arg) => typeof arg === "string" && /0\.0\.0\.0|::\b/.test(arg) && !/::1/.test(arg));
      if (needle) {
        return {
          message: "Server is launched with a wildcard bind argument.",
          evidence: commandLine(server),
          severity: "medium",
          detail: "Check whether the client honours --host; several MCP servers bind all interfaces by default.",
        };
      }
      return null;
    },
  },

  {
    id: "MCP022",
    title: "TLS certificate validation is disabled",
    category: "transport",
    severity: "high",
    target: "server",
    summary: "A variable or flag turns off certificate verification for the server process.",
    why:
      "Disabling verification makes https equivalent to http while still looking secure in reviews. It is usually " +
      "added to work around a proxy and then never removed, leaving every subsequent connection open to interception.",
    remediation: "Install the corporate root CA (NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE) instead of disabling verification.",
    references: ["https://nodejs.org/api/cli.html#node_extra_ca_certsfile"],
    check({ server }) {
      const killSwitches = {
        NODE_TLS_REJECT_UNAUTHORIZED: "0",
        PYTHONHTTPSVERIFY: "0",
        CURL_CA_BUNDLE: "",
        REQUESTS_CA_BUNDLE: "",
        SSL_CERT_FILE: "",
        GIT_SSL_NO_VERIFY: "true",
      };
      for (const [key, offValue] of Object.entries(killSwitches)) {
        const value = server.env[key];
        if (value === undefined) continue;
        const disabled = offValue === "" ? value.trim() === "" : value.trim().toLowerCase() === offValue;
        if (disabled) {
          return {
            message: `env.${key} disables TLS certificate validation.`,
            evidence: `env.${key}=${JSON.stringify(value)}`,
          };
        }
      }
      const flag = server.args.find((arg) => typeof arg === "string" && /^(?:--insecure|--no-verify|--skip-verify|--disable-ssl-verify|-k)$/.test(arg));
      if (flag) {
        return {
          message: `Launcher flag ${flag} disables certificate verification.`,
          evidence: commandLine(server),
        };
      }
      return null;
    },
  },

  {
    id: "MCP023",
    title: "Remote server has no authentication configured",
    category: "transport",
    severity: "medium",
    target: "server",
    summary: "An http/sse endpoint without headers relies on the network position alone for access control.",
    why:
      "The MCP specification expects HTTP transports to be protected by the usual web auth. A config with no " +
      "Authorization header either talks to something that needs no auth (so anyone else who can reach it can use " +
      "it) or is broken and will fail at runtime.",
    remediation: "Add an Authorization header backed by an environment reference, and confirm the server rejects unauthenticated requests.",
    references: ["https://modelcontextprotocol.io/specification/2025-06-18/basic/transports"],
    check({ server }) {
      if (server.transport !== "http" && server.transport !== "sse") return null;
      if (!server.url) return null;
      const url = safeUrl(server.url);
      if (url && isLoopbackHost(url.hostname)) return null;
      if (Object.keys(server.headers).length > 0) return null;
      return {
        message: `No authentication headers are configured for ${url?.host ?? server.url}.`,
        evidence: server.url,
      };
    },
  },
];
