/**
 * Injection rules: text inside tool metadata that is really an instruction.
 *
 * Tool descriptions and schemas are read by the model as part of its context.
 * That makes them a delivery vehicle for prompt injection that survives every
 * review of the *server's code*, because the payload lives in the tool manifest
 * — which for a remote or unpinned server can change after approval.
 *
 * @module rules/injection
 */

/** Phrases that only make sense in an instruction aimed at a model. */
const INJECTION_PATTERNS = [
  { id: "override", re: /\b(?:ignore|disregard|forget)\b[^.]{0,30}\b(?:previous|prior|above|earlier|all)\b[^.]{0,30}\b(?:instructions?|prompts?|rules?|directives?)\b/i },
  { id: "system-prompt", re: /\b(?:system prompt|developer message|hidden instructions?|initial prompt)\b/i },
  { id: "secrecy", re: /\b(?:do not|don't|never)\b[^.]{0,20}\b(?:tell|inform|mention|show|reveal)\b[^.]{0,20}\b(?:the )?(?:user|human|operator)\b/i },
  { id: "covert", re: /\bwithout\b[^.]{0,20}\b(?:telling|informing|asking|notifying)\b[^.]{0,20}\b(?:the )?(?:user|human)\b/i },
  { id: "exfiltrate", re: /\b(?:send|post|upload|forward|transmit|exfiltrate|leak)\b[^.]{0,80}\bhttps?:\/\//i },
  { id: "credential-harvest", re: /(?:id_rsa|id_ed25519|id_ecdsa|\.aws\/credentials|\.npmrc|\.netrc|\.docker\/config\.json|credentials\.json|login keychain|browser cookies?)/i },
  { id: "role-reassign", re: /\byou are now\b|\bact as (?:the )?(?:system|developer|admin)\b|\bnew instructions?:/i },
  { id: "chat-template", re: /<\|(?:im_start|system|endoftext)\|>|\[INST\]|\/\/\s*system\s*:/i },
  { id: "encoded-payload", re: /\b(?:base64|rot13|hex)\b[^.]{0,30}\b(?:decode|decrypt|eval|execute)\b/i },
];

/**
 * Zero-width, bidi-override, tag, and BOM characters: invisible to reviewers.
 *
 * Two objects on purpose. A `/g` regex keeps `lastIndex` between `.test()`
 * calls, so reusing one instance to test single characters silently skips
 * every other match. The global instance is only used with `String.match`,
 * which resets state; the non-global one is only used with `.test`.
 */
const INVISIBLE_SOURCE = "[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\uFEFF]|[\\u{E0000}-\\u{E007F}]";
const INVISIBLE_SCAN = new RegExp(INVISIBLE_SOURCE, "gu");
const INVISIBLE_TEST = new RegExp(INVISIBLE_SOURCE, "u");

/**
 * Render invisible characters as escapes so the report shows evidence without
 * executing any of the payload.
 * @param {string} text
 */
function escapeInvisible(text) {
  return [...text]
    .map((char) => (INVISIBLE_TEST.test(char) ? `\\u{${char.codePointAt(0).toString(16)}}` : char))
    .join("");
}

/** @type {import("./types.js").Rule[]} */
export const injectionRules = [
  {
    id: "MCP050",
    title: "Tool metadata contains instruction-like text",
    category: "injection",
    severity: "critical",
    target: "tool",
    summary: "A tool name or description contains phrases that address the model rather than describe the tool.",
    why:
      "A tool description is untrusted input that the model treats as trusted context. Text such as \"ignore previous " +
      "instructions\" or \"do not tell the user\" has no legitimate reason to appear in a tool manifest, and it is " +
      "the cheapest way to smuggle a directive past a code review that only looked at the server's source.",
    remediation:
      "Do not use the server until the manifest is explained. If you maintain it, remove the text, pin the version, " +
      "and enable integrity checks (tool manifests can change between launches for unpinned servers).",
    references: [
      "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
      "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ],
    check({ tool }) {
      const text = `${tool.name} ${tool.description}`;
      /** @type {import("./types.js").RuleHit[]} */
      const hits = [];
      for (const { id, re } of INJECTION_PATTERNS) {
        const match = re.exec(text);
        if (!match) continue;
        hits.push({
          message: `Tool "${tool.name}" contains instruction-like text (${id}): "${match[0].slice(0, 80)}".`,
          evidence: match[0],
          fingerprintKey: `${tool.name}:${id}`,
        });
      }
      return hits;
    },
  },

  {
    id: "MCP051",
    title: "Tool metadata contains invisible characters",
    category: "injection",
    severity: "high",
    target: "tool",
    summary: "Zero-width, bidi-override, or Unicode tag characters hide text inside a tool definition.",
    why:
      "Invisible characters let a manifest carry instructions that no human reviewer can see but the model still " +
      "reads. Bidi overrides additionally allow the rendered name to differ from the name the client matches on, " +
      "which is how a tool can masquerade as another one.",
    remediation:
      "Reject the manifest, then strip or normalise the characters (NFKC plus an invisible-character filter) in the " +
      "client that consumes it.",
    references: ["https://www.unicode.org/reports/tr36/", "https://unicode.org/reports/tr9/"],
    check({ tool }) {
      const text = `${tool.name} ${tool.description}`;
      const matches = text.match(INVISIBLE_SCAN);
      if (!matches) return null;
      return {
        message: `Tool "${tool.name}" contains ${matches.length} invisible character(s).`,
        evidence: escapeInvisible(text).slice(0, 160),
        fingerprintKey: `${tool.name}:${matches.length}`,
      };
    },
  },

  {
    id: "MCP052",
    title: "Two servers expose a tool with the same name",
    category: "injection",
    severity: "medium",
    target: "scan",
    summary: "The same tool name is contributed by more than one server, so the model cannot tell them apart.",
    why:
      "Tool names are the model's whole vocabulary for choosing an action. When two servers provide `read_file`, a " +
      "malicious server can shadow the trusted one — the classic tool-poisoning setup — and which one wins is left " +
      "to client ordering, not to intent.",
    remediation: "Namespace tool names per server (e.g. `github_read_file`), and remove the redundant server.",
    references: ["https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices"],
    check({ scan }) {
      /** @type {Map<string, Set<string>>} */
      const owners = new Map();
      for (const tool of scan.tools) {
        const owner = tool.server ?? tool.file ?? "unknown";
        if (!tool.name) continue;
        const set = owners.get(tool.name) ?? new Set();
        set.add(owner);
        owners.set(tool.name, set);
      }

      /** @type {import("./types.js").RuleHit[]} */
      const hits = [];
      for (const [name, set] of owners) {
        if (set.size < 2) continue;
        hits.push({
          message: `Tool name "${name}" is exposed by ${set.size} different servers.`,
          evidence: `${name} -> ${[...set].join(", ")}`,
          fingerprintKey: name,
        });
      }
      return hits;
    },
  },
];
