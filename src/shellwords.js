/**
 * Minimal POSIX-ish word splitter.
 *
 * Two places need it:
 *  - `mcpvet check --command "npx -y some-server"` has to turn a human-typed
 *    command line into argv without invoking a shell (never a shell).
 *  - some clients tolerate `"args": "--foo bar"` instead of an array, and we
 *    want to audit what the client will actually execute.
 *
 * Supported: single and double quotes, backslash escapes inside double quotes,
 * and backslash escapes outside quotes. No expansion of any kind, because
 * expansion is exactly the behaviour this tool exists to warn about.
 *
 * @param {string} input
 * @returns {string[]}
 */
export function splitShellWords(input) {
  const text = String(input ?? "");
  /** @type {string[]} */
  const words = [];
  let current = "";
  let hasCurrent = false;
  let quote = null;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];

    if (quote === "'") {
      if (ch === "'") quote = null;
      else current += ch;
      continue;
    }

    if (quote === '"') {
      if (ch === '"') {
        quote = null;
      } else if (ch === "\\" && i + 1 < text.length) {
        i += 1;
        current += text[i];
      } else {
        current += ch;
      }
      continue;
    }

    if (ch === "'" || ch === '"') {
      quote = ch;
      hasCurrent = true;
      continue;
    }

    if (ch === "\\" && i + 1 < text.length) {
      i += 1;
      current += text[i];
      hasCurrent = true;
      continue;
    }

    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      if (hasCurrent) {
        words.push(current);
        current = "";
        hasCurrent = false;
      }
      continue;
    }

    current += ch;
    hasCurrent = true;
  }

  if (hasCurrent) words.push(current);
  return words;
}
