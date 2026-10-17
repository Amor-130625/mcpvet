/**
 * A JSON-with-comments parser that also records where every value came from.
 *
 * Why not `JSON.parse`?
 *
 *  1. Real MCP client configs are not strict JSON. VS Code's `mcp.json` is a
 *     JSONC file and ships with comments and trailing commas in the wild.
 *     Rejecting them would mean refusing to audit the most common config on a
 *     developer's machine.
 *  2. A linter that cannot say *which line* is broken is not usable in code
 *     review. `JSON.parse` throws one message with an offset; GitHub Code
 *     Scanning needs a line number per finding, so we track positions while
 *     parsing and map every finding back to a line/column.
 *
 * The position map is keyed by RFC 6901 JSON Pointer ("" for the root), which
 * makes lookups independent of property ordering and avoids the ambiguity of
 * dot-paths when a server is literally named "a.b".
 *
 * @module jsonc
 */

/** Error raised for malformed JSONC input, carrying a 1-based location. */
export class JsoncError extends Error {
  /**
   * @param {string} message
   * @param {number} line
   * @param {number} column
   */
  constructor(message, line = 1, column = 1) {
    super(`${message} (line ${line}, column ${column})`);
    this.name = "JsoncError";
    this.line = line;
    this.column = column;
  }
}

const WHITESPACE = new Set([" ", "\t", "\r", "\n", "\u00a0", "\ufeff"]);
const PUNCTUATION = new Set(["{", "}", "[", "]", ":", ","]);

/**
 * @typedef {{ type: "punct"|"string"|"number"|"literal", value: any, line: number, column: number }} Token
 */

/**
 * @param {string} text
 * @returns {Token[]}
 */
function tokenize(text) {
  /** @type {Token[]} */
  const tokens = [];
  const length = text.length;
  let index = 0;
  let line = 1;
  let column = 1;

  /** Advance `count` code units, tracking line/column. */
  const advance = (count = 1) => {
    for (let step = 0; step < count; step += 1) {
      if (text[index] === "\n") {
        line += 1;
        column = 1;
      } else {
        column += 1;
      }
      index += 1;
    }
  };

  while (index < length) {
    const ch = text[index];

    if (WHITESPACE.has(ch)) {
      advance();
      continue;
    }

    // Line comment.
    if (ch === "/" && text[index + 1] === "/") {
      while (index < length && text[index] !== "\n") advance();
      continue;
    }

    // Block comment.
    if (ch === "/" && text[index + 1] === "*") {
      const startLine = line;
      const startColumn = column;
      advance(2);
      while (index < length && !(text[index] === "*" && text[index + 1] === "/")) advance();
      if (index >= length) throw new JsoncError("Unterminated block comment", startLine, startColumn);
      advance(2);
      continue;
    }

    const startLine = line;
    const startColumn = column;

    if (PUNCTUATION.has(ch)) {
      tokens.push({ type: "punct", value: ch, line: startLine, column: startColumn });
      advance();
      continue;
    }

    if (ch === '"') {
      advance();
      let value = "";
      for (;;) {
        if (index >= length) throw new JsoncError("Unterminated string", startLine, startColumn);
        const current = text[index];
        if (current === '"') {
          advance();
          break;
        }
        if (current === "\\") {
          const escape = text[index + 1];
          advance(2);
          switch (escape) {
            case '"':
              value += '"';
              break;
            case "\\":
              value += "\\";
              break;
            case "/":
              value += "/";
              break;
            case "b":
              value += "\b";
              break;
            case "f":
              value += "\f";
              break;
            case "n":
              value += "\n";
              break;
            case "r":
              value += "\r";
              break;
            case "t":
              value += "\t";
              break;
            case "u": {
              const hex = text.slice(index, index + 4);
              if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
                throw new JsoncError("Invalid \\u escape sequence", line, column);
              }
              value += String.fromCharCode(parseInt(hex, 16));
              advance(4);
              break;
            }
            default:
              throw new JsoncError(`Invalid escape sequence \\${escape ?? ""}`, line, column);
          }
          continue;
        }
        value += current;
        advance();
      }
      tokens.push({ type: "string", value, line: startLine, column: startColumn });
      continue;
    }

    const numberMatch = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(index));
    if (numberMatch) {
      tokens.push({
        type: "number",
        value: Number(numberMatch[0]),
        line: startLine,
        column: startColumn,
      });
      advance(numberMatch[0].length);
      continue;
    }

    if (text.startsWith("true", index)) {
      tokens.push({ type: "literal", value: true, line: startLine, column: startColumn });
      advance(4);
      continue;
    }
    if (text.startsWith("false", index)) {
      tokens.push({ type: "literal", value: false, line: startLine, column: startColumn });
      advance(5);
      continue;
    }
    if (text.startsWith("null", index)) {
      tokens.push({ type: "literal", value: null, line: startLine, column: startColumn });
      advance(4);
      continue;
    }

    throw new JsoncError(`Unexpected character ${JSON.stringify(ch)}`, startLine, startColumn);
  }

  return tokens;
}

/** Escape a single reference token per RFC 6901. */
function escapePointerToken(token) {
  return String(token).replace(/~/g, "~0").replace(/\//g, "~1");
}

/** @param {string} pointer @param {string|number} token */
function joinPointer(pointer, token) {
  return `${pointer}/${escapePointerToken(token)}`;
}

class Parser {
  /**
   * @param {Token[]} tokens
   */
  constructor(tokens) {
    this.tokens = tokens;
    this.position = 0;
    /** @type {Map<string, {line: number, column: number}>} */
    this.positions = new Map();
  }

  /** @returns {Token|undefined} */
  peek() {
    return this.tokens[this.position];
  }

  /** @returns {Token} */
  next() {
    const token = this.tokens[this.position];
    this.position += 1;
    return token;
  }

  /**
   * Record the position of a value path, first write wins. Object members are
   * recorded at their *key* token, which is the line a human reviewer expects
   * to see for `"command": "npx"`.
   *
   * @param {string} pointer
   * @param {Token} token
   */
  record(pointer, token) {
    if (token && !this.positions.has(pointer)) {
      this.positions.set(pointer, { line: token.line, column: token.column });
    }
  }

  /** @param {string} pointer */
  parseValue(pointer) {
    const token = this.peek();
    if (!token) {
      const last = this.tokens[this.tokens.length - 1];
      throw new JsoncError("Unexpected end of input", last?.line ?? 1, last?.column ?? 1);
    }

    if (token.type === "punct" && token.value === "{") return this.parseObject(pointer);
    if (token.type === "punct" && token.value === "[") return this.parseArray(pointer);

    if (token.type === "string" || token.type === "number" || token.type === "literal") {
      this.record(pointer, token);
      this.next();
      return token.value;
    }

    throw new JsoncError(`Unexpected token ${JSON.stringify(token.value)}`, token.line, token.column);
  }

  /** @param {string} pointer */
  parseObject(pointer) {
    this.record(pointer, this.peek());
    this.next(); // consume "{"
    /** @type {Record<string, any>} */
    const object = Object.create(null);

    for (;;) {
      const token = this.peek();
      if (!token) throw new JsoncError("Unterminated object", 1, 1);
      if (token.type === "punct" && token.value === "}") {
        this.next();
        break;
      }
      if (token.type !== "string") {
        throw new JsoncError("Expected a property name", token.line, token.column);
      }

      this.next(); // key
      const memberPointer = joinPointer(pointer, token.value);

      const colon = this.peek();
      if (!colon || colon.type !== "punct" || colon.value !== ":") {
        throw new JsoncError(
          `Expected ':' after property ${JSON.stringify(token.value)}`,
          colon?.line ?? token.line,
          colon?.column ?? token.column,
        );
      }
      this.next(); // consume ":"

      // Key token wins over the value token for the member's own position.
      this.positions.set(memberPointer, { line: token.line, column: token.column });
      object[token.value] = this.parseValue(memberPointer);

      const separator = this.peek();
      if (!separator) throw new JsoncError("Unterminated object", token.line, token.column);
      if (separator.type === "punct" && separator.value === ",") {
        this.next();
        continue;
      }
      if (separator.type === "punct" && separator.value === "}") {
        this.next();
        break;
      }
      throw new JsoncError("Expected ',' or '}'", separator.line, separator.column);
    }

    return object;
  }

  /** @param {string} pointer */
  parseArray(pointer) {
    this.record(pointer, this.peek());
    this.next(); // consume "["
    /** @type {any[]} */
    const array = [];
    let index = 0;

    for (;;) {
      const token = this.peek();
      if (!token) throw new JsoncError("Unterminated array", 1, 1);
      if (token.type === "punct" && token.value === "]") {
        this.next();
        break;
      }

      array.push(this.parseValue(joinPointer(pointer, index)));
      index += 1;

      const separator = this.peek();
      if (!separator) throw new JsoncError("Unterminated array", token.line, token.column);
      if (separator.type === "punct" && separator.value === ",") {
        this.next();
        continue;
      }
      if (separator.type === "punct" && separator.value === "]") {
        this.next();
        break;
      }
      throw new JsoncError("Expected ',' or ']'", separator.line, separator.column);
    }

    return array;
  }
}

/**
 * Parse a JSONC document.
 *
 * @param {string} text
 * @returns {{ value: any, positions: Map<string, {line: number, column: number}> }}
 * @throws {JsoncError}
 */
export function parseJsonc(text) {
  const source = typeof text === "string" ? text : "";
  const tokens = tokenize(source);
  if (tokens.length === 0) throw new JsoncError("Document is empty", 1, 1);
  const parser = new Parser(tokens);
  const value = parser.parseValue("");
  const trailing = parser.peek();
  if (trailing) {
    throw new JsoncError(
      `Unexpected trailing token ${JSON.stringify(trailing.value)}`,
      trailing.line,
      trailing.column,
    );
  }
  return { value, positions: parser.positions };
}

/**
 * Non-throwing variant used by the loader: a broken config is a finding, not a
 * crash.
 *
 * @param {string} text
 * @returns {{ ok: true, value: any, positions: Map<string, {line: number, column: number}> }
 *          | { ok: false, error: JsoncError }}
 */
export function tryParseJsonc(text) {
  try {
    const parsed = parseJsonc(text);
    return { ok: true, ...parsed };
  } catch (error) {
    if (error instanceof JsoncError) return { ok: false, error };
    throw error;
  }
}

/**
 * Look up a position by JSON Pointer.
 *
 * @param {Map<string, {line: number, column: number}>|undefined} positions
 * @param {string} pointer
 * @returns {{line: number, column: number}|null}
 */
export function getPosition(positions, pointer) {
  if (!positions) return null;
  return positions.get(pointer) ?? null;
}

/**
 * Walk a JSON Pointer against a parsed document. Returns `undefined` when any
 * segment is missing.
 *
 * @param {any} root
 * @param {string} pointer
 */
export function resolvePointer(root, pointer) {
  if (!pointer) return root;
  const segments = pointer
    .split("/")
    .slice(1)
    .map((segment) => segment.replace(/~1/g, "/").replace(/~0/g, "~"));
  let current = root;
  for (const segment of segments) {
    if (current === null || typeof current !== "object") return undefined;
    current = current[segment];
  }
  return current;
}
