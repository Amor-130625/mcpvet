/**
 * JSONC parser tests.
 *
 * The parser is the foundation of every line number in every report, so it gets
 * the most adversarial coverage: comments in odd places, trailing commas, BOM,
 * escapes, and — because config files are untrusted input — prototype keys.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { JsoncError, getPosition, parseJsonc, resolvePointer, tryParseJsonc } from "../src/jsonc.js";

/** The parser builds null-prototype objects on purpose; compare as plain JSON. */
const plain = (value) => JSON.parse(JSON.stringify(value));

test("parses an object with line and block comments", () => {
  const { value } = parseJsonc(`{
    // a line comment
    "a": 1,
    /* a block
       comment */
    "b": "two"
  }`);
  assert.deepEqual(plain(value), { a: 1, b: "two" });
});

test("parses trailing commas in objects and arrays", () => {
  const { value } = parseJsonc(`{
    "a": 1,
    "b": [1, 2, 3,],
  }`);
  assert.deepEqual(plain(value), { a: 1, b: [1, 2, 3] });
});

test("parses every scalar type", () => {
  const { value } = parseJsonc(`{"n": -12.5e2, "t": true, "f": false, "z": null, "s": "x"}`);
  assert.deepEqual(plain(value), { n: -1250, t: true, f: false, z: null, s: "x" });
});

test("decodes escape sequences", () => {
  const { value } = parseJsonc('{"a": "line\\nbreak\\t\\"quoted\\" \\u0041\\u00e9"}');
  assert.equal(value.a, 'line\nbreak\t"quoted" A\u00e9');
});

test("tolerates a UTF-8 BOM", () => {
  const { value } = parseJsonc('\ufeff{"a": 1}');
  assert.deepEqual(plain(value), { a: 1 });
});

test("records the line of an object member at its key", () => {
  const source = [
    "{",
    '  "mcpServers": {',
    '    "demo": {',
    '      "command": "npx",',
    '      "args": ["-y", "pkg"]',
    "    }",
    "  }",
    "}",
  ].join("\n");
  const { positions } = parseJsonc(source);

  assert.equal(getPosition(positions, "/mcpServers").line, 2);
  assert.equal(getPosition(positions, "/mcpServers/demo").line, 3);
  assert.equal(getPosition(positions, "/mcpServers/demo/command").line, 4);
  assert.equal(getPosition(positions, "/mcpServers/demo/args").line, 5);
});

test("records the line of an array element at the element", () => {
  const source = '{\n  "args": [\n    "-y",\n    "pkg"\n  ]\n}';
  const { positions } = parseJsonc(source);
  assert.equal(getPosition(positions, "/args/0").line, 3);
  assert.equal(getPosition(positions, "/args/1").line, 4);
});

test("returns null for a pointer that does not exist", () => {
  const { positions } = parseJsonc('{"a": 1}');
  assert.equal(getPosition(positions, "/a/b/c"), null);
  assert.equal(getPosition(undefined, "/a"), null);
});

test("does not inherit properties from Object.prototype", () => {
  // A config is untrusted input. If the parser used `{}`, this would poison the
  // prototype of every object created afterwards in the process.
  const { value } = parseJsonc('{"__proto__": {"polluted": true}, "constructor": {"prototype": {"x": 1}}}');
  assert.equal({}.polluted, undefined);
  assert.equal(value.polluted, undefined);
  assert.equal(typeof value.constructor, "object");
});

test("parses a deeply nested document", () => {
  const source = `${"[".repeat(60)}{"a":1}${"]".repeat(60)}`;
  const { value } = parseJsonc(source);
  let cursor = value;
  for (let depth = 0; depth < 60; depth += 1) cursor = cursor[0];
  assert.equal(cursor.a, 1);
});

test("reports a useful location for an unterminated string", () => {
  const result = tryParseJsonc('{\n  "a": "oops\n}');
  assert.equal(result.ok, false);
  assert.ok(result.error instanceof JsoncError);
  assert.match(result.error.message, /Unterminated string/);
  assert.equal(result.error.line, 2);
});

test("rejects trailing garbage", () => {
  const result = tryParseJsonc('{"a": 1} {"b": 2}');
  assert.equal(result.ok, false);
  assert.match(result.error.message, /trailing token/);
});

test("rejects an unterminated block comment", () => {
  const result = tryParseJsonc('{"a": 1} /* never closed');
  assert.equal(result.ok, false);
  assert.match(result.error.message, /Unterminated block comment/);
});

test("rejects an empty document", () => {
  const result = tryParseJsonc("   \n  ");
  assert.equal(result.ok, false);
  assert.match(result.error.message, /empty/);
});

test("rejects a missing colon", () => {
  const result = tryParseJsonc('{"a" 1}');
  assert.equal(result.ok, false);
  assert.match(result.error.message, /Expected ':'/);
});

test("rejects a bad unicode escape", () => {
  const result = tryParseJsonc('{"a": "\\u12"}');
  assert.equal(result.ok, false);
  assert.match(result.error.message, /\\u escape/);
});

test("resolves JSON Pointers, including escaped tokens", () => {
  const { value } = parseJsonc('{"a/b": {"~c": 42}}');
  assert.equal(resolvePointer(value, "/a~1b/~0c"), 42);
  assert.equal(resolvePointer(value, ""), value);
  assert.equal(resolvePointer(value, "/missing"), undefined);
});
