/**
 * Secret detection and — the part that matters — redaction.
 *
 * The invariant under test: no string that reaches a formatter may contain a
 * credential. Every case below asserts both halves: detection works, and the
 * output is clean.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  detectSecret,
  findSecrets,
  looksLikePlaceholder,
  redact,
  shannonEntropy,
} from "../src/secrets.js";

const OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
const GITHUB_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
const JWT =
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
const HEX_SECRET = "a8f5f167f44f4964e6c998dee827110c9c1b3e4a2d5f6071";

test("detects vendor-prefixed keys", () => {
  assert.equal(detectSecret(OPENAI_KEY).kind, "openai-key");
  assert.equal(detectSecret(GITHUB_TOKEN).kind, "github-token");
  assert.equal(detectSecret(JWT).kind, "jwt");
  assert.equal(detectSecret("AKIAIOSFODNN7EXAMPLE").kind, "aws-access-key");
  assert.equal(detectSecret("xoxb-1234567890-abcdefghij").kind, "slack-token");
});

test("detects an assigned secret inside a larger string", () => {
  assert.equal(detectSecret('api_key: "a8f5f167f44f4964e6c998dee827110c9c1b3e4a2d5f6071"').kind, "assigned-secret");
});

test("detects a high-entropy blob with no vendor prefix", () => {
  assert.equal(detectSecret(HEX_SECRET).kind, "high-entropy");
});

test("ignores environment references and placeholders", () => {
  for (const value of [
    "${OPENAI_API_KEY}",
    "$GITHUB_TOKEN",
    "%APPDATA%",
    "<YOUR_TOKEN_HERE>",
    "process.env.OPENAI_API_KEY",
    "YOUR_API_KEY",
    "changeme",
    "xxxxxxxxxxxxxxxxxxxxxxxx",
    "example-token-placeholder",
    "",
    "   ",
  ]) {
    assert.equal(looksLikePlaceholder(value), true, `${value} should be a placeholder`);
    assert.equal(detectSecret(value), null, `${value} should not be a secret`);
  }
});

test("does not flag ordinary values", () => {
  for (const value of [
    "debug",
    "production",
    "/home/dev/projects/app",
    "C:\\Users\\dev\\app",
    "2025-07-01",
    "550e8400-e29b-41d4-a716-446655440000", // UUID
    "https://mcp.example.com/mcp",
    "@modelcontextprotocol/server-filesystem",
    "NODE_TLS_REJECT_UNAUTHORIZED",
  ]) {
    assert.equal(detectSecret(value), null, `${value} should not be a secret`);
  }
});

test("finds several secrets in one string", () => {
  const found = findSecrets(`one ${OPENAI_KEY} two ${GITHUB_TOKEN}`);
  assert.equal(found.length, 2);
  assert.deepEqual(found.map((entry) => entry.kind), ["openai-key", "github-token"]);
});

test("redaction never leaves the secret in the output", () => {
  const inputs = [OPENAI_KEY, GITHUB_TOKEN, JWT, HEX_SECRET, `token=${JWT}`, `Authorization: Bearer ${OPENAI_KEY}`];
  for (const input of inputs) {
    const output = redact(input);
    assert.ok(!output.includes(OPENAI_KEY), "openai key leaked");
    assert.ok(!output.includes(GITHUB_TOKEN), "github token leaked");
    assert.ok(!output.includes(JWT), "jwt leaked");
    assert.ok(!output.includes(HEX_SECRET), "hex secret leaked");
    assert.match(output, /<redacted:/);
  }
});

test("redaction keeps the secret kind and a length bucket", () => {
  const output = redact(OPENAI_KEY);
  assert.match(output, /<redacted:openai-key:~\d+ch>/);
  assert.equal(redact("nothing to hide"), "nothing to hide");
});

test("redaction truncates long text", () => {
  const long = "x".repeat(500);
  assert.ok(redact(long, 100).length <= 100);
});

test("redaction is idempotent", () => {
  const once = redact(`key ${HEX_SECRET} end`);
  assert.equal(redact(once), once);
});

test("shannon entropy distinguishes random from repetitive", () => {
  assert.equal(shannonEntropy(""), 0);
  assert.equal(shannonEntropy("aaaaaaaa"), 0);
  assert.equal(shannonEntropy("ab"), 1);
  assert.ok(shannonEntropy(HEX_SECRET) > 3.5);
});
