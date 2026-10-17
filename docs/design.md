# Design notes

Why the code is shaped the way it is. Read this before changing the parser, the finding shape, or the formatters.

## Pipeline

```
paths / discovery
      │
      ▼
  loader.js ──► jsonc.js (value + positions)
      │              │
      │              └─► config.js (normalise envelopes)
      ▼
  audit.js ──► rules/*.js (pure: context in, hits out)
      │
      ▼
  findings.js (redact, fingerprint)
      │
      ▼
  report/*.js (pretty | json | sarif | markdown)
```

Each stage has one job and no stage knows about the next one's formatting. `audit()` is a pure function over loaded documents, which is why the entire rule set is testable without touching the filesystem.

## Module map

| Module | Responsibility |
| --- | --- |
| `src/jsonc.js` | Parse JSONC and record a position for every JSON Pointer |
| `src/secrets.js` | Detect credential shapes; redact them from any string |
| `src/config.js` | Map every client envelope onto one `NormalizedServer` / `NormalizedTool` |
| `src/loader.js` | Read + classify files; turn every failure into data |
| `src/discovery.js` | Known per-user and per-project config locations (injectable) |
| `src/rules/*` | One exported array per category, validated at import |
| `src/audit.js` | Fan rules out over inputs, dedupe, filter, sort |
| `src/findings.js` | Build the finding object; the only place redaction happens |
| `src/score.js` | The documented 0–100 summary |
| `src/baseline.js` | Accepted-findings storage and fingerprint matching |
| `src/report/*` | Formatters, one file per output contract |
| `src/cli.js` | Argument parsing, command dispatch, exit codes |

## Decisions

### A hand-written parser instead of `JSON.parse`

Three requirements rule out the built-in parser:

1. **Line numbers per finding.** SARIF needs `startLine`; a linter whose findings cannot be annotated is a log file.
2. **JSONC.** VS Code's `mcp.json` is JSONC. Refusing to parse the most common config on a developer machine is not a defensible default.
3. **Untrusted input.** The parser builds null-prototype objects, so `{"__proto__": {...}}` in a hostile config cannot poison anything.

The parser is ~350 lines with a tokenizer, a recursive-descent parser, and a `Map<pointer, {line,column}>`. Pointers are RFC 6901 so a server literally named `a.b` cannot collide with a nested path.

Object members are located at their **key**, not their value, because that is the line a reviewer expects: `"command": "npx"` should point at `command`.

### Rules are pure and small

A rule receives `{ server, scan }`, `{ tool, scan }`, `{ scan }`, or `{ warning | error, scan }` and returns `RuleHit | RuleHit[] | null`. No I/O, no formatting, no filesystem. Consequences:

- A rule is testable with one object literal.
- The same rule runs unchanged against a config file, a directory, a `tools/list` dump, and the output of `mcpvet check`.
- Severity can be overridden per occurrence (`hit.severity`) without changing the rule's default.

The registry validates the set at import time — duplicate ids, unknown severities, missing rationale, or a non-function `check` throw immediately. A silently missing rule would produce a clean report, which is the one failure mode that matters here.

### One redaction choke point

`createFinding()` is the only constructor for a finding, and it redacts `message`, `evidence`, and `detail` on the way in. Rules may therefore pass raw strings (a command line, a URL) without each rule having to remember to scrub. The invariant is tested from the outside: the example credentials must not appear in any of the four formats.

Redaction markers keep the *kind* and a bucketed length (`<redacted:jwt:~96ch>`) so a reviewer can reason about what was found without seeing it, and so the marker cannot fingerprint a specific secret.

### Fingerprints exclude lines

```js
fingerprint = sha256(ruleId | file | server | tool | normalisedEvidence).slice(0, 16)
```

Excluded on purpose: line and column (they move), and ordering (it is unstable). Included on purpose: the location identity and the offending configuration, so a *different* unpinned package is a *new* finding rather than a suppressed one. This is what makes a committed baseline usable over months.

### Formatters are contracts

- `json` — documented in `schema/report.schema.json`; renaming a field is a breaking change.
- `sarif` — 2.1.0, one `run`, rules limited to the ones that produced results so Code Scanning does not list the whole rule set as "open".
- `markdown` — table plus a collapsed fix list, usable as a PR comment.
- `pretty` — terminal-first; never prints a raw secret, and prints `(scan)` for findings with no single file.

### Zero dependencies

A tool whose purpose is to audit supply-chain risk must not add supply-chain risk. This constrains the design: no `commander` (hand-rolled parser), no `chalk` (ANSI constants), no `ajv` (hand-rolled schema checks), no test framework (`node --test`). The constraint is enforced by a test that fails if `dependencies` or `devDependencies` becomes non-empty.

### Exit codes are part of the API

`0` clean, `1` failing findings, `2` usage error, `3` internal error. `3` exists so that "the tool broke" can never be confused with "the config is clean" — a CI job can distinguish them.

## Testing strategy

| Level | What it proves |
| --- | --- |
| `jsonc.test.js` | Hostile input does not crash or poison; positions are right |
| `secrets.test.js` | Detection works; redaction never leaks |
| `config.test.js` | Every client envelope maps correctly, warnings carry lines |
| `rules.test.js` | Each rule fires on the mistake and stays quiet on the fix |
| `audit.test.js` | Filtering, ordering, dedupe, stats, metadata completeness |
| `report.test.js` | SARIF is structurally valid; no format leaks a secret |
| `baseline.test.js` | Fingerprint stability under line shifts and real changes |
| `cli.test.js` | Real process, real exit codes, real files |
| `self-audit.test.js` | The examples and the documented numbers are still true |

The suite runs with `node --test` and no test dependencies. `npm test` delegates to `scripts/run-tests.mjs`, which passes an explicit file list: `node --test test/` is not portable (newer Node versions treat the positional argument as something to execute, so a directory becomes `require('test')`), and globs are not portable either (shells differ, and Node only gained glob support in v22). `npm run test:inproc` runs every file in one process for environments where spawning child processes is unavailable.
