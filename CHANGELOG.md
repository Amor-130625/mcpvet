# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-10-17

First release. The engine, the rule set, and the report formats are all in place; the shape of findings, the JSON report, and the baseline format are treated as public API from here on.

### Added

- `mcpvet scan` with project and per-user config discovery for Claude Desktop, VS Code, Cursor, Windsurf, and project-level `.mcp.json` files on Windows, macOS, and Linux.
- `mcpvet check` to audit a server spec before it is written into a config.
- 26 rules across 8 categories, including unpinned launchers, credentials in `env`/argv/URLs, plaintext and wildcard transports, unbounded filesystem roots, shell bridges, confirmation bypass, instruction-like and invisible characters in tool metadata, and unconstrained tool parameters.
- JSONC parsing with exact line and column positions per finding.
- Report formats: `pretty`, `json`, `sarif` (2.1.0), and `markdown`.
- Baselines: stable fingerprints so CI gates on new risk instead of existing risk.
- `.mcpvetrc.json` settings file, `--ignore`, `--min-severity`, `--fail-on`.
- `mcpvet init` to scaffold a settings file and a GitHub Actions workflow.
- Composite GitHub Action with SARIF upload.
- Credential redaction enforced at finding construction, with tests that assert no format leaks the synthetic secrets in `examples/`.

### Security

- Redaction covers vendor-prefixed tokens, JWTs, assigned secrets, and high-entropy values; tokens are never printed in findings, SARIF properties, or error messages.
- The parser builds null-prototype objects, so `__proto__` keys in an untrusted config cannot pollute the process.
- A rule that throws fails the scan with exit code `3` instead of producing a clean report.
- Unparsable config files are reported as findings (`MCP072`) rather than skipped.

### Notes

- Zero runtime and development dependencies. `test/version.test.js` fails if that changes.
- Node.js 20.11 or newer.
- `docs/rules.md` is generated from the rule registry; `npm run docs:check` fails if it is stale.

[Unreleased]: https://github.com/Amor-130625/mcpvet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Amor-130625/mcpvet/releases/tag/v0.1.0
