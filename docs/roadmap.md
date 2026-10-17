# Roadmap

Ordered by usefulness, not by ambition. Anything that requires `mcpvet` to execute a server, make a network request, or take a dependency needs an explicit design discussion first — those properties are why the tool can be run in CI and on a laptop with no trust decisions attached.

## Next

- **TOML configs.** `.codex/config.toml` and other TOML-based clients are currently unsupported, so `scan` silently sees nothing there. A minimal TOML parser (arrays, tables, inline tables, comments) keeps the zero-dependency property.
- **`--descriptor` discovery.** Detect a sibling `tools.json` next to a config and audit both in one pass, instead of requiring the flag.
- **Per-rule documentation links in `pretty`.** `--verbose` prints the rationale today; a one-line help URL keyed on the rule id would help in a terminal.
- **Severity overrides in `.mcpvetrc.json`.** A team that considers `MCP001` blocking should not need `--ignore`.

## Later

- **Manifest diffing.** Store a fingerprint of a server's `tools/list` output and report when an already-approved server gains a tool or changes a description. This is the "rug pull" defence, and it needs a small store — the baseline format is the natural place.
- **OAuth-aware checks.** HTTP servers that declare an authorisation flow are currently flagged by `MCP023` only when no headers exist; understanding `WWW-Authenticate` would remove a class of false positives.
- **Windows-specific postures.** `cmd /c` quoting differences and PowerShell execution-policy interactions deserve their own checks.
- **A rule registry file.** Rules are code today. A declarative format would let downstreams disable or reweight checks without forking, at the cost of the validation currently guaranteed by the type-and-test setup.
- **`--fix` for the mechanical cases.** Pinning a package to its currently-latest version is mechanical and reviewable. Deliberately last: an automated "fix" of a security finding is easy to get subtly wrong.

## Not planned

- Running, installing, or connecting to an MCP server. Static analysis only.
- A hosted service. The tool is meant to run where the config lives.
- Telemetry of any kind.
- Sending a config anywhere. Credentials are in these files.
