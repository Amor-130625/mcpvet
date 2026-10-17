# Threat model

This document describes what `mcpvet` defends against, which rule covers each threat, and where the boundary of the tool sits. It is written for a maintainer deciding whether to adopt the tool, and for a reviewer deciding whether a rule is worth adding.

## Assets

| Asset | Why an agent can reach it |
| --- | --- |
| Source repositories | Filesystem and git servers are the most common MCP servers |
| Cloud credentials | Present in the environment of every process the client spawns |
| SSH keys, browser profiles | Reachable by a filesystem server rooted high enough |
| Production databases | Database servers connect with the credentials in their config |
| The integrity of the agent's decisions | Tool descriptions are model input, and the model acts on them |

## Threats

### T1 — Code executed at launch is not the code that was reviewed

`npx -y server` resolves the newest publish at every agent start. The reviewed version and the executed version diverge without any change to the repository.

- **Rules:** `MCP001` (unpinned launcher, floating tags, unpinned container images), `MCP002` (registry override, plaintext artifact), `MCP033` (script from a temporary or download directory).
- **Residual risk:** pinning does not help if the pinned package is later republished under a mutable dist-tag or the maintainer account is compromised. Lockfiles, npm provenance, and container digests reduce this; `mcpvet` does not verify signatures.

### T2 — Tool metadata carries instructions

A `tools/list` manifest is untrusted input that the model reads as trusted context. It is the cheapest injection channel, because it needs no vulnerability in the server at all: the payload is a description field.

- **Rules:** `MCP050` (instruction-like phrasing), `MCP051` (zero-width and bidi characters), `MCP052` (tool-name shadowing across servers).
- **Residual risk:** detection is pattern-based. A payload written in another language, obfuscated, or phrased as a plausible tool description will not match. `mcpvet` raises the cost of the cheap attack; it is not a sanitizer.

### T3 — Capability exceeds the task

A filesystem server rooted at `/`, a shell bridge, or a write-capable database connection turns a reasoning error into a real change.

- **Rules:** `MCP030` (filesystem root), `MCP031` (shell bridge), `MCP032` (database writes), `MCP034` (tool advertises execution).
- **Residual risk:** a server can expose more than its name suggests. Auditing a manifest with `--descriptor` closes part of that gap.

### T4 — Credentials leak out of the config

Tokens pasted into `env`, argv, or a query string end up in shell history, crash reports, process listings, and synced configuration folders.

- **Rules:** `MCP010`, `MCP011`, `MCP012`, `MCP013`.
- **Residual risk:** a correctly referenced environment variable is still readable by the child process. `mcpvet` checks that the secret is referenced, not that the child deserves it.

### T5 — The human is removed from the loop

Wildcard auto-approval and confirmation-bypass flags eliminate the last control between a poisoned tool result and an action.

- **Rule:** `MCP040` (wildcard or per-tool pre-approval, `--yolo`-class flags).
- **Residual risk:** a client may implement approval without honouring the config key `mcpvet` recognises. The tool reports what the config says, not what the client does.

### T6 — The effective configuration is not the one that was reviewed

The same server declared in two client configs with different definitions means capabilities depend on which client started.

- **Rules:** `MCP041` (conflicting definitions), `MCP070` (unusable entry, silently dropped by some clients), `MCP072` (unparsable file).

### T7 — The audit itself becomes the attack

A security tool that reads untrusted JSON is a parser exposed to attacker-controlled input.

- **Mitigations:** null-prototype objects (no `__proto__` poisoning), no `eval` of any kind, no template compilation, bounded recursion on nesting, no network, no subprocess execution, no shell.
- **Rule:** none — this is an invariant enforced in [`src/jsonc.js`](../../src/jsonc.js) and asserted in `test/jsonc.test.js`.

## Out of scope

- Server source code and dependency vulnerabilities (use a SAST tool and a dependency scanner).
- Runtime behaviour: whether the client actually enforces `autoApprove`, or whether a server honours its declared schema.
- Authentication and authorisation protocols between client and server.
- Anything hosted off-GitHub-PR forges, per the tool's own CI-first design.

## Reporting a problem with the tool

A bypass of a rule, a crash on hostile input, or a path that prints a credential is a security issue in `mcpvet`. See [SECURITY.md](../SECURITY.md).
