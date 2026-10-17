# Security policy

## Reporting a vulnerability

Report privately through GitHub's [Security Advisories](https://github.com/Amor-130625/mcpvet/security/advisories/new) — **not** in a public issue.

Please include:

- the `mcpvet` version (`npx mcpvet --version`) and Node.js version;
- the smallest config or descriptor that reproduces it;
- what you expected, what happened, and why it matters.

**Never paste a real credential.** Replace every token with a placeholder that has the same shape (`sk-proj-AAAA…`) if the shape is what triggers the bug.

## What counts as a vulnerability in mcpvet

The tool reads hostile input and prints reports about secrets, so the interesting failures are:

| Class | Example |
| --- | --- |
| Credential disclosure | A finding, SARIF report, or error message that prints a live secret |
| Denial of service | A config that hangs, exhausts memory, or throws an unhandled exception |
| Prototype pollution | A config key that modifies an object the rest of the process inherits |
| Rule bypass | A trivial reformulation of a documented bad configuration that the rule misses |
| Path traversal | Reading a file outside the paths the user named |
| False negative by silence | A file that fails to load and is not reported as `MCP072` |

## What does not count

- A rule disagreeing with your judgement about severity. Open an issue; that is a design discussion.
- Detection gaps in `MCP050` for a novel prompt-injection phrasing. Pattern-based detection is documented as best-effort in the [threat model](docs/threat-model.md); a bypass is worth reporting, but it is a known limitation rather than an embargo-worthy bug.
- Anything that requires the attacker to already control the config file and the machine it runs on, *unless* it escalates beyond what that control already implies.

## Supported versions

`mcpvet` is pre-1.0. Security fixes land on the latest minor release; there are no long-term support branches yet. Fixes are listed in [CHANGELOG.md](CHANGELOG.md) under **Security**.

## Response

- Acknowledgement within 7 days.
- An assessment within 14 days, including whether a fix or a documentation change is the right response.
- Credit in the advisory and the changelog unless you prefer otherwise.

## Our own posture

- No runtime or development dependencies (`test/version.test.js` fails if that changes).
- No network requests, no telemetry, no subprocess execution of the configs being audited.
- CI runs the full test suite, a syntax check, a generated-docs check, and `mcpvet` against its own examples on every push.
