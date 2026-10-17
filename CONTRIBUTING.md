# Contributing

Thanks for looking. This is a security tool, so the bar for "it works" is higher than usual: a rule that fires on the correct answer is as much a bug as one that misses the mistake.

## Getting set up

```console
git clone https://github.com/Amor-130625/mcpvet
cd mcpvet
node --version    # 20.11 or newer
npm run check     # syntax + generated docs + tests + self-audit
```

There is nothing to install. If `npm run check` tells you to install something, that is a bug.

If your environment blocks spawning child processes (some sandboxes do), use:

```console
npm run test:inproc
```

## The gate

`npm run check` runs, in order:

1. `npm run syntax` — `node --check` on every `.js`/`.mjs` file.
2. `npm run docs:check` — fails if `docs/rules.md` is stale.
3. `npm test` — the suite.
4. `npm run self:audit` — audits the example configs and asserts the documented outcome.

CI runs the same commands on Linux, macOS, and Windows across Node 20, 22, and 24.

## Proposing a rule

Open a **Rule proposal** issue first. A rule is worth adding when all four hold:

1. **A real configuration gets it wrong.** Link to a public README, issue, or advisory showing the mistake in the wild — not a hypothetical.
2. **The check is decidable from the config or manifest.** No heuristics about intent, no network lookups, no guessing.
3. **There is a clear fix** that a reader can apply without reading the source.
4. **It does not duplicate an existing rule.** Extend the existing one instead.

Then implement it:

- Pick the next free id in your category (`MCP0xx`). Ids are never reused or renumbered.
- Add the rule to `src/rules/<category>.js`.
- Add **both** a positive and a negative test to `test/rules.test.js`. The negative test is not optional.
- Run `npm run docs` to regenerate `docs/rules.md` and commit it.
- If the rule fires on `examples/vulnerable`, update `EXPECTED_RULES` in `test/self-audit.test.js` and `scripts/self-audit.mjs`.

## Changing an existing rule

- Tightening a check: usually fine, mention it in the PR.
- Loosening one: explain what false positive you hit, with the config that produced it.
- Changing a severity: explain the consequence in one sentence ("this lets a poisoned tool result write to the repo") and note it in `CHANGELOG.md`.
- Changing a fingerprint input: this invalidates every committed baseline. Say so loudly in the PR.

## House style

- ES modules, `.js`, no build step, no dependencies. A dependency proposal needs to explain why the code cannot be written in under ~200 lines.
- JSDoc on exported functions; the code is checked by reading, since there is no type checker.
- Comments explain *why*, not *what*. The parsing code is the exception — it is dense enough to deserve a line-by-line explanation.
- Error messages name the file and the line, and never contain a credential.
- British or American spelling is fine, but a file should be internally consistent.

## Pull requests

- One concern per pull request. A rule change plus a refactor is two pull requests.
- Fill in the template. "What could this break?" is the question reviewers care about most.
- New behaviour needs a test that fails without it. Say in the PR how you verified that.
- Never include a real credential, even in a test fixture. Use a synthetic value with the same shape and say it is synthetic.

## Commit messages

Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`) with an imperative subject. The body explains the consequence for a user, not the diff.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports go through [SECURITY.md](SECURITY.md), never a public issue.
