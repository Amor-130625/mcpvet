## What this changes

<!-- One paragraph. What is different for a user after this merges? -->

## Why

<!-- Link the issue. For a rule change: the real configuration that gets it wrong. -->

## How it was verified

- [ ] `npm run check` passes locally
- [ ] The new behaviour has a test that fails without this change
- [ ] For a new rule: a positive **and** a negative test case are included
- [ ] `docs/rules.md` regenerated (`npm run docs`) and committed, if the rule set changed

## What could this break?

<!--
  Think about:
  - existing baselines (does a fingerprint input change?)
  - the JSON report shape (schema/report.schema.json)
  - a previously clean configuration that would now fail CI
  - false positives on a common, correct setup
-->

## Checklist

- [ ] No new dependencies (runtime or development)
- [ ] No real credentials in fixtures — synthetic values only, and marked as synthetic
- [ ] `CHANGELOG.md` updated under `Unreleased` for user-visible changes
