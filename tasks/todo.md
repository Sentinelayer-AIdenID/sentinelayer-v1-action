# npm workspace-root dependency audit

- [x] Coordinate isolated ownership in Senti and branch from Action release/v1.3.x at 2d5a8edd.
- [x] Inspect current fail-closed audit and gate evidence contracts; reproduce npm 11 workspace lock/report shape.
- [x] Add fail-first tests for valid one-root audit, shared-lock evidence, vulnerabilities, and hostile or drifted workspace graphs.
- [x] Validate explicit workspace paths, manifests, root lock identities and local links; audit the complete copied graph once in private scratch.
- [x] Extend the evidence validator for truthful workspace-member rows without weakening P0 behavior.
- [x] Run focused tests, the full local CI-equivalent suite, lint, and type checks.
- [ ] Freeze exact commit for independent review and publish a PR after the workflow model route is reviewed.

Review: The first full run used a local shell without `PYTHONPATH=src`, so two unrelated subprocess import tests failed. With the CI environment set, the full unit and integration suite passed: 1816 passed, 1 skipped. Ruff, the CI mypy targets, and `git diff --check` passed. A private copy of current AIdenID main's 15 workspace manifests and root lock produced the expected npm audit dependency count (836 non-peer plus 10 peers); the live report contains seven vulnerabilities, which remain a blocking P1. No model workflow was changed or enabled by this branch.
