# npm workspace-root dependency audit

- [x] Coordinate isolated ownership in Senti and branch from Action release/v1.3.x at 2d5a8edd.
- [x] Inspect current fail-closed audit and gate evidence contracts; reproduce npm 11 workspace lock/report shape.
- [x] Add fail-first tests for valid one-root audit, shared-lock evidence, vulnerabilities, and hostile or drifted workspace graphs.
- [x] Validate explicit workspace paths, manifests, root lock identities and local links; audit the complete copied graph once in private scratch.
- [x] Extend the evidence validator for truthful workspace-member rows without weakening P0 behavior.
- [x] Run focused tests, the full local CI-equivalent suite, lint, and type checks.
- [ ] Freeze exact commit for independent review and publish a PR after the workflow model route is reviewed.

Review: The first full run used a local shell without `PYTHONPATH=src`, so two unrelated subprocess import tests failed. With the CI environment set, the full unit and integration suite passed: 1816 passed, 1 skipped. Ruff, the CI mypy targets, and `git diff --check` passed. A private copy of current AIdenID main's 15 workspace manifests and root lock produced the expected npm audit dependency count (836 non-peer plus 10 peers); the live report contains seven vulnerabilities, which remain a blocking P1. No model workflow was changed or enabled by this branch.

# Nested Python dependency audit for AIdenID #617

- [x] Verify release head and existing npm workspace fix before changing code.
- [x] Confirm AIdenID's nested `apps/api/pyproject.toml` declares only static tool settings.
- [x] Add regression cases for nested pinned Python requirements and tool-only config, plus malformed, missing-lock, unsafe-path, routing, and changed-input controls.
- [x] Validate bounded nested manifests, audit pinned input in private scratch, and preserve fail-closed evidence.
- [x] Run focused and broader tests, lint, type checks, diff check, then freeze local commit for independent review.

Review: The focused dependency-audit, npm-workspace, and gate evidence suite passes (285 tests); the full unit and integration suite passes (1,834 passed, 1 skipped). Ruff, the CI mypy targets, and `git diff --check` pass. Against the actual AIdenID #617 checkout, discovery finds three Python manifests; the 61 KB pip-compile lock yields 40 pins, and an end-to-end mock pip-audit produces a complete `requirements.lock` SHA256 receipt. This synthetic clean report proves input coverage and parsing only; it is not a live advisory result. No branch was pushed or workflow changed.

Independent review follow-up:

- [x] Replace the pre-cap whole-file Python fingerprint read with a bounded read of an opened ordinary file.
- [x] Apply the same bounded opened-handle check to source copying, direct-pin parsing, and tool-only pyproject parsing.
- [x] Cover over-cap manifests and source growth between stat and open without starting pip-audit.
- [x] Re-run focused and full suites, Ruff, CI mypy targets, and diff check after the repair.

The pip-compile pair validates coverage of declared direct names and versions; it does not independently prove extras or the complete resolved graph. The receipt must remain `declared_direct_pins` in scope.

Review: The repaired nested suite passes (21 tests); the full unit and integration suite passes (1,839 passed, 1 skipped in 186.95 seconds). Ruff over `src tests`, the CI mypy targets, and `git diff --check` pass. Over-cap Python manifests fail closed before source open or unbounded read; growth between stat and open also fails closed. Rechecking the current AIdenID #617 checkout finds the same three manifests and 40 pins with no input error. The release branch, AIdenID workflows, and hosted actions remain unchanged.
