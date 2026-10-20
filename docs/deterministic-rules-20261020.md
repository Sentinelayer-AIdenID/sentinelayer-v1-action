# Deterministic rule refresh — 2026-10-20

This refresh replaces two workflow regex rules with bounded YAML-aware checks.
It does not claim a complete workflow security proof or end-to-end runtime audit.

| Rule | Change | Evidence boundary |
|---|---|---|
| CICD-001 | Inspect executable `run` and `actions/github-script` script fields; cover PR title/body, branch refs and bracketed contexts | Environment/action arguments remain data. Native workflow validation and semantic review are still required. |
| CICD-002 | Cover version tags, reusable workflow dependencies and Docker images; accept full SHAs/digests or the exact onboarded `actions.lock` reference | Lock version, workflow membership, reference, commit and positive repository identity fields are checked structurally. GitHub enforces source identity at execution. |
| CICD-COVERAGE-INCOMPLETE | Emit a blocking finding for unreadable, invalid, duplicate-key, unsupported, oversized or over-budget workflow/lock input | Unsupported lock versions and merge keys cannot silently suppress a finding. |
| EQ-001 | Repeated state replacement becomes P4 advice with heuristic confidence; exclude functional updaters, comments and strings | React batches state updates. The match does not prove render thrashing or incorrect final state. |
| EQ-013 | Recognize a narrow monotonic deadline with a dominating exit; deadline resets and early continues do not count | The presence of a deadline word alone does not establish a bound. |
| History fixtures | One reviewed synthetic-value digest in test source remains visible as P4 | Production locations, different values and mixed real/fixture lines remain blocking. No directory-wide secret exemption. |
| Python audit | Snapshot and audit the union of root direct pins, generated hash pins and dev pins; allow known tool-only TOML | Dynamic managers, build dependencies, routing options, indirection, malformed input and conflicting versions still refuse. Coverage remains the declared pin census, not an inferred whole ecosystem dependency graph. |

PyYAML 6.0.3 is pinned with all published release hashes. Parsing uses SafeLoader
composition without constructing or executing Python objects. Input size, parser
events, nesting and expanded target traversal are bounded. Legacy workflow regex
retirements are recorded in the pattern catalogue.

OpenAI incomplete Responses cannot pass even if a partial body happens to contain
valid JSON. Cascade HTTP retries are explicit (SDK retries disabled), and returned
usage survives incomplete results. Anonymous telemetry retains the separate cost
ledger in its findings metadata; the legacy numeric cost is only the known subtotal
when the canonical total remains unknown.

Repairing the input census exposed vulnerable declared package versions. The
hash-locked runtime now uses aiohttp 3.14.4, its required yarl 1.25.1 dependency,
and certifi 2026.10.19; development
requirements and both native CI test jobs use pytest 9.0.3. A fresh public-metadata
audit of all 65 declared pins reported zero advisories on 2026-10-20. This is a
dated advisory result, not a guarantee about future disclosures or undeclared
dependencies.

The original engineering framework remains useful for correctness, architecture,
state ownership, transaction wiring, resilience, performance and testing. Its
older blanket manual-memoization expectations must be evaluated against the
project's actual React Compiler setup and measured performance. Missing runtime
metrics, load-test evidence or accessibility results stay unassessed; source
scanning cannot invent those measurements.

Primary references checked on 2026-10-20:

- [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub script injection](https://docs.github.com/en/actions/concepts/security/script-injections)
- [GitHub workflow dependency lockfiles](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles)
- [React state update queues](https://react.dev/learn/queueing-a-series-of-state-updates)
- [React Compiler](https://react.dev/learn/react-compiler/introduction)
