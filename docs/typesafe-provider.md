# TypeSafe candidate assessment configuration

The full-engine action accepts `llm_provider: typesafe` for its typed candidate
assessment path. Supply both `typesafe_api_key` and `openai_api_key` through GitHub
secrets. TypeSafe assesses candidates; the OpenAI key funds the writer and fallback.
Both keys, `intent_model_pin` and `intent_policy` are held as secret configuration values. Supply
the reviewed provider pin from an Actions variable or secret. No public default is
provided; an empty or malformed pin refuses the intent-model stage. Mutable aliases
and incomplete version strings are rejected. Public evidence contains only a
neutral intent-model label and a short SHA-256 reference to the pin.

The remaining inputs are `typesafe_timeout` (1–120 seconds, default 30),
`typesafe_max_candidates` (1–200, default 50), and `typesafe_fallback` (default true).
The latter permits the OpenAI generator fallback when typed review cannot complete.
For this provider, `model`, `model_fallback` and `codex_model` all resolve to exactly
`gpt-5.3-codex`, separately from the typed assessment model. Explicit conflicting
models, including `gpt-4.1-mini` or alternate providers, are rejected. The OpenAI key
is required even with `typesafe_fallback: false` or `use_codex: false`.

The action's empty `model` and `model_fallback` defaults mean automatic selection.
They select `gpt-5.3-codex` for TypeSafe; other providers retain their effective
`gpt-4.1-mini` defaults and existing explicit model overrides. `codex_model` keeps
its `gpt-5.3-codex` default. `codex_only: true` and the managed proxy are incompatible
with TypeSafe; a Sentinelayer token cannot replace the OpenAI writer key.

Typed answers assess source-backed candidates under the configured coverage and
policy contract. A successful request, an empty candidate list or reaching the
candidate cap does not establish a complete review. Configuration wiring alone
does not prove provider execution, policy calibration or production activation.

The typed state covers complete changed text files in bounded source spans, with
the current diff hunk, file path, language and located deterministic scanner hits.
Added and context lines must match current source; removed lines are labelled
unverified patch context. Unsupported renames, missing files, incomplete diffs and
budget overflows take the configured fallback rather than silently clipping scope.

The caller supplies a private `intent_policy` JSON profile. The Action validates
schema `omargate.private-review-policy.v1`, exact field shapes, finite probability
thresholds, question bindings and required category templates before dispatch.
No rubric, decision thresholds or critical-path list is packaged as a default.
Missing, duplicate, malformed or oversized configuration refuses typed review.
Evidence retains only a neutral policy hash reference and explicit incomplete
status. Typed choices retain their probabilities and provider-reported confidence;
neither concentration nor a profile identifier proves correctness or calibration.

For the versioned multi-model route, see [intent cascade](intent-cascade.md).
That route runs the source-bound policy stage independently of routing triage,
preserves substantive P0/P1 findings and requires complete policy coverage even
after a clean generator response. The remaining descriptions below apply to the
legacy typed/writer compatibility path unless stated otherwise.

For emitted findings, the OpenAI writer receives fixed verdicts and evidence. It
may return only the matching finding IDs, explanation and recommendation. Code
retains the original severity, category, source range, evidence hashes and typed
reason; extra, missing or verdict-changing fields refuse the writer output.
The writer request stays pinned to `gpt-5.3-codex`. A response may report that
exact name or the same family with a valid `YYYY-MM-DD` snapshot suffix; artifacts
retain the actual returned identifier. Preview names and other model families
are refused. Snapshot acceptance is a compatibility rule, not proof of a live
provider response or model pricing.
Writer failure preserves the policy-owned verdict/template and bounded failure
metadata instead of erasing the finding. It does not independently confirm clean spans.

Every resolved-clean candidate requires generator confirmation, even when other
spans emitted findings. `generator_required_clean_candidates` records those IDs;
a complete mixed/all-clean policy decision returns `typesafe_clean_requires_generator`.
Unresolved partial decisions retain `unresolved_candidates` and confirmed findings.
Fallback-off does not turn missing confirmation into successful coverage; default
`llm_failure_policy: block` remains the fail-closed choice.

Typed P0/P1 corroboration requires a reviewed `(source, rule_id, emitted category)`
producer tuple and a matching canonical typed category over the full bound span +/-5.
Availability, infrastructure, race-condition and other-security remain generator-required
and P2 under the typed guardrails. Legacy LLM/Codex instead accepts any deterministic/
harness stage finding with the same exact category and an intersecting first-line +/-5
window; typed producer restrictions/aliases do not change that lane or let a generator
end line widen it. Both lanes are guarded before composition. Full-span collisions
keep the strongest guarded severity; alternate identity/verdict provenance is limited
to eight records with explicit truncation. A non-typed winner does not inherit typed
authority at the top level. See the [full contract](CONFIGURATION.md#typesafe-review).

Recognized secret-source lines and sensitive paths are excluded from displayed typed
candidate/diff context, but original evidence/source/diff SHA-256 fingerprints remain
in provider state. Pattern coverage is bounded; redaction/digests do not establish
that every secret or low-entropy value is unrecoverable. Provider context, artifacts,
rendered summaries and external provider retention are separate boundaries (see
[data boundaries](CONFIGURATION.md#data-and-rendering-boundaries)).

`TYPESAFE_REVIEW.json` retains the assessment and final completion/failure state
and is included in the artifact manifest. The pack summary retains typed assessment
metadata even when the generator fallback supplies the final review. Dependency-audit
evidence is separate: with `run_harness: true`, schema 1.1 audit scopes/outcomes and
serialized harness findings must validate before the required LLM result or severity
threshold can pass. Typed findings, a successful writer or generator output cannot
replace an incomplete audit. See [dependency-audit coverage](CONFIGURATION.md#run_harness-and-dependency-audit-evidence). Returned
model identity is recorded separately from requested model configuration.
Provider usage and writer usage remain separate; absent TypeSafe prices are
unknown. Legacy numeric telemetry totals do not aggregate these providers and
must not be interpreted as measured zero cost or savings.
