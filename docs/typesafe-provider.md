# TypeSafe candidate assessment configuration

The full-engine action accepts `llm_provider: typesafe` for its typed candidate
assessment path. Supply both `typesafe_api_key` and `openai_api_key` through GitHub
secrets. TypeSafe assesses candidates; the OpenAI key funds the writer and fallback.
Both keys are held as secret configuration values. `typesafe_model` defaults to the pinned
`jev-1.13.0`; mutable aliases and incomplete version strings are rejected.

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

The packaged `typesafe_policy.POLICY` owns the risk questions, severity/category
choices and confidence gates. NOUL answers retain probabilities; CHOICE answers
retain the selected option, full `probabilities` distribution and provider-reported
`confidence`. Missing policy or an uncertain/incomplete decision cannot produce a
successful empty review. This candidate does not supply calibrated security policy;
that module must be delivered and independently reviewed before TypeSafe adoption.

For emitted findings, the OpenAI writer receives fixed verdicts and evidence. It
may return only the matching finding IDs, explanation and recommendation. Code
retains the original severity, category, source range, evidence hashes and typed
reason; extra, missing or verdict-changing fields refuse the writer output.
The writer request stays pinned to `gpt-5.3-codex`. A response may report that
exact name or the same family with a valid `YYYY-MM-DD` snapshot suffix; artifacts
retain the actual returned identifier. Preview names and other model families
are refused. Snapshot acceptance is a compatibility rule, not proof of a live
provider response or model pricing.
Existing independent P0/P1 corroboration guardrails still apply after assessment.

`TYPESAFE_REVIEW.json` retains the assessment and final completion/failure state
and is included in the artifact manifest. The pack summary retains typed assessment
metadata even when the generator fallback supplies the final review. Returned
model identity is recorded separately from requested model configuration.
Provider usage and writer usage remain separate; absent TypeSafe prices are
unknown. Legacy numeric telemetry totals do not aggregate these providers and
must not be interpreted as measured zero cost or savings.
