# Versioned intent model review cascade

`review_routing: intent-cascade-v1` enables this route with `llm_provider: typesafe`,
`typesafe_api_key`, `openai_api_key`, private `intent_model_pin`, private `intent_policy`,
and `llm_failure_policy: block`. Remove
`model`, `model_fallback`, and `codex_model` overrides: the versioned router owns
those choices. The default remains `legacy` until the caller migration is reviewed.

The intent model evaluates routing risk and independently assesses source-bound
policy candidates in separate stages. Its typed probabilities choose the next
reviewer; they do not authorize merging or replace
the mandatory native, deterministic or dependency audit gates.

| Evidence | Reviewer | Reasoning effort |
|---|---|---|
| Complete concentrated low-risk assessment and low independent hazard signals | `gpt-6-luna` | `max` |
| Ordinary uncertainty, structural complexity or engineering gaps | `gpt-6.1-sol` | `xhigh` |
| Sensitive paths, significant deterministic defects, high-confidence defects, unavailable or incomplete triage | `gpt-6-sol` | `max` |

The caller supplies the private routing rubric, critical-path rules, thresholds,
and engineering criteria. Public code validates the versioned schema and records
only a policy hash reference. No default rubric is packaged. This is not an
empirically validated recall claim; validate on representative labeled changes.
Incomplete generator context cannot yield a successful review. A cheap review
that fails or finds a substantial defect escalates. A medium review that fails or
finds a critical/high defect escalates. A later clean answer cannot erase an earlier
finding. Failed strongest review remains a failed review.

Source hashes are checked around model work. intent model receives redacted bounded state;
redacted, unsupported, oversized, deleted or unavailable source takes the stronger
review path and retains incomplete policy status. Even a clean strongest-model
answer cannot complete missing policy coverage. Deep/nightly inventories currently
remain unsupported by this profile and cannot pass as complete cascade reviews.

`REVIEW_ROUTING.json` and `PACK_SUMMARY.json` record the actual model, decisions,
source hashes, neutral policy/calibration references, review coverage and separate
cost calls. Each provider attempt is itemized by stage. Returned model identity is
required; the requested model is never substituted for missing response identity.
The downloadable artifact and GitHub summary/comment expose the separate intent model and
OpenAI estimates. Unknown usage or an unknown price remains null. Reasoning tokens
are already included in output tokens and are never added a second time.

Prices are a dated standard-tier token-rate estimate, not a billing record. They
exclude cache-write fees and other charges. Long-context and cached reads use their
distinct published rates. A failure without returned usage can still have incurred
cost: the total stays unknown and the known subtotal remains available.

P0–P3 retain their meanings. P4 is informational/advisory and does not block the
default P1 threshold. Confidence remains independent from severity. The engineering
excellence dimensions are source review signals with explicit unassessed states;
they are not verified organization-wide scores or replacements for security gates.

Verified 2026-10-20: [OpenAI prices](https://developers.openai.com/api/docs/pricing),
[reasoning parameters](https://developers.openai.com/api/docs/guides/reasoning),
[TypeSafe models and prices](https://docs.typesafe.ai/models), and
[TypeSafe confidence](https://docs.typesafe.ai/confidence).

OpenAI confirms GPT-5.3-Codex deprecation on October 1, 2026 with shutdown on April 1,
2027. Sol6 and Sol6.1 currently share $2 input / $10 output per million tokens for
standard short context; their cached-input prices differ. A claim of threefold
per-task savings requires workload measurements. intent model's typed outputs and
non-generative role are documented; advertised speed/cost multiples cannot establish
this pipeline's latency, recall or bill.

Supply the provider pin from a private Actions variable or secret. Public evidence
uses only an intent-model label and a short pin hash. Set `intent_price_profile:
typesafe-input-20261020` only for the reviewed pin bound to that dated published
rate; an absent/unknown profile leaves that price unknown. Earlier GitHub history
is retained; neutral naming and private configuration apply going forward.
