# Reintroduce Jev routing without changing the security reviewer

This change adds an opt-in `intent-shadow-v1` mode on the **release/v1.3.x**
scanner lineage. `main` is a separate managed bridge and is not the scanner
used by the direct Omar workflows. The legacy route remains the default. No
workflow is enabled, consumer pin advanced, or deployment changed by this PR.

## What failed, and what this change addresses

The existing intent integration combines two different contracts:

1. A small typed triage request proposes a generator tier.
2. An independent security-policy request asks risk, severity and category for
   every source candidate. Incomplete/malformed policy answers fail the review,
   even if the generator returns a clean result. Only specifically classified
   uncertainty can defer to a verified deep review.

A failure of the second contract is not proof that Jev cannot route. Conversely,
a concentrated routing answer is not proof that code is safe. Separating them
allows the routing signal to be measured while retaining the existing real
OpenAI review and deterministic gates.

Prior repairs already in this branch include:

- [#122](https://github.com/Sentinelayer-AIdenID/sentinelayer-v1-action/pull/122):
  accept distributions whose sums differ from one only by the documented
  hundredth-rounding envelope. Do not remove finite/range/label validation.
- [#123](https://github.com/Sentinelayer-AIdenID/sentinelayer-v1-action/pull/123)
  and [#124](https://github.com/Sentinelayer-AIdenID/sentinelayer-v1-action/pull/124):
  narrowly distinguish uncertain policy answers from missing/invalid evidence,
  and retain source-bound findings.
- [#134](https://github.com/Sentinelayer-AIdenID/sentinelayer-v1-action/pull/134):
  source inventory and dependency-lock evidence. Closed #127 is not evidence
  that the original tests/lockfile coverage problem is still unimplemented.

The baseline tests reproduce refusal on malformed/missing policy answers and
source-coverage failures. This PR does not claim to reproduce a historical paid
provider outage or to recover the private production rubric. It does not relax
`intent-cascade-v1` policy adjudication.

## Execution contract

| Stage | Shadow behavior |
| --- | --- |
| Source | Verify bounded complete source/diff and privacy before providers; recheck around calls |
| Jev | One typed routing request per partition; validate exact model identity, questions, finite values, complete answer set and distributions |
| Proposal | Preserve the existing low/mid/deep proposal as advisory evidence only |
| Actual reviewer | Exactly one `openai/gpt-6.1-sol` call path at `xhigh`, with response model identity validation; no cheaper fallback |
| Intent security policy | Not run; `complete=false`, `status=not_run`, `required_for_gate=false` |
| Gate | Existing native checks, deterministic findings and actual Sol findings; intent advice cannot suppress a P0/P1 |
| Jev outage/malformed answer | Record bounded reason and unavailable advice; verified source still receives fixed Sol review |
| Source/privacy gap or failed Sol | Review remains incomplete/failed; no invented successful inference |
| Spend | Itemize actual attempted calls and returned usage; unknown usage remains unknown, never zero |

The existing full-source planner and conservative preflight ceiling are reused.
The forecast still reserves the larger cascade envelope (including unused tiers
and a policy call), so it can overestimate shadow spend. This is deliberate for
initial safety; it is not a bill or a savings claim. A triage call with unknown
cost stops further full-source partitions under the existing budget rule. PR-diff
review can finish its fixed reviewer with an explicitly unknown total.

`REVIEW_ROUTING.json` records `mode`, `decision_authority`, `proposed_route`,
`triage_failure_reason`, source hashes, actual route identity/attempt/outcome and
cost ledger. Whole-source evidence retains those fields per partition in
`SOURCE_SCOPE.json`. A failed triage emits no accepted answer scores or proposed
route. The public model reference remains hashed; provider exception bodies,
credentials and private rubric text are not copied into routing evidence.

## Report compatibility

The existing comment renderer, `sentinelayer:omar-gate:` marker, status header,
Gate/Policy/Scan fields, synopsis, severity table, Top Findings, Fix,
Apply Fix and deterministic snapshot remain. The existing Review chain gains
an explicit shadow/advisory row, policy **not run**, and separate **proposed route
(not executed)**. Its collapsed defense explanation describes retained Sol
severity rather than incorrectly promising a corroboration downgrade. This
scanner reports the actual generator in its LLM and Route fields; the separate
consumer's `API-PATH` decoration is not changed by this PR. Native
check names and P0/P1 blocking policy do not change. Forecast/usage-estimate cost
labels retain the cascade's honest distinction from a provider invoice.

## Controlled consumer activation

After exact-head review and CI, update an explicitly approved consumer's action
pin to the immutable reviewed commit. Keep one active producer for each required
check name; do not enable the archived Jev and direct workflow simultaneously.
Replace its routing/provider inputs with the following, retaining its existing
secret boundary, native gates, evidence binding and release-producer rules:

```yaml
review_routing: intent-shadow-v1
llm_provider: typesafe
typesafe_api_key: ${{ secrets.TYPESAFE_API_KEY }}
openai_api_key: ${{ secrets.OPENAI_API_KEY }}
intent_model_pin: ${{ secrets.INTENT_MODEL_PIN }}
intent_policy: ${{ secrets.INTENT_POLICY }}
# Only set this for the reviewed pin bound to that published price profile.
intent_price_profile: typesafe-input-20261020
model: gpt-6.1-sol
model_fallback: gpt-6.1-sol
codex_model: gpt-6.1-sol
use_codex: "false"
codex_only: "false"
sentinelayer_managed_llm: "false"
llm_failure_policy: block
fork_policy: block
```

An absent key, invalid model pin or invalid policy refuses configuration; no key
or private policy is needed to run the offline regression tests. The integration
uses the existing TypeSafe HTTP transport and requires no new SDK. Rollback is
an immutable action pin plus the previous `legacy` direct OpenAI settings. Do
not rewrite or delete old evidence.

## Promotion to active routing

Shadow is a rollout stage, not a claim that active routing is validated. To
promote, evaluate the existing `intent-cascade-v1` with the **same** frozen source
corpus and private policy version, then review the consumer change separately.

1. Build a labeled corpus covering clean changes and P0/P1 defects across auth,
   delegation, receipts, CI credentials, infrastructure, migrations and ordinary
   UI work; keep a holdout set that was not used to tune the questions.
2. Label intended task/scope separately from defect severity. Split multi-part
   questions into atomic source-supported judgments. A model's confidence is a
   summary of its probability distribution, not independent evidence of safety.
3. Record per-head source coverage, proposal, actual returned model, findings,
   native test results, latency, actual usage, unknown costs and refusal reason.
   A clean Sol answer is not ground truth; independent review/reproduction owns
   defect labels. No manual acceptance should erase a deterministic P0/P1.
4. Measure high-severity recall and uncertainty/coverage failure rates by risk
   surface, false positives, escalation frequency, P95 latency and observed cost.
   Report denominators and confidence intervals; do not tune to a global average.
5. Predeclare acceptance thresholds and a rollback trigger with the security
   owner. Exercise missing inputs, outages, changed source, unsupported files and
   wrong response identities before any routing authority is granted.

The inactive per-span policy must be evaluated separately before the active
cascade can rely on it. A proposed cheaper tier and one passing shadow run are
insufficient to activate it or to claim cost savings.

## Primary references checked 2026-11-04

- [TypeSafe introduction](https://docs.typesafe.ai/introduction): typed atomic
  questions; decompose decisions requiring extended reasoning.
- [TypeSafe confidence](https://docs.typesafe.ai/confidence): Choice confidence is
  derived from its probabilities; thresholds depend on domain risk and measured
  performance, not a universal correctness guarantee.
- [TypeSafe API](https://docs.typesafe.ai/api/system-one): current request/answer
  contract. Retain explicit model version rather than a moving alias.

These documents explain the design; offline fixtures establish only transport,
routing and failure semantics. Live model quality, real costs, deployment and
production calibration remain to be demonstrated with the approved credentials.
