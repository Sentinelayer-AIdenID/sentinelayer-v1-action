# SentinelLayer Action Configuration

SentinelLayer (Omar Gate) is configured entirely via GitHub Action inputs (see [`action.yml`](../action.yml)). Inputs are passed via `with:` in your workflow.

**Notes:**
- GitHub Actions provides inputs as strings; the action parses booleans (`true`/`false`) and numbers automatically.
- With the default `openai` provider, an absent key permits deterministic-only operation. Explicit non-OpenAI providers require their provider key. TypeSafe requires both `typesafe_api_key` and `openai_api_key`; Sentinelayer-managed proxy mode supports `openai` only.

---

## Inputs At A Glance

### Authentication

| Input | Type | Default | Purpose |
|---|---|---|---|
| `github_token` | secret string | `""` | GitHub token for PR comments, Check Runs, and fetching diffs. Use `${{ secrets.GITHUB_TOKEN }}`. |
| `publish_github` | bool | `true` | Publish PR comments and Check Runs. Set `false` only for internal probe runs that publish a separate canonical gate. |
| `openai_api_key` | secret string | `""` | OpenAI API key (for Codex CLI + Responses API); also required for the writer and generator fallback with `llm_provider: typesafe`. |
| `typesafe_api_key` | secret string | `""` | TypeSafe API key; required with `llm_provider: typesafe`. |
| `anthropic_api_key` | secret string | `""` | Anthropic API key (for Claude models). |
| `google_api_key` | secret string | `""` | Google AI API key (for Gemini models). |
| `xai_api_key` | secret string | `""` | xAI API key (for Grok models). |
| `sentinelayer_token` | secret string | `""` | SentinelLayer token for managed LLM proxy auth and Tier 2/3 dashboard uploads. |

### LLM Provider Settings

| Input | Type | Default | Purpose |
|---|---|---|---|
| `llm_provider` | string | `openai` | LLM provider: `openai`, `anthropic`, `google`, `xai`, `typesafe`. |
| `model` | string | `""` (automatic) | Primary API model: resolves to `gpt-4.1-mini` for legacy providers, exactly `gpt-5.3-codex` for TypeSafe. |
| `model_fallback` | string | `""` (automatic) | API fallback model: resolves to `gpt-4.1-mini` for legacy providers, exactly `gpt-5.3-codex` for TypeSafe. |
| `intent_model_pin` | string | `""` | Required private `provider-MAJOR.MINOR.PATCH` version; mutable aliases rejected. |
| `intent_policy` | string | `""` | Required private JSON review profile; missing or invalid profiles refuse typed review. |
| `typesafe_timeout` | int | `30` | TypeSafe request timeout in seconds, 1–120 inclusive. |
| `typesafe_max_candidates` | int | `50` | Complete source candidate budget, 1–200 inclusive. Exceeding it requires fallback; candidates are not silently truncated. |
| `typesafe_fallback` | bool | `true` | Allow separate `gpt-5.3-codex` generator review when the typed stage cannot complete. |
| `sentinelayer_managed_llm` | bool | `false` | Route OpenAI API path through Sentinelayer-managed proxy. If false, auto-enables when `openai_api_key` is empty and `sentinelayer_token` is set. |
| `use_codex` | bool | `true` | Enable Codex CLI for deep agentic audit. Falls back to API if Codex fails. |
| `codex_only` | bool | `false` | Use Codex CLI as the only legacy LLM path. Disables API fallback; rejected for TypeSafe. |
| `codex_model` | string | `gpt-5.3-codex` | Model passed to Codex CLI `--model` flag; TypeSafe requires exactly this value. |
| `codex_timeout` | int | `300` | Timeout in seconds for Codex CLI execution. |
| `max_input_tokens` | int | `100000` | Maximum LLM context budget in tokens. Lowering reduces cost; files get truncated or skipped. |
| `llm_failure_policy` | string | `block` | What happens when LLM fails: `block` (fail-closed), `deterministic_only` (fall back to regex), `allow_with_warning`. |

### Scan Settings

| Input | Type | Default | Purpose |
|---|---|---|---|
| `scan_mode` | string | `pr-diff` | `pr-diff` (fast, scans changed files), `deep` (full repo), `nightly` (scheduled). |
| `pr_number` | int | `""` | Target PR for `workflow_dispatch` scans. Ignored when a pull request event supplies the PR number. |
| `policy_pack` | string | `omar` | Policy pack identifier (used for fingerprinting and deduplication). |
| `policy_pack_version` | string | `v1` | Policy pack version (included in finding fingerprints). |
| `run_harness` | bool | `true` | Run the fail-closed dependency audits and portable security harness. Set `false` only to opt out explicitly. |

### Gate Control

| Input | Type | Default | Purpose |
|---|---|---|---|
| `severity_gate` | string | `P1` | Finding threshold: `P0`, `P1`, `P2`, or `none`. Required dependency-audit integrity can still block at every setting. |
| `fork_policy` | string | `block` | Fork PR handling: `block` (fail closed), `limited` (deterministic only, no LLM), `allow` (full scan). |
| `run_deterministic_fix` | bool | `false` | Reserved for future autofix (currently no-op). |
| `run_llm_fix` | bool | `false` | Reserved for future LLM fix patches (currently no-op). |
| `auto_commit_fixes` | bool | `false` | Reserved for future auto-commit (currently no-op). |

### Cost Control & Rate Limiting

| Input | Type | Default | Purpose |
|---|---|---|---|
| `max_daily_scans` | int | `20` | Maximum scans per PR head SHA per 24 hours. `0` = unlimited. |
| `min_scan_interval_minutes` | int | `0` | Cooldown between scans for the same PR head SHA. `0` = disabled. |
| `rate_limit_fail_mode` | string | `closed` | On GitHub API errors during rate limit checks: `closed` (require approval) or `open` (skip enforcement). |
| `require_cost_confirmation` | float | `5.00` | If estimated LLM cost exceeds this USD amount, require approval before scanning. |
| `approval_mode` | string | `pr_label` | How to approve high-cost scans: `pr_label`, `workflow_dispatch`, `none`. |
| `approval_label` | string | `sentinelayer:approved` | PR label that approves a high-cost scan (when `approval_mode=pr_label`). |

### Telemetry

| Input | Type | Default | Purpose |
|---|---|---|---|
| `telemetry_tier` | int | `1` | `0`=off, `1`=anonymous aggregates, `2`=repo metadata, `3`=full artifact upload. |
| `telemetry` | bool | `true` | Enable anonymous telemetry (set `false` to opt out). |
| `share_metadata` | bool | `false` | Explicit opt-in to Tier 2 metadata (overrides `telemetry_tier`). |
| `share_artifacts` | bool | `false` | Explicit opt-in to Tier 3 artifact upload (overrides `telemetry_tier`). |
| `training_opt_in` | bool | `false` | Optional training consent flag; it does not define selected AI-provider storage or retention. See data boundaries below. |

---

## Authentication (Detailed)

### `github_token` (recommended)

Used to:
- Post an idempotent PR comment (updates the same comment on re-runs)
- Create a GitHub Check Run with inline annotations (up to 50)
- Fetch PR diff and changed files for `scan_mode=pr-diff`

If `github_token` is not provided, the action also checks the `GITHUB_TOKEN` environment variable. Without it, the action cannot fetch PR diffs and will fail in `pr-diff` mode.

Recommended permissions:

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write
  id-token: write    # Required for managed LLM proxy and OIDC telemetry (Tier 2+)
```

### LLM API Keys

Omar Gate supports multiple LLM providers. Pass the key for your chosen provider:

| Provider | Input | Secret Name | Models |
|---|---|---|---|
| OpenAI | `openai_api_key` | `OPENAI_API_KEY` | `gpt-4.1`, `gpt-4.1-mini`, `gpt-4o`, `gpt-5.3-codex` (Codex CLI) |
| Anthropic | `anthropic_api_key` | `ANTHROPIC_API_KEY` | `claude-opus-4-6`, `claude-sonnet-4-5` |
| Google | `google_api_key` | `GOOGLE_API_KEY` | `gemini-2.5-pro`, `gemini-2.5-flash` |
| xAI | `xai_api_key` | `XAI_API_KEY` | `grok-3`, `grok-3-mini` |
| TypeSafe + OpenAI | `typesafe_api_key` + `openai_api_key` | `TYPESAFE_API_KEY` + `OPENAI_API_KEY` | `pinned provider version` candidate assessment + `gpt-5.3-codex` writer/generator |

**OpenAI example:**
```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

**Anthropic example:**
```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    llm_provider: anthropic
    model: claude-sonnet-4-5
```

**No API key (deterministic-only):**
```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    # No LLM key — only deterministic scanners run (secrets, config, CI/CD, EQ rules).
    # No AI analysis, no Codex CLI. Free and fast.
```

### Sentinelayer-Managed Proxy (server-side key)

Use this when you want scans to run without each repository owner managing an OpenAI key.

```yaml
- uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    sentinelayer_managed_llm: ${{ secrets.OPENAI_API_KEY == '' && secrets.SENTINELAYER_TOKEN != '' }}
```

Requirements:
- `permissions: id-token: write` in the workflow.
- Sentinelayer API must expose `POST /api/v1/proxy/llm`.
- API runtime must have `SENTINELAYER_TOKEN` and `MANAGED_LLM_OPENAI_API_KEY` configured.

### `sentinelayer_token` (optional)

JWT from the SentinelLayer OAuth flow (`POST /api/v1/auth/github/callback`). Enables dashboard uploads for Tier 2/3. **Not a GitHub PAT.**

For Tier 2+, prefer OIDC (see [Telemetry](#telemetry-detailed)) — it requires no long-lived secret.

---

## Scan Settings (Detailed)

### `scan_mode`

| Mode | What It Does | When To Use |
|---|---|---|
| `pr-diff` | Includes PR diff in LLM context, prioritizes changed files. | Every PR (default). |
| `deep` | Full repo scan, prioritizes hotspots and source coverage. | Release gates, audits. |
| `nightly` | Same as `deep`, may use different prompt strategy as product evolves. | Scheduled nightly crons. |

### Codex CLI vs LLM API

Legacy providers have two LLM execution paths. TypeSafe uses the separate [typed review flow](#typesafe-review) before any generator fallback:

1. **Codex CLI** (`use_codex: true`, default) — Runs `codex exec` with a structured prompt. The CLI has its own sandbox, conversation memory, and can traverse the codebase. Best for deep agentic audit. Requires `openai_api_key`.

2. **LLM API** (fallback) — Sends a single bounded context (diff + prioritized files + codebase snapshot) to the Responses API or Messages API. Faster, cheaper, works with any provider.

**Flow:**
```
use_codex=true → try Codex CLI → success? done : codex_only=true? fail : try API
use_codex=false → skip Codex → try API
```

When `codex_only: true`, the API fallback is disabled. If Codex fails, the `llm_failure_policy` determines the outcome.

### `model` / `model_fallback`

These control the **LLM API path** (not Codex CLI, which uses `codex_model`).

- `model`: Primary API model. An empty action input selects `gpt-4.1-mini` for legacy providers. Used when Codex is disabled or unavailable.
- `model_fallback`: Secondary API model. An empty action input also selects `gpt-4.1-mini` for legacy providers. Used if the primary model fails, hits rate limits, or exceeds quota.
- For TypeSafe, empty/omitted `model` and `model_fallback` resolve to exactly `gpt-5.3-codex`; `codex_model` must also be exactly `gpt-5.3-codex`. Other explicit values fail configuration validation. The writer independently uses this fixed model, with its response accepting only the exact model name or a valid dated `gpt-5.3-codex-YYYY-MM-DD` version.

```yaml
with:
  model: gpt-5.3-codex
  model_fallback: gpt-4.1-mini
```

### TypeSafe review

Set `llm_provider: typesafe` and provide both `typesafe_api_key` and `openai_api_key`. `intent_model_pin` requires a private pinned provider version and accepts only pinned `provider-MAJOR.MINOR.PATCH` names. `codex_only: true` and `sentinelayer_managed_llm: true` are invalid with this provider.

Supply `intent_policy` from a private Actions secret. It must be a complete JSON
profile with schema `omargate.private-review-policy.v1` and the `routing`, `typed`
and `generator_instructions` sections. Routing carries domain descriptors,
questions, critical-path tokens/groups and thresholds; typed assessment carries
criteria, support floors, templates, instructions and policy/calibration identity.
Public source validates shapes and bounded values without supplying deployment
rubric data. Profiles are bounded to 64 KiB, reject duplicate fields and invalid
probabilities, and are never printed in validation errors. Public evidence uses
neutral hash references. Model pins and profiles can rotate without an Action
source release. Obtain a reviewed private profile from the operator.

`review_routing: intent-cascade-v1` uses the [cascade contract](intent-cascade.md).
Its independent policy stage is mandatory; incomplete coverage cannot be replaced
by a clean strongest-model answer. It also preserves substantive uncorroborated
P0/P1 findings. The three-stage typed/writer descriptions below describe the
legacy compatibility profile, not those cascade exceptions.

**Experimental status:** This configuration does not establish empirical recall, calibrated security quality, independent security/release approval or adoption approval. Use an independently approved action revision before enabling this provider.

The stages have separate responsibilities:

1. **Source-bound candidate assessment:** Complete supported changed files are divided into consecutive spans of at most 40 lines. Candidate identity binds the file, start/end lines, exact source hash and evidence hash. Source bytes are verified before and after assessment; supplied diff head/context lines are checked against source before assessment, while removed lines remain unverified patch context. The intent model returns typed risk probabilities and severity/category choices; source text is untrusted data. Private operator policy owns completeness checks, thresholds, labels, finding text and remediation templates.
2. **Fixed-verdict explanation:** When findings exist, `gpt-5.3-codex` may explain each exact finding ID once. The response may replace only message/recommendation prose; it cannot change severity, category, source span, evidence, typed reason or finding count. Writer failure preserves the policy-owned typed verdict and template text with a warning and bounded failure metadata; it does not erase the findings or automatically require generator review.
3. **Generator fallback:** With `typesafe_fallback: true`, an unsuccessful typed stage runs the separate OpenAI `gpt-5.3-codex` review: Codex CLI first when `use_codex: true`, then the API if necessary; `use_codex: false` selects the API directly. `use_codex` does not disable the fixed-verdict writer.

The typed inventory currently supports `pr-diff` with complete, nonempty UTF-8 changed files from the ingest inventory. Each file is limited to 1,000,000 bytes; binary/deleted/renamed/copied or otherwise unsupported source/diff forms require fallback. The supplied diff is bounded to 100,000 UTF-8 bytes; typed state to 24,000 bytes and the state/questions request to 48,000 bytes. Source, state and candidate budgets are completeness checks, not permission to silently truncate coverage. The default candidate cap is 50 (configurable 1–200) and the default request timeout is 30 seconds (configurable 1–120).

**Completeness and failure behavior:**

- Uncertain or malformed answers, missing coverage, invalid policy bindings, unsupported scope and source-integrity failures do not establish successful typed review. Source-integrity failure rejects unverified typed output. Generator fallback or the configured `llm_failure_policy` follows; `block` is the default failure policy.
- A valid partial policy decision carries confirmed findings plus `unresolved_candidates`. Confirmed findings are passed into fallback composition rather than discarded merely because other candidates remain unresolved. Each lane is guardrailed separately before composition; a stronger guarded fallback can win an exact collision while retaining bounded typed alternate provenance (see below).
- Any candidate span resolved clean requires generator confirmation, even when other spans emitted findings. For a complete policy decision, a nonempty `generator_required_clean_candidates` list returns `typesafe_clean_requires_generator`. That list contains verified inventory candidate IDs that emitted neither a finding nor an unresolved decision. Partial decisions retain their incomplete reason. Transport success, zero candidates, a finding elsewhere or the policy/calibration identifier alone does not establish confirmed source coverage.
- Typed P0/P1 in `availability`, `infrastructure`, `race-condition` or `other-security` requires generator review and remains P2 under the current typed guardrails. A complete policy decision returns `typesafe_category_requires_generator` when no clean-candidate condition took precedence. If both trigger sets exist, `typesafe_clean_requires_generator` wins and both `generator_required_clean_candidates` and `generator_required_categories` remain in the assessment.
- `typesafe_fallback: false` disables generator fallback. It does not upgrade an incomplete, typed-clean or unsupported blocking-category assessment to successful review. Keep `llm_failure_policy: block` for fail-closed operation.

`TYPESAFE_REVIEW.json` retains candidate/source hashes, question bindings, typed answers, policy/calibration identifiers, unresolved reasons and writer/failure metadata when a run directory is provided. `policy_decision_complete` and `typed_assessment_complete` describe policy coverage; `complete` and `review_complete` describe the typed stage's accepted result. A policy-complete all-clean or mixed clean/finding decision can therefore still have `review_complete: false` pending generator review. `generator_required_clean_candidates` and `generator_required_categories` identify the respective trigger sets; an incomplete policy decision separately retains `unresolved_candidates` and its decision reason. The existing `llm_*` outputs describe the resulting review path; inspect the typed assessment and fallback chain to distinguish stages.

**Composition, final merge and provenance:**

- Typed and generator findings are independently guardrailed before composition. A merged record is not sent back through the typed trust path. Generator JSON cannot supply `typed_candidate`, `source` or `rule_id`; both API and Codex parsers reject these unknown fields. Typed binding validation checks structure, while its origin depends on this parser boundary and the verified typed inventory.
- Composition resolves exact source-bound overlaps by normalized path, complete start/end span and category. Only bound typed candidates receive typed aliases; generator labels are not granted that vocabulary. Final merge also includes `line_end` in its collision key, so otherwise matching findings with different end lines remain separate. Final categories use the typed alias map for bound typed findings, the exact producer map for reviewed non-LLM rows, and otherwise the normalized raw category.
- A collision selects the strongest already-guardrailed severity (`P0`, `P1`, `P2`, then `P3`), rather than the first input. Trust is a severity tie-break only: reviewed producer, source-bound typed candidate, other deterministic/harness/system, then generator. Remaining ties use finite confidence and stable content identity; final finding order is deterministic. This does not restore an uncorroborated P0/P1 that guardrails already downgraded to P2.
- The winner remains authoritative at the top level. A non-typed winner does not inherit `typed_candidate`, `typed_verdict`, `typed_reason` or `typed_recommendation`. Alternate `collision_provenance` stores selected identity/verdict metadata, prioritizing typed records, with at most eight alternate records. `collision_provenance_truncated: true` signals omitted alternates or an inherited truncation; it is not a complete archive of all messages, snippets or evidence. Consult `TYPESAFE_REVIEW.json` and original independent evidence for the typed assessment.

These documented source contracts do not demonstrate empirical model recall, calibrated security quality, or independent approval to adopt TypeSafe as the gate. Source review, runtime fixes, independent security review and adoption evidence remain separate.

### `.sentinelayerignore`

The action respects a `.sentinelayerignore` file at repo root (gitignore-style patterns). This is the primary control for reducing scan scope in monorepos or large repositories.

Example `.sentinelayerignore`:

```text
node_modules/**
dist/**
**/*.min.js
vendor/**
docs/generated/**
```

---

## Gate Control (Detailed)

### `run_harness` and dependency-audit evidence

When `run_harness` is `true`, Omar Gate requires a complete, recognized audit result
for each applicable ecosystem. Bounded no-follow discovery rejects symlink-ambiguous
trees. Independent nested npm projects are audited individually; nested Python and
Cargo layouts remain indeterminate rather than being claimed absent.

npm requires `package.json` plus `package-lock.json` or `npm-shrinkwrap.json` at
lockfile version 2 or 3 per project. A strict dependency-free manifest without a lock
records an empty declared graph. Existing locks must still validate and be audited.
The 32-project limit is checked before registry commands. Project input hashes are
checked after every audit and again after the full set; changed inputs remain
blocking while the earlier observed result is retained against its input hash.
Workspaces, peer/peer-optional dependencies, linked packages,
mixed registries, non-HTTPS sources, and credentialed or missing resolved URLs are
unsupported. All packages
must resolve through the exact canonical `https://registry.npmjs.org` origin. Custom
or private registries, localhost, and IP-literal origins stop before spawn. Omar Gate
passes only the canonical origin to npm and never forwards registry credentials. The
output dependency count must match the validated lock and any reported npm
vulnerability produces vulnerable evidence. Enabling the harness authorizes npm
audit to send the validated copied lock graph, including package names and versions,
to that public npm registry endpoint.

Python's supported input is a nonempty root `requirements.txt` containing only exact
`name==version` pins, with no other Python dependency manifest. The output must match
the normalized names and exact versions. This is evidence for declared direct pins
only; `--no-deps` does not prove their transitive closure. **Metadata egress:** with
the harness enabled, pip-audit may send those pinned names and versions to its public
vulnerability service. Repository or inherited pip routing—including alternate
indexes or `find-links` sources—makes the input unsupported and stops before spawning; use
`run_harness: false` to opt out instead of silently redirecting private metadata.
`pyproject.toml`, `Pipfile.lock`, Poetry, uv, PDM, `pylock.*`, alternate
`requirements-*.txt`, and `requirements/*.txt` inputs are conservatively unsupported
and cannot be ignored alongside `requirements.txt`; `requirements*.in` and
`requirements/*.in` source manifests are handled the same way.

Rust requires `Cargo.toml`, a valid `Cargo.lock`, and a cargo-audit result whose
dependency count matches that copied lock. A separately provisioned, version-pinned
`cargo-audit` executable is required. The composite action does not install it, so an
applicable Rust audit fails closed until the workflow provisions the reviewed version.

Dependency-audit evidence schema `1.2` carries an exact coverage-scope map:
`package_lock_registry_graph` for npm, `declared_direct_pins` for pip, and
`cargo_lock_packages` for Cargo. The gate rejects missing, renamed, or additional
scope entries before evaluating the finding-severity threshold.
The required `npm_projects` object contains `discovered_manifests` and `audits`.
Every declared manifest needs one project-local record with raw input hashes,
review mode, stable-input flag and outcome. Missing, duplicate, escaping or
contradictory records refuse a clean aggregate. Both idempotency contract tokens
rotate with this schema, preventing replay of an older root-only audit receipt.

Audit subprocesses use isolated home, config, cache, and temporary directories
outside the scanned repository. They do not inherit provider credentials,
GitHub/OIDC tokens, `INPUT_*` values, or repository-controlled tool configuration.
Only validated credential-free proxy origins, bounded `NO_PROXY` entries, and
copies of CA material located outside the workspace may be forwarded. npm executes
the canonical Node binary directly against private copies of the validated manifest
and lockfile, so it does not load a repository `.npmrc` or an npm command wrapper.
All supported audit inputs are copied into private scratch space. These boundaries
isolate local configuration and credentials; they do not make live advisory audits
offline. Teardown is bounded and the complete subprocess tree must be proven empty.
If that proof fails, fixed containment-error evidence is emitted and both private
tool-state and copied-input scratch are retained rather than deleted beneath a child
whose death is unproven.

Timeouts, missing tools or lockfiles, unsafe inputs, malformed or unrecognized JSON,
and contradictory exit/result states are indeterminate and block before the normal
severity threshold is evaluated. This also applies to `severity_gate: none`.
`run_harness: false` is the only explicit opt-out from the audit-evidence requirement.

### `severity_gate`

Defines the minimum severity that blocks the merge:

| Gate | Blocks On | Use Case |
|---|---|---|
| `P0` | Only P0 (critical) | Permissive — only stops catastrophic issues |
| `P1` | P0 + P1 (critical + high) | **Recommended default** |
| `P2` | P0 + P1 + P2 (medium+) | Strict — catches more but may increase noise |
| `none` | No finding severity blocks | Report-only findings; required audit/LLM integrity checks still apply |

### `fork_policy`

Controls how fork PRs are handled:
- `block` (default): Fail closed — do not proceed.
- `limited`: Proceed with deterministic scanning only (no LLM, no API keys needed).
- `allow`: Full scan including LLM (use with care — requires `pull_request_target` with strict safeguards).

**Important:** GitHub does not provide secrets to workflows triggered from fork PRs under `pull_request`. Options:
- Skip forks: `if: github.event.pull_request.head.repo.fork == false`
- Use `pull_request_target` with workflow hardening.
- Use `fork_policy: limited` for free deterministic scanning on forks.

---

## Cost Control & Rate Limiting (Detailed)

### `max_daily_scans` and `min_scan_interval_minutes`

Rate limits are enforced using GitHub Check Run history for the PR head SHA:
- Pushing a new commit (new head SHA) resets the window.
- The limits apply to the Check Run named `Omar Gate` on that commit.
- `max_daily_scans: 0` disables the daily cap.
- `min_scan_interval_minutes: 0` disables the cooldown.

Every run requires fresh source-bound review evidence. The run key binds effective review settings, private configuration hashes, dependency-audit contract and UTC day. Remote check names, summaries and external IDs are not authenticated reusable receipts; no prior check can authorize a skipped run.

Rate limits use check history only to enforce cooldown and the rolling daily cap. A limit that prevents a fresh review returns a blocking result with artifacts and telemetry, including when `run_harness: false`. Wait for an allowed scan or adjust the rate-limit policy; skipped reviews cannot inherit a prior pass.

### `require_cost_confirmation`, `approval_mode`, `approval_label`

Before running AI analysis, Omar Gate estimates LLM cost from PR stats (file count, diff size, model pricing). If the estimate exceeds `require_cost_confirmation`, the run is blocked until approved.

**Approval modes:**
- `pr_label`: Requires the `approval_label` on the PR (needs `issues: read` permission).
- `workflow_dispatch`: Only allows runs triggered manually.
- `none`: Disables cost confirmation entirely.

---

## Telemetry (Detailed)

Telemetry is best-effort: upload failures **never** block the gate.

### Tiers

| Tier | Data Sent | Auth Required |
|---|---|---|
| 0 | Nothing | — |
| 1 | Anonymous aggregates (counts, timing, exit code) | None |
| 2 | Tier 1 + repo identity + finding metadata | OIDC or `sentinelayer_token` |
| 3 | Tier 2 + full artifact upload | Explicit opt-in + auth |

### Auth priority

1. **OIDC** (preferred for Tier 2+) — Requires `permissions: id-token: write`. No secret to rotate.
2. **`sentinelayer_token`** — JWT from SentinelLayer OAuth flow. For non-GitHub CI or when OIDC is unavailable.
3. **No auth** — Tier 1 only. **Never send a Bearer token for Tier 1** (if OIDC verification fails server-side, it causes a spurious 401 even though Tier 1 doesn't need auth).

### Consent resolution

- If you set `share_metadata`, `share_artifacts`, or `telemetry: false`, those explicit flags take priority.
- Otherwise, `telemetry_tier` controls behavior.

### OIDC configuration

Default audience: `sentinelayer`. Override with `SENTINELAYER_OIDC_AUDIENCE` env var.

```yaml
permissions:
  id-token: write
```

---

## False Positive Defense

Omar Gate checks deterministic evidence before LLM P0/P1 findings can retain blocking severity. Uncorroborated findings become P2, which is advisory at the default P1 gate; a P2 gate also blocks P2 findings. Fail-closed system findings are separate from model claims.

### Layer 1: AST & Syntax-Aware Deterministic Analysis

- **Python `eval()`/`exec()`**: Detected via `ast.parse()` + `ast.walk()`, not regex. Only actual call nodes are flagged — comments, strings, and documentation mentioning "eval()" are ignored.
- **JS/TS comment & string stripping**: Before regex matching, all comments (`//`, `/* */`) and string literals are blanked (line offsets preserved). Prevents flagging rule descriptions or documentation inside strings.
- **Entropy-based secret detection**: Multi-stage pipeline:
  1. **Identifier filter** (`_looks_like_non_secret_identifier`) — Skips `SCREAMING_SNAKE_CASE`, `snake_case` identifiers, file paths (containing `/` or `.`), and tokens with low character-class diversity.
  2. **Context filter** (`_likely_secret_context`) — Requires nearby secret keywords (`token`, `password`, `api_key`, `bearer`, etc.) unless the candidate has a known secret prefix (`ghp_`, `sk_live_`, `AKIA`, etc.).
  3. **Strong entropy threshold** — Candidates without secret context need Shannon entropy > 4.7 AND length >= 32 to be flagged, and only at P2 (advisory, non-blocking).
  4. **With secret context** — Flagged at P1 with confidence 1.0.

### Layer 2: Git-Aware Diff Scoping (Harness Noise Reduction)

- Only **added lines** in the PR diff can produce blocking (P0/P1) findings.
- **Removed lines** are scanned separately at P3 (advisory only) for manual triage.
- **Entropy matches in doc files** (`.md`, `.rst`, `.txt`) found in git history are dropped entirely.
- **Historical entropy findings** in git history are auto-downgraded to P3 with confidence capped at 0.45.

### Layer 3: LLM Guardrails (Corroboration Required)

Implemented in [`orchestrator.py:_apply_llm_guardrails()`](../src/omargate/analyze/orchestrator.py):

- **File validation**: LLM findings pointing to files not in the scanned diff/ingest are dropped.
- **Line clamping**: Line numbers are clamped to actual file bounds; hallucinated locations are discarded.
- **Typed-only producer binding**: For a validated TypeSafe candidate, corroborating non-LLM output must match an exact `(source, rule_id, emitted category)` entry in [`_REVIEWED_CORROBORATION_PRODUCERS`](../src/omargate/analyze/orchestrator.py). Missing/unknown rules, relabelled categories, generic infrastructure/quality/web rules and harness-health output do not supply typed corroboration. Producer labels are not authenticated by the typed alias map. For example, `(deterministic, SEC-016, auth)` is accepted for typed auth; the same category with a missing/unknown rule, or `SEC-016` relabelled `csrf`, is rejected.
- **Legacy LLM/Codex corroboration**: Any finding from the deterministic/harness stages can corroborate when the normalized file and exact emitted category match and its span intersects `[max(1, line_start - 5), line_start + 5]`. The typed producer allowlist does not restrict this existing scanner-rule eligibility. A model-controlled `line_end` does not expand the first-line window; this is not a return to an end-line-expanded window.
- **Validated TypeSafe corroboration**: A source-bound typed candidate may use its complete reviewed span expanded by 5 lines on each side. Its narrow category alias must match the canonical category of the exact reviewed producer tuple. For example, typed `ci-cd` can match `(harness, HARNESS-CICD-PERMS, ci_cd)`; legacy generator `ci-cd` does not gain that alias. This exception does not widen the legacy rule.
- **Unsupported typed blocking categories**: `availability`, `infrastructure`, `race-condition` and `other-security` require generator review and never obtain typed corroboration from the current producer map.
- **Missing corroboration**: LLM/Codex P0/P1 becomes P2 with confidence capped at 0.75 and explicit missing-corroboration metadata. This does not erase the policy-owned typed verdict from its provenance fields.

| Canonical TypeSafe candidate category | Typed labels (trimmed, lowercase; not producer authentication) |
|---|---|
| `auth` | `auth`, `auth_bypass`, `csrf` |
| `injection` | `injection`, `sql_injection`, `sql-injection`, `xss`, `rce`, `path_traversal`, `path-traversal`, `deserialization`, `log_injection`, `log-injection`, `xxe`, `ssti`, `prompt_injection`, `prompt-injection` |
| `ci-cd` | `ci-cd`, `ci_cd` |
| Other declared categories | Exact labels only: `crypto`, `secrets`, `privacy`, `ssrf`, `misconfig`, `exposure`, `supply-chain`, `availability`, `infrastructure`, `race-condition`, `other-security` (the last four still require generator review) |

### What this means in practice

| Finding Source | P0/P1 Blocks Merge? | Notes |
|---|---|---|
| Deterministic scanner | Yes | Regex, AST, config rules — high precision |
| Harness (dep audit, secrets-in-git) | Yes | Validated npm, pip-audit, cargo-audit, and gitleaks output |
| Legacy Codex/OpenAI with corroboration | Yes | Any deterministic/harness scanner rule with exact emitted category nearby confirms it |
| Source-bound TypeSafe with corroboration | Yes | Reviewed producer/rule/category tuple confirms the canonical typed category |
| LLM without compatible corroboration | **No** at the default P1 gate (downgraded to P2) | A P2 gate also blocks P2; exact collisions retain the strongest guarded severity |

### Handling persistent false positives

1. Check if the deterministic scanner rule needs refinement (open an issue or PR).
2. For entropy findings, verify whether the identifier filter or context filter should exclude the candidate.
3. For uncorroborated LLM P0/P1 findings, check the downgrade to P2 and the selected gate threshold. A P2 gate intentionally includes P2 findings.
4. Add patterns to `.sentinelayerignore` to exclude known-safe directories.
5. Add entries to `.gitleaks.toml` allowlist for known test fixtures.

---

## Outputs

The action sets these outputs (use in subsequent workflow steps via `${{ steps.<id>.outputs.<name> }}`):

| Output | Description |
|---|---|
| `gate_status` | `passed`, `blocked`, `bypassed`, `needs_approval`, `error` |
| `p0_count` / `p1_count` / `p2_count` / `p3_count` | Finding counts by severity |
| `run_id` | Unique run identifier |
| `estimated_cost_usd` | Actual-call token-rate USD estimate, or `unknown` for incomplete usage; not a bill. Inspect the cost ledger for each model and the known subtotal. |
| `idempotency_key` | Idempotency key used for dedupe |
| `findings_artifact` | Path to `FINDINGS.jsonl` |
| `pack_summary_artifact` | Path to `PACK_SUMMARY.json` |
| `ingest_artifact` | Path to `INGEST.json` (full ingest payload) |
| `codebase_ingest_artifact` | Path to `CODEBASE_INGEST.json` |
| `codebase_ingest_summary_artifact` | Path to `CODEBASE_INGEST_SUMMARY.json` |
| `codebase_ingest_summary_md_artifact` | Path to `CODEBASE_INGEST_SUMMARY.md` |
| `review_brief_artifact` | Path to `REVIEW_BRIEF.md` (if generated) |
| `audit_report_artifact` | Path to `AUDIT_REPORT.md` (if generated) |

---

## Artifact Locations

Default run directory: `.sentinelayer/runs/<run_id>/`

Override with environment variable: `SENTINELAYER_RUNS_DIR`

| Artifact | Format | Purpose |
|---|---|---|
| `FINDINGS.jsonl` | NDJSON | Machine-readable findings (all severities) |
| `REVIEW_BRIEF.md` | Markdown | Reviewer summary with priority table |
| `AUDIT_REPORT.md` | Markdown | Full detailed report |
| `PACK_SUMMARY.json` | JSON | Counts, checksums, run metadata |
| `CODEBASE_INGEST_SUMMARY.md` | Markdown | Deterministic codebase snapshot |
| `CODEBASE_INGEST_SUMMARY.json` | JSON | Same snapshot, machine-readable |
| `CODEBASE_INGEST.md` | Markdown | Bounded source index |
| `CODEBASE_INGEST.json` | JSON | Full ingest payload + file inventory |
| `ARTIFACT_MANIFEST.json` | JSON | SHA-256 hashes of all artifacts (integrity verification) |

### Uploading artifacts

```yaml
- name: Upload Omar Gate artifacts
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: sentinelayer-${{ steps.omar.outputs.run_id }}
    path: .sentinelayer/runs/${{ steps.omar.outputs.run_id }}
    if-no-files-found: warn
```

---

## Runtime and Import Boundaries

The `action.yml` entry in this revision is a composite action. Dependency installation runs from `${{ github.action_path }}` and invokes both pip upgrade and the hash-locked install with `python -P -m pip`. Analysis runs in `${{ github.workspace }}`, while `PYTHONPATH` is set to the action-owned `src`, `PYTHONSAFEPATH=1` is exported and `python -P -m omargate.main` starts the action package. Import isolation and the scanned repository's working directory are separate concerns.

The repository also supplies a Docker image; it is not the current `runs.using` mode. Its normal `entrypoint.sh` sets `/app/src` as `PYTHONPATH`, enables safe-path behavior and invokes `python -P -m omargate.main`. A command explicitly supplied to that entrypoint takes its separate command-execution branch. Standalone workflow or self-hosted invocations must establish their own action-owned import path; a generic `python -m` example does not prove the composite action's boundary applies there.

Harness audit commands use an explicit environment allowlist and private home/config/cache/temp state from [`runner.py`](../src/omargate/harness/runner.py). Provider, GitHub/OIDC and `INPUT_*` credentials are excluded. Only validated credential-free proxy origins, bounded `NO_PROXY` entries and copies of CA material outside the scanned workspace may be forwarded. npm uses the canonical Node binary with copied validated inputs instead of repository `.npmrc` or a command wrapper; PATH/CA controls reject lexical and resolved workspace containment. These are configuration/process boundaries, not filesystem or network sandboxes. Live public advisory metadata egress and direct-only Python coverage are described under [`run_harness`](#run_harness-and-dependency-audit-evidence).

Every nested npm project retains the original checkout root for process, PATH,
CA and scratch isolation; its own directory is only the manifest/lock input
location. Manifest discovery excludes only installed `node_modules` trees.
Names such as `build`, `dist`, `vendor`, `target`, `venv` and cache names cannot
hide application projects. If traversal exceeds its depth/entry bounds or cannot
read required directories, coverage remains incomplete and the gate refuses.

Codex has a separate allowlist and receives the configured OpenAI/Codex credential and model for its review task. The dependency audit's schema 1.2 project/scope/outcome evidence and exact serialized audit finding identities are validated before required LLM evidence and the severity threshold. A valid clean outcome applies only to its declared scope; an environment filter or a missing finding alone is not completion evidence.

## Data and Rendering Boundaries

- **Selected-provider context:** AI review sends bounded context to the selected provider. TypeSafe candidate evidence and verified diff context pass through recognized secret-source exclusion and diagnostic sanitization. Current source rules include prefixed password/access-key assignments, credential-bearing connection URLs, quoted Authorization/Bearer fields, common token/private-key patterns and designated sensitive file paths. Exclusion substitutes complete recognized source lines; scanner observations are context, not a claim that every unknown secret is detected or excluded.
- **Fingerprints:** Typed provider state still carries original evidence/source/diff SHA-256 fingerprints alongside display-safe context. A digest is a binding fingerprint, not encryption or proof that a low-entropy omitted value cannot be guessed. Local evidence integrity and provider-payload privacy are separate properties.
- **Artifacts and retention:** Typed assessment artifacts retain source hashes, candidate/question bindings, answers and completion/failure metadata. Treat artifacts and logs as potentially sensitive. Telemetry flags and the action's local execution do not establish an external provider's storage/retention policy.
- **Step Summary:** The summary renderer encodes untrusted displayed scalars (including finding path/category/message, reason, synopsis and snapshot strings) while preserving its fixed status/table template. This rendering boundary is separate from JSON/evidence data and from other renderers, including PR-comment location/link formatting; do not infer one sink's safety from another sink's source change.
