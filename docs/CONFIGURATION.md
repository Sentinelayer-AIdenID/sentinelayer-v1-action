# SentinelLayer Action Configuration

SentinelLayer (Omar Gate) is configured entirely via GitHub Action inputs (see [`action.yml`](../action.yml)). Inputs are passed via `with:` in your workflow.

**Notes:**
- GitHub Actions provides inputs as strings; the action parses booleans (`true`/`false`) and numbers automatically.
- No single API key is "required" — without any key, only deterministic scanning runs (no AI analysis). AI analysis can run via BYO provider keys or Sentinelayer-managed proxy mode.

---

## Inputs At A Glance

### Authentication

| Input | Type | Default | Purpose |
|---|---|---|---|
| `github_token` | secret string | `""` | GitHub token for PR comments, Check Runs, and fetching diffs. Use `${{ secrets.GITHUB_TOKEN }}`. |
| `publish_github` | bool | `true` | Publish PR comments and Check Runs. Set `false` only for internal probe runs that publish a separate canonical gate. |
| `openai_api_key` | secret string | `""` | OpenAI API key (for Codex CLI + Responses API). |
| `anthropic_api_key` | secret string | `""` | Anthropic API key (for Claude models). |
| `google_api_key` | secret string | `""` | Google AI API key (for Gemini models). |
| `xai_api_key` | secret string | `""` | xAI API key (for Grok models). |
| `sentinelayer_token` | secret string | `""` | SentinelLayer token for managed LLM proxy auth and Tier 2/3 dashboard uploads. |

### LLM Provider Settings

| Input | Type | Default | Purpose |
|---|---|---|---|
| `llm_provider` | string | `openai` | LLM provider: `openai`, `anthropic`, `google`, `xai`. |
| `model` | string | `gpt-5.3-codex` | Primary LLM API model (used when Codex CLI is unavailable or disabled). |
| `model_fallback` | string | `gpt-4.1-mini` | Fallback LLM API model (if primary fails or quota exceeded). |
| `sentinelayer_managed_llm` | bool | `false` | Route OpenAI API path through Sentinelayer-managed proxy. If false, auto-enables when `openai_api_key` is empty and `sentinelayer_token` is set. |
| `use_codex` | bool | `true` | Enable Codex CLI for deep agentic audit. Falls back to API if Codex fails. |
| `codex_only` | bool | `false` | Recommended for OpenAI users. Use Codex CLI as the only LLM path. Disables API fallback entirely. |
| `codex_model` | string | `gpt-5.3-codex` | Model passed to Codex CLI `--model` flag. |
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
| `run_harness` | bool | `true` | Run the portable security test harness (dep audit, secret-in-git checks). |

### Gate Control

| Input | Type | Default | Purpose |
|---|---|---|---|
| `severity_gate` | string | `P1` | Block threshold: `P0` (only criticals), `P1` (criticals + high), `P2` (medium+), `none` (report only, never blocks). |
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
| `training_opt_in` | bool | `false` | Optional training consent. Findings are de-identified; your code is never stored. |

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

Omar Gate has two LLM execution paths:

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

- `model`: Primary model. Default `gpt-5.3-codex`. Used when Codex is disabled or unavailable.
- `model_fallback`: Secondary model. Default `gpt-4.1-mini`. Used if the primary model fails, hits rate limits, or exceeds quota.

```yaml
with:
  model: gpt-5.3-codex
  model_fallback: gpt-4.1-mini
```

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

### `severity_gate`

Defines the minimum severity that blocks the merge:

| Gate | Blocks On | Use Case |
|---|---|---|
| `P0` | Only P0 (critical) | Permissive — only stops catastrophic issues |
| `P1` | P0 + P1 (critical + high) | **Recommended default** |
| `P2` | P0 + P1 + P2 (medium+) | Strict — catches more but may increase noise |
| `none` | Never blocks | Report-only / advisory mode |

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

Omar Gate uses three independent layers to minimize false positives. **LLM analysis can never unilaterally block a merge.**

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
- **Legacy generator corroboration**: Codex/OpenAI P0/P1 findings require any **deterministic or harness finding** in the same file, with the exact emitted category, whose range is within 5 lines of the generator finding's starting line. The TypeSafe producer allowlist does not narrow this established scanner-rule contract.
- **Typed corroboration**: Source-bound TypeSafe P0/P1 findings map policy aliases to canonical categories and accept only reviewed producer/rule/emitted-category tuples. The complete bound TypeSafe span, expanded by 5 lines, is used for proximity. A non-allowlisted producer cannot promote a typed finding above P2.
- **Clean-span confirmation**: Every TypeSafe candidate span resolved clean requires the generator, even when other spans emitted typed findings. If `typesafe_fallback` is disabled, the review stays incomplete instead of treating the clean span as confirmed.
- This means LLM analysis enriches results (adds context, explanations, risk assessment) but cannot independently block a merge.

### What this means in practice

| Finding Source | P0/P1 Blocks Merge? | Notes |
|---|---|---|
| Deterministic scanner | Yes | Regex, AST, config rules — high precision |
| Harness (dep audit, secrets-in-git) | Yes | External tool output (pip-audit, gitleaks) |
| Legacy Codex/OpenAI with corroboration | Yes | Any deterministic/harness scanner rule with exact emitted category nearby confirms it |
| Source-bound TypeSafe with corroboration | Yes | Reviewed producer/rule/category tuple confirms the canonical typed category |
| LLM without compatible corroboration | **No** (downgraded to P2) | Preserved as review hint |

### Handling persistent false positives

1. Check if the deterministic scanner rule needs refinement (open an issue or PR).
2. For entropy findings, verify whether the identifier filter or context filter should exclude the candidate.
3. For LLM findings, they should already be P2 by guardrails. If still blocking, check corroboration logic.
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
| `estimated_cost_usd` | Estimated LLM cost for this run |
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

## Docker Action vs Host Runner

Omar Gate can run in two modes:

### Docker Action (default for marketplace consumers)

- Uses `action.yml` with `runs.using: docker`.
- Runs as **root** inside an ephemeral container. GitHub Actions mounts `/github/workspace` and `/github/file_commands` as host UID; non-root breaks post-step writes (`GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`).
- Container is destroyed after the job step.
- Codex CLI is pre-installed in the image at a pinned version.

### Host Runner (for CI pipelines like `security-review.yml`)

- Runs `python -m omargate.main` directly on the runner.
- LLM CLIs are installed via npm in a prior step (with caching).
- Uses the runner's own user context and Python environment.
- More control over CLI versions and caching strategy.

Choose Docker for simplicity (one `uses:` line). Choose host runner when you need parallel jobs, custom CLI versions, or shared Python environments.
