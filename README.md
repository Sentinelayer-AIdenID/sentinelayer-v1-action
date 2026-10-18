# Omar Gate

**AI-powered security gate that blocks P0/P1 vulnerabilities before merge.**

[![Action Version](https://img.shields.io/badge/action-v1.3.11-blue)](https://github.com/mrrCarter/sentinelayer-v1-action)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests: 298 passing](https://img.shields.io/badge/tests-298%20passing-brightgreen)](https://github.com/mrrCarter/sentinelayer-v1-action/actions/workflows/quality-gates.yml)

Omar Gate runs a 7-layer security analysis on every pull request — combining deterministic pattern scanning, codebase-aware ingestion, and deep AI-powered code review — then blocks the merge if critical vulnerabilities are found.

Works on any repo. Any language. Use your own LLM key, or Sentinelayer-managed onboarding mode.

---

## Quick Start (2 minutes)

### Step 1: Choose LLM Access Mode

Pick one:

1. Bring your own API key (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.)
2. Use Sentinelayer-managed mode with `SENTINELAYER_TOKEN` (server-side key, trial limits enforced)

> Managed mode requires `permissions: id-token: write` in your workflow so the action can send GitHub OIDC identity.

### Step 2: Add Secret(s) to Your Repo

1. Go to your GitHub repo
2. Click **Settings** (top bar) > **Secrets and variables** > **Actions**
3. Click **New repository secret**
4. Add one of:
   - `OPENAI_API_KEY` (BYO billing), or
   - `SENTINELAYER_TOKEN` (managed mode)
5. Optional: set both. Omar Gate prefers `OPENAI_API_KEY` when present.
6. Click **Add secret**

> You do NOT need to create a `GITHUB_TOKEN` secret — GitHub provides it automatically.

### Step 3: Create the Workflow File

In your repo, create the file `.github/workflows/security-review.yml`:

```yaml
name: Security Review
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write
  checks: write
  id-token: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Omar Gate
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          sentinelayer_managed_llm: ${{ secrets.SENTINELAYER_TOKEN != '' }}
```

### Step 4: Open a Pull Request

Commit the workflow file, push it to a branch, and open a PR. Omar Gate runs automatically and will:

1. Scan your codebase for secrets, vulnerabilities, and misconfigurations (free, ~10s)
2. Send high-risk files for deep AI analysis (~30s, uses your API key)
3. Post a detailed security report as a PR comment
4. Block the merge if P0 (critical) or P1 (high) issues are found
5. Upload full audit artifacts you can download from the Actions tab

**That's it. Four steps.**

### Runtime Model (Important)

Omar Gate runs directly on the GitHub-hosted runner (composite action mode), not in a Docker action container.

- Installs Python dependencies on the runner
- Installs Codex CLI on the runner (`@openai/codex`)
- Executes analysis against the checked-out repository at `$GITHUB_WORKSPACE`

---

## Setup Options

### Option A: Minimal (Quick Start above)
Just `github_token` + your LLM API key. Works on any repo, any language.

### Option B: Use a Different LLM Provider

**Anthropic (Claude)**
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    llm_provider: anthropic
    model: claude-sonnet-4-5
```

**Google (Gemini)**
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    google_api_key: ${{ secrets.GOOGLE_API_KEY }}
    llm_provider: google
    model: gemini-2.5-pro
```

### Option C: No API Key (Deterministic Only, Free)
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    llm_failure_policy: deterministic_only
```

Runs secrets scanning, config analysis, dependency auditing, and pattern matching — no LLM required. Free, fast (~10s). Catches hardcoded secrets, `eval()`/`exec()`, insecure configs, and known CVEs.

### Option D: Sentinelayer-Managed LLM (Use Sentinelayer Key)
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    sentinelayer_token: ${{ secrets.SENTINELAYER_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    sentinelayer_managed_llm: ${{ secrets.SENTINELAYER_TOKEN != '' }}
```

Without a BYO OpenAI key, this mode forwards bounded LLM context through `POST /api/v1/proxy/llm`. With a BYO OpenAI key, BYO remains primary and Sentinelayer-managed capacity is tried once only after quota/rate-limit fallback exhaustion. The API applies per-repo trial and budget limits, then returns model output to Omar Gate.

### Common Customizations

```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}

    # What blocks the merge?
    severity_gate: P1        # P0 = only criticals, P1 = critical+high (default), P2 = medium+, none = report only

    # What to scan?
    scan_mode: pr-diff        # pr-diff = changed files only (fast, default), deep = full repo

    # Which model?
    model: gpt-5.3-codex      # default primary model
    model_fallback: gpt-4.1-mini  # default fallback model
```

---

## Choose Your LLM

| Model | Provider | Quality | Cost | Speed | Best For |
|-------|----------|:-------:|:----:|:-----:|----------|
| `gpt-5.3-codex` | OpenAI | best | $$$ | Medium | Deep agentic audit, full codebase understanding |
| `claude-opus-4-6` | Anthropic | best | $$$ | Medium | Nuanced analysis, architectural review |
| `claude-sonnet-4-5` | Anthropic | great | $$ | Fast | Strong balance of quality and cost |
| `gpt-4.1` | OpenAI | great | $$ | Fast | Reliable all-rounder, great default |
| `gemini-2.5-pro` | Google | great | $$ | Fast | Large context window, good for big repos |
| `gpt-4.1-mini` | OpenAI | good | $ | Very Fast | Budget-friendly, frequent scans |
| `gemini-2.5-flash` | Google | good | $ | Very Fast | Cheapest option with decent quality |

**Cost estimates per scan:**

| Repo Size | Files | Premium ($$$/scan) | Standard ($$/scan) | Budget ($/scan) |
|-----------|------:|:------------------:|:------------------:|:---------------:|
| Small | <100 | ~$0.50 | ~$0.20 | ~$0.05 |
| Medium | 100-500 | ~$2-5 | ~$1-2 | ~$0.25-0.50 |
| Large | 500-2000 | ~$5-15 | ~$3-8 | ~$1-3 |
| Monorepo | 2000+ | ~$15-30 | ~$8-15 | ~$3-8 |

---

## How It Works

Omar Gate runs a two-phase analysis pipeline:

### Phase 1: Deterministic Analysis (free, fast, always runs)

| Layer | Engine | Time | What It Catches |
|:-----:|--------|:----:|-----------------|
| 1 | Codebase ingest | ~1s | File tree, LOC counts, god components, complexity metrics |
| 2 | Pattern scanner | ~7s | Hardcoded secrets, `eval()`, known-bad patterns, leaked credentials |
| 3 | Config scanner | ~2s | Insecure `.env` files, weak TypeScript config, HTTP dependencies |
| 4 | Dep audit + harness | ~5s | Known CVEs (pip-audit, npm-audit), workflow injection, privilege escalation |

### Phase 2: AI-Powered Analysis (uses your LLM key, runs after Phase 1)

| Layer | Engine | Time | What It Catches |
|:-----:|--------|:----:|-----------------|
| 5 | AI deep analysis | ~30-120s | RCE, SQLi, auth bypass, business logic flaws, broken references |
| 6 | LLM guardrails | ~1s | Validates AI findings against deterministic evidence |
| 7 | Fail-closed gate | ~1s | Blocks merge if P0/P1 found, posts findings to PR |

**How the AI phase works:**
- Phase 1 produces structured data (file metrics, hotspot files, ingest summary)
- The AI receives this data + the PR diff + your README — it does NOT crawl the codebase blindly
- The AI targets specific files identified as high-risk by the deterministic scan
- This dramatically reduces token usage and cost while maintaining deep analysis quality

---

## What You Get

### PR Comment
Every scan posts a detailed report to your PR:
- **Gate status** (passed/blocked) with severity breakdown
- **Top findings** with file paths, line numbers, and GitHub permalinks
- **Risk hotspots** ranked by severity and category
- **Codebase metrics** — LOC, god components, complexity scores

### Check Run
A GitHub check run appears on the PR with pass/fail status.

### Downloadable Artifacts
Full audit artifacts available from the Actions tab:
- `AUDIT_REPORT.md` — complete findings report
- `REVIEW_BRIEF.md` — reviewer summary with priority order
- `FINDINGS.jsonl` — machine-readable findings (for CI integration)
- `PACK_SUMMARY.json` — counts, integrity hash, metadata
- `CODEBASE_INGEST_SUMMARY.md` — deterministic codebase snapshot

---

## Outputs

Use these in subsequent workflow steps:

| Output | Description |
|--------|-------------|
| `gate_status` | `passed`, `blocked`, `bypassed`, or `error` |
| `p0_count` / `p1_count` / `p2_count` / `p3_count` | Finding counts by severity |
| `run_id` | Unique run identifier |
| `estimated_cost_usd` | Estimated LLM cost for the run |
| `findings_artifact` | Path to findings JSONL |
| `audit_report_artifact` | Path to `AUDIT_REPORT.md` |

---

## Configuration Reference

### Required

| Input | Description |
|-------|-------------|
| `github_token` | GitHub token. Use `${{ secrets.GITHUB_TOKEN }}` (provided automatically). |
| LLM auth | Provide BYO key (`openai_api_key`, `anthropic_api_key`, `google_api_key`) or managed mode (`sentinelayer_token` + `sentinelayer_managed_llm=true`). |

### Scan Settings

| Input | Default | Description |
|-------|---------|-------------|
| `severity_gate` | `P1` | Block threshold: `P0`, `P1`, `P2`, or `none` (report only) |
| `scan_mode` | `pr-diff` | `pr-diff` (changed files), `deep` (full repo), `nightly` (alias of `deep`) |
| `pr_number` | `""` | Target PR for `workflow_dispatch` scans; PR event payloads take precedence |
| `llm_failure_policy` | `block` | If LLM fails: `block`, `deterministic_only`, `allow_with_warning` |
| `run_harness` | `true` | Run dep audit (pip-audit, npm-audit) and security harness |

### LLM Settings

| Input | Default | Description |
|-------|---------|-------------|
| `llm_provider` | `openai` | `openai`, `anthropic`, `google`, `xai` |
| `model` | `gpt-5.3-codex` | Primary LLM model |
| `model_fallback` | `gpt-4.1-mini` | Fallback if primary fails |
| `sentinelayer_managed_llm` | `false` | Use Sentinelayer-managed OpenAI capacity. With no `openai_api_key`, OpenAI calls use the managed proxy; with BYO OpenAI, BYO remains primary and managed is tried once only after quota/rate-limit fallback exhaustion. |
| `use_codex` | `true` | Use Codex CLI for deep agentic audit (OpenAI only, requires host runner) |
| `codex_model` | `gpt-5.3-codex` | Model for Codex CLI |

### Rate Limiting

| Input | Default | Description |
|-------|---------|-------------|
| `max_daily_scans` | `20` | Max scans per repo per day |
| `min_scan_interval_minutes` | `0` | Cooldown between scans |

### Security

| Input | Default | Description |
|-------|---------|-------------|
| `fork_policy` | `block` | Fork PRs: `block`, `limited` (deterministic only), `allow` |

### Telemetry

| Input | Default | Description |
|-------|---------|-------------|
| `telemetry` | `true` | Anonymous usage metrics (no code sent) |
| `telemetry_tier` | `1` | `0` = off, `1` = anonymous, `2` = repo metadata, `3` = findings |

See [action.yml](action.yml) for all 30+ options. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for detailed explanations.

`policy_pack` and `policy_pack_version` are currently metadata-only tags. They are recorded in outputs/artifacts but do not switch policy engines yet.

---

## Advanced Examples

### Strict Security Gate (Production)
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    severity_gate: P1
    llm_failure_policy: block
    fork_policy: block
```

### Report-Only Mode (No Blocking)
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    severity_gate: none
```

### Throughput Mode
```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    model: gpt-5.3-codex
    model_fallback: gpt-4.1-mini
    use_codex: false
    max_input_tokens: 40000
```

### Nightly Deep Scan
```yaml
name: Nightly Security Audit
on:
  schedule:
    - cron: '0 3 * * *'

jobs:
  deep-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Omar Gate (Deep)
        uses: mrrCarter/sentinelayer-v1-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          scan_mode: deep
          severity_gate: P2
```

---

## False Positive Defense

Omar Gate uses three independent layers so that **LLM analysis can never unilaterally block a merge**:

### Layer 1 — AST & Syntax-Aware Deterministic Analysis
- Python `eval()`/`exec()` detected via `ast.parse` + `ast.walk`, not regex
- JS/TS comment and string literals are blanked before pattern matching
- Entropy-based secret detection requires context keywords, min length 32, Shannon entropy >4.7

### Layer 2 — Git-Aware Diff Scoping
- Only **added** lines can produce blocking (P0/P1) findings
- Removed lines are scanned separately at P3 (advisory only)

### Layer 3 — LLM Guardrails (Corroboration Required)
- Legacy Codex/OpenAI P0/P1 findings are **downgraded to P2** unless any deterministic or harness finding has the *same file*, exact emitted *category*, and a range within *5 lines of the generator finding's starting line*. This preserves the existing scanner-rule contract; it does not use the TypeSafe producer allowlist.
- Source-bound TypeSafe P0/P1 findings use canonical category aliases and a reviewed producer/rule/category allowlist. Their complete bound span (plus 5 lines on each side) may be corroborated; unreviewed producer tuples cannot make a typed finding block.
- Every TypeSafe candidate span resolved clean requires generator confirmation, even when another span produced a typed finding. With `typesafe_fallback: false`, the typed review remains incomplete instead of accepting that clean span as confirmed.
- Findings referencing files not in the scanned diff are dropped entirely

| Finding Source | Can Block Merge? |
|---|:---:|
| Deterministic scanner (regex, AST, config) | Yes |
| Harness (pip-audit, gitleaks) | Yes |
| Legacy Codex/OpenAI **with** deterministic or harness corroboration | Yes |
| Source-bound TypeSafe **with** reviewed producer corroboration | Yes |
| LLM **without compatible corroboration** | No (advisory P2) |

---

## Troubleshooting

### "Illegal header value b'Bearer '"
**Fix:** Add `github_token: ${{ secrets.GITHUB_TOKEN }}` to your `with:` block.

### "LLM analysis skipped"
**Fix:** Add a BYO key (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GOOGLE_API_KEY`) or enable managed mode (`SENTINELAYER_TOKEN` + `sentinelayer_managed_llm: true`).

### "OIDC token is required for managed LLM usage"
**Fix:** Add `id-token: write` under workflow `permissions` so GitHub Actions can mint OIDC identity for the proxy call.

### Too many findings on first run
This is normal. The deterministic scanner scans your entire codebase. Most findings are P3 (informational). Focus on P0/P1. Subsequent PR scans only analyze changed files.

### Action doesn't trigger
The workflow file must exist on the PR branch. If adding it for the first time, it needs to be part of the PR itself.

---

## FAQ

**Do you store my code?**
No. Analysis runs entirely in your GitHub runner. Anonymous telemetry (Tier 1) sends only aggregate counts — no code, no file paths, no repo name. Higher tiers are opt-in. In managed mode, only bounded prompt context is sent to the Sentinelayer proxy for forwarding.

**What about false positives?**
Omar Gate has a 3-layer defense. LLM-only findings without deterministic corroboration are automatically downgraded to advisory P2 — they can't block your merge. See [False Positive Defense](#false-positive-defense).

**How much does it cost?**
The action itself is free. You pay your LLM provider for API usage. A typical PR scan on a medium repo costs $0.10-$0.50. See the [Choose Your LLM](#choose-your-llm) table for cost tiers.

**What languages does it support?**
All of them. Deterministic scanners have rules for Python, JavaScript/TypeScript, Go, Java, Ruby, PHP, C#, and more. The AI analysis works on any language your LLM understands.

---

## Test Coverage

**219 tests** (unit + integration) — all passing. Covers deterministic scanners, LLM fallback, telemetry, rate limiting, gate logic, and config validation.

---

## New to AI-driven development?

If you want to build the right way from day one — start at **[sentinelayer.com](https://sentinelayer.com)**.

Describe your project idea and Sentinelayer generates a FAANG-grade spec sheet: database schema, API design, security checklist, and a phase-by-phase build plan. Then we wire Omar Gate directly into your repo so every pull request is reviewed against your spec automatically.

**You get the spec. We set up Omar. Your team ships with a security gate already in place.**

→ [Get your spec at sentinelayer.com](https://sentinelayer.com)

---

## License

MIT License — Copyright (c) 2026 PlexAura Inc.

---

**Built by [PlexAura](https://plexaura.com) | [Sentinelayer](https://sentinelayer.com) — Stop vulnerabilities before they ship.**
