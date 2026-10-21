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
5. Optional: set both. Omar Gate prefers `OPENAI_API_KEY` when present. For the TypeSafe provider, also add `TYPESAFE_API_KEY`; both keys are required (see Option E).
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

- Installs Python dependencies from the action directory using `python -P -m pip`
- Installs Codex CLI on the runner (`@openai/codex`)
- Scans the checked-out repository at `$GITHUB_WORKSPACE`, while imports use the action-owned `src` with `PYTHONSAFEPATH=1` and `python -P -m omargate.main`
- Runs dependency audits with private tool state/copied inputs and sanitized credential-free connectivity; schema 1.1 evidence is validated separately from finding thresholds (see `run_harness` below)

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

### Option E: TypeSafe Candidate Assessment + OpenAI Writer

This provider first asks the privately pinned intent model to assess source-backed candidates. Private operator policy owns the severity/category decisions; `gpt-5.3-codex` writes explanations for fixed verdicts. Generator fallback is a separate review path.

**Experimental status:** This configuration does not establish empirical recall, calibrated security quality, independent security/release approval or adoption approval. Use an independently approved action revision before enabling this provider.

```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    llm_provider: typesafe
    typesafe_api_key: ${{ secrets.TYPESAFE_API_KEY }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    intent_model_pin: ${{ secrets.INTENT_MODEL_PIN }}
    intent_policy: ${{ secrets.INTENT_POLICY }}
    typesafe_fallback: true
```

The typed path currently requires a complete supported `pr-diff` inventory and verified diff context. Unsupported scope, exhausted budgets, uncertain decisions and source-integrity failures require generator fallback or the configured failure policy (default `block`). Every candidate span resolved clean requires generator confirmation, including a complete policy review that also finds issues in other spans; the assessment records `generator_required_clean_candidates`. This confirmation requirement remains in place until empirical recall evidence is available. `typesafe_fallback: false` disables generator fallback; it does not turn an incomplete or typed-clean assessment into a successful review.

`model`, `model_fallback` and `codex_model` resolve to exactly `gpt-5.3-codex` for this provider; other explicit values and `codex_only: true` are rejected. Managed proxy mode supports `openai` only. See [TypeSafe review](docs/CONFIGURATION.md#typesafe-review) for coverage limits, failure behavior and the merge and bounded provenance contract. These source contracts do not establish empirical recall or approval to adopt the provider as a security gate.

### Common Customizations

```yaml
- name: Omar Gate
  uses: mrrCarter/sentinelayer-v1-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}

    # What blocks the merge?
    severity_gate: P1        # none disables finding-severity blocks; integrity checks remain

    # What to scan?
    scan_mode: pr-diff        # pr-diff = changed files only (fast, default), deep = full repo

    # Which model?
    model: gpt-5.3-codex      # explicit API model; empty uses the provider default
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
| 4 | Dep audit + harness | ~5s | Known CVEs (npm, pip, Cargo), workflow injection, privilege escalation |

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
- This bounds the context sent through the legacy API review path
- With `llm_provider: typesafe`, intent model assesses complete source-bound candidates and private operator policy decides verdicts; a separate fixed-verdict writer and, when required, generator fallback follow (see [TypeSafe review](docs/CONFIGURATION.md#typesafe-review))

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
| `estimated_cost_usd` | With `intent-cascade-v1`, a token-rate estimate from observed model usage, or `unknown` when usage is incomplete. Its cost ledger separates model estimates and the known subtotal. Legacy routing and pre-analysis rate-limit exits may report a PR-size forecast instead. Neither is a bill. |
| `findings_artifact` | Path to findings JSONL |
| `audit_report_artifact` | Path to `AUDIT_REPORT.md` |

---

## Configuration Reference

### Required

| Input | Description |
|-------|-------------|
| `github_token` | GitHub token. Use `${{ secrets.GITHUB_TOKEN }}` (provided automatically). |
| LLM auth | Provide the selected provider's BYO key or OpenAI managed mode (`sentinelayer_token` + `sentinelayer_managed_llm=true`). TypeSafe requires both `typesafe_api_key` and `openai_api_key`. |

### Scan Settings

| Input | Default | Description |
|-------|---------|-------------|
| `severity_gate` | `P1` | Finding threshold: `P0`, `P1`, `P2`, or `none`; required audit integrity still fails closed |
| `scan_mode` | `pr-diff` | `pr-diff` (changed files), `deep` (full repo), `nightly` (alias of `deep`) |
| `pr_number` | `""` | Target PR for `workflow_dispatch` scans; PR event payloads take precedence |
| `llm_failure_policy` | `block` | If LLM fails: `block`, `deterministic_only`, `allow_with_warning` |
| `run_harness` | `true` | Run fail-closed npm, pip, and Cargo dependency audits plus the security harness |

With `run_harness: true`, every applicable dependency audit must produce recognized,
internally consistent JSON. A missing tool or lockfile, timeout, malformed result, or
unsupported Python dependency input blocks the run even when `severity_gate: none`;
`run_harness: false` is the explicit opt-out. Bounded, no-follow manifest discovery
rejects nested or multi-project layouts instead of silently reporting them as clean.

npm projects require a non-workspace `package-lock.json` or `npm-shrinkwrap.json`
at lockfile version 2 or 3. Peer/peer-optional dependencies are unsupported because
npm audit does not cover them. Every remaining non-link package must resolve through one
credential-free canonical `https://registry.npmjs.org` origin, which is passed
explicitly to npm. Custom/private, localhost, IP-literal, credentialed, mixed, and
non-HTTPS origins fail closed before spawn; registry credentials are never forwarded.
Any vulnerability reported by npm is vulnerable evidence. Enabling the harness
authorizes npm audit to send the validated copied lock graph (package names and
versions) to that public npm registry endpoint.

Python coverage is deliberately narrower: a root `requirements.txt` must contain a
nonempty set of exact `name==version` pins, no other Python dependency manifest may
be present, and pip-audit's result must contain that exact normalized name/version
set. This covers the declared direct pins only, not their transitive dependency
closure. Enabling the harness authorizes pip-audit to send those pinned names and
versions to its public vulnerability service. Repositories with pip routing
configuration—including alternate indexes or `find-links` sources—are unsupported
and fail before that metadata can be sent.
Other Python inputs—including `pyproject.toml`, `Pipfile.lock`, Poetry, uv, PDM,
`pylock.*`, alternate `requirements-*.txt`, and `requirements/*.txt`—make the
direct-pin claim indeterminate rather than being silently ignored. The same applies
to `requirements*.in` and `requirements/*.in` source manifests.

Rust projects require a valid `Cargo.lock`; cargo-audit's reported dependency count
must match it. A separately provisioned, version-pinned `cargo-audit` executable is
required because this action intentionally does not install it.

Machine evidence uses schema `1.1` and binds the exact coverage scopes
`package_lock_registry_graph`, `declared_direct_pins`, and `cargo_lock_packages` for
npm, pip, and Cargo respectively. Consumers reject a missing or altered scope map.

Audit tools run with private home, config, cache, and temporary directories outside
the scanned workspace. Provider, GitHub, OIDC, and `INPUT_*` secrets are excluded.
Only validated credential-free proxy origins, bounded `NO_PROXY` entries, and copied
CA material from outside the workspace can be forwarded. npm runs through the
canonical Node executable against private copies of only the validated manifest and
lockfile, so a repository `.npmrc` or command wrapper is not loaded. npm, pip, and
Cargo inputs are copied to private scratch space before validation and audit; this is
configuration isolation, not an offline audit guarantee. Process-tree teardown is
bounded and verified; if the OS cannot prove it, the run fails with fixed containment
evidence and retains both tool-state and copied-input scratch instead of deleting it
beneath a potentially live child.

### LLM Settings

| Input | Default | Description |
|-------|---------|-------------|
| `llm_provider` | `openai` | `openai`, `anthropic`, `google`, `xai`, `typesafe` |
| `model` | `""` (automatic) | API model: `gpt-4.1-mini` for legacy providers; exactly `gpt-5.3-codex` for TypeSafe |
| `model_fallback` | `""` (automatic) | API fallback: `gpt-4.1-mini` for legacy providers; exactly `gpt-5.3-codex` for TypeSafe |
| `intent_model_pin` | `""` | Required private `provider-MAJOR.MINOR.PATCH` version; mutable aliases rejected |
| `intent_policy` | `""` | Required private JSON review profile; no default rubric. |
| `typesafe_timeout` | `30` | TypeSafe timeout in seconds, 1–120 |
| `typesafe_max_candidates` | `50` | Maximum complete source candidates, 1–200; budget exhaustion is incomplete coverage |
| `typesafe_fallback` | `true` | Allow separate `gpt-5.3-codex` generator review when the typed stage cannot complete |
| `sentinelayer_managed_llm` | `false` | Use Sentinelayer-managed OpenAI capacity. With no `openai_api_key`, OpenAI calls use the managed proxy; with BYO OpenAI, BYO remains primary and managed is tried once only after quota/rate-limit fallback exhaustion. |
| `use_codex` | `true` | Use Codex CLI for deep agentic audit (OpenAI only, requires host runner) |
| `codex_model` | `gpt-5.3-codex` | Model for Codex CLI |

### Rate Limiting

| Input | Default | Description |
|-------|---------|-------------|
| `max_daily_scans` | `20` | Max matching completed checks per PR head in a rolling 24-hour window |
| `min_scan_interval_minutes` | `0` | Cooldown between scans |

Every run requires fresh source-bound review evidence. The run key binds effective review settings, private configuration hashes, dependency-audit contract and UTC day. Remote check names, summaries and external IDs are not authenticated reusable receipts; no prior check can authorize a skipped run.

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

### Report-Only Finding Threshold

This disables finding-severity blocks. Required dependency-audit and LLM integrity
checks remain fail-closed; set `run_harness: false` to opt out of dependency audits.

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

Omar Gate applies deterministic evidence checks before an LLM finding can retain P0/P1 severity. At the default `severity_gate: P1`, an uncorroborated LLM finding is advisory P2; selecting `severity_gate: P2` also blocks on P2 findings. Fail-closed system findings are separate from model claims.

### Layer 1 — AST & Syntax-Aware Deterministic Analysis
- Python `eval()`/`exec()` detected via `ast.parse` + `ast.walk`, not regex
- JS/TS comment and string literals are blanked before pattern matching
- Entropy-based secret detection requires context keywords, min length 32, Shannon entropy >4.7

### Layer 2 — Git-Aware Diff Scoping
- Only **added** lines can produce blocking (P0/P1) findings
- Removed lines are scanned separately at P3 (advisory only)

### Layer 3 — LLM Guardrails (Corroboration Required)
- Legacy LLM/Codex P0/P1 findings accept any finding from the deterministic/harness stages in the *same file*, with the *exact emitted category*, whose span intersects the first reported line ±5. The typed producer allowlist does not apply to this lane, and a model-supplied `line_end` does not widen its window.
- A validated TypeSafe candidate may use its source-bound full span ±5 and narrow typed-category aliases. The corroborating producer must independently match the exact reviewed tuple; aliases do not authenticate producer output. Typed P0/P1 in `availability`, `infrastructure`, `race-condition` or `other-security` require generator review and remain P2 under the current guardrails.
- Uncorroborated P0/P1 findings are **downgraded to P2**. Findings referencing files outside the ingest inventory are dropped. Typed and generator lanes are guarded separately before composition; full-span collisions retain the strongest guarded severity with bounded alternate provenance. See [the detailed contract](docs/CONFIGURATION.md#layer-3-llm-guardrails-corroboration-required).

| Finding Source | P0/P1 Can Block at the Default Gate? |
|---|:---:|
| Deterministic scanner (regex, AST, config) | Yes |
| Harness (dependency audit, gitleaks) | Yes |
| Legacy Codex/OpenAI **with** deterministic or harness corroboration | Yes |
| Source-bound TypeSafe **with** reviewed producer corroboration | Yes |
| LLM **without compatible corroboration** | No at the default P1 gate; a P2 gate includes P2 |

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
The action executes on your runner, while the selected AI providers receive bounded review context. The TypeSafe path sends display-safe source context and original-source fingerprints; recognized secret lines are excluded, which is not a guarantee that every secret or low-entropy value is unrecoverable. Tier 1 telemetry sends aggregate counts; higher-tier uploads are opt-in. Managed OpenAI mode forwards bounded context through the Sentinelayer proxy. Provider storage and retention are governed separately from the runner's local execution. See [data boundaries](docs/CONFIGURATION.md#data-and-rendering-boundaries).

**What about false positives?**
LLM-only P0/P1 findings without compatible deterministic or harness corroboration are downgraded to P2. They do not block the default P1 gate; a P2 gate also blocks P2 findings. See [False Positive Defense](#false-positive-defense).

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
