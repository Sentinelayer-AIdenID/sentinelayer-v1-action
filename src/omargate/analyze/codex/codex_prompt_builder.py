from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ...ingest.codebase_snapshot import build_codebase_snapshot
from ...ingest.quick_learn import QuickLearnSummary

# Persona is proprietary to the Omar Pack and must remain inline (not externalized).
_PERSONA_SYSTEM_PROMPT = """You are Omar Singh, a senior CI/CD and release engineering specialist.

Background: You spent years building deployment pipelines at scale. You believe that
if something isn't automated, it doesn't exist. You are strict about deterministic
builds, gating checks, and rollback readiness.

Your core question for every review: "Can we deploy this safely, repeatedly, and
recover quickly if it fails?"

What you are strict about:
- Deterministic, reproducible builds
- Proper gating checks (lint -> test -> security -> build -> deploy)
- Artifact integrity and provenance
- Rollback procedures being tested and documented
- Pipeline stages being complete (no skipped gates)

Red flags you ALWAYS escalate to P0:
- Production deployment without tests passing
- No rollback plan or procedure
- Secrets exposed in CI/CD workflows or logs
- Manual steps in what should be an automated pipeline

Your review style:
- You read code changes through the lens of "what happens when this deploys?"
- You check that error handling covers deployment failure scenarios
- You verify that config changes won't break other environments
- You look for missing validation at system boundaries
- You consider the blast radius of every change

Backend reliability checks (always apply):
- Every network call must have a timeout
- Write/mutation endpoints must be idempotent
- Rate limiting must fail-closed (never fail-open)
- Error responses must follow a consistent schema with requestId
- Auth/authz enforcement must be present on all protected routes
- Retries must have bounds (no infinite retry loops)
- External service calls need circuit breaker or fallback patterns
"""


TRUNCATION_MARKER = "... (truncated)"


@dataclass(frozen=True)
class BuiltCodexPrompt:
    prompt: str
    token_count: int
    files_included: list[str]
    files_truncated: list[str]


class CodexPromptBuilder:
    """
    Build the non-interactive Codex prompt with a strict token budget.

    The prompt includes:
    - Omar persona (inline system-style instructions)
    - Quick Learn project summary
    - Deterministic findings summary
    - PR diff or hotspot files (budget controlled)
    - Stack-aware engineering quality checklist
    - JSONL-only output contract
    """

    def __init__(self, max_tokens: int = 100000, chars_per_token: float = 4.0) -> None:
        self.max_tokens = int(max_tokens)
        self.chars_per_token = float(chars_per_token)

    def estimate_tokens(self, text: str) -> int:
        if not text:
            return 0
        return int(len(text) / self.chars_per_token)

    def build_prompt(
        self,
        *,
        repo_root: Path,
        quick_learn: QuickLearnSummary | None,
        deterministic_findings: list[dict],
        tech_stack: list[str],
        scan_mode: str,
        diff_content: str | None = None,
        hotspot_files: list[str] | None = None,
        ingest: dict | None = None,
    ) -> BuiltCodexPrompt:
        repo_root = repo_root.resolve()
        deterministic_findings = deterministic_findings or []
        tech_stack = tech_stack or []
        output_contract = self._build_output_contract()
        output_contract_tokens = self.estimate_tokens(output_contract)
        # Always reserve budget for the output contract so downstream parsing remains deterministic.
        body_budget = max(self.max_tokens - output_contract_tokens, 0)

        parts: list[str] = []
        used_tokens = 0
        files_included: list[str] = []
        files_truncated: list[str] = []

        def add(text: str, allow_truncate: bool = False) -> None:
            nonlocal used_tokens
            if not text:
                return
            remaining = body_budget - used_tokens
            if remaining <= 0:
                return
            tokens = self.estimate_tokens(text)
            if tokens <= remaining:
                parts.append(text)
                used_tokens += tokens
                return
            if not allow_truncate:
                return
            max_chars = int(remaining * self.chars_per_token)
            if max_chars <= 0:
                return
            truncated = text[:max_chars]
            if "\n" in truncated:
                truncated = truncated.rsplit("\n", 1)[0] + "\n"
            parts.append(truncated)
            used_tokens += self.estimate_tokens(truncated)

        add(self._build_persona_section())
        add(self._build_project_context(quick_learn), allow_truncate=True)
        add(self._build_codebase_snapshot_section(ingest), allow_truncate=True)
        add(self._build_deterministic_summary(deterministic_findings))
        add(self._build_task_instructions(tech_stack))

        if scan_mode == "pr-diff" and diff_content:
            add("## Code to Review (PR Diff)\n", allow_truncate=False)
            add(f"{diff_content.strip()}\n\n", allow_truncate=True)
        else:
            selected = self._select_review_files(hotspot_files or [], ingest)
            if selected:
                add("## Code to Review (Hotspot Files)\n")
                for rel_path in selected:
                    content = self._read_file_bounded(repo_root / rel_path)
                    if not content:
                        continue
                    header = f"### File: {rel_path}\n"
                    header_tokens = self.estimate_tokens(header)
                    if self.max_tokens - used_tokens <= header_tokens:
                        break
                    add(header)
                    before = used_tokens
                    add(f"```text\n{content}\n```\n\n", allow_truncate=True)
                    files_included.append(rel_path)
                    if used_tokens == before:
                        # Couldn't fit content; drop the header we added.
                        parts.pop()
                        used_tokens -= header_tokens
                        files_included.pop()
                        break
                    if content.endswith(TRUNCATION_MARKER):
                        files_truncated.append(rel_path)

        parts.append(output_contract)
        used_tokens += output_contract_tokens

        prompt = "".join(parts)
        token_count = min(self.max_tokens, used_tokens)
        return BuiltCodexPrompt(
            prompt=prompt,
            token_count=token_count,
            files_included=files_included,
            files_truncated=files_truncated,
        )

    def _build_codebase_snapshot_section(self, ingest: dict | None) -> str:
        if not ingest:
            return ""
        try:
            snapshot = build_codebase_snapshot(
                ingest,
                max_largest_files=10,
                max_god_files=10,
                hotspot_examples=3,
            )
        except Exception:
            return ""

        stats = snapshot.get("stats", {}) if isinstance(snapshot, dict) else {}
        source_loc = stats.get("source_loc_total")
        in_scope = stats.get("in_scope_files")
        threshold = snapshot.get("god_threshold_loc", 1000)
        languages = snapshot.get("languages", []) if isinstance(snapshot, dict) else []
        god_files = snapshot.get("god_files", []) if isinstance(snapshot, dict) else []

        lines: list[str] = ["## Codebase Snapshot (Deterministic)"]
        if in_scope is not None:
            lines.append(f"- In-scope files (source): {in_scope}")
        if source_loc is not None:
            lines.append(f"- Source LOC: {source_loc}")
        if languages:
            top_langs = ", ".join(
                f"{item.get('language', 'unknown')}={item.get('loc', 0)}"
                for item in languages[:8]
            )
            lines.append(f"- Top languages: {top_langs}")
        if god_files:
            top_god = ", ".join(str(item.get("path") or "?") for item in god_files[:5])
            lines.append(f"- God components (>= {threshold} LOC): {top_god}")
        lines.append("")
        return "\n".join(lines) + "\n"

    def _build_persona_section(self) -> str:
        return (
            "# System\n"
            f"{_PERSONA_SYSTEM_PROMPT.strip()}\n\n"
            "# CI/CD & Release Engineering Audit\n\n"
        )

    def _build_project_context(self, quick_learn: QuickLearnSummary | None) -> str:
        if not quick_learn:
            return "## Project Context\nunknown\n\n"
        stack = ", ".join(quick_learn.tech_stack) if quick_learn.tech_stack else "unknown"
        entry_points = (
            ", ".join(quick_learn.entry_points) if quick_learn.entry_points else "unknown"
        )
        desc = (quick_learn.description or "").strip()
        if len(desc) > 100:
            desc = desc[:97] + "..."
        return (
            "## Project Context\n"
            f"- Project: {quick_learn.project_name or 'unknown'}\n"
            f"- Description: {desc}\n"
            f"- Tech stack: {stack}\n"
            f"- Architecture: {quick_learn.architecture or 'unknown'}\n"
            f"- Entry points: {entry_points}\n\n"
        )

    def _build_deterministic_summary(self, findings: list[dict]) -> str:
        if not findings:
            return "## Already Found (Deterministic)\n0 findings.\n\n"
        lines = [
            "## Already Found (Deterministic)",
            f"{len(findings)} findings already identified by automated scanners.",
            "Focus on issues that require code understanding beyond pattern matching.",
            "",
        ]
        for f in findings[:20]:
            lines.append(
                "- {severity}: {message} ({file}:{line})".format(
                    severity=f.get("severity", "?"),
                    message=(f.get("message", "?") or "").strip(),
                    file=f.get("file_path", "?"),
                    line=f.get("line_start", "?"),
                )
            )
        if len(findings) > 20:
            lines.append(f"... and {len(findings) - 20} more")
        return "\n".join(lines) + "\n\n"

    def _build_task_instructions(self, tech_stack: list[str]) -> str:
        checklist = self._build_engineering_checklist(tech_stack)
        stack = ", ".join(tech_stack) if tech_stack else "unknown"
        return (
            "## Your Task\n"
            "Review this repository as a CI/CD & release engineer first, then as a security reviewer.\n"
            "You MUST inspect `.github/workflows/*` first when present.\n\n"
            "1. Deployment and release safety (can this be safely shipped repeatedly?)\n"
            "2. CI/CD workflow integrity (gates, approvals, artifact flow, rollback readiness)\n"
            "3. Security vulnerabilities (P0-P3)\n"
            "4. Backend reliability (timeouts, idempotency, error handling, rate limits)\n"
            "5. Logic errors, race conditions, and architectural issues\n\n"
            "## CI/CD First-Pass Checklist (Mandatory)\n"
            "- Workflow graph is complete: lint -> test -> security -> build -> deploy\n"
            "- Production deploy requires protected environment + human approval for critical services\n"
            "- No prod deploy path can run when tests fail\n"
            "- Artifact is built once and promoted; provenance/signing/attestation gaps are flagged\n"
            "- Cloud access uses OIDC/workload identity (no long-lived static cloud keys)\n"
            "- Rollback runbook/procedure exists and is tested; absence is high severity\n"
            "- Canary/feature-flag/blue-green strategy exists, or explicit risk is documented\n"
            "- Concurrency controls avoid overlapping prod deploys\n"
            "- Actions/dependencies are pinned to deterministic versions\n\n"
            "## Commands You Should Reference In Findings\n"
            "- `analyze .github/workflows`\n"
            "- `build reproducibility checks`\n\n"
            "## Severity Scale\n"
            "- P0: Critical\n"
            "- P1: High\n"
            "- P2: Medium\n"
            "- P3: Low\n\n"
            f"## Engineering Quality Checks ({stack})\n"
            f"{checklist}\n\n"
        )

    def _build_engineering_checklist(self, tech_stack: list[str]) -> str:
        stack = [t.lower() for t in (tech_stack or [])]
        joined = " ".join(stack)

        checks: list[str] = [
            "- Deterministic builds (lockfiles, pinned deps, no floating versions)",
            "- Proper gating (lint -> test -> security -> build -> deploy), no skipped steps",
            "- Artifact integrity/provenance, versioning, and rollback readiness",
            "- Secrets are never printed in CI logs or embedded in config",
            "- Network calls have timeouts; retries are bounded with backoff",
            "- Rate limiting fails closed; auth/authz is enforced on protected routes",
            "- Mutations are idempotent where applicable; request/trace IDs are consistent",
        ]

        is_frontend = any(m in joined for m in ("react", "next", "vue", "angular"))
        is_backend = any(m in joined for m in ("node", "express", "django", "fastapi", "go", "python"))

        if is_frontend:
            checks.extend(
                [
                    "- Avoid dangerouslySetInnerHTML or sanitize strictly",
                    "- useEffect dependencies and cleanup correctness",
                    "- No console.log/debug artifacts in production code paths",
                    "- Avoid per-render inline object/function props in hot components",
                ]
            )

        if is_backend:
            checks.extend(
                [
                    "- Avoid SQL string concatenation; use parameterized queries",
                    "- Avoid eval/new Function; prevent RCE",
                    "- External service calls have fallbacks/circuit breakers",
                    "- Auth endpoints have rate limiting and do not fail open",
                ]
            )

        return "\n".join(checks)

    def _build_output_contract(self) -> str:
        return (
            "## Output Format\n"
            "Output ONLY valid JSONL (one JSON object per line). Use this schema:\n"
            '{"severity":"P1","category":"cicd","file_path":".github/workflows/deploy.yml",'
            '"line_start":42,"line_end":68,"message":"...","evidence_snippet":"...",'
            '"impact":"...","verification":"...","recommendation":"...",'
            '"fix_plan":"1-3 sentence actionable pseudo-code plan for this exact code path",'
            '"confidence":0.90,"source_agent":"OmarPack",'
            '"provenance_tag":"cicd_release_engineering_v1"}\n'
            "\n`fix_plan` must be code-specific, actionable, and concise (1-3 sentences, no fluff).\n"
            "\nIf no findings, output exactly:\n"
            '{"no_findings": true}\n'
            "\nDo not include markdown fences or commentary.\n"
        )

    def _select_review_files(self, hotspot_files: list[str], ingest: dict | None) -> list[str]:
        seen: set[str] = set()
        selected: list[str] = []
        ingest_paths: list[str] = []
        if isinstance(ingest, dict):
            for file_info in ingest.get("files", []) or []:
                if not isinstance(file_info, dict):
                    continue
                rel_path = str(file_info.get("path") or "").replace("\\", "/")
                if rel_path:
                    ingest_paths.append(rel_path)

        cicd_paths = [path for path in ingest_paths if self._is_cicd_file(path)]
        cicd_paths.sort(key=self._cicd_priority_key)

        for rel_path in cicd_paths:
            if rel_path in seen:
                continue
            if self._is_excluded_path(rel_path):
                continue
            seen.add(rel_path)
            selected.append(rel_path)
            if len(selected) >= 16:
                return selected

        for rel_path in hotspot_files:
            if not rel_path or rel_path in seen:
                continue
            normalized = rel_path.replace("\\", "/")
            if self._is_excluded_path(normalized):
                continue
            seen.add(normalized)
            selected.append(normalized)
            if len(selected) >= 16:
                break
        return selected

    def _is_cicd_file(self, rel_path: str) -> bool:
        p = rel_path.replace("\\", "/").lower()
        name = p.rsplit("/", 1)[-1]

        if p.startswith(".github/workflows/") and (p.endswith(".yml") or p.endswith(".yaml")):
            return True
        if name == "dockerfile" or name.startswith("dockerfile."):
            return True
        if "docker-compose" in name and (name.endswith(".yml") or name.endswith(".yaml")):
            return True
        if name in {"vercel.json", "netlify.toml", "render.yaml", "render.yml"}:
            return True
        if name in {"makefile", "taskfile.yml", "taskfile.yaml"}:
            return True
        if "/scripts/" in f"/{p}" and ("deploy" in name or "release" in name):
            return True
        if name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "pipfile.lock"}:
            return True
        if "/terraform/" in f"/{p}" or "/pulumi/" in f"/{p}" or "/cdk/" in f"/{p}":
            return True
        if "/k8s/" in f"/{p}" or "/kubernetes/" in f"/{p}" or "/helm/" in f"/{p}":
            return True
        if name.startswith(".releaserc") or "/.changeset/" in f"/{p}" or "/changesets/" in f"/{p}":
            return True
        return False

    def _cicd_priority_key(self, rel_path: str) -> tuple[int, str]:
        p = rel_path.replace("\\", "/").lower()
        name = p.rsplit("/", 1)[-1]
        if p.startswith(".github/workflows/"):
            return (0, p)
        if name == "dockerfile" or name.startswith("dockerfile.") or "docker-compose" in name:
            return (1, p)
        if name in {"vercel.json", "netlify.toml", "render.yaml", "render.yml"}:
            return (2, p)
        if "/terraform/" in f"/{p}" or "/pulumi/" in f"/{p}" or "/cdk/" in f"/{p}" or "/k8s/" in f"/{p}" or "/kubernetes/" in f"/{p}" or "/helm/" in f"/{p}":
            return (3, p)
        if name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "pipfile.lock"}:
            return (4, p)
        if name.startswith(".releaserc") or "/.changeset/" in f"/{p}" or "/changesets/" in f"/{p}":
            return (5, p)
        return (6, p)

    def _is_excluded_path(self, rel_path: str) -> bool:
        p = rel_path.lower()
        if p.startswith("tests/") or "/tests/" in p:
            return True
        if "__tests__" in p or ".spec." in p or ".test." in p:
            return True
        if p.startswith("dist/") or "/dist/" in p or p.startswith("build/") or "/build/" in p:
            return True
        if p.endswith(".min.js") or p.endswith(".min.css"):
            return True
        return False

    def _read_file_bounded(self, file_path: Path, max_lines: int = 350, max_bytes: int = 1_000_000) -> str:
        try:
            if file_path.stat().st_size > max_bytes:
                return ""
        except OSError:
            return ""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        lines = content.splitlines()
        truncated = False
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            truncated = True
        bounded = "\n".join(lines)
        if truncated:
            if bounded and not bounded.endswith("\n"):
                bounded += "\n"
            bounded += TRUNCATION_MARKER
        return bounded

