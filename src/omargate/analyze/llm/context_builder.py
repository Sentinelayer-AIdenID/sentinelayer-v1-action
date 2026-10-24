from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ...ingest.codebase_snapshot import build_codebase_snapshot
from ...ingest.quick_learn import QuickLearnSummary
from ...repo_paths import plain_repo_file


TRUNCATION_MARKER = "... (truncated)"


@dataclass
class ContextBudget:
    max_tokens: int
    used_tokens: int
    remaining_tokens: int


@dataclass
class BuiltContext:
    content: str
    token_count: int
    files_included: List[str]
    files_truncated: List[str]
    files_skipped: List[str]
    hotspots_included: List[str]
    sections_incomplete: List[str] = field(default_factory=list)


class ContextBuilder:
    """Build LLM context from ingest data and deterministic findings."""

    def __init__(self, max_tokens: int = 80000, chars_per_token: float = 4.0) -> None:
        self.max_tokens = max_tokens
        self.chars_per_token = chars_per_token

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimation."""
        if not text:
            return 0
        return int(len(text) / self.chars_per_token)

    def build_context(
        self,
        ingest: dict,
        deterministic_findings: List[dict],
        repo_root: Path,
        quick_learn: Optional[QuickLearnSummary] = None,
        spec_context: Optional[dict] = None,
        scan_mode: str = "pr-diff",
        diff_content: Optional[str] = None,
        changed_files: Optional[List[str]] = None,
    ) -> BuiltContext:
        """
        Build context for LLM analysis.

        Each section added until budget exhausted.
        """
        ingest = ingest or {}
        context_parts: List[str] = []
        used_tokens = 0

        files_included: List[str] = []
        files_truncated: List[str] = []
        files_skipped: List[str] = []
        hotspots_included: List[str] = []
        sections_incomplete: List[str] = []

        def add_with_budget(text: str, allow_truncate: bool = False) -> tuple[bool, bool, int]:
            nonlocal used_tokens
            if not text:
                return False, False, 0
            remaining = self.max_tokens - used_tokens
            if remaining <= 0:
                return False, False, 0
            tokens = self.estimate_tokens(text)
            if tokens <= remaining:
                context_parts.append(text)
                used_tokens += tokens
                return True, False, tokens
            if not allow_truncate:
                return False, False, 0
            max_chars = int(remaining * self.chars_per_token)
            if max_chars <= 0:
                return False, False, 0
            truncated_text = text[:max_chars]
            if "\n" in truncated_text:
                truncated_text = truncated_text.rsplit("\n", 1)[0] + "\n"
            truncated_tokens = self.estimate_tokens(truncated_text)
            if truncated_tokens <= 0:
                return False, False, 0
            context_parts.append(truncated_text)
            used_tokens += truncated_tokens
            return True, True, truncated_tokens

        def add_section(name: str, text: str, *, allow_truncate: bool = False) -> None:
            added, truncated, _ = add_with_budget(text, allow_truncate)
            if text and (not added or truncated):
                sections_incomplete.append(name)

        quick_learn_context = self._build_quick_learn_context(quick_learn)
        add_section("quick_learn", quick_learn_context, allow_truncate=True)

        if spec_context:
            spec_context_section = self._build_spec_context_section(spec_context)
            add_section("spec", spec_context_section, allow_truncate=True)

        system_context = self._build_system_context(ingest)
        add_section("system", system_context)

        deterministic_context = self._build_deterministic_context(deterministic_findings)
        add_section("deterministic", deterministic_context)

        if scan_mode == "pr-diff" and diff_content:
            diff_section = f"## PR Diff\n{diff_content.strip()}\n"
            add_section("diff", diff_section, allow_truncate=True)

        priority_files = self._prioritize_files(ingest, changed_files, scan_mode, repo_root)
        hotspot_set = set()
        for files in ingest.get("hotspots", {}).values():
            hotspot_set.update(files)

        for rel_path in priority_files:
            if rel_path in files_included or rel_path in files_skipped:
                continue
            file_path = repo_root / rel_path
            content = self._read_file_bounded(file_path)
            if not content:
                files_skipped.append(rel_path)
                continue

            header = f"## File: {rel_path}\n"
            header_tokens = self.estimate_tokens(header)
            remaining = self.max_tokens - used_tokens
            if remaining <= header_tokens:
                files_skipped.append(rel_path)
                continue

            header_added, _, _ = add_with_budget(header)
            if not header_added:
                files_skipped.append(rel_path)
                continue

            added, truncated, _ = add_with_budget(f"{content}\n", allow_truncate=True)
            if not added:
                context_parts.pop()
                used_tokens -= header_tokens
                files_skipped.append(rel_path)
                continue

            files_included.append(rel_path)
            if truncated or content.endswith(TRUNCATION_MARKER):
                files_truncated.append(rel_path)
            if rel_path in hotspot_set:
                hotspots_included.append(rel_path)

        content = "".join(context_parts)
        token_count = min(self.max_tokens, used_tokens)

        return BuiltContext(
            content=content,
            token_count=token_count,
            files_included=files_included,
            files_truncated=files_truncated,
            files_skipped=files_skipped,
            hotspots_included=hotspots_included,
            sections_incomplete=sections_incomplete,
        )

    def _build_quick_learn_context(self, quick_learn: Optional[QuickLearnSummary]) -> str:
        """Build lightweight project summary header."""
        if not quick_learn:
            return ""
        stack = ", ".join(quick_learn.tech_stack) if quick_learn.tech_stack else "unknown"
        entry_points = (
            ", ".join(quick_learn.entry_points) if quick_learn.entry_points else "unknown"
        )
        description = quick_learn.description or ""
        excerpt = quick_learn.raw_excerpt.strip()
        if excerpt:
            excerpt = f"\n### Excerpt ({quick_learn.source_doc})\n{excerpt}\n"
        return (
            "## Project Context (Quick Learn)\n"
            f"- Project: {quick_learn.project_name or 'unknown'}\n"
            f"- Description: {description}\n"
            f"- Tech stack: {stack}\n"
            f"- Architecture: {quick_learn.architecture or 'unknown'}\n"
            f"- Entry points: {entry_points}\n"
            f"{excerpt}"
        )

    def _build_spec_context_section(self, spec_context: dict) -> str:
        tech_stack = spec_context.get("tech_stack", [])
        if not isinstance(tech_stack, list):
            tech_stack = []
        tech_stack_label = ", ".join(str(item) for item in tech_stack) if tech_stack else "N/A"
        return (
            "## SENTINELAYER SPEC CONTEXT\n"
            "This repository has a Sentinelayer-generated project spec. "
            "Use this context to make your review spec-aware.\n\n"
            f"**Project:** {spec_context.get('project_name', 'Unknown')}\n"
            f"**Synopsis:** {spec_context.get('synopsis', '')}\n"
            f"**Tech Stack:** {tech_stack_label}\n"
            f"**Mode:** {spec_context.get('mode', 'quick')}\n\n"
            "### Security Rules (from spec)\n"
            f"{spec_context.get('security_rules', 'N/A')}\n\n"
            "### Quality Gates (from spec)\n"
            f"{spec_context.get('quality_gates', 'N/A')}\n\n"
            "### Domain-Specific Rules\n"
            f"{spec_context.get('domain_rules', 'N/A')}\n\n"
            "When reporting findings, reference the relevant spec section "
            "(e.g., 'Per spec Section 5.1: ...'). "
            "This helps the developer understand WHY the rule exists.\n"
        )

    def _build_system_context(self, ingest: dict) -> str:
        """Build system context header."""
        stats = ingest.get("stats", {})
        dependencies = ingest.get("dependencies", {})

        overview = (
            "## Repository Overview\n"
            f"- Total files: {stats.get('total_files', '?')}\n"
            f"- In-scope files: {stats.get('in_scope_files', '?')}\n"
            f"- Total lines: {stats.get('total_lines', '?')}\n"
            f"- Package manager: {dependencies.get('package_manager', 'unknown')}\n\n"
        )

        snapshot_section = ""
        try:
            snapshot = build_codebase_snapshot(
                ingest,
                max_largest_files=10,
                max_god_files=10,
                hotspot_examples=3,
            )
        except Exception:
            snapshot = {}

        if isinstance(snapshot, dict) and snapshot:
            snap_stats = snapshot.get("stats", {}) if isinstance(snapshot.get("stats"), dict) else {}
            source_loc = snap_stats.get("source_loc_total")
            threshold = snapshot.get("god_threshold_loc", 1000)
            languages = snapshot.get("languages", []) if isinstance(snapshot.get("languages"), list) else []
            god_files = snapshot.get("god_files", []) if isinstance(snapshot.get("god_files"), list) else []

            snapshot_lines: List[str] = []
            if source_loc is not None:
                snapshot_lines.append(f"- Source LOC: {source_loc}")
            if languages:
                top_langs = ", ".join(
                    f"{item.get('language', 'unknown')}={item.get('loc', 0)}"
                    for item in languages[:8]
                )
                snapshot_lines.append(f"- Top languages: {top_langs}")
            if god_files:
                top_god = ", ".join(str(item.get("path") or "?") for item in god_files[:5])
                snapshot_lines.append(f"- God components (>= {threshold} LOC): {top_god}")

            if snapshot_lines:
                snapshot_section = (
                    "## Codebase Snapshot (Deterministic)\n"
                    + "\n".join(snapshot_lines)
                    + "\n\n"
                )

        hotspots_section = (
            "## Hotspot Categories\n" f"{self._format_hotspots(ingest.get('hotspots', {}))}\n"
        )

        return overview + snapshot_section + hotspots_section

    def _build_deterministic_context(self, findings: List[dict]) -> str:
        """Summarize deterministic findings for LLM context."""
        if not findings:
            return "## Deterministic Scan Results\nNo issues detected by pattern scanners.\n"

        lines = ["## Deterministic Scan Results", f"Found {len(findings)} issues:", ""]
        for finding in findings[:20]:
            lines.append(
                "- {severity}: {message} in {file_path}:{line_start}".format(
                    severity=finding.get("severity", "?"),
                    message=finding.get("message", "?"),
                    file_path=finding.get("file_path", "?"),
                    line_start=finding.get("line_start", "?"),
                )
            )
        if len(findings) > 20:
            lines.append(f"... and {len(findings) - 20} more")
        return "\n".join(lines) + "\n"

    def _format_hotspots(self, hotspots: Dict[str, List[str]]) -> str:
        if not hotspots:
            return "- (none detected)"
        lines = []
        for category, files in hotspots.items():
            if not files:
                continue
            lines.append(f"- {category}: {len(files)} files")
        if not lines:
            return "- (none detected)"
        return "\n".join(lines)

    def _read_file_bounded(self, file_path: Path, max_lines: int = 500) -> str:
        """Read file content with line limit."""
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

    def _prioritize_files(
        self, ingest: dict, changed_files: Optional[List[str]], scan_mode: str,
        repo_root: Optional[Path] = None,
    ) -> List[str]:
        """Return files in priority order for context inclusion."""
        priority: List[str] = []
        ingest_paths = {
            file_info.get("path")
            for file_info in ingest.get("files", [])
            if file_info.get("path")
        }

        if scan_mode == "pr-diff" and changed_files:
            for rel_path in changed_files:
                # Ingest already vetted its own paths (it skips symlinks). A changed
                # path ingest did not list (a test, a lockfile) is read only when it
                # is a regular file reached without any symlink and outside .git/.
                if rel_path not in ingest_paths and plain_repo_file(repo_root, rel_path) is None:
                    continue
                if rel_path not in priority:
                    priority.append(rel_path)

        cicd_paths = sorted(
            (
                path
                for path in ingest_paths
                if isinstance(path, str) and self._is_cicd_file(path)
            ),
            key=self._cicd_priority_key,
        )
        for rel_path in cicd_paths:
            if rel_path not in priority:
                priority.append(rel_path)

        for files in ingest.get("hotspots", {}).values():
            for rel_path in files:
                if rel_path not in priority:
                    priority.append(rel_path)

        for file_info in ingest.get("files", []):
            rel_path = file_info.get("path")
            if not rel_path:
                continue
            if file_info.get("category") != "source":
                continue
            if rel_path in priority:
                continue
            priority.append(rel_path)

        return priority

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
        if "/terraform/" in f"/{p}" or "/pulumi/" in f"/{p}" or "/cdk/" in f"/{p}" or "/k8s/" in f"/{p}" or "/kubernetes/" in f"/{p}" or "/helm/" in f"/{p}":
            return (2, p)
        if name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "pipfile.lock"}:
            return (3, p)
        return (4, p)
