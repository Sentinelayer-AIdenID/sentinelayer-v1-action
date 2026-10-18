from __future__ import annotations

import asyncio
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

from .detectors import ProjectFacts, detect_project_facts

if TYPE_CHECKING:
    from ..analyze.deterministic.pattern_scanner import Finding


# Audit tools need executable discovery, a small amount of platform context, and
# temporary-directory/locale settings.  Passing the complete Action environment
# would also pass provider credentials, GitHub/OIDC tokens, and arbitrary INPUT_*
# secrets to commands whose configuration is controlled by the scanned repository.
_HARNESS_PROCESS_ENV_KEYS = frozenset(
    {
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "SHELL",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SYSTEMROOT",
        "WINDIR",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
        "NO_COLOR",
        "FORCE_COLOR",
    }
)


def _harness_child_env(inherited: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the complete, bounded environment passed to harness commands."""

    source = os.environ if inherited is None else inherited
    return {
        key: value
        for key, value in source.items()
        if key in _HARNESS_PROCESS_ENV_KEYS
    }


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


async def run_command(args: list[str], cwd: Path, timeout_s: int) -> CommandResult:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_harness_child_env(),
        )
    except FileNotFoundError:
        return CommandResult(args=args, returncode=127, stdout="", stderr="command not found")

    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        stdout_b, stderr_b = await proc.communicate()
        return CommandResult(
            args=args,
            returncode=-1,
            stdout=(stdout_b or b"").decode("utf-8", errors="ignore"),
            stderr=(stderr_b or b"").decode("utf-8", errors="ignore"),
            timed_out=True,
        )

    return CommandResult(
        args=args,
        returncode=int(proc.returncode or 0),
        stdout=(stdout_b or b"").decode("utf-8", errors="ignore"),
        stderr=(stderr_b or b"").decode("utf-8", errors="ignore"),
        timed_out=False,
    )


class SecuritySuite(ABC):
    @abstractmethod
    async def run(self, project_root: str) -> list[Finding]:
        raise NotImplementedError

    @abstractmethod
    def applies_to(self, tech_stack: list[str]) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError


class HarnessRunner:
    def __init__(
        self,
        project_root: str,
        tech_stack: list[str],
        *,
        pip_audit_ignore_ids: str = "",
        per_suite_timeout_s: int = 60,
        total_timeout_s: int = 180,
    ) -> None:
        self.project_root = project_root
        self.tech_stack = tech_stack or []
        self.pip_audit_ignore_ids = pip_audit_ignore_ids
        self.per_suite_timeout_s = int(per_suite_timeout_s)
        self.total_timeout_s = int(total_timeout_s)

    def _select_suites(self) -> list[SecuritySuite]:
        # Lazy import to avoid circular imports (suites import SecuritySuite/run_command).
        from .suites import (
            BuildIntegritySuite,
            ConfigHardeningSuite,
            DepAuditSuite,
            HttpSecurityHeadersSuite,
            SecretsInGitSuite,
        )

        root = Path(self.project_root)
        facts: ProjectFacts = detect_project_facts(root, self.tech_stack)

        suites: list[SecuritySuite] = [SecretsInGitSuite(tech_stack=self.tech_stack)]

        if facts.is_node or facts.is_python or facts.is_rust:
            suites.append(
                DepAuditSuite(
                    tech_stack=self.tech_stack,
                    pip_audit_ignore_ids=self.pip_audit_ignore_ids,
                )
            )

        if (
            facts.is_node
            or facts.is_python
            or facts.has_dockerfile
            or facts.has_terraform
            or facts.has_workflows
        ):
            suites.append(ConfigHardeningSuite(tech_stack=self.tech_stack))

        if facts.is_node:
            suites.append(BuildIntegritySuite(tech_stack=self.tech_stack))

        if facts.is_web:
            suites.append(HttpSecurityHeadersSuite(tech_stack=self.tech_stack))

        return suites

    def _timeout_finding(self, suite_name: str, timeout_s: int) -> Finding:
        from ..analyze.deterministic.pattern_scanner import Finding

        return Finding(
            id=f"HARNESS-TIMEOUT-{suite_name}",
            pattern_id="HARNESS-TIMEOUT",
            severity="P2",
            category="harness",
            file_path=".sentinelayer/harness",
            line_start=1,
            line_end=1,
            snippet="",
            message=f"Harness suite timed out: {suite_name}",
            recommendation=f"Re-run with more time; suite timeout was {timeout_s}s",
            confidence=1.0,
            source="harness",
        )

    def _error_finding(self, suite_name: str, exc: Exception) -> Finding:
        from ..analyze.deterministic.pattern_scanner import Finding, _truncate_snippet

        msg = _truncate_snippet(str(exc) or "unknown error", max_chars=200)
        return Finding(
            id=f"HARNESS-ERROR-{suite_name}",
            pattern_id="HARNESS-ERROR",
            severity="P2",
            category="harness",
            file_path=".sentinelayer/harness",
            line_start=1,
            line_end=1,
            snippet="",
            message=f"Harness suite error: {suite_name} ({msg})",
            recommendation="Fix the underlying error or disable run_harness for this repo",
            confidence=0.8,
            source="harness",
        )

    def _ensure_harness_source(self, finding: Finding) -> Finding:
        from ..analyze.deterministic.pattern_scanner import Finding

        if getattr(finding, "source", None) == "harness":
            return finding
        return Finding(
            id=finding.id,
            pattern_id=finding.pattern_id,
            severity=finding.severity,
            category=finding.category,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            snippet=finding.snippet,
            message=finding.message,
            recommendation=finding.recommendation,
            confidence=finding.confidence,
            source="harness",
        )

    async def run(self) -> list[Finding]:
        suites = self._select_suites()
        findings: list[Finding] = []

        start = time.monotonic()
        deadline = start + max(self.total_timeout_s, 0)

        for suite in suites:
            remaining_total = max(0.0, deadline - time.monotonic())
            if remaining_total <= 0:
                break

            timeout_s = min(float(self.per_suite_timeout_s), remaining_total)
            try:
                suite_findings = await asyncio.wait_for(
                    suite.run(self.project_root),
                    timeout=timeout_s,
                )
                for f in suite_findings:
                    findings.append(self._ensure_harness_source(f))
            except TimeoutError:
                findings.append(self._timeout_finding(suite.name, int(timeout_s)))
            except Exception as exc:
                findings.append(self._error_finding(suite.name, exc))

        return findings
