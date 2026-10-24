from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ...analyze.deterministic.pattern_scanner import Finding
from ...analyze.deterministic.secret_scanner import scan_for_secrets
from ..runner import SecuritySuite, run_command


def _is_diff_path_line(line: str) -> str | None:
    if line.startswith("+++ b/"):
        p = line[6:].strip()
        return None if p == "/dev/null" else p
    if line.startswith("--- a/"):
        p = line[6:].strip()
        return None if p == "/dev/null" else p
    return None


@dataclass
class SecretsInGitSuite(SecuritySuite):
    tech_stack: list[str]

    @property
    def name(self) -> str:
        return "secrets_in_git"

    def applies_to(self, tech_stack: list[str]) -> bool:
        return True

    async def run(self, project_root: str) -> list[Finding]:
        root = Path(project_root)
        if not (root / ".git").exists():
            return []

        # Ensure git exists.
        version = await run_command(["git", "--version"], cwd=root, timeout_s=5)
        if version.returncode != 0:
            return []

        log_res = await run_command(
            ["git", "log", "-n", "50", "--pretty=format:%H"],
            cwd=root,
            timeout_s=10,
        )
        if log_res.returncode != 0 or not log_res.stdout.strip():
            return []

        commits = [c.strip() for c in log_res.stdout.splitlines() if c.strip()]
        if not commits:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, int]] = set()

        for commit in commits:
            show_res = await run_command(
                ["git", "show", "--format=", "--unified=0", commit],
                cwd=root,
                timeout_s=10,
            )
            if show_res.returncode != 0 or not show_res.stdout:
                continue

            current_file: str | None = None
            file_lines: dict[str, dict[str, list[str]]] = {}
            for line in show_res.stdout.splitlines():
                maybe_path = _is_diff_path_line(line)
                if maybe_path is not None:
                    current_file = maybe_path
                    if current_file and current_file not in file_lines:
                        file_lines[current_file] = {"added": [], "removed": []}
                    continue

                if not current_file:
                    continue

                if line.startswith("+++ ") or line.startswith("--- "):
                    continue
                if line.startswith("+") and not line.startswith("+++"):
                    file_lines[current_file]["added"].append(line[1:])
                if line.startswith("-") and not line.startswith("---"):
                    file_lines[current_file]["removed"].append(line[1:])

            for file_path, diff_lines in file_lines.items():
                added_lines = diff_lines.get("added", [])
                removed_lines = diff_lines.get("removed", [])

                if added_lines:
                    content = "\n".join(added_lines)
                    for f in scan_for_secrets(content, file_path):
                        _lower = file_path.lower()
                        if f.pattern_id == "SEC-ENTROPY" and (
                            _lower.endswith((".md", ".rst", ".txt"))
                            or "lock" in _lower
                        ):
                            continue
                        key = (f.pattern_id, f.file_path, f.line_start)
                        if key in seen:
                            continue
                        seen.add(key)
                        severity = f.severity
                        confidence = f.confidence
                        message = f"{f.message} (found in git history)"
                        # Historical entropy findings are high-noise; keep as advisory only.
                        if f.pattern_id == "SEC-ENTROPY":
                            severity = "P3"
                            confidence = min(float(confidence), 0.45)
                            message = "Historical high-entropy string detected (manual triage recommended)"

                        findings.append(
                            Finding(
                                id=f"HARNESS-HISTORY-{f.id}",
                                pattern_id=f.pattern_id,
                                severity=severity,
                                category=f.category,
                                file_path=f.file_path,
                                line_start=f.line_start,
                                line_end=f.line_end,
                                snippet=f.snippet,
                                message=message,
                                recommendation=f.recommendation,
                                confidence=confidence,
                                source="harness",
                            )
                        )

                # Removed lines may indicate credentials that were present in history.
                if removed_lines:
                    content = "\n".join(removed_lines)
                    for f in scan_for_secrets(content, file_path):
                        key = (f.pattern_id, f.file_path, f.line_start)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(
                            Finding(
                                id=f"HARNESS-HISTORY-REMOVED-{f.id}",
                                pattern_id=f.pattern_id,
                                severity="P3",
                                category=f.category,
                                file_path=f.file_path,
                                line_start=f.line_start,
                                line_end=f.line_end,
                                snippet=f.snippet,
                                message="Potential secret detected in removed line (verify history cleanup)",
                                recommendation="Confirm credential revocation/rotation and purge history if needed",
                                confidence=min(float(f.confidence), 0.4),
                                source="harness",
                            )
                        )

        return findings

