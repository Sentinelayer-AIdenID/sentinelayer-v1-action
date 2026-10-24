from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ...analyze.deterministic.pattern_scanner import Finding, _truncate_snippet
from ..detectors import read_text_best_effort
from ..runner import SecuritySuite


@dataclass
class ConfigHardeningSuite(SecuritySuite):
    tech_stack: list[str]

    @property
    def name(self) -> str:
        return "config_hardening"

    def applies_to(self, tech_stack: list[str]) -> bool:
        return True

    async def run(self, project_root: str) -> list[Finding]:
        root = Path(project_root)
        findings: list[Finding] = []

        # Node hardening (static check)
        if (root / "package.json").is_file():
            npmrc = root / ".npmrc"
            content = read_text_best_effort(npmrc).lower() if npmrc.is_file() else ""
            if "ignore-scripts=true" not in content.replace(" ", ""):
                findings.append(
                    Finding(
                        id="HARNESS-NODE-IGNORE-SCRIPTS",
                        pattern_id="HARNESS-NODE-IGNORE-SCRIPTS",
                        severity="P3",
                        category="supply-chain",
                        file_path=".npmrc" if npmrc.is_file() else "package.json",
                        line_start=1,
                        line_end=1,
                        snippet="",
                        message="Node installs may allow lifecycle scripts (ignore-scripts not enabled)",
                        recommendation="Consider setting ignore-scripts=true in CI (.npmrc) and explicitly allow only trusted scripts where needed",
                        confidence=0.6,
                        source="harness",
                    )
                )

        # Docker hardening (static checks only)
        dockerfile = root / "Dockerfile"
        if dockerfile.is_file():
            content = read_text_best_effort(dockerfile)
            from_count = len(re.findall(r"(?im)^\s*from\s+", content))
            if from_count < 2:
                findings.append(
                    Finding(
                        id="HARNESS-DOCKER-MULTISTAGE",
                        pattern_id="HARNESS-DOCKER-MULTISTAGE",
                        severity="P3",
                        category="infrastructure",
                        file_path="Dockerfile",
                        line_start=1,
                        line_end=1,
                        snippet="",
                        message="Dockerfile is not using a multi-stage build",
                        recommendation="Use a multi-stage build to reduce image size and attack surface",
                        confidence=0.7,
                        source="harness",
                    )
                )

            if re.search(r"(?im)^\s*copy\s+.*\.env\b", content):
                findings.append(
                    Finding(
                        id="HARNESS-DOCKER-COPY-ENV",
                        pattern_id="HARNESS-DOCKER-COPY-ENV",
                        severity="P1",
                        category="secrets",
                        file_path="Dockerfile",
                        line_start=1,
                        line_end=1,
                        snippet=_truncate_snippet("COPY ... .env", max_chars=200),
                        message="Dockerfile appears to copy a .env file into the image",
                        recommendation="Do not bake secrets into images; use runtime secrets/env injection",
                        confidence=0.8,
                        source="harness",
                    )
                )

        # Terraform hardening (best-effort, static)
        tf_files = list(root.rglob("*.tf"))
        if tf_files:
            joined = "\n".join(read_text_best_effort(p) for p in tf_files[:25])
            # HARNESS-TF-BACKEND removed: duplicate of EQ-019, low confidence (0.6)
            if re.search(r'(?is)backend\s+"s3"\s*\{[^}]*\}', joined) and "encrypt" not in joined:
                findings.append(
                    Finding(
                        id="HARNESS-TF-STATE-ENCRYPT",
                        pattern_id="HARNESS-TF-STATE-ENCRYPT",
                        severity="P2",
                        category="infrastructure",
                        file_path="*.tf",
                        line_start=1,
                        line_end=1,
                        snippet="",
                        message="Terraform S3 backend detected without obvious state encryption setting",
                        recommendation="Ensure Terraform state is encrypted at rest (e.g., encrypt=true for S3 backend, and KMS where appropriate)",
                        confidence=0.5,
                        source="harness",
                    )
                )

        # CI/CD workflow permissions hardening
        workflows_dir = root / ".github" / "workflows"
        if workflows_dir.is_dir():
            for wf in list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml")):
                text = read_text_best_effort(wf)
                if re.search(r"(?im)^\s*permissions\s*:\s*write-all\s*$", text):
                    findings.append(
                        Finding(
                            id=f"HARNESS-CICD-PERMS-{wf.name}",
                            pattern_id="HARNESS-CICD-PERMS",
                            severity="P2",
                            category="ci_cd",
                            file_path=str(wf.relative_to(root)).replace("\\", "/"),
                            line_start=1,
                            line_end=1,
                            snippet=_truncate_snippet("permissions: write-all", max_chars=200),
                            message="Workflow uses write-all permissions (overly broad)",
                            recommendation="Restrict workflow permissions to the minimum required for the job",
                            confidence=0.9,
                            source="harness",
                        )
                    )

        return findings
