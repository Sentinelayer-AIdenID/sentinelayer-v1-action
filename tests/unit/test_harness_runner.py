from __future__ import annotations

import asyncio
import os
from pathlib import Path
import subprocess
import sys

import pytest

from omargate.harness.runner import (
    _HARNESS_PROCESS_ENV_KEYS,
    HarnessRunner,
    SecuritySuite,
    run_command,
)


ROOT = Path(__file__).resolve().parents[2]


def _touch(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_node_project_selects_expected_suites(tmp_path: Path) -> None:
    _touch(tmp_path / "package.json", '{"name":"x","dependencies":{}}')
    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=["Node.js"])
    suites = runner._select_suites()
    names = {s.name for s in suites}
    assert "secrets_in_git" in names
    assert "dependency_audit" in names
    assert "config_hardening" in names
    assert "build_integrity" in names


def test_python_project_selects_expected_suites(tmp_path: Path) -> None:
    _touch(tmp_path / "pyproject.toml", "[project]\nname='x'\n")
    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=["Python"])
    suites = runner._select_suites()
    names = {s.name for s in suites}
    assert "secrets_in_git" in names
    assert "dependency_audit" in names
    assert "config_hardening" in names
    assert "build_integrity" not in names


def test_empty_project_runs_only_secrets_in_git(tmp_path: Path) -> None:
    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=[])
    suites = runner._select_suites()
    assert [s.name for s in suites] == ["secrets_in_git"]


def test_harness_public_import_isolated_from_analyze_initialization(tmp_path: Path) -> None:
    child_env = os.environ.copy()
    child_env["PYTHONPATH"] = str(ROOT / "src")
    child_env["PYTHONSAFEPATH"] = "1"

    probe = subprocess.run(
        [
            sys.executable,
            "-P",
            "-c",
            "from omargate.harness import HarnessRunner; print(HarnessRunner.__name__)",
        ],
        cwd=tmp_path,
        env=child_env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "HarnessRunner"


@pytest.mark.anyio
async def test_audit_subprocess_receives_only_allowlisted_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inherited_secrets = {
        "INPUT_TYPESAFE_API_KEY": "typesafe-private",
        "OPENAI_API_KEY": "openai-private",
        "ANTHROPIC_API_KEY": "anthropic-private",
        "GITHUB_TOKEN": "github-private",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-private",
        "AWS_SECRET_ACCESS_KEY": "aws-private",
        "DATABASE_PASSWORD": "database-private",
        "NODE_OPTIONS": "--require=./workspace-controlled.js",
        "PYTHONPATH": "./workspace-controlled",
        "NPM_CONFIG_USERCONFIG": "./workspace-controlled.npmrc",
    }
    monkeypatch.setenv("PATH", "safe-tool-path")
    for key, value in inherited_secrets.items():
        monkeypatch.setenv(key, value)

    captured: dict[str, object] = {}

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return b"{}", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs.get("env")
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = await run_command(["npm", "audit", "--json"], cwd=tmp_path, timeout_s=5)

    assert result.returncode == 0
    child_env = captured["env"]
    assert isinstance(child_env, dict)
    assert child_env["PATH"] == "safe-tool-path"
    assert set(child_env).issubset(_HARNESS_PROCESS_ENV_KEYS)
    assert set(child_env).isdisjoint(inherited_secrets)


@pytest.mark.anyio
async def test_suite_timeout_is_enforced(tmp_path: Path, monkeypatch) -> None:
    class SlowSuite(SecuritySuite):
        @property
        def name(self) -> str:
            return "slow"

        def applies_to(self, tech_stack: list[str]) -> bool:
            return True

        async def run(self, project_root: str):
            await asyncio.sleep(10)
            return []

    runner = HarnessRunner(
        project_root=str(tmp_path),
        tech_stack=[],
        per_suite_timeout_s=1,
        total_timeout_s=2,
    )
    monkeypatch.setattr(runner, "_select_suites", lambda: [SlowSuite()])
    findings = await runner.run()
    assert any(f.pattern_id == "HARNESS-TIMEOUT" for f in findings)
    assert all(f.source == "harness" for f in findings)


@pytest.mark.anyio
async def test_findings_are_harness_source(tmp_path: Path, monkeypatch) -> None:
    from omargate.analyze.deterministic.pattern_scanner import Finding

    class OneFindingSuite(SecuritySuite):
        @property
        def name(self) -> str:
            return "one"

        def applies_to(self, tech_stack: list[str]) -> bool:
            return True

        async def run(self, project_root: str):
            return [
                Finding(
                    id="X",
                    pattern_id="X",
                    severity="P3",
                    category="harness",
                    file_path="x",
                    line_start=1,
                    line_end=1,
                    snippet="",
                    message="x",
                    recommendation="x",
                    confidence=1.0,
                    source="harness",
                )
            ]

    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=[])
    monkeypatch.setattr(runner, "_select_suites", lambda: [OneFindingSuite()])
    findings = await runner.run()
    assert len(findings) == 1
    assert findings[0].source == "harness"

