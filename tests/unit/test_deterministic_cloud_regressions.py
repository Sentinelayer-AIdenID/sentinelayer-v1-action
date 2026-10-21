import json
from pathlib import Path

import pytest

from omargate.analyze.deterministic.eng_quality_helpers import bounded_python_deadline_loops
from omargate.analyze.deterministic.eng_quality_scanner import EngQualityScanner
from omargate.harness.runner import CommandResult
from omargate.harness.suites import dep_audit
from omargate.harness.suites.secrets_in_git import SecretsInGitSuite

pytestmark = pytest.mark.anyio


def test_monotonic_deadline_is_a_bound_but_word_presence_or_reset_is_not():
    source = ("import time\nTIMEOUT = 3.0\nasync def poll():\n"
              "    deadline = time.monotonic() + TIMEOUT\n    while True:\n"
              "        if time.monotonic() >= deadline:\n            return False\n"
              "        await asyncio.sleep(0.01)\n")
    assert bounded_python_deadline_loops(source) == {5}
    scanner = EngQualityScanner(["Python"])
    assert not any(f.pattern_id == "EQ-013" for f in scanner.scan({"src/poll.py": source}))
    reset = source.replace("        if time.monotonic()", "        deadline = time.monotonic() + TIMEOUT\n        if time.monotonic()")
    assert not bounded_python_deadline_loops(reset)
    early_continue = source.replace("        if time.monotonic()", "        if ready:\n            continue\n        if time.monotonic()")
    assert not bounded_python_deadline_loops(early_continue)
    unbounded = "async def retry():\n    while True:\n        # deadline is just a comment\n        await asyncio.sleep(1)\n"
    assert not bounded_python_deadline_loops(unbounded)
    assert any(f.pattern_id == "EQ-013" for f in scanner.scan({"src/retry.py": unbounded}))


@pytest.mark.parametrize("path", ["tests/unit/test_redaction.py", "src/config.py"])
async def test_secret_history_has_no_fixture_or_test_directory_exemption(tmp_path, monkeypatch, path):
    token = "AKIA" + "1234567890ABCDEF"
    (tmp_path / ".git").mkdir()
    async def git_command(args, **kwargs):
        if args[1] == "--version":
            stdout = "git version fixture"
        elif args[1] == "log":
            stdout = "a" * 40
        else:
            assert args[1] == "show"
            stdout = f"--- a/{path}\n+++ b/{path}\n+AWS_ACCESS_KEY_ID = '{token}'\n"
        return CommandResult(args=args, status="exited", returncode=0, stdout=stdout)
    monkeypatch.setattr("omargate.harness.suites.secrets_in_git.run_command", git_command)
    findings = await SecretsInGitSuite([]).run(str(tmp_path))
    detected = [row for row in findings if row.pattern_id == "SEC-004"]
    assert len(detected) == 1
    assert detected[0].severity == "P0"


def test_hash_pins_union_and_tool_configuration_are_supported_without_execution(tmp_path):
    (tmp_path / "requirements.txt").write_text("alpha==1.0\n")
    (tmp_path / "requirements.lock.txt").write_text("alpha==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\nbeta==2.0\n")
    (tmp_path / "requirements-dev.txt").write_text("tester==3.0\n")
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\ntestpaths = ["tests"]\n')
    scratch = tmp_path / "audit"
    scratch.mkdir()
    manifests = tuple(tmp_path / name for name in ["requirements.txt", "requirements.lock.txt", "requirements-dev.txt", "pyproject.toml"])
    pins, error = dep_audit._prepare_python_pins(tmp_path, manifests, scratch)
    assert error is None and pins == frozenset({("alpha", "1.0"), ("beta", "2.0"), ("tester", "3.0")})
    assert (scratch / "requirements.txt").read_text() == "alpha==1.0\nbeta==2.0\ntester==3.0\n"


@pytest.mark.parametrize("extra", [
    '[project]\ndependencies = ["hidden>=1"]\n',
    '[tool.poetry.dependencies]\nhidden = "*"\n',
    '[build-system]\nrequires = ["builder"]\n',
    '[tool.unknown]\nplugin = "hidden"\n',
])
def test_tool_only_exception_does_not_hide_dependency_managers(tmp_path, extra):
    (tmp_path / "requirements.txt").write_text("alpha==1.0\n")
    (tmp_path / "pyproject.toml").write_text(extra)
    scratch = tmp_path / "audit"
    scratch.mkdir()
    pins, error = dep_audit._prepare_python_pins(tmp_path, (tmp_path / "requirements.txt", tmp_path / "pyproject.toml"), scratch)
    assert pins is None and error == "unsupported_pip_input"


@pytest.mark.parametrize("extra", ["alpha==2.0\n", "alpha==1.0 --index-url=https://private.invalid\n", "-r hidden.txt\n"])
def test_conflicts_routing_and_indirection_still_refuse(tmp_path, extra):
    (tmp_path / "requirements.txt").write_text("alpha==1.0\n")
    (tmp_path / "requirements-dev.txt").write_text(extra)
    scratch = tmp_path / "audit"
    scratch.mkdir()
    pins, error = dep_audit._prepare_python_pins(tmp_path, (tmp_path / "requirements.txt", tmp_path / "requirements-dev.txt"), scratch)
    assert pins is None and error in {"unsupported_pip_input", "unsafe_pip_input"}


async def test_complete_copied_pin_census_is_required_in_real_audit_path(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("alpha==1.0\n")
    (tmp_path / "requirements.lock.txt").write_text("alpha==1.0\nbeta==2.0\n")
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\ntestpaths = ["tests"]\n')
    monkeypatch.setattr(dep_audit, "_has_pip_routing_configuration", lambda root: False)
    observed = []
    async def audit(args, cwd, **kwargs):
        assert not Path(cwd).is_relative_to(tmp_path)
        assert "--disable-pip" in args and "--no-deps" in args
        content = Path(args[args.index("-r") + 1]).read_text()
        assert content == "alpha==1.0\nbeta==2.0\n"
        observed.append(content)
        return CommandResult(args=args, status="exited", returncode=0,
            stdout=json.dumps({"dependencies": [{"name": "alpha", "version": "1.0", "vulns": []},
                                                 {"name": "beta", "version": "2.0", "vulns": []}], "fixes": []}))
    monkeypatch.setattr(dep_audit, "run_command", audit)
    finding, outcome = await dep_audit.DepAuditSuite([])._pip_audit(tmp_path)
    assert observed and finding is None and outcome.state == "clean"
