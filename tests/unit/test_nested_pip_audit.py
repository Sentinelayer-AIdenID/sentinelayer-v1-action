"""Python manifests nested in a repository remain covered by the audit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from omargate.harness.runner import CommandResult
from omargate.harness.suites import dep_audit
from omargate.harness.suites.dep_audit import DepAuditSuite


@pytest.fixture(autouse=True)
def _clear_pip_routing(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in dep_audit._PIP_ROUTING_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def _result(name: str = "example", version: str = "1.0.0") -> CommandResult:
    return CommandResult(
        args=[], status="exited", returncode=0,
        stdout=json.dumps({
            "dependencies": [{"name": name, "version": version, "vulns": []}],
            "fixes": [],
        }),
        stderr="", reason_code="exited", cleanup_proven=True,
    )


def _api_dir(root: Path) -> Path:
    api = root / "apps" / "api"
    api.mkdir(parents=True)
    return api


def _hashed_pin(name: str, version: str) -> str:
    return f"{name}=={version} --hash=sha256:{'a' * 64}\n"


@pytest.mark.anyio
async def test_aidenid_nested_tool_only_pyproject_is_not_applicable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api_dir(tmp_path)
    (api / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\npythonpath = ["."]\n'
        '[tool.ruff]\nline-length = 100\n'
        '[tool.ruff.lint]\nselect = ["E", "F"]\n', encoding="utf-8",
    )

    async def no_spawn(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("tool-only configuration has no packages to audit")

    monkeypatch.setattr(dep_audit, "run_command", no_spawn)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))

    assert result.findings == []
    assert result.evidence.complete is True
    pip = next(item for item in result.evidence.outcomes if item.ecosystem == "pip")
    assert pip.applicable is False
    assert pip.lockfile_path is None


@pytest.mark.anyio
async def test_nested_pinned_requirements_are_audited_in_private_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api_dir(tmp_path)
    (api / "pyproject.toml").write_text(
        '[tool.ruff]\nline-length = 100\n', encoding="utf-8",
    )
    (api / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    calls: list[Path] = []

    async def fake_run(
        args: list[str], *, cwd: Path, timeout_s: int, project_root: Path,
    ) -> CommandResult:
        calls.append(cwd)
        assert args[:4] == ["pip-audit", "--strict", "--disable-pip", "--no-deps"]
        assert (cwd / "requirements.txt").read_text(encoding="utf-8") == "example==1.0.0\n"
        assert cwd != api and tmp_path.resolve() not in cwd.resolve().parents
        assert project_root == tmp_path.resolve() and timeout_s == 50
        return _result()

    monkeypatch.setattr(dep_audit, "run_command", fake_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)

    assert finding is None and outcome.state == "clean"
    assert outcome.lockfile_path == "apps/api/requirements.txt"
    assert len(calls) == 1 and not calls[0].exists()


@pytest.mark.anyio
async def test_nested_requirements_directory_pins_are_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirements = _api_dir(tmp_path) / "requirements"
    requirements.mkdir()
    (requirements / "production.txt").write_text("example==1.0.0\n", encoding="utf-8")
    calls = 0

    async def fake_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal calls
        calls += 1
        return _result()

    monkeypatch.setattr(dep_audit, "run_command", fake_run)
    _, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)
    assert outcome.state == "clean" and calls == 1
    assert outcome.lockfile_path == "apps/api/requirements/production.txt"


@pytest.mark.anyio
@pytest.mark.parametrize("pair_location", ("root", "nested"))
async def test_aidenid_pip_compile_lock_covers_declared_inputs(
    pair_location: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api_dir(tmp_path)
    (api / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\npythonpath = ["."]\n'
        '[tool.ruff]\nline-length = 100\n', encoding="utf-8",
    )
    pair = tmp_path if pair_location == "root" else api
    (pair / "requirements.in").write_text(
        "alembic\nclick>=8.3.3\n", encoding="utf-8",
    )
    (pair / "requirements.lock").write_text(
        _hashed_pin("alembic", "1.18.4") + _hashed_pin("click", "8.3.3"),
        encoding="utf-8",
    )
    calls = 0

    async def fake_run(
        args: list[str], *, cwd: Path, timeout_s: int, project_root: Path,
    ) -> CommandResult:
        nonlocal calls
        calls += 1
        assert (cwd / "requirements.txt").read_text(encoding="utf-8") == (
            "alembic==1.18.4\nclick==8.3.3\n"
        )
        assert cwd != tmp_path and project_root == tmp_path.resolve()
        return CommandResult(
            args=args, status="exited", returncode=0,
            stdout=json.dumps({
                "dependencies": [
                    {"name": "alembic", "version": "1.18.4", "vulns": []},
                    {"name": "click", "version": "8.3.3", "vulns": []},
                ],
                "fixes": [],
            }),
            stderr="", reason_code="exited", cleanup_proven=True,
        )

    monkeypatch.setattr(dep_audit, "run_command", fake_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)
    assert finding is None and outcome.state == "clean"
    assert outcome.lockfile_path == (
        "requirements.lock" if pair_location == "root"
        else "apps/api/requirements.lock"
    )
    assert calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case", ["missing_lock", "unpinned_lock", "unhashed_lock", "drifted_lock"],
)
async def test_pip_compile_lock_pair_fails_closed_when_invalid(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "requirements.in").write_text("click>=8.3.3\n", encoding="utf-8")
    if case != "missing_lock":
        lock = {
            "unpinned_lock": "click>=8.3.3\n",
            "unhashed_lock": "click==8.3.3\n",
            "drifted_lock": _hashed_pin("click", "8.2.0"),
        }[case]
        (tmp_path / "requirements.lock").write_text(lock, encoding="utf-8")

    async def no_spawn(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("invalid lock graph must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", no_spawn)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)
    assert finding is not None and finding.severity == "P0"
    assert outcome.state == "indeterminate"
    assert outcome.reason_code == (
        "missing_lockfile" if case == "missing_lock"
        else "unsupported_pip_input" if case == "drifted_lock"
        else "unsafe_pip_input"
    )
    if case == "missing_lock":
        assert outcome.lockfile_path is None


@pytest.mark.anyio
async def test_symlinked_nested_python_input_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    external = tmp_path.parent / f"{tmp_path.name}-outside-requirements.txt"
    external.write_text("example==1.0.0\n", encoding="utf-8")
    manifest = _api_dir(tmp_path) / "requirements.txt"
    try:
        manifest.symlink_to(external)
    except (NotImplementedError, OSError):
        pytest.skip("file symlinks are not available")

    async def no_spawn(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("symlinked input must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", no_spawn)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)
    assert finding is not None and finding.severity == "P0"
    assert outcome.state == "indeterminate"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case", [
        "unlocked_project", "malformed_pyproject", "unpinned_requirements",
        "requirements_in", "nested_private_index", "conflicting_pins",
        "too_many_manifests",
    ],
)
async def test_nested_python_invalid_inputs_fail_closed_before_spawn(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api_dir(tmp_path)
    if case == "unlocked_project":
        (api / "pyproject.toml").write_text(
            '[project]\nname = "api"\ndependencies = ["example>=1"]\n', encoding="utf-8",
        )
    elif case == "malformed_pyproject":
        (api / "pyproject.toml").write_text("[tool.ruff\n", encoding="utf-8")
    elif case == "unpinned_requirements":
        (api / "requirements.txt").write_text("example>=1\n", encoding="utf-8")
    elif case == "requirements_in":
        (api / "requirements.in").write_text("example==1.0.0\n", encoding="utf-8")
    elif case == "nested_private_index":
        (api / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
        (api / "pip.conf").write_text(
            "[global]\nindex-url=https://private.example/simple\n", encoding="utf-8",
        )
    elif case == "conflicting_pins":
        (tmp_path / "requirements.txt").write_text("example==2.0.0\n", encoding="utf-8")
        (api / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    else:
        for index in range(33):
            directory = tmp_path / "apps" / f"api{index}"
            directory.mkdir()
            (directory / "requirements.txt").write_text(
                "example==1.0.0\n", encoding="utf-8",
            )

    async def no_spawn(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("invalid or unbounded input must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", no_spawn)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)
    assert finding is not None and finding.severity == "P0"
    assert outcome.state == "indeterminate"


@pytest.mark.anyio
async def test_nested_python_source_change_during_audit_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirements = _api_dir(tmp_path) / "requirements.txt"
    requirements.write_text("example==1.0.0\n", encoding="utf-8")

    async def fake_run(*_args: object, **_kwargs: object) -> CommandResult:
        requirements.write_text("example==2.0.0\n", encoding="utf-8")
        return _result()

    monkeypatch.setattr(dep_audit, "run_command", fake_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)
    assert finding is not None and finding.severity == "P0"
    assert outcome.reason_code == "audit_input_changed"


@pytest.mark.anyio
@pytest.mark.parametrize("name", ["requirements.txt", "pyproject.toml"])
async def test_oversized_nested_python_manifest_is_rejected_before_open_or_read(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _api_dir(tmp_path) / name
    manifest.write_bytes(b"x" * (dep_audit._MAX_REQUIREMENTS_BYTES + 1))
    original_open = dep_audit.os.open
    original_read_bytes = Path.read_bytes

    def guarded_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if Path(path) == manifest:
            raise AssertionError("oversized source must not be opened")
        return original_open(path, flags, *args, **kwargs)

    def guarded_read_bytes(path: Path) -> bytes:
        if path == manifest:
            raise AssertionError("oversized source must not use Path.read_bytes")
        return original_read_bytes(path)

    async def no_spawn(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("oversized source must not spawn")

    monkeypatch.setattr(dep_audit.os, "open", guarded_open)
    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    monkeypatch.setattr(dep_audit, "run_command", no_spawn)

    assert dep_audit._python_manifest_fingerprint(tmp_path, manifest) is None
    assert not dep_audit._copy_safe_project_file(
        manifest.parent, manifest, tmp_path / "copy.txt",
        max_bytes=dep_audit._MAX_REQUIREMENTS_BYTES,
    )
    if name == "pyproject.toml":
        assert not dep_audit._tool_only_pyproject(manifest)
    else:
        assert dep_audit._load_pinned_requirements(manifest.parent, manifest) is None
        assert dep_audit._load_declared_requirements(manifest.parent, manifest) is None

    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)
    assert finding is not None and finding.severity == "P0"
    assert outcome.state == "indeterminate"
    assert outcome.reason_code == "unsafe_pip_input"


def test_python_manifest_growth_between_stat_and_open_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("example==1.0.0\n", encoding="utf-8")
    original_open = dep_audit.os.open
    original_read_bytes = Path.read_bytes
    opened = False

    def grow_before_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal opened
        if Path(path) == manifest:
            opened = True
            manifest.write_bytes(b"x" * (dep_audit._MAX_REQUIREMENTS_BYTES + 1))
        return original_open(path, flags, *args, **kwargs)

    def forbid_read_bytes(path: Path) -> bytes:
        if path == manifest:
            raise AssertionError("grown source must not use Path.read_bytes")
        return original_read_bytes(path)

    monkeypatch.setattr(dep_audit.os, "open", grow_before_open)
    monkeypatch.setattr(Path, "read_bytes", forbid_read_bytes)

    assert dep_audit._read_safe_project_bytes(
        tmp_path, manifest, max_bytes=dep_audit._MAX_REQUIREMENTS_BYTES,
    ) is None
    assert opened
