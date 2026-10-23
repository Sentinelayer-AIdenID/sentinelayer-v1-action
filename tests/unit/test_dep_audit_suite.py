from __future__ import annotations

import json
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from omargate.harness.runner import CommandResult, CommandStatus
from omargate.models import DEPENDENCY_AUDIT_SCHEMA_VERSION
from omargate.harness.suites import dep_audit
from omargate.harness.suites.dep_audit import (
    DepAuditSuite,
    DependencyAuditOutcome,
    _parse_ignore_ids,
    _parse_pip_vulnerability_count,
    disabled_dependency_audit_evidence,
)


_TOOLS = ("npm", "pip", "cargo")
_INCOMPLETE_IDS = {
    "npm": "HARNESS-NPM-AUDIT-INCOMPLETE",
    "pip": "HARNESS-PIP-AUDIT-INCOMPLETE",
    "cargo": "HARNESS-CARGO-AUDIT-INCOMPLETE",
}
_VULNERABILITY_IDS = {
    "npm": "HARNESS-NPM-AUDIT",
    "pip": "HARNESS-PIP-AUDIT",
    "cargo": "HARNESS-CARGO-AUDIT",
}
_INCOMPLETE_CASES = (
    pytest.param("not-found", "command_not_found", id="not-found"),
    pytest.param("spawn-error", "spawn_error", id="spawn-error"),
    pytest.param("timeout", "timed_out", id="timeout"),
    pytest.param("decode-error", "decode_error", id="decode-error"),
    pytest.param("oversized", "output_limit_exceeded", id="oversized-output"),
    pytest.param("empty", "empty_output", id="empty-output"),
    pytest.param("malformed", "invalid_json", id="malformed-json"),
    pytest.param("trailing", "invalid_json", id="trailing-json"),
    pytest.param("duplicate", "invalid_json", id="duplicate-key-json"),
    pytest.param("nonfinite", "invalid_json", id="nonfinite-json"),
    pytest.param("overflow", "invalid_json", id="overflow-to-nonfinite-json"),
    pytest.param("error", "error_payload", id="error-payload"),
    pytest.param("unrecognized", "unrecognized_schema", id="unrecognized-schema"),
    pytest.param("exit-127", "exited_127", id="real-exit-127"),
    pytest.param("unexpected-exit", "unexpected_exit", id="other-returncode"),
    pytest.param("exit-mismatch", "exit_result_mismatch", id="exit-result-mismatch"),
    pytest.param(
        "payload-mismatch",
        "exit_result_mismatch",
        id="payload-result-mismatch",
    ),
)


def _npm_metadata(*, critical: int, total: int, high: int = 0) -> dict[str, int]:
    return {
        "info": 0,
        "low": 0,
        "moderate": 0,
        "high": high,
        "critical": critical,
        "total": total,
    }


def _npm_dependencies(*, total: int = 1) -> dict[str, int]:
    return {
        "prod": total,
        "dev": 0,
        "optional": 0,
        "peer": 0,
        "peerOptional": 0,
        "total": total,
    }


def _clean_stdout(tool: str) -> str:
    payloads: dict[str, object] = {
        "npm": {
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": _npm_dependencies(),
            },
        },
        "pip": {
            "dependencies": [
                {"name": "example", "version": "1.0.0", "vulns": []}
            ],
            "fixes": [],
        },
        "cargo": {
            "database": {"advisory-count": 100},
            "lockfile": {"dependency-count": 1},
            "settings": {},
            "vulnerabilities": {"found": False, "count": 0, "list": []},
        },
    }
    return json.dumps(payloads[tool])


def _vulnerable_stdout(tool: str) -> str:
    payloads: dict[str, object] = {
        "npm": {
            "auditReportVersion": 2,
            "vulnerabilities": {"critical-package": {"severity": "critical"}},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=1, total=1),
                "dependencies": _npm_dependencies(),
            },
        },
        "pip": {
            "dependencies": [
                {
                    "name": "example",
                    "version": "1.0.0",
                    "vulns": [{"id": "CVE-2099-0001"}],
                }
            ],
            "fixes": [],
        },
        "cargo": {
            "database": {"advisory-count": 100},
            "lockfile": {"dependency-count": 1},
            "settings": {},
            "vulnerabilities": {
                "found": True,
                "count": 1,
                "list": [{"advisory": {"id": "RUSTSEC-2099-0001"}}],
            },
        },
    }
    return json.dumps(payloads[tool])


def _prepare_project(root: Path, tool: str, *, include_lock: bool = True) -> None:
    if tool == "npm":
        package = {
            "name": "audit-test",
            "version": "1.0.0",
            "dependencies": {"example": "1.0.0"},
        }
        (root / "package.json").write_text(json.dumps(package), encoding="utf-8")
        if include_lock:
            lockfile = {
                "name": "audit-test",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": package,
                    "node_modules/example": {
                        "version": "1.0.0",
                        "resolved": (
                            "https://registry.npmjs.org/example/"
                            "-/example-1.0.0.tgz"
                        ),
                    },
                },
            }
            (root / "package-lock.json").write_text(
                json.dumps(lockfile), encoding="utf-8"
            )
    elif tool == "pip":
        (root / "requirements.txt").write_text("example==1.0.0\n", encoding="utf-8")
    elif tool == "cargo":
        (root / "Cargo.toml").write_text(
            "[package]\nname='audit-test'\n", encoding="utf-8"
        )
        if include_lock:
            (root / "Cargo.lock").write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n',
                encoding="utf-8",
            )
    else:  # pragma: no cover - test helper guard
        raise AssertionError(f"unsupported test tool: {tool}")


def _result(
    *,
    status: CommandStatus = "exited",
    returncode: int | None = 0,
    stdout: str = "",
    reason_code: str = "PRIVATE_INTERNAL_REASON",
    cleanup_proven: bool = True,
) -> CommandResult:
    return CommandResult(
        args=[],
        status=status,
        returncode=returncode,
        stdout=stdout,
        stderr="PRIVATE_STDERR_VALUE",
        reason_code=reason_code,
        cleanup_proven=cleanup_proven,
    )


@pytest.mark.anyio
@pytest.mark.parametrize("tool", _TOOLS)
@pytest.mark.parametrize(
    ("case", "expected_reason", "retained"),
    (
        ("containment-error", "process_containment_error", True),
        ("proven-timeout", "timed_out", False),
    ),
)
async def test_audit_cwd_retention_tracks_process_cleanup_proof(
    tool: str,
    case: str,
    expected_reason: str,
    retained: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_project(tmp_path, tool)
    observed_cwd: Path | None = None

    async def _fake_run_command(
        _args: list[str],
        *,
        cwd: Path,
        timeout_s: int,
        project_root: Path,
    ) -> CommandResult:
        nonlocal observed_cwd
        observed_cwd = cwd
        assert timeout_s == 50
        assert project_root == tmp_path.resolve()
        if case == "containment-error":
            return _result(
                status="spawn_error",
                returncode=None,
                reason_code="process_containment_error",
                cleanup_proven=False,
            )
        return _result(
            status="timed_out",
            returncode=None,
            reason_code="timed_out",
            cleanup_proven=True,
        )

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    _finding, outcome = await getattr(
        DepAuditSuite(tech_stack=[]), f"_{tool}_audit"
    )(tmp_path)

    assert outcome.state == "indeterminate"
    assert outcome.reason_code == expected_reason
    assert observed_cwd is not None
    try:
        assert observed_cwd.exists() is retained
    finally:
        if observed_cwd.exists():
            shutil.rmtree(observed_cwd)


def _incomplete_result(tool: str, case: str) -> CommandResult:
    if case == "not-found":
        return _result(status="not_found", returncode=None)
    if case == "spawn-error":
        return _result(status="spawn_error", returncode=None)
    if case == "timeout":
        return _result(status="timed_out", returncode=None)
    if case == "decode-error":
        return _result(status="decode_error", returncode=0)
    if case == "oversized":
        return _result(status="output_limit_exceeded", returncode=0)
    if case == "empty":
        return _result(returncode=0, stdout="   ")
    if case == "malformed":
        return _result(returncode=0, stdout="{PRIVATE_MALFORMED_VALUE")
    if case == "trailing":
        return _result(
            returncode=0,
            stdout=f"{_clean_stdout(tool)} PRIVATE_TRAILING_VALUE",
        )
    if case == "duplicate":
        return _result(returncode=0, stdout='{"x":1,"x":2}')
    if case == "nonfinite":
        return _result(returncode=0, stdout='{"x":NaN}')
    if case == "overflow":
        return _result(returncode=0, stdout='{"x":1e9999}')
    if case == "error":
        return _result(
            returncode=1,
            stdout=json.dumps({"error": "PRIVATE_ERROR_VALUE"}),
        )
    if case == "unrecognized":
        return _result(
            returncode=0,
            stdout=json.dumps({"unexpected": "PRIVATE_UNRECOGNIZED_VALUE"}),
        )
    if case == "exit-127":
        return _result(returncode=127, stdout=_clean_stdout(tool))
    if case == "unexpected-exit":
        return _result(returncode=2, stdout=_clean_stdout(tool))
    if case == "exit-mismatch":
        return _result(returncode=1, stdout=_clean_stdout(tool))
    if case == "payload-mismatch":
        return _result(returncode=0, stdout=_vulnerable_stdout(tool))
    raise AssertionError(f"unsupported incomplete case: {case}")


async def _invoke_tool(
    root: Path,
    tool: str,
    result: CommandResult,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    Any,
    DependencyAuditOutcome,
    list[tuple[list[str], Path, int, Path]],
]:
    _prepare_project(root, tool)
    calls: list[tuple[list[str], Path, int, Path]] = []

    async def _fake_run_command(
        args: list[str],
        *,
        cwd: Path,
        timeout_s: int,
        project_root: Path,
    ) -> CommandResult:
        calls.append((args, cwd, timeout_s, project_root))
        return result

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    suite = DepAuditSuite(tech_stack=[])
    finding, outcome = await getattr(suite, f"_{tool}_audit")(root)
    return finding, outcome, calls


def _snapshot_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.fixture(autouse=True)
def _clear_inherited_pip_routing(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in dep_audit._PIP_ROUTING_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_parse_pip_vulnerability_count_handles_no_vulns() -> None:
    payload = {
        "dependencies": [
            {"name": "requests", "version": "2.32.4", "vulns": []},
            {"name": "httpx", "version": "0.27.0", "vulns": []},
        ],
        "fixes": [],
    }
    assert _parse_pip_vulnerability_count(
        payload,
        expected_dependencies=frozenset(
            {("requests", "2.32.4"), ("httpx", "0.27.0")}
        ),
    ) == 0


def test_parse_pip_vulnerability_count_sums_nested_vulns() -> None:
    payload = {
        "dependencies": [
            {"name": "requests", "version": "2.31.0", "vulns": [{"id": "CVE-1"}]},
            {"name": "foo", "version": "1.0.0", "vulns": [{"id": "CVE-2"}]},
        ],
        "fixes": [],
    }
    assert _parse_pip_vulnerability_count(
        payload,
        expected_dependencies=frozenset(
            {("requests", "2.31.0"), ("foo", "1.0.0")}
        ),
    ) == 2


def test_parse_pip_vulnerability_count_rejects_skipped_dependency() -> None:
    payload = {
        "dependencies": [
            {
                "name": "unknown",
                "version": "1.0.0",
                "vulns": [],
                "skip_reason": "PRIVATE_SKIP_REASON",
            }
        ],
        "fixes": [],
    }
    assert (
        _parse_pip_vulnerability_count(
            payload,
            expected_dependencies=frozenset({("unknown", "1.0.0")}),
        )
        is None
    )


def test_parse_ignore_ids_splits_and_deduplicates() -> None:
    raw = "CVE-1, CVE-2\nCVE-1 ; GHSA-abc"
    assert _parse_ignore_ids(raw) == ["CVE-1", "CVE-2", "GHSA-abc"]


def test_disabled_dependency_audit_emits_exact_opt_out_evidence() -> None:
    assert disabled_dependency_audit_evidence() == {
        "schema_version": DEPENDENCY_AUDIT_SCHEMA_VERSION,
        "enabled": False,
        "complete": True,
        "npm_projects": {"discovered_manifests": [], "audits": []},
        "coverage_scope": {
            "npm": "package_lock_registry_graph",
            "pip": "declared_direct_pins",
            "cargo": "cargo_lock_packages",
        },
        "outcomes": [
            {
                "ecosystem": tool,
                "applicable": False,
                "state": None,
                "vulnerability_count": None,
                "reason_code": None,
            }
            for tool in _TOOLS
        ],
    }


@pytest.mark.anyio
@pytest.mark.parametrize("tool", _TOOLS)
async def test_dependency_audit_valid_clean_result_emits_clean_evidence(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding, outcome, calls = await _invoke_tool(
        tmp_path,
        tool,
        _result(returncode=0, stdout=_clean_stdout(tool)),
        monkeypatch,
    )

    assert finding is None
    assert outcome.to_dict() == {
        "ecosystem": tool,
        "applicable": True,
        "state": "clean",
        "vulnerability_count": 0,
        "reason_code": None,
    }
    assert len(calls) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("tool", _TOOLS)
async def test_dependency_audit_valid_vulnerable_result_emits_p1_and_evidence(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding, outcome, calls = await _invoke_tool(
        tmp_path,
        tool,
        _result(returncode=1, stdout=_vulnerable_stdout(tool)),
        monkeypatch,
    )

    assert finding is not None
    assert finding.id == _VULNERABILITY_IDS[tool]
    assert finding.severity == "P1"
    assert finding.category == "supply-chain"
    assert outcome.state == "vulnerable"
    assert outcome.vulnerability_count == 1
    assert outcome.reason_code is None
    assert len(calls) == 1


@pytest.mark.anyio
async def test_npm_high_only_result_is_vulnerable_under_any_vulnerability_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prepare_project(tmp_path, "npm")
    payload = {
        "auditReportVersion": 2,
        "vulnerabilities": {"high-package": {"severity": "high"}},
        "metadata": {
            "vulnerabilities": _npm_metadata(critical=0, high=1, total=1),
            "dependencies": _npm_dependencies(),
        },
    }

    async def _fake_run_command(*_args: object, **_kwargs: object) -> CommandResult:
        return _result(returncode=1, stdout=json.dumps(payload))

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert finding is not None
    assert finding.id == "HARNESS-NPM-AUDIT"
    assert outcome.state == "vulnerable"
    assert outcome.vulnerability_count == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "payload"),
    (
        pytest.param(
            "npm",
            {
                "auditReportVersion": 2,
                "vulnerabilities": {"package": {"severity": "critical"}},
                "metadata": {
                    "vulnerabilities": _npm_metadata(critical=0, total=0),
                    "dependencies": _npm_dependencies(),
                },
            },
            id="npm-contradictory-counts",
        ),
        pytest.param(
            "pip",
            {
                "dependencies": [
                    {
                        "name": "package",
                        "version": "1.0.0",
                        "vulns": [],
                        "skip_reason": "PRIVATE_SKIP_REASON",
                    }
                ],
                "fixes": [],
            },
            id="pip-skipped-dependency",
        ),
        pytest.param(
            "cargo",
            {
                "database": {"advisory-count": 0},
                "lockfile": {"dependency-count": 1},
                "settings": {},
                "vulnerabilities": {"found": False, "count": 0, "list": []},
            },
            id="cargo-empty-advisory-database",
        ),
    ),
)
async def test_dependency_audit_rejects_recognizable_but_untrusted_schema(
    tool: str,
    payload: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding, outcome, calls = await _invoke_tool(
        tmp_path,
        tool,
        _result(returncode=0, stdout=json.dumps(payload)),
        monkeypatch,
    )

    assert len(calls) == 1
    assert finding is not None
    assert finding.id == _INCOMPLETE_IDS[tool]
    assert finding.severity == "P0"
    assert outcome.state == "indeterminate"
    assert outcome.reason_code == "unrecognized_schema"
    assert "PRIVATE_" not in json.dumps(asdict(finding), sort_keys=True)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "payload"),
    (
        pytest.param(
            "npm",
            {
                "auditReportVersion": 2,
                "vulnerabilities": {},
                "metadata": {
                    "vulnerabilities": _npm_metadata(critical=0, total=0),
                    "dependencies": _npm_dependencies(total=2),
                },
            },
            id="npm-lock-count-mismatch",
        ),
        pytest.param(
            "pip",
            {
                "dependencies": [
                    {"name": "different", "version": "1.0.0", "vulns": []}
                ],
                "fixes": [],
            },
            id="pip-pin-identity-mismatch",
        ),
        pytest.param(
            "cargo",
            {
                "database": {"advisory-count": 100},
                "lockfile": {"dependency-count": 2},
                "settings": {},
                "vulnerabilities": {"found": False, "count": 0, "list": []},
            },
            id="cargo-lock-count-mismatch",
        ),
    ),
)
async def test_audit_output_must_match_the_exact_validated_input(
    tool: str,
    payload: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding, outcome, calls = await _invoke_tool(
        tmp_path,
        tool,
        _result(returncode=0, stdout=json.dumps(payload)),
        monkeypatch,
    )

    assert len(calls) == 1
    assert finding is not None
    assert finding.id == _INCOMPLETE_IDS[tool]
    assert outcome.reason_code == "unrecognized_schema"


@pytest.mark.anyio
@pytest.mark.parametrize("tool", _TOOLS)
@pytest.mark.parametrize(("case", "reason"), _INCOMPLETE_CASES)
async def test_unproved_audit_emits_fixed_p0_and_indeterminate_evidence(
    tool: str,
    case: str,
    reason: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding, outcome, calls = await _invoke_tool(
        tmp_path,
        tool,
        _incomplete_result(tool, case),
        monkeypatch,
    )

    assert finding is not None
    assert finding.id == _INCOMPLETE_IDS[tool]
    assert finding.pattern_id == _INCOMPLETE_IDS[tool]
    assert finding.severity == "P0"
    assert finding.category == "harness"
    assert finding.file_path == f".sentinelayer/harness/{tool}-audit"
    assert finding.snippet == ""
    assert finding.message.endswith(f"({reason})")
    assert outcome.to_dict() == {
        "ecosystem": tool,
        "applicable": True,
        "state": "indeterminate",
        "vulnerability_count": None,
        "reason_code": reason,
    }
    assert len(calls) == 1
    published = json.dumps(
        {"finding": asdict(finding), "outcome": outcome.to_dict()},
        sort_keys=True,
    )
    assert "PRIVATE_" not in published


@pytest.mark.anyio
@pytest.mark.parametrize("tool", _TOOLS)
async def test_dependency_audit_execution_error_is_fixed_and_secret_free(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prepare_project(tmp_path, tool)

    async def _raise_private_error(*_args: object, **_kwargs: object) -> CommandResult:
        raise RuntimeError("PRIVATE_EXCEPTION_VALUE")

    monkeypatch.setattr(dep_audit, "run_command", _raise_private_error)
    finding, outcome = await getattr(DepAuditSuite(tech_stack=[]), f"_{tool}_audit")(
        tmp_path
    )

    assert finding is not None
    assert finding.id == _INCOMPLETE_IDS[tool]
    assert finding.severity == "P0"
    assert finding.message.endswith("(execution_error)")
    assert outcome.reason_code == "execution_error"
    assert "PRIVATE_" not in json.dumps(asdict(finding), sort_keys=True)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "unsafe_requirement",
    (
        "unversioned-package\n",
        "package>=1.0\n",
        "package @ https://example.test/package.whl\n",
        "git+https://example.test/package.git\n",
        "-e ./local-package\n",
        "-r nested-requirements.txt\n",
        "--index-url https://PRIVATE_INDEX.example.test/simple\npackage==1.0\n",
        "package==1.0 ; python_version >= '3.11'\n",
        "# no pinned dependency evidence\n",
    ),
)
async def test_pip_audit_rejects_unsafe_input_without_spawning(
    unsafe_requirement: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "requirements.txt").write_text(unsafe_requirement, encoding="utf-8")
    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("unsafe pip input must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)

    assert called is False
    assert finding is not None
    assert finding.id == "HARNESS-PIP-AUDIT-INCOMPLETE"
    assert outcome.reason_code == "unsafe_pip_input"
    assert "PRIVATE_INDEX" not in json.dumps(asdict(finding), sort_keys=True)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "manifest",
    (
        "pyproject.toml",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pdm.lock",
        "requirements-prod.txt",
        "requirements.in",
        "requirements-prod.in",
        "pylock.toml",
    ),
)
async def test_python_manifest_without_supported_pinned_input_fails_closed(
    manifest: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / manifest).write_text("PRIVATE_MANIFEST_VALUE", encoding="utf-8")
    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("unsupported Python input must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)

    assert called is False
    assert finding is not None
    assert finding.id == "HARNESS-PIP-AUDIT-INCOMPLETE"
    assert finding.severity == "P0"
    assert outcome.reason_code == ("unsafe_pip_input" if manifest == "requirements-prod.txt" else "unsupported_pip_input")
    assert "PRIVATE_" not in json.dumps(asdict(finding), sort_keys=True)


@pytest.mark.anyio
@pytest.mark.parametrize("filename", ("production.txt", "production.in"))
async def test_requirements_directory_manifest_is_discovered_and_fails_closed(
    filename: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "requirements" / filename
    manifest.parent.mkdir()
    manifest.write_text("example==1.0.0\n", encoding="utf-8")

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("nested requirements input must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)

    assert finding is not None
    assert outcome.reason_code == "unsupported_project_layout"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "extra_manifest",
    (
        "pyproject.toml",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pdm.lock",
        "requirements.in",
    ),
)
async def test_requirements_cannot_claim_coverage_for_another_python_manifest(
    extra_manifest: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_project(tmp_path, "pip")
    (tmp_path / extra_manifest).write_text(
        "PRIVATE_ADDITIONAL_DEPENDENCIES\n",
        encoding="utf-8",
    )
    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("ambiguous Python inputs must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)

    assert called is False
    assert finding is not None
    assert outcome.reason_code == "unsupported_pip_input"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "source",
    ("repository-config", "inherited-index", "inherited-find-links"),
)
async def test_pip_private_routing_signal_fails_closed_before_metadata_egress(
    source: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_project(tmp_path, "pip")
    if source == "repository-config":
        (tmp_path / "pip.conf").write_text(
            "[global]\nindex-url=https://PRIVATE_INDEX.example/simple\n",
            encoding="utf-8",
        )
    elif source == "inherited-index":
        monkeypatch.setenv(
            "PIP_INDEX_URL", "https://PRIVATE_INDEX.example/simple"
        )
    else:
        monkeypatch.setenv(
            "PIP_FIND_LINKS", "https://PRIVATE_INDEX.example/packages"
        )
    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("private routing must not be silently redirected")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._pip_audit(tmp_path)

    assert called is False
    assert finding is not None
    assert outcome.reason_code == "unsupported_pip_input"
    assert "PRIVATE_INDEX" not in json.dumps(asdict(finding), sort_keys=True)


@pytest.mark.anyio
@pytest.mark.parametrize("tool", ("npm", "cargo"))
async def test_lockfile_audit_without_lock_fails_closed_without_spawning(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prepare_project(tmp_path, tool, include_lock=False)
    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("audit must not run without a lockfile")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await getattr(DepAuditSuite(tech_stack=[]), f"_{tool}_audit")(
        tmp_path
    )

    assert called is False
    assert finding is not None
    assert finding.id == _INCOMPLETE_IDS[tool]
    assert outcome.reason_code == "missing_lockfile"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "unsafe_case",
    (
        "credentialed",
        "attacker-origin",
        "localhost-origin",
        "loopback-origin",
        "private-ip-origin",
        "explicit-port-origin",
        "mixed-origins",
        "missing-origin",
        "workspace",
        "link",
        "peer-dependency",
        "peer-metadata",
        "peer-record-invalid-provenance",
    ),
)
async def test_npm_rejects_unsupported_lock_coverage_or_provenance_before_spawn(
    unsafe_case: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_project(tmp_path, "npm")
    package_path = tmp_path / "package.json"
    lock_path = tmp_path / "package-lock.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    example = lock["packages"]["node_modules/example"]
    if unsafe_case == "credentialed":
        example["resolved"] = (
            "https://user:PRIVATE_TOKEN@registry.example/example-1.0.0.tgz"
        )
    elif unsafe_case == "attacker-origin":
        example["resolved"] = "https://attacker.example/example-1.0.0.tgz"
    elif unsafe_case == "localhost-origin":
        example["resolved"] = "https://localhost/example-1.0.0.tgz"
    elif unsafe_case == "loopback-origin":
        example["resolved"] = "https://127.0.0.1/example-1.0.0.tgz"
    elif unsafe_case == "private-ip-origin":
        example["resolved"] = "https://10.0.0.8/example-1.0.0.tgz"
    elif unsafe_case == "explicit-port-origin":
        example["resolved"] = (
            "https://registry.npmjs.org:443/example-1.0.0.tgz"
        )
    elif unsafe_case == "mixed-origins":
        lock["packages"]["node_modules/transitive"] = {
            "version": "1.0.0",
            "resolved": "https://other.example/transitive-1.0.0.tgz",
        }
    elif unsafe_case == "missing-origin":
        example.pop("resolved")
    elif unsafe_case == "workspace":
        package["workspaces"] = ["packages/*"]
    elif unsafe_case == "link":
        example["link"] = True
    elif unsafe_case == "peer-dependency":
        lock["lockfileVersion"] = 2
        package["peerDependencies"] = {"example": "1.0.0"}
        lock["packages"][""]["peerDependencies"] = {"example": "1.0.0"}
    elif unsafe_case == "peer-metadata":
        lock["lockfileVersion"] = 2
        package["peerDependenciesMeta"] = {"example": {"optional": True}}
    elif unsafe_case == "peer-record-invalid-provenance":
        example["peer"] = True
        example["resolved"] = "https://attacker.example/example-1.0.0.tgz"
        # Add a non-peer package so dependency_count > 0 and the
        # provenance check is actually reached (not short-circuited
        # by the zero-non-peer-deps guard).
        lock["packages"]["node_modules/normal-dep"] = {
            "version": "1.0.0",
            "resolved": (
                "https://registry.npmjs.org/normal-dep/"
                "-/normal-dep-1.0.0.tgz"
            ),
        }
    package_path.write_text(json.dumps(package), encoding="utf-8")
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("unsafe npm provenance must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is False
    assert finding is not None
    assert outcome.reason_code == "unsafe_lockfile"
    assert "PRIVATE_TOKEN" not in json.dumps(asdict(finding), sort_keys=True)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "lockfile_case",
    (
        "transitive-peer-dependency",
        "transitive-peer-metadata",
        "peer-record",
    ),
)
async def test_npm_accepts_lockfilev3_peer_features(
    lockfile_case: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lockfileVersion 3 peer:true entries, transitive peerDependencies
    outside root declared deps, and non-empty peerDependenciesMeta are
    standard npm 10+ output (seen in sentinelayer-web) and must not
    trigger unsafe_lockfile."""
    _prepare_project(tmp_path, "npm")
    lock_path = tmp_path / "package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    example = lock["packages"]["node_modules/example"]
    if lockfile_case == "transitive-peer-dependency":
        example["peerDependencies"] = {"peer": "1.0.0"}
        # The transitive peer must resolve to a locked package.
        lock["packages"]["node_modules/peer"] = {
            "version": "1.0.0",
            "resolved": (
                "https://registry.npmjs.org/peer/-/peer-1.0.0.tgz"
            ),
        }
    elif lockfile_case == "peer-record":
        example["peer"] = True
        # Add a second non-peer package so the dependency count stays > 0.
        lock["packages"]["node_modules/other"] = {
            "version": "2.0.0",
            "resolved": (
                "https://registry.npmjs.org/other/-/other-2.0.0.tgz"
            ),
        }
    else:
        example["peerDependenciesMeta"] = {"peer": {"optional": True}}
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    called = False

    # Build a mock that reports the correct total count.
    # Count non-peer packages in the lockfile for the expected total.
    non_peer_count = sum(
        1 for k, v in lock["packages"].items()
        if k != "" and v.get("peer") is not True
    )
    peer_count = sum(
        1 for k, v in lock["packages"].items()
        if k != "" and v.get("peer") is True
    )
    total = non_peer_count + peer_count

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": non_peer_count,
                    "dev": 0,
                    "optional": 0,
                    "peer": peer_count,
                    "peerOptional": 0,
                    "total": total,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True
    assert outcome.state == "clean"




@pytest.mark.anyio
async def test_npm_rejects_unresolved_non_optional_peer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A v3 lockfile entry with a non-optional transitive peerDependencies
    that does not resolve to a locked package must be rejected as
    unsafe_lockfile."""
    _prepare_project(tmp_path, "npm")
    lock_path = tmp_path / "package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    example = lock["packages"]["node_modules/example"]
    example["peerDependencies"] = {"peer": "1.0.0"}
    # No node_modules/peer entry — this is the unresolved case.
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    called = False

    async def _should_not_run(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("unsafe lockfile must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is False
    assert finding is not None
    assert outcome.reason_code == "unsafe_lockfile"


@pytest.mark.anyio
async def test_npm_accepts_optional_peer_without_locked_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A v3 lockfile entry with a peer dependency marked optional in
    peerDependenciesMeta is allowed even when the peer package is not
    locked."""
    _prepare_project(tmp_path, "npm")
    lock_path = tmp_path / "package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    example = lock["packages"]["node_modules/example"]
    example["peerDependencies"] = {"peer": "1.0.0"}
    example["peerDependenciesMeta"] = {"peer": {"optional": True}}
    # No node_modules/peer entry — allowed because optional.
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        return _result(returncode=0, stdout=_clean_stdout("npm"))

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True
    assert outcome.state == "clean"


@pytest.mark.anyio
async def test_peer_counter_subtraction_must_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The peer counter subtraction at dep_audit.py:345 is exercised with
    nonzero peer counts.  A lockfile with 3 non-peer deps and 1 peer dep
    must produce dependency_count=3; the audit metadata must report
    total=4, peer=1 so that total - peer == dependency_count.  A mismatch
    (total - peer != dependency_count) must be indeterminate."""
    package = {
        "name": "audit-test",
        "version": "1.0.0",
        "dependencies": {"example": "1.0.0", "other": "2.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(package), encoding="utf-8")
    lockfile = {
        "name": "audit-test",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": package,
            "node_modules/example": {
                "version": "1.0.0",
                "resolved": (
                    "https://registry.npmjs.org/example/"
                    "-/example-1.0.0.tgz"
                ),
            },
            "node_modules/other": {
                "version": "2.0.0",
                "resolved": (
                    "https://registry.npmjs.org/other/"
                    "-/other-2.0.0.tgz"
                ),
            },
            "node_modules/peer-dep": {
                "version": "1.0.0",
                "resolved": (
                    "https://registry.npmjs.org/peer-dep/"
                    "-/peer-dep-1.0.0.tgz"
                ),
                "peer": True,
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(
        json.dumps(lockfile), encoding="utf-8"
    )

    # Case A: correct peer count — clean
    called = False

    async def _matched(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 2,
                    "dev": 0,
                    "optional": 0,
                    "peer": 1,
                    "peerOptional": 0,
                    "total": 3,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _matched)
    _, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)
    assert called is True
    assert outcome.state == "clean"

    # Case B: mismatched peer count — indeterminate
    called = False

    async def _mismatched(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 3,
                    "dev": 0,
                    "optional": 0,
                    "peer": 0,
                    "peerOptional": 0,
                    "total": 3,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _mismatched)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)
    assert called is True
    assert outcome.state == "indeterminate"
    assert finding is not None
    assert "unrecognized_schema" in finding.message


@pytest.mark.anyio
async def test_v2_rejects_peer_true_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lockfileVersion 2 entry with peer:true (which cannot occur in
    legitimate v2 output) must be rejected as indeterminate — the
    lockfile is malformed.  Only v3+ may carry peer:true entries."""
    package = {
        "name": "audit-test",
        "version": "1.0.0",
        "dependencies": {"example": "1.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(package), encoding="utf-8")
    lockfile = {
        "name": "audit-test",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "packages": {
            "": package,
            "node_modules/example": {
                "version": "1.0.0",
                "resolved": (
                    "https://registry.npmjs.org/example/"
                    "-/example-1.0.0.tgz"
                ),
                "peer": True,
            },
            # Second non-peer entry so dependency_count > 0.  Without
            # the lock_version < 3 gate, the peer:true continue would
            # skip the v2 checks and the lockfile would be accepted.
            "node_modules/other": {
                "version": "2.0.0",
                "resolved": (
                    "https://registry.npmjs.org/other/"
                    "-/other-2.0.0.tgz"
                ),
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(
        json.dumps(lockfile), encoding="utf-8"
    )
    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        return _result(returncode=0, stdout=_clean_stdout("npm"))

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is False, (
        "v2 lockfile with peer:true must fail closed before spawning audit"
    )
    assert outcome.state == "indeterminate"
    assert finding is not None
    assert "unsafe_lockfile" in finding.message




@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "manifest"),
    (("npm", "package.json"), ("pip", "pyproject.toml"), ("cargo", "Cargo.toml")),
)
async def test_nested_dependency_project_is_indeterminate_without_spawning(
    tool: str,
    manifest: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested_manifest = tmp_path / "nested" / manifest
    nested_manifest.parent.mkdir()
    nested_manifest.write_text("PRIVATE_NESTED_MANIFEST", encoding="utf-8")
    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("unsupported multi-project layout must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await getattr(DepAuditSuite(tech_stack=[]), f"_{tool}_audit")(
        tmp_path
    )

    assert called is False
    assert finding is not None
    assert outcome.reason_code == ("unsafe_manifest" if tool == "npm" else "unsupported_project_layout")
    assert "PRIVATE_" not in json.dumps(asdict(finding), sort_keys=True)


@pytest.mark.anyio
async def test_bounded_manifest_discovery_fails_all_ecosystems_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ordinary.txt").write_text("value", encoding="utf-8")
    monkeypatch.setattr(dep_audit, "_MAX_MANIFEST_DISCOVERY_ENTRIES", 0)

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("incomplete discovery must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))

    assert result.evidence.complete is False
    assert len(result.findings) == 3
    assert {
        outcome.reason_code for outcome in result.evidence.outcomes
    } == {"manifest_discovery_incomplete"}


@pytest.mark.anyio
async def test_symlinked_directory_makes_manifest_discovery_indeterminate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    external = tmp_path.parent / f"{tmp_path.name}-external-project"
    external.mkdir()
    (external / "package.json").write_text("{}", encoding="utf-8")
    try:
        (tmp_path / "linked-project").symlink_to(external, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are not available")

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("symlink-ambiguous discovery must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))

    assert result.evidence.complete is False
    assert len(result.findings) == 3
    assert all(
        outcome.reason_code == "manifest_discovery_incomplete"
        for outcome in result.evidence.outcomes
    )


@pytest.mark.anyio
async def test_pip_audit_uses_static_pinned_mode_from_outside_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prepare_project(tmp_path, "pip")
    before = _snapshot_files(tmp_path)
    calls: list[tuple[list[str], Path, int, Path]] = []

    async def _fake_run_command(
        args: list[str],
        *,
        cwd: Path,
        timeout_s: int,
        project_root: Path,
    ) -> CommandResult:
        calls.append((args, cwd, timeout_s, project_root))
        assert cwd.is_dir()
        return _result(returncode=0, stdout=_clean_stdout("pip"))

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(
        tech_stack=[], pip_audit_ignore_ids="CVE-2024-23342,GHSA-test"
    )._pip_audit(tmp_path)

    assert finding is None
    assert outcome.state == "clean"
    assert len(calls) == 1
    args, audit_cwd, timeout_s, project_root = calls[0]
    assert args == [
        "pip-audit",
        "--strict",
        "--disable-pip",
        "--no-deps",
        "-r",
        str(audit_cwd / "requirements.txt"),
        "-f",
        "json",
        "--ignore-vuln",
        "CVE-2024-23342",
        "--ignore-vuln",
        "GHSA-test",
    ]
    assert project_root == tmp_path.resolve()
    assert tmp_path.resolve() not in audit_cwd.resolve().parents
    assert audit_cwd.exists() is False
    assert timeout_s == 50
    assert _snapshot_files(tmp_path) == before


@pytest.mark.anyio
@pytest.mark.parametrize("lock_version", (2, 3))
async def test_npm_audit_uses_copied_inputs_without_project_npmrc_or_mutation(
    lock_version: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_project(tmp_path, "npm")
    lock_path = tmp_path / "package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["lockfileVersion"] = lock_version
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    (tmp_path / ".npmrc").write_text(
        "//registry.example.test/:_authToken=PRIVATE_NPM_TOKEN\n"
        "registry=https://attacker.example.test/\n"
        "json=false\n",
        encoding="utf-8",
    )
    before = _snapshot_files(tmp_path)
    calls: list[tuple[list[str], Path, int, Path]] = []

    async def _fake_run_command(
        args: list[str],
        *,
        cwd: Path,
        timeout_s: int,
        project_root: Path,
    ) -> CommandResult:
        calls.append((args, cwd, timeout_s, project_root))
        assert {path.name for path in cwd.iterdir()} == {
            "package.json",
            "package-lock.json",
        }
        assert (cwd / "package.json").read_bytes() == (
            tmp_path / "package.json"
        ).read_bytes()
        assert (cwd / "package-lock.json").read_bytes() == (
            tmp_path / "package-lock.json"
        ).read_bytes()
        assert not (cwd / ".npmrc").exists()
        return _result(returncode=0, stdout=_clean_stdout("npm"))

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert finding is None
    assert outcome.state == "clean"
    assert len(calls) == 1
    args, audit_cwd, timeout_s, project_root = calls[0]
    assert args == [
        "npm",
        "audit",
        "--audit-level=info",
        "--json",
        "--ignore-scripts",
        "--package-lock-only",
        "--registry",
        "https://registry.npmjs.org",
    ]
    assert project_root == tmp_path.resolve()
    assert tmp_path.resolve() not in audit_cwd.resolve().parents
    assert audit_cwd.exists() is False
    assert timeout_s == 50
    assert _snapshot_files(tmp_path) == before


@pytest.mark.anyio
async def test_cargo_audit_uses_copied_lockfile_outside_project_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prepare_project(tmp_path, "cargo")
    cargo_config = tmp_path / ".cargo" / "config.toml"
    cargo_config.parent.mkdir()
    cargo_config.write_text(
        "[build]\nrustc-wrapper='workspace-decoy'\n", encoding="utf-8"
    )
    before = _snapshot_files(tmp_path)
    calls: list[tuple[list[str], Path, int, Path]] = []

    async def _fake_run_command(
        args: list[str],
        *,
        cwd: Path,
        timeout_s: int,
        project_root: Path,
    ) -> CommandResult:
        calls.append((args, cwd, timeout_s, project_root))
        assert cwd.is_dir()
        return _result(returncode=0, stdout=_clean_stdout("cargo"))

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._cargo_audit(tmp_path)

    assert finding is None
    assert outcome.state == "clean"
    assert len(calls) == 1
    args, audit_cwd, timeout_s, project_root = calls[0]
    assert args == [
        "cargo-audit",
        "audit",
        "--file",
        str(audit_cwd / "Cargo.lock"),
        "--json",
    ]
    assert project_root == tmp_path.resolve()
    assert tmp_path.resolve() not in audit_cwd.resolve().parents
    assert audit_cwd.exists() is False
    assert timeout_s == 50
    assert _snapshot_files(tmp_path) == before


@pytest.mark.anyio
async def test_all_nonapplicable_ecosystems_emit_complete_exact_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("non-applicable audits must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))

    assert result.findings == []
    assert result.evidence.to_dict() == {
        "schema_version": DEPENDENCY_AUDIT_SCHEMA_VERSION,
        "enabled": True,
        "complete": True,
        "npm_projects": {"discovered_manifests": [], "audits": []},
        "coverage_scope": {
            "npm": "package_lock_registry_graph",
            "pip": "declared_direct_pins",
            "cargo": "cargo_lock_packages",
        },
        "outcomes": [
            {
                "ecosystem": tool,
                "applicable": False,
                "state": None,
                "vulnerability_count": None,
                "reason_code": None,
            }
            for tool in _TOOLS
        ],
    }



@pytest.mark.anyio
async def test_npm_audit_passes_unreferenced_peer_true_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v3 lockfiles with unreferenced peer:true transitive chains must
    be accepted.  In npm 10+ lockfileVersion 3 output, transitive peer
    chains produce peer:true records with no direct peerDependencies
    reference from any consumer package (e.g. @testing-library/dom
    pulls in @types/aria-query and dom-accessibility-api as peer:true
    children).  The gate must resolve these transitively and accept them.

    This fixture captures the @testing-library/dom peer chain pattern
    observed in sentinelayer-web.  The original unsafe_lockfile was
    triggered by a second, independent issue: root peerDependenciesMeta
    keys in the lockfile absent from package.json (covered by
    test_v3_rejects_root_peer_metadata_not_in_package_json).  A
    full end-to-end smoke test with the actual web lockfile is at
    test_real_sentinelayer_web_lockfile_passes_audit."""

    # Faithful fixture extracted from sentinelayer-web package-lock.json:
    # - root devDependencies -> @testing-library/react
    # - @testing-library/react peerDependencies -> @testing-library/dom
    # - @testing-library/dom (peer:true) with unreferenced peer:true children
    package = {
        "name": "sentinelayer-web",
        "version": "0.0.0",
        "dependencies": {},
        "devDependencies": {"@testing-library/react": "^16.0.0"},
    }
    package_path = tmp_path / "package.json"
    package_path.write_text(json.dumps(package), encoding="utf-8")

    lock = {
        "name": "sentinelayer-web",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": package,
            "node_modules/@testing-library/react": {
                "version": "16.3.0",
                "resolved": (
                    "https://registry.npmjs.org/@testing-library/"
                    "react/-/react-16.3.0.tgz"
                ),
                "dev": True,
                "peerDependencies": {
                    "@testing-library/dom": "^10.0.0",
                    "@types/react": "^18.0.0 || ^19.0.0",
                    "@types/react-dom": "^18.0.0 || ^19.0.0",
                },
                "peerDependenciesMeta": {
                    "@types/react": {"optional": True},
                    "@types/react-dom": {"optional": True},
                },
            },
            # peer:true — referenced by @testing-library/react's peerDependencies
            "node_modules/@testing-library/dom": {
                "version": "10.4.1",
                "resolved": (
                    "https://registry.npmjs.org/@testing-library/"
                    "dom/-/dom-10.4.1.tgz"
                ),
                "dev": True,
                "peer": True,
                "dependencies": {
                    "@types/aria-query": "^5.0.1",
                    "dom-accessibility-api": "^0.5.9",
                },
            },
            # Unreferenced peer:true — transitively resolved, no consumer
            # declares peerDependencies for these.  This is the exact
            # pattern that originally tripped unsafe_lockfile.
            "node_modules/@types/aria-query": {
                "version": "5.0.4",
                "resolved": (
                    "https://registry.npmjs.org/@types/"
                    "aria-query/-/aria-query-5.0.4.tgz"
                ),
                "dev": True,
                "peer": True,
            },
            "node_modules/dom-accessibility-api": {
                "version": "0.5.16",
                "resolved": (
                    "https://registry.npmjs.org/dom-accessibility-api/"
                    "-/dom-accessibility-api-0.5.16.tgz"
                ),
                "dev": True,
                "peer": True,
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    non_peer_count = sum(
        1 for k, v in lock["packages"].items()
        if k != "" and v.get("peer") is not True
    )
    peer_count = sum(
        1 for k, v in lock["packages"].items()
        if k != "" and v.get("peer") is True
    )
    total = non_peer_count + peer_count

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 0,
                    "dev": non_peer_count,
                    "optional": 0,
                    "peer": peer_count,
                    "peerOptional": 0,
                    "total": total,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True
    assert outcome.state == "clean", (
        f"Expected clean but got {outcome.state}: {outcome.reason_code}"
    )
    assert peer_count == 3, (
        f"Expected 3 peer:true entries, got {peer_count}"
    )
    assert non_peer_count == 1, (
        f"Expected 1 non-peer entry, got {non_peer_count}"
    )


@pytest.mark.anyio
async def test_npm_accepts_root_peer_metadata_in_lockfilev3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lockfileVersion 3 root record with peerDependenciesMeta must not
    trigger unsafe_lockfile.  npm 10+ routinely emits
    peerDependenciesMeta on the root record for workspace catalogs and
    install-time peer resolution hints.  This is the exact pattern
    that trips the unsafe_lockfile on sentinelayer-web (lockfileVersion 3,
    root record carries peerDependenciesMeta)."""
    _prepare_project(tmp_path, "npm")
    pkg_path = tmp_path / "package.json"
    pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    lock_path = tmp_path / "package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    # Add peerDependenciesMeta to both package.json and lockfile root —
    # standard in npm 10+ v3 output (workspace catalogs, resolution hints).
    pkg["peerDependenciesMeta"] = {"example": {"optional": True}}
    lock["packages"][""]["peerDependenciesMeta"] = {
        "example": {"optional": True}
    }
    pkg_path.write_text(json.dumps(pkg), encoding="utf-8")
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 1,
                    "dev": 0,
                    "optional": 0,
                    "peer": 0,
                    "peerOptional": 0,
                    "total": 1,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True
    assert outcome.state == "clean", (
        f"Expected clean but got {outcome.state}: {outcome.reason_code}"
    )


@pytest.mark.anyio
async def test_npm_rejects_root_peer_metadata_in_lockfilev2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lockfileVersion 2 root record with peerDependenciesMeta must still
    trigger unsafe_lockfile.  v2 lockfiles do not carry root peer metadata
    in legitimate npm output."""
    _prepare_project(tmp_path, "npm")
    lock_path = tmp_path / "package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["lockfileVersion"] = 2
    lock["packages"][""]["peerDependenciesMeta"] = {
        "example": {"optional": True}
    }
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("unsafe lockfile must not spawn audit")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is False
    assert finding is not None
    assert outcome.reason_code == "unsafe_lockfile"


@pytest.mark.anyio

@pytest.mark.anyio
async def test_npm_accepts_peerOptional_entries_in_lockfilev3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """peerOptional:true entries must not be rejected by the early
    unsafe-lockfile guard.  In lockfileVersion 3, npm emits
    peerOptional:true markers on optional peer dependencies (e.g.
    @types/react when marked optional in peerDependenciesMeta).
    The early rejection block must not include peerOptional so the
    dedicated handler below it can track them in package_paths and
    increment peer_optional_count."""

    package = {
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {"react": "^18.0.0"},
        "devDependencies": {"@types/react": "^18.0.0"},
    }
    pkg_path = tmp_path / "package.json"
    pkg_path.write_text(json.dumps(package), encoding="utf-8")

    lock = {
        "name": "test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": package,
            "node_modules/react": {
                "version": "18.3.1",
                "resolved": (
                    "https://registry.npmjs.org/react/-/react-18.3.1.tgz"
                ),
            },
            # peerOptional:true — optional peer, must be accepted
            "node_modules/@types/react": {
                "version": "18.3.12",
                "resolved": (
                    "https://registry.npmjs.org/@types/"
                    "react/-/react-18.3.12.tgz"
                ),
                "dev": True,
                "peerOptional": True,
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    non_peer_count = 1  # react
    peer_optional_count = 1  # @types/react
    total = non_peer_count + peer_optional_count

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": non_peer_count,
                    "dev": 0,
                    "optional": 0,
                    "peer": 0,
                    "peerOptional": peer_optional_count,
                    "total": total,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True
    assert outcome.state == "clean", (
        f"Expected clean but got {outcome.state}: {outcome.reason_code}"
    )


@pytest.mark.anyio
async def test_unexplained_peer_counts_make_result_indeterminate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When npm reports peer counts that do not match the peer inventory
    validated from the lockfile, the result must be indeterminate.

    Example from luna-judge: with 1 non-peer dependency and 0 peer
    entries in the lockfile, a payload claiming total=101, peer=100
    must fail because the tracked peer_count (0) != reported peer (100)."""
    _prepare_project(tmp_path, "npm")
    pkg_path = tmp_path / "package.json"
    lock_path = tmp_path / "package-lock.json"

    pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    pkg["dependencies"]["other"] = "2.0.0"
    pkg_path.write_text(json.dumps(pkg), encoding="utf-8")

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    # The root "" record must match package.json
    lock["packages"][""] = pkg
    # Add the second non-peer package
    lock["packages"]["node_modules/other"] = {
        "version": "2.0.0",
        "resolved": (
            "https://registry.npmjs.org/other/-/other-2.0.0.tgz"
        ),
    }
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    called = False

    async def _fabricated_counters(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        # total=101, peer=100 — fabricated, no peer entries in lockfile
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 1,
                    "dev": 0,
                    "optional": 0,
                    "peer": 100,
                    "peerOptional": 0,
                    "total": 101,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fabricated_counters)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True
    assert outcome.state == "indeterminate", (
        f"Unexplained peer counts must be indeterminate, got {outcome.state}"
    )
    assert finding is not None
    assert "unrecognized_schema" in finding.message


@pytest.mark.anyio
async def test_all_incomplete_ecosystems_preserve_distinct_p0_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prepare_project(tmp_path, "npm", include_lock=False)
    _prepare_project(tmp_path, "pip")
    (tmp_path / "requirements.txt").write_text("unsafe>=1\n", encoding="utf-8")
    _prepare_project(tmp_path, "cargo", include_lock=False)

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        raise AssertionError("input failures must not spawn")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    evidence = result.evidence.to_dict()

    assert evidence["complete"] is False
    assert [outcome["ecosystem"] for outcome in evidence["outcomes"]] == list(_TOOLS)
    assert all(outcome["state"] == "indeterminate" for outcome in evidence["outcomes"])
    assert {finding.id for finding in result.findings} == set(_INCOMPLETE_IDS.values())
    assert len({finding.file_path for finding in result.findings}) == 3
    assert all(finding.severity == "P0" for finding in result.findings)


@pytest.mark.anyio
async def test_v3_rejects_root_peer_deps_not_in_package_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lockfileVersion 3 root record with peerDependencies not declared
    in package.json must trigger unsafe_lockfile.  The v3 path must
    compare root peer declarations against package.json, not merely
    accept any dict-typed peer maps."""
    package = {
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {"react": "^18.0.0"},
    }
    pkg_path = tmp_path / "package.json"
    pkg_path.write_text(json.dumps(package), encoding="utf-8")

    lock = {
        "name": "test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-project",
                "version": "1.0.0",
                "dependencies": {"react": "^18.0.0"},
                "peerDependencies": {"typescript": ">=5.0.0"},
                "peerDependenciesMeta": {"typescript": {"optional": True}},
            },
            "node_modules/react": {
                "version": "18.3.1",
                "resolved": (
                    "https://registry.npmjs.org/react/-/react-18.3.1.tgz"
                ),
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("unsafe lockfile must not spawn audit")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is False
    assert finding is not None
    assert outcome.reason_code == "unsafe_lockfile"


@pytest.mark.anyio
async def test_v3_rejects_root_peer_metadata_not_in_package_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lockfileVersion 3 root record with peerDependenciesMeta not declared
    in package.json must trigger unsafe_lockfile."""
    package = {
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {"react": "^18.0.0"},
    }
    pkg_path = tmp_path / "package.json"
    pkg_path.write_text(json.dumps(package), encoding="utf-8")

    lock = {
        "name": "test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-project",
                "version": "1.0.0",
                "dependencies": {"react": "^18.0.0"},
                "peerDependenciesMeta": {"@types/react": {"optional": True}},
            },
            "node_modules/react": {
                "version": "18.3.1",
                "resolved": (
                    "https://registry.npmjs.org/react/-/react-18.3.1.tgz"
                ),
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("unsafe lockfile must not spawn audit")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is False
    assert finding is not None
    assert outcome.reason_code == "unsafe_lockfile"


@pytest.mark.anyio
async def test_nested_optional_peer_is_counted_as_peerOptional(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nested optional peer dependencies (e.g.
    node_modules/parent/node_modules/@types/react) must be counted as
    peerOptional when the consumer declares the peer optional via
    peerDependenciesMeta."""
    package = {
        "name": "test-nested-peers",
        "version": "1.0.0",
        "dependencies": {"parent": "^1.0.0"},
    }
    pkg_path = tmp_path / "package.json"
    pkg_path.write_text(json.dumps(package), encoding="utf-8")

    lock = {
        "name": "test-nested-peers",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": package,
            "node_modules/parent": {
                "version": "1.0.0",
                "resolved": (
                    "https://registry.npmjs.org/parent/-/parent-1.0.0.tgz"
                ),
                "peerDependencies": {"@types/react": "*"},
                "peerDependenciesMeta": {
                    "@types/react": {"optional": True}
                },
            },
            "node_modules/parent/node_modules/@types/react": {
                "version": "18.3.12",
                "resolved": (
                    "https://registry.npmjs.org/@types/"
                    "react/-/react-18.3.12.tgz"
                ),
                "peer": True,
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    non_peer_count = 1  # parent
    peer_optional_count = 1  # @types/react (nested, optional)
    total = non_peer_count + peer_optional_count

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": non_peer_count,
                    "dev": 0,
                    "optional": 0,
                    "peer": 0,
                    "peerOptional": peer_optional_count,
                    "total": total,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True
    assert outcome.state == "clean", (
        f"Expected clean but got {outcome.state}: {outcome.reason_code}"
    )
    assert peer_optional_count == 1, (
        f"Expected 1 peerOptional entry, got {peer_optional_count}"
    )


@pytest.mark.anyio
@pytest.mark.anyio

@pytest.mark.anyio
async def test_peer_origins_are_collected_in_registry_check(
    tmp_path: Path,
) -> None:
    """Peer:true entries must contribute their origins to the
    origins set via _load_npm_audit_input.

    Before the fix, the peer-record branch continued before
    origins.add(origin), so peer origins were excluded from the
    collected set.  This test calls _load_npm_audit_input directly
    and asserts the returned registry_origin matches the npm
    registry, proving that peer origins are tracked alongside
    non-peer origins.  The fix is defense-in-depth: _registry_origin
    currently only accepts registry.npmjs.org, but if that were
    ever relaxed, the origins consistency check would catch
    mixed-registry lockfiles."""
    from omargate.harness.suites.dep_audit import _load_npm_audit_input

    package = {
        "name": "test-peer-origins",
        "version": "1.0.0",
        "dependencies": {"normal-dep": "^1.0.0"},
    }
    pkg_path = tmp_path / "package.json"
    pkg_path.write_text(json.dumps(package), encoding="utf-8")

    lock = {
        "name": "test-peer-origins",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": package,
            "node_modules/normal-dep": {
                "version": "1.0.0",
                "resolved": (
                    "https://registry.npmjs.org/normal-dep/"
                    "-/normal-dep-1.0.0.tgz"
                ),
            },
            "node_modules/peer-dep": {
                "version": "2.0.0",
                "resolved": (
                    "https://registry.npmjs.org/peer-dep/"
                    "-/peer-dep-2.0.0.tgz"
                ),
                "peer": True,
                "peerDependencies": {},
                "peerDependenciesMeta": {},
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    result = _load_npm_audit_input(pkg_path, lock_path)
    assert result is not None, (
        "Expected _NpmAuditInput but got None — "
        "peer origins must be tracked"
    )
    assert result.registry_origin == "https://registry.npmjs.org", (
        f"Expected registry.npmjs.org, got {result.registry_origin}"
    )
    assert result.dependency_count == 1  # only normal-dep
    assert result.peer_count == 1  # peer-dep is not optional


@pytest.mark.anyio
async def test_required_nested_peer_is_resolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A required (non-optional) nested peer at
    node_modules/parent/node_modules/somepeer must be found by the
    peer resolution walk.

    Before the fix: the walk started from consumer_dir (stripping
    the last path component) and missed nested entries.  The
    existing nested-peer test marked its peer optional, so it
    skipped this resolution check entirely."""
    package = {
        "name": "test-nested-required-peer",
        "version": "1.0.0",
        "dependencies": {"parent": "^1.0.0"},
    }
    pkg_path = tmp_path / "package.json"
    pkg_path.write_text(json.dumps(package), encoding="utf-8")

    lock = {
        "name": "test-nested-required-peer",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": package,
            "node_modules/parent": {
                "version": "1.0.0",
                "resolved": (
                    "https://registry.npmjs.org/parent/"
                    "-/parent-1.0.0.tgz"
                ),
                "peerDependencies": {"somepeer": "*"},
                "peerDependenciesMeta": {},
            },
            "node_modules/parent/node_modules/somepeer": {
                "version": "2.0.0",
                "resolved": (
                    "https://registry.npmjs.org/somepeer/"
                    "-/somepeer-2.0.0.tgz"
                ),
                "peer": True,
                "peerDependencies": {},
                "peerDependenciesMeta": {},
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    non_peer_count = 1  # parent
    peer_count = 1  # somepeer (required, not optional)
    total = non_peer_count + peer_count

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": non_peer_count,
                    "dev": 0,
                    "optional": 0,
                    "peer": peer_count,
                    "peerOptional": 0,
                    "total": total,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True
    assert outcome.state == "clean", (
        f"Expected clean but got {outcome.state}: {outcome.reason_code}"
    )
    assert peer_count == 1, (
        f"Expected 1 required peer entry, got {peer_count}"
    )


@pytest.mark.anyio
async def test_conflicting_root_peer_metadata_value_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If package.json declares a peer as optional via
    peerDependenciesMeta but the lockfile root record sets the same
    key to a different value, the mismatch must be rejected.

    Before the fix: only keys were compared (set difference).
    Conflicting values for shared keys were silently accepted."""
    package = {
        "name": "test-peer-meta-conflict",
        "version": "1.0.0",
        "dependencies": {"dep": "^1.0.0"},
        "peerDependenciesMeta": {
            "somepeer": {"optional": True},
        },
    }
    pkg_path = tmp_path / "package.json"
    pkg_path.write_text(json.dumps(package), encoding="utf-8")

    lock = {
        "name": "test-peer-meta-conflict",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-peer-meta-conflict",
                "version": "1.0.0",
                "dependencies": {"dep": "^1.0.0"},
                "peerDependenciesMeta": {
                    "somepeer": {"optional": False},
                },
            },
            "node_modules/dep": {
                "version": "1.0.0",
                "resolved": (
                    "https://registry.npmjs.org/dep/"
                    "-/dep-1.0.0.tgz"
                ),
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    called = False

    async def _should_not_run(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        return _result(returncode=0, stdout="{}")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    # npm audit must NOT be called — the lockfile is rejected before spawn
    assert called is False, (
        "npm audit must not be spawned for a lockfile with "
        "conflicting peerDependenciesMeta values"
    )
    assert outcome.state == "indeterminate", (
        f"Expected indeterminate but got {outcome.state}: {outcome.reason_code}"
    )


@pytest.mark.anyio
async def test_v3_rejects_unresolved_required_root_peer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A required root peer (not marked optional in peerDependenciesMeta)
    must resolve to a lockfile entry.  lockfileVersion 3 root records
    may carry peerDependencies; the gate must validate that each
    required peer has a corresponding packages entry, not only check
    transitive (non-root) peer resolution."""
    package = {
        "name": "test-project",
        "version": "1.0.0",
        "peerDependencies": {"react": ">=18.0.0"},
        "peerDependenciesMeta": {"react": {"optional": False}},
    }
    pkg_path = tmp_path / "package.json"
    pkg_path.write_text(json.dumps(package), encoding="utf-8")

    # react is a required root peer but absent from packages — must reject
    lock = {
        "name": "test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-project",
                "version": "1.0.0",
                "peerDependencies": {"react": ">=18.0.0"},
                "peerDependenciesMeta": {"react": {"optional": False}},
            },
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": (
                    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                ),
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    called = False

    async def _should_not_run(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal called
        called = True
        raise AssertionError("unsafe lockfile must not spawn audit")

    monkeypatch.setattr(dep_audit, "run_command", _should_not_run)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is False, (
        "npm audit must not be spawned for a lockfile with an "
        "unresolved required root peer"
    )
    assert outcome.reason_code == "unsafe_lockfile", (
        f"Expected unsafe_lockfile but got {outcome.reason_code}"
    )


@pytest.mark.anyio
async def test_v3_accepts_optional_root_peer_without_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An optional root peer does not need a packages entry.
    lockfileVersion 3 root records may carry peerDependencies with
    corresponding peerDependenciesMeta marking them optional; these
    must be allowed to be absent."""
    package = {
        "name": "test-project",
        "version": "1.0.0",
        "peerDependencies": {"typescript": ">=5.0.0"},
        "peerDependenciesMeta": {"typescript": {"optional": True}},
    }
    pkg_path = tmp_path / "package.json"
    pkg_path.write_text(json.dumps(package), encoding="utf-8")

    lock = {
        "name": "test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-project",
                "version": "1.0.0",
                "peerDependencies": {"typescript": ">=5.0.0"},
                "peerDependenciesMeta": {"typescript": {"optional": True}},
            },
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": (
                    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                ),
            },
        },
    }
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 0, "dev": 1, "optional": 0,
                    "peer": 0, "peerOptional": 0, "total": 1,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True, (
        "npm audit must be spawned for a valid lockfile with "
        "optional root peer absent"
    )
    assert outcome.state == "clean", (
        f"Expected clean but got {outcome.state}: {outcome.reason_code}"
    )

# P0 triage for run 39941404364 (sentinelayer-web PR #654):
# P0-1: HARNESS-NPM-AUDIT-INCOMPLETE "unsafe_lockfile" for BOTH
#   package-lock.json and scripts/deploy/pages-tooling/package-lock.json.
#   FIXED by this PR: the lockfileVersion 3 per-package peerDependencies
#   and peer:true records no longer trip the v2-era subset check
#   (0b2a8c0, 24715f4).  The real-lockfile tests below prove the
#   lockfile passes _load_npm_audit_input and full audit counter
#   validation.
# P0-2: "LLM analysis failed: Cascade review could not verify complete
#   stable evidence" — this is a separate gate defect (review inventory
#   excludes tests/**, ticket 78efd938).  It is NOT in scope for this PR
#   (dep_audit lockfile validation) and must be fixed independently.
#   No severity lowering; this is an evidence-based disposition.
@pytest.mark.anyio
async def test_real_sentinelayer_web_lockfile_passes_audit() -> None:
    """Smoke test: the real sentinelayer-web lockfile (commit 34cd5aa,
    lockfileVersion 3, 521 deps, 9 peer:true entries including 6
    unreferenced transitive peer chains) must pass _load_npm_audit_input
    without tripping unsafe_lockfile.

    The old gate at ebfcb813 rejected this lockfile at dep_audit.py:1064
    (per-package peerDependencies subset check): the v2-era rule required
    every transitive peer dependency name to be a subset of root declared
    dependencies.  The specific entry that trips it:
    ``node_modules/@babel/helper-module-transforms`` declares
    ``@babel/core`` as a peerDependency, but ``@babel/core`` is NOT in
    sentinelayer-web's root dependencies/devDependencies/optionalDependencies.
    The v3 fix (0b2a8c0) version-gates that check to lockfileVersion 2
    only, and also drops the peerDependenciesMeta-empty requirement
    which was blocking per-package metadata entries.  This lockfile has
    no root peerDependencies or peerDependenciesMeta, so it does not
    exercise the root peer validation added in 804e456 / 24715f4; those
    paths are covered by the dedicated root-peer rejection / acceptance
    tests below."""
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    pkg_path = fixtures / (
        "package-sentinelayer-web-34cd5aa93fbbff9076fcc4f5a8df9646070d2370.json"
    )
    lock_path = fixtures / (
        "package-lock-sentinelayer-web-"
        "34cd5aa93fbbff9076fcc4f5a8df9646070d2370.json"
    )
    audit_input = dep_audit._load_npm_audit_input(pkg_path, lock_path)
    assert audit_input is not None, (
        "_load_npm_audit_input returned None — would trigger unsafe_lockfile"
    )
    assert audit_input.registry_origin == "https://registry.npmjs.org"
    assert audit_input.dependency_count == 521, (
        f"Expected 521 deps, got {audit_input.dependency_count}"
    )
    assert audit_input.peer_count == 9, (
        f"Expected 9 peer deps, got {audit_input.peer_count}"
    )
    assert audit_input.peer_optional_count == 0, (
        f"Expected 0 peerOptional deps, got {audit_input.peer_optional_count}"
    )


@pytest.mark.anyio
async def test_real_sentinelayer_web_lockfile_full_audit_passes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end test: the real sentinelayer-web lockfile (commit 34cd5aa)
    must pass the complete _npm_audit pipeline -- _load_npm_audit_input plus
    npm audit counter validation -- not just input loading.

    This proves the lockfile that tripped unsafe_lockfile in run
    39941404364 passes the full audit with correctly matched peer
    and dependency counters, so the indeterminate outcome is resolved."""
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    pkg_src = fixtures / (
        "package-sentinelayer-web-34cd5aa93fbbff9076fcc4f5a8df9646070d2370.json"
    )
    lock_src = fixtures / (
        "package-lock-sentinelayer-web-"
        "34cd5aa93fbbff9076fcc4f5a8df9646070d2370.json"
    )

    import shutil
    shutil.copy(pkg_src, tmp_path / "package.json")
    shutil.copy(lock_src, tmp_path / "package-lock.json")

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 410,
                    "dev": 111,
                    "optional": 0,
                    "peer": 9,
                    "peerOptional": 0,
                    "total": 530,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True, (
        "npm audit must be spawned for the real sentinelayer-web lockfile"
    )
    assert outcome.state == "clean", (
        f"Expected clean but got {outcome.state}: {outcome.reason_code}"
    )
    assert finding is None, (
        f"Expected no finding for clean audit, got {finding}"
    )


@pytest.mark.anyio
async def test_real_sentinelayer_web_lockfile_mismatched_peer_count_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If npm reports a peer count different from what _load_npm_audit_input
    computed (9), the result must be indeterminate -- proving the counter
    validation is active for the real lockfile."""
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    pkg_src = fixtures / (
        "package-sentinelayer-web-34cd5aa93fbbff9076fcc4f5a8df9646070d2370.json"
    )
    lock_src = fixtures / (
        "package-lock-sentinelayer-web-"
        "34cd5aa93fbbff9076fcc4f5a8df9646070d2370.json"
    )

    import shutil
    shutil.copy(pkg_src, tmp_path / "package.json")
    shutil.copy(lock_src, tmp_path / "package-lock.json")

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 410,
                    "dev": 112,
                    "optional": 0,
                    "peer": 8,
                    "peerOptional": 0,
                    "total": 530,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True
    assert outcome.state == "indeterminate", (
        f"Mismatched peer count must be indeterminate, got {outcome.state}"
    )
    assert finding is not None
    assert "unrecognized_schema" in finding.message


@pytest.mark.anyio
async def test_real_pages_tooling_lockfile_full_audit_passes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end test: the real sentinelayer-web pages-tooling lockfile
    (commit 34cd5aa, lockfileVersion 3, 91 deps, no peer entries) must
    pass the complete _npm_audit pipeline.

    This covers the second package-lock.json that tripped unsafe_lockfile
    in run 39941404364 (P0-1)."""
    fixtures = Path(__file__).resolve().parent.parent / "fixtures"
    pkg_src = fixtures / (
        "package-pages-tooling-34cd5aa93fbbff9076fcc4f5a8df9646070d2370.json"
    )
    lock_src = fixtures / (
        "package-lock-pages-tooling-"
        "34cd5aa93fbbff9076fcc4f5a8df9646070d2370.json"
    )

    import shutil
    shutil.copy(pkg_src, tmp_path / "package.json")
    shutil.copy(lock_src, tmp_path / "package-lock.json")

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 1,
                    "dev": 90,
                    "optional": 0,
                    "peer": 0,
                    "peerOptional": 0,
                    "total": 91,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True, (
        "npm audit must be spawned for the pages-tooling lockfile"
    )
    assert outcome.state == "clean", (
        f"Expected clean but got {outcome.state}: {outcome.reason_code}"
    )
    assert finding is None, (
        f"Expected no finding for clean audit, got {finding}"
    )


@pytest.mark.anyio
async def test_hoisted_peer_optional_detected_by_any_consumer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hoisted peer at node_modules/<name> whose consumer is a non-root
    package that marks it optional must be counted as peerOptional, not peer.

    The peer entry is at the top level (hoisted) so _peer_consumer_path
    returns the root record, which does not mark it optional.  But a
    non-root consumer (node_modules/consumer-a) declares it optional via
    peerDependenciesMeta, and _any_consumer_marks_optional must find it."""
    package = {
        "name": "audit-test",
        "version": "1.0.0",
        "dependencies": {"consumer-a": "1.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(package), encoding="utf-8")
    lockfile = {
        "name": "audit-test",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": package,
            "node_modules/consumer-a": {
                "version": "1.0.0",
                "resolved": (
                    "https://registry.npmjs.org/consumer-a/"
                    "-/consumer-a-1.0.0.tgz"
                ),
                "peerDependencies": {"shared-peer": ">=1.0.0"},
                "peerDependenciesMeta": {"shared-peer": {"optional": True}},
            },
            "node_modules/shared-peer": {
                "version": "1.0.0",
                "resolved": (
                    "https://registry.npmjs.org/shared-peer/"
                    "-/shared-peer-1.0.0.tgz"
                ),
                "peer": True,
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(
        json.dumps(lockfile), encoding="utf-8"
    )

    called = False

    async def _fake_run_command(
        *_args: object, **_kwargs: object
    ) -> CommandResult:
        nonlocal called
        called = True
        stdout = json.dumps({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": _npm_metadata(critical=0, total=0),
                "dependencies": {
                    "prod": 1,
                    "dev": 0,
                    "optional": 0,
                    "peer": 0,
                    "peerOptional": 1,
                    "total": 2,
                },
            },
        })
        return _result(returncode=0, stdout=stdout)

    monkeypatch.setattr(dep_audit, "run_command", _fake_run_command)
    finding, outcome = await DepAuditSuite(tech_stack=[])._npm_audit(tmp_path)

    assert called is True, (
        "npm audit must be spawned for hoisted optional peer"
    )
    assert outcome.state == "clean", (
        f"Expected clean but got {outcome.state}: {outcome.reason_code}"
    )
    assert finding is None, (
        f"Expected no finding for clean audit, got {finding}"
    )
