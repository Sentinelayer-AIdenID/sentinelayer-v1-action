"""A peer declaration may refer to a package already in the regular audit graph."""
import json
import re
import shutil
from dataclasses import asdict

import pytest

import test_dep_audit_suite as fixture
from test_nested_npm_audits import evaluate
from omargate.harness.suites import dep_audit
from omargate.harness.suites.dep_audit import DepAuditSuite
from omargate.harness.runner import run_command

pytestmark = pytest.mark.anyio


async def test_real_npm_initializes_under_isolated_config_without_network(tmp_path):
    if not shutil.which("npm"):
        pytest.skip("real npm required for configuration startup proof")
    root, working = tmp_path / "checkout", tmp_path / "private-inputs"
    root.mkdir()
    working.mkdir()
    (root / ".npmrc").write_text("registry=https://untrusted.invalid/\n")
    result = await run_command(["npm", "--version"], cwd=working, timeout_s=15, project_root=root)
    assert result.cleanup_proven and result.status == "exited" and result.returncode == 0
    assert re.fullmatch(r"\d+\.\d+\.\d+\s*", result.stdout), "npm must resolve isolated config before auditing"


def project(root):
    fixture._prepare_project(root, "npm")
    manifest_path, lock_path = root / "package.json", root / "package-lock.json"
    manifest, lock = json.loads(manifest_path.read_text()), json.loads(lock_path.read_text())
    manifest["dependencies"]["consumer"] = "1.0.0"
    lock["packages"][""]["dependencies"]["consumer"] = "1.0.0"
    lock["packages"]["node_modules/consumer"] = {
        "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/consumer/-/consumer-1.0.0.tgz",
        "peerDependencies": {"example": "^1.0.0"},
    }
    manifest_path.write_text(json.dumps(manifest))
    lock_path.write_text(json.dumps(lock))
    return manifest, lock


@pytest.mark.parametrize("result_kind", ["clean", "vulnerable", "missing-record-count", "peer-only-count"])
async def test_already_declared_peer_is_audited_and_cannot_hide_bad_results(tmp_path, monkeypatch, result_kind):
    project(tmp_path)
    calls = []

    async def command(args, *, cwd, timeout_s, project_root):
        calls.append(args)
        assert project_root == tmp_path.resolve() and not cwd.is_relative_to(tmp_path)
        copied = json.loads((cwd / "package-lock.json").read_text())
        assert copied["packages"]["node_modules/consumer"]["peerDependencies"] == {"example": "^1.0.0"}
        assert "node_modules/example" in copied["packages"]
        vulnerable = result_kind == "vulnerable"
        payload = json.loads(fixture._vulnerable_stdout("npm") if vulnerable else fixture._clean_stdout("npm"))
        payload["metadata"]["dependencies"] = fixture._npm_dependencies(total=1 if result_kind == "missing-record-count" else 2)
        if result_kind == "peer-only-count":
            payload["metadata"]["dependencies"]["peer"] = 1
        return fixture._result(returncode=1 if vulnerable else 0, stdout=json.dumps(payload))

    monkeypatch.setattr(dep_audit, "run_command", command)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    gate = evaluate(tmp_path, result.evidence.to_dict(), findings=[asdict(f) for f in result.findings])
    assert len(calls) == 1, "released peer-declaration refusal prevents a real audit of an already regular package"
    npm = next(row for row in result.evidence.outcomes if row.ecosystem == "npm")
    if result_kind in {"missing-record-count", "peer-only-count"}:
        assert not result.evidence.complete and npm.state == "indeterminate" and gate.block_merge
    else:
        assert result.evidence.complete
        assert npm.state == ("vulnerable" if result_kind == "vulnerable" else "clean")
        assert gate.block_merge is (result_kind == "vulnerable")


@pytest.mark.parametrize("case", ["undeclared", "missing-record", "peer-record", "metadata", "bad-mapping", "bad-value"])
async def test_unsupported_peer_coverage_refuses_before_audit(tmp_path, monkeypatch, case):
    _, lock = project(tmp_path)
    lock["lockfileVersion"] = 2
    consumer = lock["packages"]["node_modules/consumer"]
    if case == "undeclared":
        consumer["peerDependencies"] = {"not-in-regular-graph": "^1.0.0"}
    elif case == "missing-record":
        lock["packages"].pop("node_modules/example")
    elif case == "peer-record":
        lock["packages"]["node_modules/example"]["peer"] = True
    elif case == "metadata":
        consumer["peerDependenciesMeta"] = {"example": {"optional": True}}
    elif case == "bad-mapping":
        consumer["peerDependencies"] = []
    else:
        consumer["peerDependencies"] = {"example": None}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))

    calls = []

    async def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError("unsupported peer graph must be refused before transport")

    monkeypatch.setattr(dep_audit, "run_command", forbidden)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    assert not calls, "unsupported peer graph reached a child process"
    assert not result.evidence.complete and evaluate(tmp_path, result.evidence.to_dict()).block_merge
