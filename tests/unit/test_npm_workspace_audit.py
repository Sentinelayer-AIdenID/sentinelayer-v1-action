import copy
import json

import pytest

import test_dep_audit_suite as fixture
import test_gate as gate_fixture
from omargate.gate import evaluate_gate
from omargate.harness.suites import dep_audit
from omargate.harness.suites.dep_audit import DepAuditSuite
from omargate.models import GateConfig, GateStatus


pytestmark = pytest.mark.anyio


def _write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _workspace(tmp_path):
    root = {"name": "example-root", "version": "1.0.0",
            "workspaces": ["packages/a", "packages/b"],
            "dependencies": {"is-number": "7.0.0"}}
    a = {"name": "@example/a", "version": "1.0.0",
         "dependencies": {"is-number": "7.0.0"}}
    b = {"name": "@example/b", "version": "1.0.0"}
    lock = {"name": "example-root", "version": "1.0.0", "lockfileVersion": 3,
            "requires": True, "packages": {
                "": {k: v for k, v in root.items()},
                "node_modules/@example/a": {"resolved": "packages/a", "link": True},
                "node_modules/@example/b": {"resolved": "packages/b", "link": True},
                "node_modules/is-number": {"version": "7.0.0",
                                           "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"},
                "packages/a": a, "packages/b": b,
            }}
    _write(tmp_path / "package.json", root)
    _write(tmp_path / "package-lock.json", lock)
    _write(tmp_path / "packages/a/package.json", a)
    _write(tmp_path / "packages/b/package.json", b)
    return lock


def _report(count=0, *, dependency_total=5):
    records = {"is-number": {"severity": "high"}} if count else {}
    return json.dumps({"auditReportVersion": 2, "vulnerabilities": records,
                       "metadata": {"vulnerabilities": fixture._npm_metadata(
                           critical=0, high=count, total=count),
                           "dependencies": fixture._npm_dependencies(total=dependency_total)}})


def _gate(root, evidence):
    payload = gate_fixture._valid_summary(root, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dependency_audit_evidence"] = evidence
    gate_fixture._write_summary(root, payload)
    return evaluate_gate(root, GateConfig(require_dependency_audit_success=True))


@pytest.mark.parametrize("vulnerabilities", [0, 1])
async def test_workspace_audits_shared_root_lock_once(tmp_path, monkeypatch, vulnerabilities):
    _workspace(tmp_path)
    calls = []

    async def command(args, *, cwd, timeout_s, project_root):
        calls.append(args)
        assert not cwd.is_relative_to(tmp_path)
        assert (cwd / "package-lock.json").is_file()
        assert (cwd / "packages/a/package.json").is_file()
        assert (cwd / "packages/b/package.json").is_file()
        return fixture._result(returncode=int(vulnerabilities > 0),
                               stdout=_report(vulnerabilities))

    monkeypatch.setattr(dep_audit, "run_command", command)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    assert len(calls) == 1
    proof = result.evidence.to_dict()["npm_projects"]
    assert [row["mode"] for row in proof["audits"]] == [
        "registry_graph", "workspace_member", "workspace_member"]
    assert {row["lockfile_path"] for row in proof["audits"]} == {"package-lock.json"}
    assert len({row["lockfile_sha256"] for row in proof["audits"]}) == 1
    assert [row["outcome"]["vulnerability_count"] for row in proof["audits"]] == [
        vulnerabilities, 0, 0]
    assert result.evidence.complete
    if vulnerabilities:
        assert result.evidence.outcomes[0].state == "vulnerable"
    else:
        assert _gate(tmp_path, result.evidence.to_dict()).status == GateStatus.PASSED


async def test_workspace_only_lock_has_no_registry_package_but_still_audits(tmp_path, monkeypatch):
    lock = _workspace(tmp_path)
    lock["packages"][""].pop("dependencies")
    lock["packages"]["packages/a"].pop("dependencies")
    del lock["packages"]["node_modules/is-number"]
    _write(tmp_path / "package-lock.json", lock)
    for path in (tmp_path / "package.json", tmp_path / "packages/a/package.json"):
        manifest = json.loads(path.read_text())
        manifest.pop("dependencies")
        _write(path, manifest)
    calls = []

    async def command(*args, **kwargs):
        calls.append(1)
        return fixture._result(stdout=_report(dependency_total=4))

    monkeypatch.setattr(dep_audit, "run_command", command)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    assert result.evidence.complete and calls == [1]
    assert _gate(tmp_path, result.evidence.to_dict()).status == GateStatus.PASSED


async def test_workspace_member_mutation_during_audit_blocks_merge(tmp_path, monkeypatch):
    _workspace(tmp_path)

    async def command(*args, **kwargs):
        member = tmp_path / "packages/a/package.json"
        payload = json.loads(member.read_text())
        payload["dependencies"]["is-number"] = "8.0.0"
        _write(member, payload)
        return fixture._result(stdout=_report())

    monkeypatch.setattr(dep_audit, "run_command", command)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    assert not result.evidence.complete
    assert _gate(tmp_path, result.evidence.to_dict()).block_merge
    assert next(row for row in result.evidence.to_dict()["npm_projects"]["audits"]
                if row["manifest_path"] == "packages/a/package.json")["input_unchanged"] is False


async def test_nested_workspace_root_still_anchors_member_evidence(tmp_path, monkeypatch):
    project = tmp_path / "services/gateway"
    _workspace(project)
    calls = []

    async def command(*args, **kwargs):
        calls.append(1)
        return fixture._result(stdout=_report())

    monkeypatch.setattr(dep_audit, "run_command", command)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    assert calls == [1] and result.evidence.complete
    assert _gate(tmp_path, result.evidence.to_dict()).status == GateStatus.PASSED


@pytest.mark.parametrize("drift", [
    "root_workspaces", "member_name", "member_version", "member_dependencies",
    "missing_member", "missing_link", "wrong_link", "extra_link", "undeclared_member",
    "unlocked_member_dependency", "unsafe_path", "glob_path", "symlink_member",
    "member_lock", "missing_root_lock", "duplicate_name", "nested_workspace",
    "nested_registry_outside_member", "root_unlocked_dependency",
])
async def test_workspace_lock_drift_blocks_before_npm(tmp_path, monkeypatch, drift):
    lock = _workspace(tmp_path)
    root_path = tmp_path / "package.json"
    member_path = tmp_path / "packages/a/package.json"
    if drift == "root_workspaces":
        lock["packages"][""]["workspaces"] = ["packages/a"]
    elif drift == "member_name":
        payload = json.loads(member_path.read_text())
        payload["name"] = "@example/changed"
        _write(member_path, payload)
    elif drift == "member_version":
        payload = json.loads(member_path.read_text())
        payload["version"] = "2.0.0"
        _write(member_path, payload)
    elif drift == "member_dependencies":
        payload = json.loads(member_path.read_text())
        payload["dependencies"]["is-number"] = "8.0.0"
        _write(member_path, payload)
    elif drift == "missing_member":
        member_path.unlink()
    elif drift == "missing_link":
        del lock["packages"]["node_modules/@example/a"]
    elif drift == "wrong_link":
        lock["packages"]["node_modules/@example/a"]["resolved"] = "packages/b"
    elif drift == "extra_link":
        lock["packages"]["node_modules/evil"] = {"resolved": "packages/a", "link": True}
    elif drift == "undeclared_member":
        lock["packages"]["packages/evil"] = {"name": "evil", "version": "1.0.0"}
    elif drift == "unlocked_member_dependency":
        payload = json.loads(member_path.read_text())
        payload["dependencies"]["missing"] = "1.0.0"
        lock["packages"]["packages/a"]["dependencies"]["missing"] = "1.0.0"
        _write(member_path, payload)
    elif drift == "member_lock":
        _write(tmp_path / "packages/a/package-lock.json", {"lockfileVersion": 3})
    elif drift == "missing_root_lock":
        (tmp_path / "package-lock.json").unlink()
    elif drift == "duplicate_name":
        payload = json.loads((tmp_path / "packages/b/package.json").read_text())
        payload["name"] = "@example/a"
        _write(tmp_path / "packages/b/package.json", payload)
        lock["packages"]["packages/b"]["name"] = "@example/a"
    elif drift == "nested_workspace":
        payload = json.loads(member_path.read_text())
        payload["workspaces"] = ["nested"]
        _write(member_path, payload)
    elif drift == "nested_registry_outside_member":
        lock["packages"]["other/node_modules/evil"] = {
            "version": "1.0.0", "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"}
    elif drift == "root_unlocked_dependency":
        payload = json.loads(root_path.read_text())
        payload["dependencies"]["missing"] = "1.0.0"
        lock["packages"][""]["dependencies"]["missing"] = "1.0.0"
        _write(root_path, payload)
    elif drift in {"unsafe_path", "glob_path"}:
        root = json.loads(root_path.read_text())
        root["workspaces"][0] = "../escape" if drift == "unsafe_path" else "packages/*"
        lock["packages"][""]["workspaces"] = root["workspaces"]
        _write(root_path, root)
    elif drift == "symlink_member":
        member_path.unlink()
        member_path.symlink_to(tmp_path / "packages/b/package.json")
    if drift not in {"unsafe_path", "glob_path", "missing_root_lock"}:
        _write(tmp_path / "package-lock.json", lock)

    calls = []

    async def forbidden(*args, **kwargs):
        calls.append(1)
        return fixture._result(stdout=_report())

    monkeypatch.setattr(dep_audit, "run_command", forbidden)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    assert calls == []
    assert not result.evidence.complete
    assert result.evidence.outcomes[0].state == "indeterminate"
    assert any(f.severity == "P0" for f in result.findings)


@pytest.mark.parametrize("tamper", ["missing_root", "wrong_lock", "wrong_hash",
                                  "wrong_mode", "nonzero_member", "false_clean_member"])
async def test_gate_rejects_forged_workspace_member_evidence(tmp_path, monkeypatch, tamper):
    _workspace(tmp_path)

    async def command(*args, **kwargs):
        return fixture._result(stdout=_report())

    monkeypatch.setattr(dep_audit, "run_command", command)
    evidence = copy.deepcopy((await DepAuditSuite(tech_stack=[]).run_with_evidence(
        str(tmp_path))).evidence.to_dict())
    audits = evidence["npm_projects"]["audits"]
    if tamper == "missing_root":
        audits.pop(0)
        evidence["npm_projects"]["discovered_manifests"].pop(0)
    elif tamper == "wrong_lock":
        audits[1]["lockfile_path"] = "other/package-lock.json"
    elif tamper == "wrong_hash":
        audits[1]["lockfile_sha256"] = "0" * 64
    elif tamper == "wrong_mode":
        audits[1]["mode"] = "registry_graph"
    elif tamper == "nonzero_member":
        audits[1]["outcome"].update(state="vulnerable", vulnerability_count=1)
    else:
        audits[1]["outcome"].update(state="vulnerable", vulnerability_count=0)
    assert _gate(tmp_path, evidence).status == GateStatus.ERROR
