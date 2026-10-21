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


@pytest.fixture
def projects(tmp_path, monkeypatch):
    parent = tmp_path / "services/gateway"
    parent.mkdir(parents=True)
    (parent / "package.json").write_text(json.dumps({"name": "fixture-parent", "scripts": {"test": "node --test"}}))
    for name in ("admission", "gateway"):
        leaf = parent / "deploy" / name
        leaf.mkdir(parents=True)
        fixture._prepare_project(leaf, "npm")
    calls = []
    async def command(args, *, cwd, timeout_s, project_root):
        calls.append(project_root)
        assert not cwd.is_relative_to(tmp_path)
        assert (cwd / "package.json").is_file() and (cwd / "package-lock.json").is_file()
        return fixture._result(stdout=fixture._clean_stdout("npm"))
    monkeypatch.setattr(dep_audit, "run_command", command)
    return tmp_path, parent, calls


async def run(projects):
    return await DepAuditSuite(tech_stack=[]).run_with_evidence(str(projects[0]))


def evaluate(root, evidence, *, findings=None):
    payload = gate_fixture._valid_summary(root, {"P0": 0, "P1": len(findings or []), "P2": 0, "P3": 0}, findings=findings)
    payload["dependency_audit_evidence"] = evidence
    gate_fixture._write_summary(root, payload)
    return evaluate_gate(root, GateConfig(require_dependency_audit_success=True))


async def test_parent_empty_graph_and_two_nested_lockfiles_receive_complete_independent_audits(projects):
    root, parent, calls = projects
    result = await run(projects)
    evidence = result.evidence.to_dict()
    assert result.findings == [] and evidence["complete"]
    assert {path.name for path in calls} == {"admission", "gateway"} and len(calls) == 2
    rows = evidence["npm_projects"]["audits"]
    assert len(rows) == 3
    assert rows[-1]["mode"] == "empty_declared_graph" and rows[-1]["lockfile_path"] is None
    assert all(len(row["manifest_sha256"]) == 64 for row in rows)
    assert all(row["input_unchanged"] is True for row in rows)
    assert {row["manifest_path"] for row in rows} == set(evidence["npm_projects"]["discovered_manifests"])
    assert evaluate(root, evidence).status == GateStatus.PASSED


@pytest.mark.parametrize("change", ["missing_lock", "malformed_manifest", "workspaces", "peer_metadata"])
async def test_incomplete_leaf_cannot_hide_behind_clean_parent_or_sibling(projects, change):
    root, parent, calls = projects
    leaf = parent / "deploy/gateway"
    if change == "missing_lock":
        (leaf / "package-lock.json").unlink()
    elif change == "malformed_manifest":
        (leaf / "package.json").write_text("not JSON")
    else:
        payload = json.loads((leaf / "package.json").read_text())
        payload["workspaces" if change == "workspaces" else "peerDependenciesMeta"] = ["../other"] if change == "workspaces" else {"unknown": {"optional": True}}
        (leaf / "package.json").write_text(json.dumps(payload))
    result = await run(projects)
    assert not result.evidence.complete
    assert next(item for item in result.evidence.outcomes if item.ecosystem == "npm").state == "indeterminate"
    assert len(calls) == 1
    assert evaluate(root, result.evidence.to_dict()).block_merge


async def test_vulnerability_in_last_project_retained_while_other_project_is_incomplete(projects, monkeypatch):
    root, parent, _ = projects
    (parent / "deploy/admission/package-lock.json").unlink()
    async def vulnerable(*args, **kwargs):
        return fixture._result(returncode=1, stdout=fixture._vulnerable_stdout("npm"))
    monkeypatch.setattr(dep_audit, "run_command", vulnerable)
    result = await run(projects)
    assert not result.evidence.complete
    rows = result.evidence.to_dict()["npm_projects"]["audits"]
    assert any(row["outcome"]["state"] == "vulnerable" for row in rows)
    assert any(row["outcome"]["state"] == "indeterminate" for row in rows)
    assert evaluate(root, result.evidence.to_dict()).block_merge


async def test_earlier_manifest_changed_during_later_audit_never_completes(projects, monkeypatch):
    root, parent, _ = projects
    async def change(args, *, cwd, timeout_s, project_root):
        if project_root.name == "gateway":
            (parent / "deploy/admission/package.json").write_text("changed")
        return fixture._result(stdout=fixture._clean_stdout("npm"))
    monkeypatch.setattr(dep_audit, "run_command", change)
    result = await run(projects)
    assert not result.evidence.complete and evaluate(root, result.evidence.to_dict()).block_merge
    assert result.evidence.to_dict()["npm_projects"]["audits"][0]["input_unchanged"] is False


@pytest.mark.parametrize("case", ["omit", "duplicate", "undeclared", "bad_hash", "path_escape", "wrong_parent_lock", "empty_graph_with_lock", "misleading_clean", "bool_count"])
async def test_gate_rejects_forged_or_partial_project_coverage(projects, case):
    root, _, _ = projects
    evidence = json.loads(json.dumps((await run(projects)).evidence.to_dict()))
    proof = evidence["npm_projects"]
    if case == "omit":
        proof["audits"].pop()
    elif case == "duplicate":
        proof["audits"][1] = copy.deepcopy(proof["audits"][0])
    elif case == "undeclared":
        proof["discovered_manifests"].pop()
    elif case == "bad_hash":
        proof["audits"][0]["manifest_sha256"] = "unknown"
    elif case == "path_escape":
        proof["audits"][0]["manifest_path"] = "../package.json"
    elif case == "wrong_parent_lock":
        proof["audits"][0]["lockfile_path"] = "elsewhere/package-lock.json"
    elif case == "empty_graph_with_lock":
        proof["audits"][0]["mode"] = "empty_declared_graph"
    elif case == "misleading_clean":
        proof["audits"][0]["outcome"].update(state="vulnerable", vulnerability_count=1)
    else:
        proof["audits"][0]["outcome"]["vulnerability_count"] = False
    result = evaluate(root, evidence)
    assert result.status == GateStatus.ERROR and result.block_merge


async def test_project_budget_refuses_before_registry_queries(tmp_path, monkeypatch):
    for index in range(33):
        leaf = tmp_path / str(index)
        leaf.mkdir()
        fixture._prepare_project(leaf, "npm")
    async def forbidden(*args, **kwargs):
        raise AssertionError("project budget must be decided before any command")
    monkeypatch.setattr(dep_audit, "run_command", forbidden)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    assert not result.evidence.complete
    assert result.evidence.to_dict()["npm_projects"]["audits"] == []


@pytest.mark.parametrize("key,value", [("dependencies", []), ("workspaces", []), ("bundledDependencies", []), ("peerDependenciesMeta", {"peer": {"optional": True}})])
async def test_parent_empty_graph_shortcut_cannot_cover_unsupported_declarations(projects, key, value):
    root, parent, _ = projects
    payload = json.loads((parent / "package.json").read_text())
    payload[key] = value
    (parent / "package.json").write_text(json.dumps(payload))
    result = await run(projects)
    assert not result.evidence.complete and evaluate(root, result.evidence.to_dict()).block_merge


async def test_empty_parent_cannot_ignore_a_present_but_invalid_lock_graph(projects):
    root, parent, calls = projects
    (parent / "package-lock.json").write_text("invalid lock graph")
    result = await run(projects)
    assert not result.evidence.complete and len(calls) == 2
    parent_row = result.evidence.to_dict()["npm_projects"]["audits"][-1]
    assert parent_row["outcome"]["reason_code"] == "unsafe_lockfile"
    assert evaluate(root, result.evidence.to_dict()).block_merge


async def test_project_evidence_uses_portable_order_for_mixed_case_paths(projects):
    root, parent, _ = projects
    for name in ("Zeta", "alpha"):
        leaf = parent / "deploy" / name
        leaf.mkdir()
        fixture._prepare_project(leaf, "npm")
    result = await run(projects)
    proof = result.evidence.to_dict()["npm_projects"]
    assert proof["discovered_manifests"] == sorted(proof["discovered_manifests"])
    assert [row["manifest_path"] for row in proof["audits"]] == proof["discovered_manifests"]
    assert evaluate(root, result.evidence.to_dict()).status == GateStatus.PASSED
