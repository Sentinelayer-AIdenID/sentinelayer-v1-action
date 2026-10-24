"""Replay actual npm 11 graph reports; advisory outcomes are deliberately synthetic."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from omargate.harness.runner import CommandResult
from omargate.harness.suites import dep_audit

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
CAPTURED = json.loads((FIXTURES / "npm11-audit-reports.json").read_text(encoding="utf-8"))
SPEC = importlib.util.spec_from_file_location("npm11_replay", FIXTURES / "replay_npm11_audit_reports.py")
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)


@pytest.mark.anyio
@pytest.mark.parametrize("case_name", CAPTURED["cases"])
@pytest.mark.parametrize("result_kind", ["empty", "vulnerable", "wrong-total", "invented-peerOptional"])
async def test_npm11_reports_preserve_optional_peers_and_real_graphs(tmp_path, monkeypatch, case_name, result_kind):
    case = CAPTURED["cases"][case_name]
    inputs = REPLAY.input_bytes(case, FIXTURES)
    for name, raw in inputs.items():
        (tmp_path / name).write_bytes(raw)
    captured = case["captured"]
    assert captured["npm_version"] == "11.11.0"
    assert captured["inventory_count"] == case["expected_total"]
    assert captured["report"]["metadata"]["dependencies"]["peer"] == case["expected_peers"]
    assert captured["report"]["metadata"]["dependencies"]["peerOptional"] == 0
    assert all(edge["valid"] for edge in captured["optional_peer_edges"])
    payload = copy.deepcopy(captured["report"])
    dependencies = payload["metadata"]["dependencies"]
    if result_kind == "vulnerable":
        payload["vulnerabilities"] = {case["vulnerability_package"]: {"severity": "high"}}
        payload["metadata"]["vulnerabilities"].update(high=1, total=1)
    elif result_kind == "wrong-total":
        dependencies["total"] -= 1
    elif result_kind == "invented-peerOptional":
        dependencies["peerOptional"] = 1
        if dependencies["peer"]:
            dependencies["peer"] -= 1
        else:
            dependencies["total"] += 1

    calls = []

    async def command(args, *, cwd, timeout_s, project_root):
        calls.append(args)
        assert "--package-lock-only" in args
        assert all((cwd / name).read_bytes() == raw for name, raw in inputs.items())
        return CommandResult(args=args, status="exited", returncode=int(result_kind == "vulnerable"),
                             stdout=json.dumps(payload), stderr="", cleanup_proven=True)

    monkeypatch.setattr(dep_audit, "run_command", command)
    records = []
    _, outcome = await dep_audit.DepAuditSuite(tech_stack=[])._npm_audit(tmp_path, project_records=records)
    assert len(calls) == 1
    assert records[0]["manifest_sha256"] == hashlib.sha256(inputs["package.json"]).hexdigest()
    assert records[0]["lockfile_sha256"] == hashlib.sha256(inputs["package-lock.json"]).hexdigest()
    assert records[0]["input_unchanged"]
    if result_kind == "empty":
        assert outcome.state == "clean"
    elif result_kind == "vulnerable":
        assert outcome.state == "vulnerable" and outcome.vulnerability_count == 1
    else:
        assert outcome.state == "indeterminate" and outcome.reason_code == "unrecognized_schema"
