from __future__ import annotations

import json
from pathlib import Path

from omargate.idempotency import compute_idempotency_key
from omargate.models import Finding
import omargate.packaging as packaging
from omargate.packaging import get_run_dir, new_run_dir, write_findings_jsonl, write_pack_summary
from omargate.utils import sha256_hex


def test_idempotency_key_is_stable() -> None:
    key1 = compute_idempotency_key(
        repo="octo/repo",
        pr_number=1,
        head_sha="abc",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
    )
    key2 = compute_idempotency_key(
        repo="octo/repo",
        pr_number=1,
        head_sha="abc",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
    )

    assert key1 == key2
    assert len(key1) == 64


def test_packaging_writes_summary(tmp_path: Path) -> None:
    run_dir = new_run_dir(tmp_path)
    findings = [
        Finding(
            finding_id="F1",
            severity="P2",
            category="test",
            file_path="file.py",
            line_start=1,
            line_end=2,
            message="msg",
            recommendation="fix",
            fingerprint="fp",
            confidence=0.9,
        )
    ]

    findings_path = run_dir / "FINDINGS.jsonl"
    write_findings_jsonl(findings_path, findings)
    llm_evidence = {
        "schema_version": "1.0",
        "attempted": True,
        "success": True,
        "output_valid": True,
        "no_findings_reported": True,
        "reported_finding_count": 0,
        "parse_error_count": 0,
        "usage_recorded": True,
        "engine": "codex",
        "provider": "openai",
        "model": "gpt-5.3-codex",
        "latency_ms": 25,
    }
    dependency_audit_evidence = {
        "schema_version": "1.1",
        "enabled": True,
        "complete": True,
        "coverage_scope": {
            "npm": "package_lock_registry_graph",
            "pip": "declared_direct_pins",
            "cargo": "cargo_lock_packages",
        },
        "outcomes": [
            {
                "ecosystem": ecosystem,
                "applicable": False,
                "state": None,
                "vulnerability_count": None,
                "reason_code": None,
            }
            for ecosystem in ("npm", "pip", "cargo")
        ],
    }
    summary_path = write_pack_summary(
        run_dir=run_dir,
        run_id=run_dir.name,
        writer_complete=True,
        findings_path=findings_path,
        counts={"P0": 0, "P1": 0, "P2": 1, "P3": 0},
        tool_versions={"action": "1.0"},
        stages_completed=["packaging"],
        fingerprint_count=1,
        dedupe_key="dedupe-key",
        policy_pack="omar",
        policy_pack_version="v1",
        llm_evidence=llm_evidence,
        dependency_audit_evidence=dependency_audit_evidence,
        error=None,
    )

    data = json.loads(summary_path.read_text(encoding="utf-8"))
    assert data["counts"]["total"] == 1
    assert data["findings_file_sha256"] == sha256_hex(findings_path.read_bytes())
    assert data["fingerprint_count"] == 1
    assert data["dedupe_key"] == "dedupe-key"
    assert data["llm_evidence"] == llm_evidence
    assert data["dependency_audit_evidence"] == dependency_audit_evidence


def test_get_run_dir_prefers_workspace(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    monkeypatch.delenv("SENTINELAYER_RUNS_DIR", raising=False)

    run_dir = get_run_dir("run-123")

    expected_base = workspace / ".sentinelayer" / "runs"
    assert run_dir.parent == expected_base


def test_get_run_dir_falls_back_to_runner_temp(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner_temp"
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
    monkeypatch.delenv("SENTINELAYER_RUNS_DIR", raising=False)

    def fake_writable(path: Path) -> bool:
        return path != workspace / ".sentinelayer" / "runs"

    monkeypatch.setattr(packaging, "ensure_writable_dir", fake_writable)

    run_dir = get_run_dir("run-456")

    expected_base = runner_temp / "sentinelayer" / "runs"
    assert run_dir.parent == expected_base
