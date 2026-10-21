from __future__ import annotations

import json
from pathlib import Path

import pytest

from omargate.gate import evaluate_gate
from omargate.models import (
    DEPENDENCY_AUDIT_COVERAGE_SCOPE,
    DEPENDENCY_AUDIT_INDETERMINATE_REASONS,
    DEPENDENCY_AUDIT_SCHEMA_VERSION,
    GateConfig,
    GateStatus,
)
from omargate.utils import sha256_hex


def _write_summary(run_dir: Path, payload: dict) -> None:
    (run_dir / "PACK_SUMMARY.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_findings(run_dir: Path, content: str = "{}") -> Path:
    findings = run_dir / "FINDINGS.jsonl"
    findings.write_text(content, encoding="utf-8")
    return findings


def _valid_summary(
    run_dir: Path,
    counts: dict,
    findings: list[dict] | None = None,
) -> dict:
    finding_records = [{}] if findings is None else findings
    findings_path = _write_findings(
        run_dir,
        "\n".join(json.dumps(finding) for finding in finding_records),
    )
    return {
        "run_id": "test-run",
        "writer_complete": True,
        "counts": counts,
        "findings_file": findings_path.name,
        "findings_file_sha256": sha256_hex(findings_path.read_bytes()),
    }


def _valid_llm_evidence() -> dict:
    return {
        "schema_version": "1.0",
        "attempted": True,
        "success": True,
        "output_valid": True,
        "no_findings_reported": True,
        "reported_finding_count": 0,
        "accepted_finding_count": 0,
        "parse_error_count": 0,
        "failure_class": None,
        "usage_recorded": True,
        "engine": "codex",
        "provider": "openai",
        "model": "gpt-5.3-codex",
        "route": None,
        "tokens_in": None,
        "tokens_out": None,
        "latency_ms": 25,
        "fallback_used": False,
    }


def _valid_dependency_audit_evidence() -> dict:
    return {
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
                "ecosystem": "npm",
                "applicable": True,
                "state": "clean",
                "vulnerability_count": 0,
                "reason_code": None,
            },
            {
                "ecosystem": "pip",
                "applicable": False,
                "state": None,
                "vulnerability_count": None,
                "reason_code": None,
            },
            {
                "ecosystem": "cargo",
                "applicable": False,
                "state": None,
                "vulnerability_count": None,
                "reason_code": None,
            },
        ],
    }


def _dependency_outcome(evidence: dict, ecosystem: str) -> dict:
    return next(
        outcome
        for outcome in evidence["outcomes"]
        if outcome["ecosystem"] == ecosystem
    )


def _dependency_audit_finding(ecosystem: str, **overrides: object) -> dict:
    finding_id = {
        "npm": "HARNESS-NPM-AUDIT",
        "pip": "HARNESS-PIP-AUDIT",
        "cargo": "HARNESS-CARGO-AUDIT",
    }[ecosystem]
    finding: dict[str, object] = {
        "id": finding_id,
        "pattern_id": finding_id,
        "severity": "P1",
        "source": "harness",
        "category": "supply-chain",
    }
    finding.update(overrides)
    return finding


def test_gate_missing_summary_blocks(tmp_path: Path) -> None:
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_dependency_audit_requirement_defaults_off() -> None:
    assert GateConfig().require_dependency_audit_success is False


def test_dependency_audit_indeterminate_reason_contract_is_fixed() -> None:
    assert DEPENDENCY_AUDIT_INDETERMINATE_REASONS == frozenset(
        {
            "command_not_found",
            "decode_error",
            "empty_output",
            "error_payload",
            "execution_error",
            "exit_result_mismatch",
            "exited_127",
            "invalid_json",
            "manifest_discovery_incomplete",
            "missing_lockfile",
            "output_limit_exceeded",
            "process_containment_error",
            "spawn_error",
            "suite_error",
            "suite_not_run",
            "suite_timed_out",
            "timed_out",
            "unexpected_exit",
            "unrecognized_schema",
            "unsupported_project_layout",
            "unsafe_lockfile",
            "unsafe_manifest",
            "unsafe_pip_input",
            "unsafe_working_directory",
            "unsupported_pip_input",
        }
    )


def test_dependency_audit_coverage_contract_is_fixed() -> None:
    assert DEPENDENCY_AUDIT_SCHEMA_VERSION == "1.1"
    assert DEPENDENCY_AUDIT_COVERAGE_SCOPE == {
        "npm": "package_lock_registry_graph",
        "pip": "declared_direct_pins",
        "cargo": "cargo_lock_packages",
    }


def test_gate_corrupted_summary_blocks(tmp_path: Path) -> None:
    (tmp_path / "PACK_SUMMARY.json").write_text("{ not json", encoding="utf-8")
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_incomplete_summary_blocks(tmp_path: Path) -> None:
    _write_summary(tmp_path, {"writer_complete": False})
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_hash_mismatch_blocks(tmp_path: Path) -> None:
    findings = _write_findings(tmp_path)
    _write_summary(
        tmp_path,
        {
            "run_id": "test-run",
            "writer_complete": True,
            "counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
            "findings_file": findings.name,
            "findings_file_sha256": "deadbeef",
        },
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_missing_required_fields_blocks(tmp_path: Path) -> None:
    findings = _write_findings(tmp_path)
    _write_summary(
        tmp_path,
        {
            "run_id": "test-run",
            "writer_complete": True,
            "findings_file": findings.name,
            "findings_file_sha256": sha256_hex(findings.read_bytes()),
        },
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.ERROR


def test_gate_p0_blocks_on_p1_threshold(tmp_path: Path) -> None:
    _write_summary(
        tmp_path,
        _valid_summary(tmp_path, {"P0": 1, "P1": 0, "P2": 0, "P3": 0}),
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.block_merge is True
    assert result.status == GateStatus.BLOCKED


def test_gate_p1_passes_on_p0_threshold(tmp_path: Path) -> None:
    _write_summary(
        tmp_path,
        _valid_summary(tmp_path, {"P0": 0, "P1": 1, "P2": 0, "P3": 0}),
    )
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P0"))
    assert result.block_merge is False
    assert result.status == GateStatus.PASSED


def test_gate_sets_dedupe_key_from_summary(tmp_path: Path) -> None:
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dedupe_key"] = "dedupe-xyz"
    _write_summary(tmp_path, payload)
    result = evaluate_gate(tmp_path, GateConfig(severity_gate="P1"))
    assert result.dedupe_key == "dedupe-xyz"


def test_gate_severity_none_still_requires_valid_live_llm_evidence(tmp_path: Path) -> None:
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["llm_evidence"] = _valid_llm_evidence()
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(severity_gate="none", require_llm_success=True),
    )

    assert result.block_merge is False
    assert result.status == GateStatus.PASSED


@pytest.mark.parametrize(
    ("field", "value", "reason_fragment"),
    [
        ("attempted", False, "not attempted"),
        ("success", False, "did not succeed"),
        ("output_valid", False, "output contract"),
        ("usage_recorded", False, "usage evidence"),
        ("parse_error_count", 1, "parse errors"),
        ("no_findings_reported", False, "neither findings nor an explicit clean result"),
        ("model", "", "field model"),
        ("latency_ms", 0, "latency evidence"),
    ],
)
def test_gate_invalid_live_llm_evidence_blocks_even_when_severity_gate_is_none(
    tmp_path: Path,
    field: str,
    value: object,
    reason_fragment: str,
) -> None:
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    evidence = _valid_llm_evidence()
    evidence[field] = value
    payload["llm_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(severity_gate="none", require_llm_success=True),
    )

    assert result.block_merge is True
    assert result.status == GateStatus.ERROR
    assert reason_fragment in result.reason


def test_gate_findings_result_is_valid_live_llm_evidence(tmp_path: Path) -> None:
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 1, "P3": 0})
    evidence = _valid_llm_evidence()
    evidence["reported_finding_count"] = 1
    evidence["accepted_finding_count"] = 1
    evidence["no_findings_reported"] = False
    payload["llm_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(severity_gate="none", require_llm_success=True),
    )

    assert result.block_merge is False
    assert result.status == GateStatus.PASSED


def test_gate_dependency_audit_is_checked_before_disabled_severity(
    tmp_path: Path,
) -> None:
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(
            severity_gate="none",
            require_dependency_audit_success=True,
        ),
    )

    assert result.status == GateStatus.ERROR
    assert result.block_merge is True
    assert "dependency audit evidence is missing" in result.reason


def test_gate_clean_dependency_audit_passes_disabled_severity(
    tmp_path: Path,
) -> None:
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dependency_audit_evidence"] = _valid_dependency_audit_evidence()
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(
            severity_gate="none",
            require_dependency_audit_success=True,
        ),
    )

    assert result.status == GateStatus.PASSED
    assert result.block_merge is False


@pytest.mark.parametrize(
    "case",
    [
        "extra_top_level_field",
        "legacy_schema",
        "unsupported_schema",
        "missing_coverage_scope",
        "coverage_scope_not_object",
        "missing_coverage_ecosystem",
        "extra_coverage_ecosystem",
        "wrong_coverage_scope",
        "non_boolean_complete",
        "outcomes_not_list",
        "missing_outcome_field",
        "unhashable_ecosystem",
        "duplicate_ecosystem",
        "non_boolean_applicable",
        "unhashable_state",
        "non_applicable_with_result",
        "clean_with_vulnerabilities",
        "vulnerable_without_vulnerabilities",
        "boolean_vulnerability_count",
    ],
)
def test_gate_malformed_dependency_audit_evidence_fails_closed(
    tmp_path: Path,
    case: str,
) -> None:
    evidence = _valid_dependency_audit_evidence()
    if case == "extra_top_level_field":
        evidence["unexpected"] = True
    elif case == "legacy_schema":
        evidence["schema_version"] = "1.0"
    elif case == "unsupported_schema":
        evidence["schema_version"] = "2.0"
    elif case == "missing_coverage_scope":
        evidence.pop("coverage_scope")
    elif case == "coverage_scope_not_object":
        evidence["coverage_scope"] = []
    elif case == "missing_coverage_ecosystem":
        evidence["coverage_scope"].pop("cargo")
    elif case == "extra_coverage_ecosystem":
        evidence["coverage_scope"]["nuget"] = "packages_lock_graph"
    elif case == "wrong_coverage_scope":
        evidence["coverage_scope"]["pip"] = "resolved_transitive_graph"
    elif case == "non_boolean_complete":
        evidence["complete"] = "true"
    elif case == "outcomes_not_list":
        evidence["outcomes"] = {}
    elif case == "missing_outcome_field":
        evidence["outcomes"][0].pop("reason_code")
    elif case == "unhashable_ecosystem":
        evidence["outcomes"][0]["ecosystem"] = []
    elif case == "duplicate_ecosystem":
        evidence["outcomes"][1]["ecosystem"] = "npm"
    elif case == "non_boolean_applicable":
        evidence["outcomes"][0]["applicable"] = 1
    elif case == "unhashable_state":
        evidence["outcomes"][0]["state"] = []
    elif case == "non_applicable_with_result":
        outcome = _dependency_outcome(evidence, "pip")
        outcome["state"] = "clean"
        outcome["vulnerability_count"] = 0
    elif case == "clean_with_vulnerabilities":
        evidence["outcomes"][0]["vulnerability_count"] = 1
    elif case == "vulnerable_without_vulnerabilities":
        evidence["outcomes"][0]["state"] = "vulnerable"
    elif case == "boolean_vulnerability_count":
        evidence["outcomes"][0]["vulnerability_count"] = False

    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert result.block_merge is True
    assert result.reason.startswith("FAIL-CLOSED:")
    assert "dependency audit" in result.reason


def test_gate_validates_coverage_before_disabled_or_incomplete_state(
    tmp_path: Path,
) -> None:
    evidence = _valid_dependency_audit_evidence()
    evidence["enabled"] = False
    evidence["complete"] = False
    evidence["coverage_scope"].pop("cargo")
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert result.block_merge is True
    assert "dependency audit coverage scope fields are invalid" in result.reason


@pytest.mark.parametrize(
    ("ecosystem", "reason_code"),
    [
        ("npm", "command_not_found"),
        ("npm", "manifest_discovery_incomplete"),
        ("npm", "process_containment_error"),
        ("pip", "unsupported_pip_input"),
        ("cargo", "timed_out"),
        ("cargo", "unsupported_project_layout"),
    ],
)
def test_gate_indeterminate_dependency_audit_fails_closed_for_each_ecosystem(
    tmp_path: Path,
    ecosystem: str,
    reason_code: str,
) -> None:
    evidence = _valid_dependency_audit_evidence()
    outcome = _dependency_outcome(evidence, ecosystem)
    outcome.update(
        applicable=True,
        state="indeterminate",
        vulnerability_count=None,
        reason_code=reason_code,
    )
    evidence["complete"] = False
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(
            severity_gate="none",
            require_dependency_audit_success=True,
        ),
    )

    assert result.status == GateStatus.ERROR
    assert result.block_merge is True
    assert f"{ecosystem} dependency audit is indeterminate" in result.reason


def test_gate_incomplete_dependency_audit_fails_closed(tmp_path: Path) -> None:
    evidence = _valid_dependency_audit_evidence()
    evidence["complete"] = False
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert "dependency audit did not complete" in result.reason


def test_gate_rejects_unknown_indeterminate_dependency_audit_reason(
    tmp_path: Path,
) -> None:
    evidence = _valid_dependency_audit_evidence()
    evidence["outcomes"][0].update(
        state="indeterminate",
        vulnerability_count=None,
        reason_code="plausible_but_unknown",
    )
    evidence["complete"] = False
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert "indeterminate dependency audit evidence is invalid" in result.reason


def test_gate_disabled_dependency_audit_fails_when_required(tmp_path: Path) -> None:
    evidence = _valid_dependency_audit_evidence()
    evidence["enabled"] = False
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert "dependency audit was not enabled" in result.reason


def test_gate_dependency_audit_requirement_false_is_the_opt_out(
    tmp_path: Path,
) -> None:
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    payload["dependency_audit_evidence"] = {"enabled": False}
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(
            severity_gate="none",
            require_dependency_audit_success=False,
        ),
    )

    assert result.status == GateStatus.PASSED
    assert result.block_merge is False


def test_gate_dependency_audit_is_validated_before_llm_evidence(
    tmp_path: Path,
) -> None:
    payload = _valid_summary(tmp_path, {"P0": 0, "P1": 0, "P2": 0, "P3": 0})
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(
            severity_gate="none",
            require_llm_success=True,
            require_dependency_audit_success=True,
        ),
    )

    assert result.status == GateStatus.ERROR
    assert "dependency audit evidence is missing" in result.reason


@pytest.mark.parametrize(
    ("severity_gate", "expected_status", "expected_block_merge"),
    [
        ("P1", GateStatus.BLOCKED, True),
        ("P0", GateStatus.PASSED, False),
        ("none", GateStatus.PASSED, False),
    ],
)
def test_gate_dependency_vulnerability_uses_normal_severity_threshold(
    tmp_path: Path,
    severity_gate: str,
    expected_status: GateStatus,
    expected_block_merge: bool,
) -> None:
    evidence = _valid_dependency_audit_evidence()
    evidence["outcomes"][0].update(
        state="vulnerable",
        vulnerability_count=2,
    )
    payload = _valid_summary(
        tmp_path,
        {"P0": 0, "P1": 1, "P2": 0, "P3": 0},
        findings=[_dependency_audit_finding("npm")],
    )
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(
            severity_gate=severity_gate,
            require_dependency_audit_success=True,
        ),
    )

    assert result.status == expected_status
    assert result.block_merge is expected_block_merge


def test_gate_unrelated_p1_cannot_mask_missing_dependency_audit_finding(
    tmp_path: Path,
) -> None:
    evidence = _valid_dependency_audit_evidence()
    evidence["outcomes"][0].update(
        state="vulnerable",
        vulnerability_count=1,
    )
    payload = _valid_summary(
        tmp_path,
        {"P0": 0, "P1": 1, "P2": 0, "P3": 0},
        findings=[
            {
                "id": "UNRELATED-P1",
                "pattern_id": "UNRELATED-P1",
                "severity": "P1",
                "source": "deterministic",
                "category": "security",
            }
        ],
    )
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert result.block_merge is True
    assert "npm vulnerability evidence is missing its audit finding" in result.reason


def test_gate_wrong_ecosystem_audit_finding_fails_closed(tmp_path: Path) -> None:
    evidence = _valid_dependency_audit_evidence()
    evidence["outcomes"][0].update(
        state="vulnerable",
        vulnerability_count=1,
    )
    payload = _valid_summary(
        tmp_path,
        {"P0": 0, "P1": 1, "P2": 0, "P3": 0},
        findings=[_dependency_audit_finding("pip")],
    )
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert result.block_merge is True
    assert "pip audit finding contradicts not-applicable evidence" in result.reason


def test_gate_duplicate_dependency_audit_finding_fails_closed(
    tmp_path: Path,
) -> None:
    evidence = _valid_dependency_audit_evidence()
    evidence["outcomes"][0].update(
        state="vulnerable",
        vulnerability_count=2,
    )
    payload = _valid_summary(
        tmp_path,
        {"P0": 0, "P1": 2, "P2": 0, "P3": 0},
        findings=[
            _dependency_audit_finding("npm"),
            _dependency_audit_finding("npm"),
        ],
    )
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert result.block_merge is True
    assert "duplicate npm dependency audit findings" in result.reason


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "OTHER"),
        ("pattern_id", "OTHER"),
        ("severity", "P2"),
        ("source", "deterministic"),
        ("category", "harness"),
    ],
)
def test_gate_dependency_audit_finding_requires_exact_producer_identity(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    evidence = _valid_dependency_audit_evidence()
    evidence["outcomes"][0].update(
        state="vulnerable",
        vulnerability_count=1,
    )
    payload = _valid_summary(
        tmp_path,
        {"P0": 0, "P1": 1, "P2": 0, "P3": 0},
        findings=[_dependency_audit_finding("npm", **{field: value})],
    )
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert result.block_merge is True
    assert "npm dependency audit finding is invalid" in result.reason


@pytest.mark.parametrize("ecosystem", ["npm", "pip"])
def test_gate_non_vulnerable_evidence_rejects_audit_finding(
    tmp_path: Path,
    ecosystem: str,
) -> None:
    evidence = _valid_dependency_audit_evidence()
    payload = _valid_summary(
        tmp_path,
        {"P0": 0, "P1": 1, "P2": 0, "P3": 0},
        findings=[_dependency_audit_finding(ecosystem)],
    )
    payload["dependency_audit_evidence"] = evidence
    _write_summary(tmp_path, payload)

    result = evaluate_gate(
        tmp_path,
        GateConfig(require_dependency_audit_success=True),
    )

    assert result.status == GateStatus.ERROR
    assert result.block_merge is True
    expected_state = "clean" if ecosystem == "npm" else "not-applicable"
    assert f"{ecosystem} audit finding contradicts {expected_state} evidence" in (
        result.reason
    )
