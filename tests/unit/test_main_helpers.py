from __future__ import annotations

from omargate.config import OmarGateConfig
from omargate.main import (
    _build_spec_compliance_from_findings,
    _check_name,
    _counts_from_check_run_output,
    _exit_code_from_gate_result,
    _gate_result_from_check_run,
    _github_publish_enabled,
    _latest_completed_check_run,
    _map_category_to_spec_sections,
)
from omargate.models import GateStatus
from omargate.utils import parse_iso8601


def test_parse_iso8601_handles_z_suffix() -> None:
    ts = parse_iso8601("2026-02-08T05:31:22.137538Z")
    assert ts is not None
    assert ts.tzinfo is not None


def test_check_name_uses_comment_tag_when_set() -> None:
    assert _check_name("") == "Omar Gate"
    assert _check_name("gemini") == "Omar Gate (gemini)"


def test_github_publish_enabled_defaults_true(monkeypatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    assert _github_publish_enabled(OmarGateConfig()) is True


def test_github_publish_enabled_honors_false(monkeypatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_PUBLISH_GITHUB", "false")
    assert _github_publish_enabled(OmarGateConfig()) is False


def test_latest_completed_check_run_picks_newest_completed() -> None:
    runs = [
        {"status": "completed", "completed_at": "2026-02-08T05:30:00Z", "id": 1},
        {"status": "in_progress", "completed_at": "2026-02-08T05:40:00Z", "id": 2},
        {"status": "completed", "completed_at": "2026-02-08T05:31:00Z", "id": 3},
    ]
    latest = _latest_completed_check_run(runs)
    assert latest is not None
    assert latest.get("id") == 3


def test_counts_from_check_run_output_prefers_marker() -> None:
    summary = "🔴 P0=9 • 🟠 P1=9 • 🟡 P2=9 • ⚪ P3=9"
    text = (
        "Some reason\n\n"
        "<!-- sentinelayer:counts:{\"P0\":1,\"P1\":2,\"P2\":3,\"P3\":4} -->"
    )
    counts = _counts_from_check_run_output(summary=summary, text=text)
    assert (counts.p0, counts.p1, counts.p2, counts.p3) == (1, 2, 3, 4)


def test_counts_from_check_run_output_falls_back_to_summary() -> None:
    summary = "🔴 P0=1 • 🟠 P1=2 • 🟡 P2=3 • ⚪ P3=4"
    counts = _counts_from_check_run_output(summary=summary, text="")
    assert (counts.p0, counts.p1, counts.p2, counts.p3) == (1, 2, 3, 4)


def test_gate_result_from_check_run_strips_counts_marker_from_reason() -> None:
    run = {
        "conclusion": "success",
        "external_id": "abc",
        "output": {
            "summary": "🔴 P0=0 • 🟠 P1=0 • 🟡 P2=0 • ⚪ P3=0",
            "text": "No blocking findings\n\n<!-- sentinelayer:counts:{\"P0\":0,\"P1\":0,\"P2\":0,\"P3\":0} -->",
        },
    }
    result = _gate_result_from_check_run(
        run, fallback_reason="Fallback", extra_note="Mirrored"
    )
    assert result.status == GateStatus.PASSED
    assert "sentinelayer:counts" not in result.reason
    assert "Mirrored" in result.reason


def test_exit_code_from_gate_result_needs_approval_is_13() -> None:
    run = {
        "conclusion": "action_required",
        "external_id": "abc",
        "output": {
            "summary": "🔴 P0=0 • 🟠 P1=0 • 🟡 P2=0 • ⚪ P3=0",
            "text": "Approval required",
        },
    }
    result = _gate_result_from_check_run(run, fallback_reason="Fallback", extra_note="")
    assert result.status == GateStatus.NEEDS_APPROVAL
    assert _exit_code_from_gate_result(result) == 13


def test_map_category_to_spec_sections() -> None:
    assert _map_category_to_spec_sections("security.xss") == {"5"}
    assert _map_category_to_spec_sections("quality.lint") == {"7"}


def test_build_spec_compliance_from_findings() -> None:
    payload = _build_spec_compliance_from_findings(
        spec_context={
            "spec_hash": "a" * 64,
            "security_rules": "-",
            "quality_gates": "-",
            "domain_rules": "",
        },
        findings=[
            {"category": "security.auth", "severity": "P1"},
            {"category": "quality.lint", "severity": "P2"},
        ],
    )
    assert payload is not None
    assert payload.spec_hash == "a" * 64
    assert payload.sections_checked == ["5", "7"]
    assert payload.sections_violated == ["5", "7"]

