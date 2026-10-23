from __future__ import annotations

from policy_fixture import FAKE_POLICY_JSON

from types import SimpleNamespace

import pytest

from omargate.config import OmarGateConfig
from omargate.main import (
    _build_llm_evidence,
    _llm_display_cost,
    _llm_display_identity,
    _llm_fallback_used,
)
from omargate.models import Counts, GateResult, GateStatus
from omargate.telemetry_runtime import _write_github_outputs


@pytest.mark.parametrize("usage,expected_identity", [
    (None, ("NOT_ATTEMPTED", "unknown")),
    ({}, ("NOT_ATTEMPTED", "unknown")),
    ({"provider": "typesafe", "model": None, "requested_model": "model-under-test-1.13.0"}, ("NOT_ATTEMPTED", "unknown")),
    ({"provider": "typesafe", "model": "gpt-5.3-codex"}, ("NOT_ATTEMPTED", "unknown")),
])
def test_llm_display_no_attempt_is_not_attempted(usage, expected_identity) -> None:
    analysis = SimpleNamespace(llm_attempted=False, llm_success=False, llm_usage=usage)

    assert _llm_display_identity(analysis) == expected_identity
    # Not attempted, not successful, no cost ledger → cost unknown (None, never 0.0)
    cost, complete = _llm_display_cost(analysis)
    assert cost is None


@pytest.mark.parametrize(("success", "usage", "expected"), [
    (True, {"provider": "typesafe", "model": "model-under-test-1.13.0"}, ("typesafe", "model-under-test-1.13.0")),
    (False, {"provider": "typesafe", "model": None, "requested_model": "model-under-test-1.13.0"}, ("ATTEMPTED-FAILED", "unknown")),
    (True, {"provider": "openai", "engine": "codex", "model": "reported-model"}, ("codex", "reported-model")),
    (False, {"provider": "openai", "model": "reported-model"}, ("ATTEMPTED-FAILED", "unknown")),
    (True, None, ("llm", "unknown")),
    (False, None, ("ATTEMPTED-FAILED", "unknown")),
    (True, {"provider": "openai", "model": "  "}, ("openai", "unknown")),
])
def test_llm_display_attempt_uses_only_observed_model(success, usage, expected) -> None:
    analysis = SimpleNamespace(llm_attempted=True, llm_success=success, llm_usage=usage)

    assert _llm_display_identity(analysis) == expected


@pytest.mark.parametrize(("success", "usage", "expected"), [
    (False, None, None),
    (False, {"provider": "typesafe", "cost_usd": None}, None),
    (False, {"cost_usd": 0.125}, 0.125),
    (False, {"cost_usd": 0}, 0.0),
    (True, None, None),
    (True, {"cost_usd": None}, None),
    (True, {"cost_usd": 0.125}, 0.125),
])
def test_llm_display_attempt_cost_is_unknown_unless_reported(success, usage, expected) -> None:
    analysis = SimpleNamespace(llm_attempted=True, llm_success=success, llm_usage=usage)

    cost, complete = _llm_display_cost(analysis)
    assert cost == expected


def test_llm_display_success_without_attempt_flag_does_not_invent_identity_or_free_cost() -> None:
    analysis = SimpleNamespace(llm_attempted=False, llm_success=True, llm_usage=None)

    assert _llm_display_identity(analysis) == ("llm", "unknown")
    cost, complete = _llm_display_cost(analysis)
    assert cost is None


def test_preflight_failure_evidence_stays_failed_while_comment_identity_is_disabled() -> None:
    usage = {
        "provider": "typesafe", "model": None, "requested_model": "model-under-test-1.13.0",
        "tokens_in": None, "tokens_out": None, "cost_usd": None,
        "typesafe_assessment": {"failure_class": "typesafe_policy_unavailable"},
    }
    analysis = SimpleNamespace(
        llm_usage=usage, llm_attempted=False, llm_success=False,
        llm_output_valid=False, llm_no_findings_reported=False,
        llm_reported_finding_count=0, llm_count=1, llm_parse_error_count=0,
        llm_failure_class="typesafe_policy_unavailable",
    )
    config = OmarGateConfig(
        llm_provider="typesafe", typesafe_api_key="fixture-typed-key",
        openai_api_key="fixture-writer-key", sentinelayer_spec_id="fixture",
     intent_model_pin="model-under-test-1.13.0", intent_policy=FAKE_POLICY_JSON)

    evidence = _build_llm_evidence(analysis, config)

    assert _llm_display_identity(analysis) == ("NOT_ATTEMPTED", "typesafe_policy_unavailable")
    assert evidence["attempted"] is False and evidence["success"] is False
    assert evidence["output_valid"] is False and evidence["model"] == ""
    assert evidence["provider"] == "typesafe" and evidence["usage_recorded"] is True
    assert evidence["failure_class"] == "typesafe_policy_unavailable"
    assert analysis.llm_usage is usage and usage["model"] is None


def test_llm_fallback_used_detects_configured_fallback_model() -> None:
    assert _llm_fallback_used(
        {"model": "gemini-2.5-flash"},
        model_fallback="gemini-2.5-flash",
    )


def test_llm_fallback_used_detects_managed_capacity_route() -> None:
    assert _llm_fallback_used(
        {
            "model": "gpt-5.3-codex",
            "route": "managed_after_byo_capacity",
        },
        model_fallback="gemini-2.5-flash",
    )


def test_llm_fallback_used_ignores_primary_byo_route() -> None:
    assert not _llm_fallback_used(
        {
            "model": "gpt-5.3-codex",
            "route": "byo",
        },
        model_fallback="gemini-2.5-flash",
    )


def test_build_llm_evidence_records_successful_codex_contract() -> None:
    analysis = SimpleNamespace(
        llm_usage={
            "engine": "codex",
            "provider": "openai",
            "model": "gpt-5.3-codex",
            "tokens_in": None,
            "tokens_out": None,
            "cost_usd": None,
            "latency_ms": 125,
        },
        llm_attempted=True,
        llm_success=True,
        llm_output_valid=True,
        llm_no_findings_reported=True,
        llm_reported_finding_count=0,
        llm_count=0,
        llm_parse_error_count=0,
        llm_failure_class=None,
    )

    evidence = _build_llm_evidence(
        analysis,
        OmarGateConfig(openai_api_key="sk_test_dummy"),
    )

    assert evidence == {
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
        "latency_ms": 125,
        "fallback_used": False,
    }


def test_build_llm_evidence_preserves_failed_attempt_metadata() -> None:
    analysis = SimpleNamespace(
        llm_usage={
            "provider": "openai",
            "model": "gpt-5.3-codex",
            "latency_ms": 25,
            "route": "managed_after_byo_capacity_failed",
        },
        llm_attempted=True,
        llm_success=False,
        llm_output_valid=False,
        llm_no_findings_reported=False,
        llm_reported_finding_count=0,
        llm_count=1,
        llm_parse_error_count=0,
        llm_failure_class="provider_failure",
    )

    evidence = _build_llm_evidence(
        analysis,
        OmarGateConfig(openai_api_key="sk_test_dummy"),
    )

    assert evidence["success"] is False
    assert evidence["output_valid"] is False
    assert evidence["failure_class"] == "provider_failure"
    assert evidence["usage_recorded"] is True
    assert evidence["model"] == "gpt-5.3-codex"
    assert evidence["fallback_used"] is True


def test_github_outputs_expose_live_llm_evidence(tmp_path, monkeypatch) -> None:
    findings_path = tmp_path / "FINDINGS.jsonl"
    pack_summary_path = tmp_path / "PACK_SUMMARY.json"
    output_path = tmp_path / "github-output.txt"
    findings_path.write_text("", encoding="utf-8")
    pack_summary_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    _write_github_outputs(
        run_id="test-run",
        idem_key="idem",
        findings_path=findings_path,
        pack_summary_path=pack_summary_path,
        gate_result=GateResult(
            status=GateStatus.ERROR,
            reason="live LLM failed",
            block_merge=True,
            counts=Counts(p0=1),
        ),
        llm_attempted=True,
        llm_success=False,
        llm_output_valid=False,
        llm_no_findings_reported=False,
        llm_findings_count=0,
        llm_parse_error_count=2,
        llm_failure_class="invalid_output",
    )

    output = output_path.read_text(encoding="utf-8")
    assert "llm_attempted=true\n" in output
    assert "llm_success=false\n" in output
    assert "llm_output_valid=false\n" in output
    assert "llm_no_findings_reported=false\n" in output
    assert "llm_findings_count=0\n" in output
    assert "llm_parse_error_count=2\n" in output
    assert "llm_failure_class=invalid_output\n" in output


def test_not_attempted_review_reports_not_attempted_with_routing_reason() -> None:
    """PR #660 scenario: attempted=False, success=False, routing has source_failure_reason.
    Should report 'NOT_ATTEMPTED' with the routing reason, not failure_class."""
    usage = {
        "provider": "typesafe", "model": None, "requested_model": "model-under-test-1.13.0",
        "tokens_in": None, "tokens_out": None, "cost_usd": None,
        "review_routing": {
            "triage_status": "source_scope_incomplete",
            "source_failure_reason": "candidate_budget_exceeded",
            "routes": [{"tier": "deep", "model": "gpt-6-sol", "effort": "max",
                         "success": False, "reported_model": "", "identity_matches": False}],
        },
    }
    analysis = SimpleNamespace(
        llm_usage=usage, llm_attempted=False, llm_success=False,
        llm_output_valid=False, llm_failure_class="cascade_source_scope_incomplete",
    )

    # With routing data: uses source_failure_reason
    assert _llm_display_identity(analysis, routing=usage["review_routing"]) == ("NOT_ATTEMPTED", "candidate_budget_exceeded")
    # Without routing data: falls back to failure_class
    assert _llm_display_identity(analysis) == ("NOT_ATTEMPTED", "cascade_source_scope_incomplete")
    # Cost unknown (not $0.00) when the review was refused
    cost, complete = _llm_display_cost(analysis)
    assert cost is None


def test_refused_review_with_cost_ledger_reports_known_cost() -> None:
    """Refused review with partial cost ledger: report known cost as subtotal."""
    usage = {
        "provider": "typesafe",
        "cost_ledger": {"complete": False, "known_estimated_usd": 0.042,
                        "estimated_total_usd": None, "calls": [
                            {"estimated_usd": 0.042, "stage": "triage", "model": "intent-model:abc123",
                             "provider": "typesafe"},
                        ]},
        "review_routing": {
            "triage_status": "source_scope_incomplete",
            "source_failure_reason": "candidate_budget_exceeded",
        },
    }
    analysis = SimpleNamespace(
        llm_usage=usage, llm_attempted=False, llm_success=False,
        llm_output_valid=False, llm_failure_class="cascade_source_scope_incomplete",
    )

    assert _llm_display_identity(analysis) == ("NOT_ATTEMPTED", "cascade_source_scope_incomplete")
    cost, complete = _llm_display_cost(analysis)
    assert cost == 0.042
    assert complete is False  # Incomplete ledger — subtotal only
