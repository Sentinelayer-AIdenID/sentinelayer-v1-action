import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from omargate.analyze.review_cascade import (
    DEEP, LOW, MID, DOMAINS, choose_route, excellence_coverage,
    response_model_matches, triage_questions,
)
from omargate.analyze.review_costs import cost_ledger, estimate_usage
from omargate.analyze.typesafe_client import ChoiceAnswer, TypeSafeResult
from omargate.analyze.orchestrator import AnalysisOrchestrator, LLMAnalysisResult
from omargate.analyze.llm.providers.openai_provider import OpenAIProvider
from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger

pytestmark = pytest.mark.anyio


def triage(label="low", *, sensitive=.01, confidence=.99):
    probabilities = dict.fromkeys(["low", "review", "defect"], .005)
    probabilities[label] = .99
    answers = {key: .01 for key in triage_questions()}
    answers["risk"] = ChoiceAnswer(label, probabilities, confidence)
    answers["sensitive"] = sensitive
    return TypeSafeResult("jev-1.13.0", answers, {"input_tokens": 1000, "output_tokens": 45}, 1)


def test_route_uses_independent_impact_confidence_and_sensitivity():
    assert choose_route(triage(), paths=["src/format.py"], findings=[]) == LOW
    assert choose_route(triage("review"), paths=["src/format.py"], findings=[]) == MID
    assert choose_route(triage(confidence=.7), paths=["src/format.py"], findings=[]) == MID
    assert choose_route(triage(), paths=["auth/routes.py"], findings=[]) == DEEP
    assert choose_route(triage(), paths=[".github/workflows/test.yml"], findings=[]) == DEEP
    assert choose_route(triage(sensitive=.5), paths=["x.py"], findings=[]) == DEEP
    assert choose_route(triage(), paths=["x.py"], findings=[{"severity": "P1"}]) == DEEP
    assert choose_route(triage(), paths=["x.py"], findings=[{"severity": "P4"}]) == LOW
    assert choose_route(triage(), paths=["x.py"], findings=[{"severity": "P2"}]) == MID
    assert choose_route(triage("defect"), paths=["x.py"], findings=[]).tier == "deep"
    risky = triage()
    risky.answers["gap_data_flow"] = .7
    assert choose_route(risky, paths=["x.py"], findings=[]) == MID


def test_malformed_or_missing_triage_is_never_low():
    malformed = triage()
    malformed.answers.pop("structural")
    with pytest.raises(Exception, match="invalid"):
        choose_route(malformed, paths=["x.py"], findings=[])


def test_framework_keeps_unassessed_separate_from_verified_score():
    assert sum(weight for weight, _ in DOMAINS.values()) == 100
    assert all(row["status"] == "unassessed" and row["gap_probability"] is None
               for row in excellence_coverage(None)["domains"])
    assert "score" not in excellence_coverage(triage().answers)


@pytest.mark.parametrize("actual,expected", [
    ("gpt-6-sol", True), ("gpt-6-sol-2026-10-01", True),
    ("gpt-6-sol-2026-99-99", False), ("gpt-6-sol-other", False),
    ("gpt-6.1-sol", False),
])
def test_actual_response_model_identity(actual, expected):
    assert response_model_matches(actual, "gpt-6-sol") is expected


def test_separate_costs_cache_and_unknowns():
    jev = estimate_usage("typesafe", "jev-1.13.0", {"input_tokens": 1_000_000, "output_tokens": 1000})
    sol = estimate_usage("openai", "gpt-6.1-sol", {"input_tokens": 100000, "output_tokens": 10000,
        "input_tokens_details": {"cached_tokens": 20000}, "output_tokens_details": {"reasoning_tokens": 9000}})
    assert jev["estimated_usd"] == .042
    assert sol["estimated_usd"] == .262  # reasoning already part of output
    assert cost_ledger([jev, sol])["estimated_total_usd"] == .304
    assert cost_ledger([jev, estimate_usage("openai", "gpt-6-sol", None)])["estimated_total_usd"] is None
    assert estimate_usage("openai", "unknown", {"input_tokens": 1, "output_tokens": 1})["estimated_usd"] is None
    assert estimate_usage("openai", "gpt-6-sol", {"input_tokens": True, "output_tokens": 1})["status"] == "usage_unknown"
    assert estimate_usage("openai", "gpt-6-sol", {"input_tokens": 2, "output_tokens": 1, "input_tokens_details": {"cached_tokens": 3}})["status"] == "usage_invalid"
    assert estimate_usage("openai", "gpt-6-luna", {"input_tokens": 300000, "output_tokens": 1000})["estimated_usd"] == .06075


async def test_openai_effort_is_transmitted_and_sampling_omitted():
    usage = SimpleNamespace(input_tokens=10, output_tokens=20, model_dump=lambda: {"input_tokens": 10, "output_tokens": 20})
    create = AsyncMock(return_value=SimpleNamespace(usage=usage, output_text='{"no_findings":true}', model="gpt-6-luna"))
    client = SimpleNamespace(responses=SimpleNamespace(create=create))
    provider = OpenAIProvider("test-only", client_getter=lambda: client, reasoning_effort="max")
    result = await provider.call(model="gpt-6-luna", system="review", user="x", max_tokens=100, temperature=.1, timeout=1)
    assert create.call_args.kwargs["reasoning"] == {"effort": "max"}
    assert "temperature" not in create.call_args.kwargs
    assert result.raw_usage["output_tokens"] == 20


@pytest.fixture
def configured(tmp_path, monkeypatch):
    for key in list(__import__("os").environ):
        if key.startswith("INPUT_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    config = OmarGateConfig(llm_provider="typesafe", typesafe_api_key="test-only", openai_api_key="test-only",
                            review_routing="jev-cascade-v1", run_harness=False)
    assert config.model == "gpt-6-sol"
    (tmp_path / "x.py").write_text("value = 1\n")
    return AnalysisOrchestrator(config, OmarLogger("test-cascade"), tmp_path)


def generator_result(route, findings=None, success=True):
    findings = findings or []
    return LLMAnalysisResult(findings, success, {
        "provider": "openai", "model": route.model, "raw_usage": {"input_tokens": 1000, "output_tokens": 100},
    }, None, attempted=True, output_valid=success, no_findings_reported=not findings,
        reported_finding_count=len(findings))


async def run_review(orchestrator, *, scan_mode="pr-diff", run_dir=None):
    return await orchestrator._run_cascade_analysis(ingest={"files": [{"path": "x.py"}]}, changed_files=["x.py"],
        scan_mode=scan_mode, deterministic_findings=[], quick_learn=None, spec_context=None,
        diff_content="+value = 1", run_dir=run_dir)


async def test_real_orchestrator_low_route_requires_generator_and_writes_separate_costs(configured, monkeypatch, tmp_path):
    rate = AsyncMock(return_value=triage())
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    async def review(**kwargs):
        assert kwargs["review_route"] == LOW
        return generator_result(LOW)
    configured._run_llm_analysis = AsyncMock(side_effect=review)
    result = await run_review(configured, run_dir=tmp_path / "evidence")
    assert result.success
    configured._run_llm_analysis.assert_awaited_once()
    payload = json.loads((tmp_path / "evidence/REVIEW_ROUTING.json").read_text())
    assert [r["provider"] for r in payload["costs"]["calls"]] == ["typesafe", "openai"]
    assert payload["routing"]["routes"][0]["effort"] == "max"


async def test_low_defect_escalates_and_later_clean_cannot_erase(configured, monkeypatch):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage()))
    defect = {"severity": "P1", "file_path": "x.py", "line_start": 1, "category": "auth", "message": "defect", "source": "llm"}
    results = [generator_result(LOW, [defect]), generator_result(DEEP)]
    configured._run_llm_analysis = AsyncMock(side_effect=results)
    result = await run_review(configured)
    assert result.findings and result.findings[0]["severity"] == "P1"
    assert [call.kwargs["review_route"].model for call in configured._run_llm_analysis.call_args_list] == [LOW.model, DEEP.model]
    assert result.no_findings_reported is False
    assert len(result.usage["cost_ledger"]["calls"]) == 3


async def test_missing_scope_goes_direct_to_deep_and_no_fake_jev_cost(configured, monkeypatch):
    rate = AsyncMock(side_effect=AssertionError("must not call"))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    configured._run_llm_analysis = AsyncMock(return_value=generator_result(DEEP))
    result = await run_review(configured, scan_mode="deep")
    rate.assert_not_awaited()
    assert configured._run_llm_analysis.call_args.kwargs["review_route"] == DEEP
    assert result.usage["excellence"]["domains"][0]["status"] == "unassessed"
    assert [r["provider"] for r in result.usage["cost_ledger"]["calls"]] == ["openai"]


async def test_source_change_during_triage_fails_closed(configured, monkeypatch):
    async def change(self, **kwargs):
        (configured.repo_root / "x.py").write_text("different = 2\n")
        return triage()
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", change)
    review = AsyncMock(return_value=generator_result(DEEP))
    configured._run_llm_analysis = review
    result = await run_review(configured)
    assert not result.success
    review.assert_not_awaited()


def test_cascade_cannot_ignore_failures_or_override_tiers():
    with pytest.raises(ValidationError):
        OmarGateConfig(review_routing="jev-cascade-v1")
    with pytest.raises(ValidationError):
        OmarGateConfig(llm_provider="typesafe", typesafe_api_key="test-only", openai_api_key="test-only",
                       review_routing="jev-cascade-v1", model="gpt-4.1-mini")


async def test_diff_truncation_cannot_generate_clean_review(configured, monkeypatch):
    from omargate.analyze.llm.context_builder import ContextBuilder
    configured.context_builder = ContextBuilder(max_tokens=100)
    response = AsyncMock(side_effect=AssertionError("provider must not run on incomplete context"))
    monkeypatch.setattr("omargate.analyze.orchestrator.LLMClient.analyze", response)
    result = await configured._run_llm_analysis(ingest={}, deterministic_findings=[], quick_learn=None,
        spec_context=None, scan_mode="pr-diff", diff_content="+long changed code\n" * 1000,
        changed_files=[], review_route=LOW)
    assert not result.success and result.failure_class == "cascade_context_incomplete"
    response.assert_not_awaited()


async def test_incomplete_openai_response_keeps_cost_but_cannot_pass():
    from omargate.analyze.llm.llm_client import LLMClient
    usage = SimpleNamespace(input_tokens=10, output_tokens=20, model_dump=lambda: {"input_tokens": 10, "output_tokens": 20})
    create = AsyncMock(return_value=SimpleNamespace(usage=usage, status="incomplete",
        output_text='{"no_findings":true}', model="gpt-6-luna"))
    client = LLMClient("test-only", primary_model="gpt-6-luna", fallback_model="gpt-6-luna",
                       reasoning_effort="max", allow_fallback=False, max_retries=1)
    client._client = SimpleNamespace(responses=SimpleNamespace(create=create))
    result = await client.analyze("review", "source")
    assert not result.success and result.usage.raw_usage["input_tokens"] == 10
    create.assert_awaited_once()


def test_cascade_disables_hidden_sdk_retries(monkeypatch):
    from omargate.analyze.llm.llm_client import LLMClient
    import openai
    received = []
    monkeypatch.setattr(openai, "AsyncOpenAI", lambda **kwargs: received.append(kwargs) or object())
    client = LLMClient("test-only", reasoning_effort="max")
    assert client.client is not None
    assert received == [{"api_key": "test-only", "max_retries": 0}]
