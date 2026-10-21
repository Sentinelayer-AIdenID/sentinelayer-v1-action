from policy_fixture import FAKE_POLICY_JSON, FAKE_POLICY

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from omargate.analyze.review_cascade import (
    DEEP, LOW, MID, choose_route, excellence_coverage,
    response_model_matches, triage_questions,
)
from omargate.analyze.review_costs import cost_ledger, estimate_usage
from omargate.analyze.typesafe_client import ChoiceAnswer, TypeSafeResult
from omargate.analyze.orchestrator import AnalysisOrchestrator, LLMAnalysisResult
from omargate.analyze.llm.providers.openai_provider import OpenAIProvider
from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger
from omargate.analyze.typesafe_review import TypedReview, review_inventory as real_review_inventory

pytestmark = pytest.mark.anyio


def triage(label="low", *, sensitive=.01, confidence=.99):
    probabilities = dict.fromkeys(["low", "review", "defect"], .005)
    probabilities[label] = .99
    answers = {key: .01 for key in triage_questions(FAKE_POLICY)}
    answers["risk"] = ChoiceAnswer(label, probabilities, confidence)
    answers["sensitive"] = sensitive
    return TypeSafeResult("model-under-test-1.13.0", answers, {"input_tokens": 1000, "output_tokens": 45}, 1)


def test_route_uses_independent_impact_confidence_and_sensitivity():
    assert choose_route(FAKE_POLICY, triage(), paths=["src/format.py"], findings=[]) == LOW
    assert choose_route(FAKE_POLICY, triage("review"), paths=["src/format.py"], findings=[]) == MID
    assert choose_route(FAKE_POLICY, triage(confidence=.7), paths=["src/format.py"], findings=[]) == MID
    assert choose_route(FAKE_POLICY, triage(), paths=["fixture-critical/routes.py"], findings=[]) == DEEP
    assert choose_route(FAKE_POLICY, triage(), paths=["fixture-group/fixture-workflows/test.yml"], findings=[]) == DEEP
    assert choose_route(FAKE_POLICY, triage(sensitive=.5), paths=["x.py"], findings=[]) == DEEP
    assert choose_route(FAKE_POLICY, triage(), paths=["x.py"], findings=[{"severity": "P1"}]) == DEEP
    assert choose_route(FAKE_POLICY, triage(), paths=["x.py"], findings=[{"severity": "P4"}]) == LOW
    assert choose_route(FAKE_POLICY, triage(), paths=["x.py"], findings=[{"severity": "P2"}]) == MID
    assert choose_route(FAKE_POLICY, triage("defect"), paths=["x.py"], findings=[]).tier == "deep"
    risky = triage()
    risky.answers["gap_fixture"] = .7
    assert choose_route(FAKE_POLICY, risky, paths=["x.py"], findings=[]) == MID


def test_malformed_or_missing_triage_is_never_low():
    malformed = triage()
    malformed.answers.pop("structural")
    with pytest.raises(Exception, match="invalid"):
        choose_route(FAKE_POLICY, malformed, paths=["x.py"], findings=[])


def test_framework_keeps_unassessed_separate_from_verified_score():
    assert sum(weight for weight, _ in FAKE_POLICY.routing["domains"].values()) == 100
    assert all(row["status"] == "unassessed" and row["gap_probability"] is None
               for row in excellence_coverage(FAKE_POLICY, None)["domains"])
    assert "score" not in excellence_coverage(FAKE_POLICY, triage().answers)


@pytest.mark.parametrize("actual,expected", [
    ("gpt-6-sol", True), ("gpt-6-sol-2026-10-01", True),
    ("gpt-6-sol-2026-99-99", False), ("gpt-6-sol-other", False),
    ("gpt-6.1-sol", False),
])
def test_actual_response_model_identity(actual, expected):
    assert response_model_matches(actual, "gpt-6-sol") is expected


def test_separate_costs_cache_and_unknowns():
    intent = estimate_usage("typesafe", "model-under-test-1.13.0", {"input_tokens": 1_000_000, "output_tokens": 1000}, intent_price_profile="typesafe-input-20261020")
    sol = estimate_usage("openai", "gpt-6.1-sol", {"input_tokens": 100000, "output_tokens": 10000,
        "input_tokens_details": {"cached_tokens": 20000}, "output_tokens_details": {"reasoning_tokens": 9000}})
    assert intent["estimated_usd"] == .042
    assert sol["estimated_usd"] == .262  # reasoning already part of output
    assert cost_ledger([intent, sol])["estimated_total_usd"] == .304
    assert cost_ledger([intent, estimate_usage("openai", "gpt-6-sol", None)])["estimated_total_usd"] is None
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
                            review_routing="intent-cascade-v1", run_harness=False, intent_model_pin="model-under-test-1.13.0", intent_price_profile="typesafe-input-20261020", intent_policy=FAKE_POLICY_JSON)
    assert config.model == "gpt-6-sol"
    (tmp_path / "x.py").write_text("value = 1\n")
    monkeypatch.setattr("omargate.analyze.orchestrator.review_inventory",
        AsyncMock(return_value=TypedReview([], {"typesafe_usage": {"input_tokens": 100, "output_tokens": 0}}, {"complete": True})))
    return AnalysisOrchestrator(config, OmarLogger("test-cascade"), tmp_path)


def generator_result(route, findings=None, success=True):
    findings = findings or []
    return LLMAnalysisResult(findings, success, {
        "provider": "openai", "model": route.model, "raw_usage": {"input_tokens": 1000, "output_tokens": 100},
    }, None, attempted=True, output_valid=success, no_findings_reported=not findings,
        reported_finding_count=len(findings))


@pytest.fixture
def generator_transport(monkeypatch):
    usage = SimpleNamespace(input_tokens=10, output_tokens=5,
                            model_dump=lambda: {"input_tokens": 10, "output_tokens": 5})
    create = AsyncMock(return_value=SimpleNamespace(
        usage=usage, output_text='{"no_findings":true}', model=DEEP.model))
    sdk = SimpleNamespace(responses=SimpleNamespace(create=create))
    monkeypatch.setattr(OpenAIProvider, "client", property(lambda self: sdk))
    return create


async def test_rejected_changed_source_never_reaches_generator_sdk(configured, monkeypatch, generator_transport):
    # Construct credential-shaped bytes at runtime; never publish key-shaped fixtures.
    source = 'api_key = "' + 'sk' + '-' + 'A' * 32 + '"\n'
    (configured.repo_root / "x.py").write_text(source)
    rate = AsyncMock(side_effect=AssertionError("rejected source must not leave the runner"))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    result = await configured._run_cascade_analysis(
        ingest={"files": [{"path": "x.py"}]}, changed_files=["x.py"], scan_mode="pr-diff",
        deterministic_findings=[], quick_learn=None, spec_context=None, run_dir=None,
        diff_content="diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+" + source)
    rate.assert_not_awaited()
    generator_transport.assert_not_awaited()
    assert not result.success
    assert not result.attempted
    assert not result.usage["cost_ledger"]["calls"]


@pytest.mark.parametrize("auxiliary", ["readme", "spec", "finding"])
@pytest.mark.parametrize("secret_kind", ["provider", "json", "url"])
async def test_auxiliary_secret_never_reaches_generator_sdk(
    configured, generator_transport, auxiliary, secret_kind,
):
    from omargate.ingest.quick_learn import QuickLearnSummary
    secrets = {
        "provider": 'sk' + '-' + 'A' * 32,
        "json": '{"token": "' + 'Z' * 32 + '"}',
        "url": "https://example.invalid/?access_token=" + 'Z' * 32,
    }
    material = secrets[secret_kind]
    quick = QuickLearnSummary("Sample", "Project description", [], "", [], "README.md", material)
    result = await configured._run_llm_analysis(
        ingest={"files": [{"path": "x.py"}]},
        deterministic_findings=[{"file_path": "x.py", "message": material, "severity": "P2",
                                 "category": "fixture", "line_start": 1}]
        if auxiliary == "finding" else [],
        quick_learn=quick if auxiliary == "readme" else None,
        spec_context={"security_rules": material} if auxiliary == "spec" else None,
        scan_mode="pr-diff", diff_content="+value = 1\n", changed_files=["x.py"], review_route=DEEP)
    generator_transport.assert_not_awaited()
    assert not result.success and not result.attempted
    assert result.failure_class == "cascade_source_privacy_incomplete"


async def test_public_project_metadata_still_reaches_generator_sdk(configured, generator_transport):
    from omargate.ingest.quick_learn import QuickLearnSummary
    quick = QuickLearnSummary("PublicProject", "A public project", [], "", [], "README.md",
                              "Project: PublicProject\nconsumer project: public-example\n")
    await configured._run_llm_analysis(
        ingest={"files": [{"path": "x.py"}]}, deterministic_findings=[], quick_learn=quick,
        spec_context=None, scan_mode="pr-diff", diff_content="+value = 1\n",
        changed_files=["x.py"], review_route=DEEP)
    generator_transport.assert_awaited_once()
    assert "Project: PublicProject" in generator_transport.call_args.kwargs["input"]


async def test_verified_source_can_still_escalate_after_intent_transport_failure(
    configured, monkeypatch, generator_transport,
):
    from omargate.analyze.typesafe_client import TypeSafeError
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate",
                        AsyncMock(side_effect=TypeSafeError("request_failed")))
    result = await run_review(configured)
    generator_transport.assert_awaited_once()
    assert generator_transport.call_args.kwargs["model"] == DEEP.model
    assert result.attempted


def test_source_privacy_contract_invalidates_same_config_receipts(configured, monkeypatch):
    import omargate.idempotency as module
    current = module.review_config_digest(configured.config)
    monkeypatch.setattr(module, "GENERATOR_SOURCE_BOUNDARY_VERSION", "pre-source-privacy")
    assert module.review_config_digest(configured.config) != current


def test_source_privacy_contract_does_not_stamp_legacy_routing_receipts(configured, monkeypatch):
    import omargate.idempotency as module
    legacy = configured.config.model_copy(update={"review_routing": "legacy"})
    current = module.review_config_digest(legacy)
    monkeypatch.setattr(module, "GENERATOR_SOURCE_BOUNDARY_VERSION", "another-cascade-contract")
    assert module.review_config_digest(legacy) == current


@pytest.mark.parametrize("failed_stage", ["triage", "source-policy"])
async def test_orchestrator_keeps_validated_http_usage_when_answers_fail(configured, monkeypatch, failed_stage):
    import httpx
    original_client = httpx.AsyncClient
    calls = []
    observed = {"input_tokens": 1234, "output_tokens": 56}

    def handler(request):
        payload = json.loads(request.content)
        stage = "triage" if "risk" in payload["questions"] else "source-policy"
        calls.append(stage)
        answers = {} if stage == failed_stage else {
            name: answer.as_dict() if isinstance(answer, ChoiceAnswer) else {"type": "noul", "noul": answer}
            for name, answer in triage().answers.items()
        }
        return httpx.Response(200, json={"model": payload["model"], "usage": observed, "answers": answers})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs))
    if failed_stage == "source-policy":
        monkeypatch.setattr("omargate.analyze.orchestrator.review_inventory", real_review_inventory)
    configured._run_llm_analysis = AsyncMock(return_value=generator_result(DEEP))
    result = await run_review(configured)
    assert calls == (["triage"] if failed_stage == "triage" else ["triage", "source-policy"])
    record = next(row for row in result.usage["cost_ledger"]["calls"] if row["stage"] == failed_stage)
    assert (record["input_tokens"], record["output_tokens"], record["status"]) == (1234, 56, "estimated")
    assert record["estimated_usd"] == estimate_usage("typesafe", "model-under-test-1.13.0", observed,
                                                   intent_price_profile=configured.config.intent_price_profile)["estimated_usd"]
    if failed_stage == "source-policy":
        assert not result.success and result.failure_class == "cascade_policy_incomplete"
        assert result.usage["policy_assessment"]["reason_code"] == "typesafe_answers_invalid"


async def test_unattempted_generator_refusal_has_no_fake_model_mismatch_or_cost(configured, monkeypatch):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage(sensitive=1)))
    configured._run_llm_analysis = AsyncMock(return_value=LLMAnalysisResult(
        [], False, None, None, attempted=False, failure_class="cascade_source_privacy_incomplete"))
    result = await run_review(configured)
    assert result.failure_class == "cascade_source_privacy_incomplete"
    assert not result.attempted
    assert all(row["provider"] == "typesafe" for row in result.usage["cost_ledger"]["calls"])
    assert result.usage["review_routing"]["routes"][0]["identity_matches"] is False


async def run_review(orchestrator, *, scan_mode="pr-diff", run_dir=None):
    return await orchestrator._run_cascade_analysis(ingest={"files": [{"path": "x.py"}]}, changed_files=["x.py"],
        scan_mode=scan_mode, deterministic_findings=[], quick_learn=None, spec_context=None,
        diff_content="diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+value = 1\n", run_dir=run_dir)


async def test_real_orchestrator_low_route_requires_generator_and_writes_separate_costs(configured, monkeypatch, tmp_path):
    rate = AsyncMock(return_value=triage())
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    async def review(**kwargs):
        assert kwargs["review_route"] == LOW
        return generator_result(LOW)
    configured._run_llm_analysis = AsyncMock(side_effect=review)
    result = await run_review(configured, run_dir=tmp_path / "evidence")
    assert result.success, result.usage.get("policy_assessment")
    configured._run_llm_analysis.assert_awaited_once()
    payload = json.loads((tmp_path / "evidence/REVIEW_ROUTING.json").read_text())
    assert [r["provider"] for r in payload["costs"]["calls"]] == ["typesafe", "typesafe", "openai"]
    assert payload["policy_assessment"]["complete"] is True
    assert payload["routing"]["routes"][0]["effort"] == "max"
    assert "dimension-1" in payload["routing"]["answers"]
    assert "gap_fixture" not in payload["routing"]["answers"]
    sent = rate.call_args_list[0].kwargs["state"]
    assert sent["diff_head_lines_verified"] is True
    assert sent["candidate_context"][sent["candidates"][0]["candidate_id"]]["diff_hunks"]


async def test_low_defect_escalates_and_later_clean_cannot_erase(configured, monkeypatch):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage()))
    defect = {"severity": "P1", "file_path": "x.py", "line_start": 1, "category": "auth", "message": "defect", "source": "llm"}
    results = [generator_result(LOW, [defect]), generator_result(DEEP)]
    configured._run_llm_analysis = AsyncMock(side_effect=results)
    result = await run_review(configured)
    assert result.findings and result.findings[0]["severity"] == "P1"
    assert [call.kwargs["review_route"].model for call in configured._run_llm_analysis.call_args_list] == [LOW.model, DEEP.model]
    assert result.no_findings_reported is False
    assert len(result.usage["cost_ledger"]["calls"]) == 4
    assert result.findings[0]["review_model"] == LOW.model
    assert result.findings[0]["review_tier"] == "low"


async def test_missing_scope_refuses_before_any_model_or_fake_cost(configured, monkeypatch):
    rate = AsyncMock(side_effect=AssertionError("must not call"))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    configured._run_llm_analysis = AsyncMock(return_value=generator_result(DEEP))
    result = await run_review(configured, scan_mode="deep")
    rate.assert_not_awaited()
    configured._run_llm_analysis.assert_not_awaited()
    assert not result.success and not result.attempted
    assert result.usage["excellence"]["domains"][0]["status"] == "unassessed"
    assert result.usage["cost_ledger"]["calls"] == []


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
        OmarGateConfig(review_routing="intent-cascade-v1")
    with pytest.raises(ValidationError):
        OmarGateConfig(llm_provider="typesafe", typesafe_api_key="test-only", openai_api_key="test-only",
                       review_routing="intent-cascade-v1", model="gpt-4.1-mini", intent_model_pin="model-under-test-1.13.0", intent_price_profile="typesafe-input-20261020", intent_policy=FAKE_POLICY_JSON)


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


async def test_real_source_policy_runs_and_a_clean_generator_cannot_remove_its_p1(configured, monkeypatch):
    monkeypatch.setattr("omargate.analyze.orchestrator.review_inventory", real_review_inventory)
    seen = []
    async def rate(self, *, state, questions, model):
        seen.append(set(questions))
        assert model == "model-under-test-1.13.0"  # private transport receives the real pin
        if "risk" in questions:
            return triage()
        answers = {}
        for name, question in questions.items():
            if question["type"] == "noul":
                answers[name] = 1.0
            else:
                selected = "P1" if name.startswith("severity::") else "auth"
                answers[name] = ChoiceAnswer(selected, {key: float(key == selected) for key in question["criteria"]}, 1.0)
        return TypeSafeResult(model, answers, {"input_tokens": 100, "output_tokens": 0}, 1)
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    configured._run_llm_analysis = AsyncMock(return_value=generator_result(DEEP))
    result = await run_review(configured)
    assert len(seen) == 2 and any(name.startswith("risk::") for name in seen[1]), result.usage.get("policy_assessment")
    assert result.findings[0]["severity"] == "P1"
    assert result.findings[0]["review_tier"] == "intent-policy"
    guarded = configured._apply_llm_guardrails(llm_findings=result.findings, non_llm_findings=[], ingest={"files": [{"path": "x.py"}]})
    assert guarded[0]["severity"] == "P1"  # missing deterministic corroboration cannot erase it
    assert result.usage["policy_assessment"]["complete"] is True
    assert result.usage["policy_assessment"]["answers"]
    assert result.usage["policy_assessment"]["question_candidates"]
    assert "context" not in result.usage["policy_assessment"]
    assert "Test-only" not in json.dumps(result.usage["policy_assessment"])
    assert len(result.usage["cost_ledger"]["calls"]) == 3


async def test_incomplete_source_policy_keeps_review_unknown_after_clean_deep_result(configured, monkeypatch):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage()))
    monkeypatch.setattr("omargate.analyze.orchestrator.review_inventory", AsyncMock(return_value=TypedReview([], {}, {"complete": False})))
    configured._run_llm_analysis = AsyncMock(return_value=generator_result(DEEP))
    result = await run_review(configured)
    assert not result.success and result.failure_class == "cascade_policy_incomplete"


async def test_private_policy_p4_is_preserved_without_forcing_expensive_review(configured, monkeypatch):
    from pydantic import SecretStr
    data = json.loads(FAKE_POLICY_JSON)
    data["typed"]["severity_criteria"]["P4"] = "Test-only informational finding"
    data["typed"]["severity_support_floors"]["P4"] = data["typed"]["severity_support_floors"]["P3"]
    configured.config = configured.config.model_copy(update={"intent_policy": SecretStr(json.dumps(data))})
    monkeypatch.setattr("omargate.analyze.orchestrator.review_inventory", real_review_inventory)
    async def rate(self, *, state, questions, model):
        if "risk" in questions:
            return triage()
        answers = {}
        for key, question in questions.items():
            selected = "P4" if key.startswith("severity::") else "auth"
            answers[key] = (1.0 if question["type"] == "noul" else
                ChoiceAnswer(selected, {label: float(label == selected) for label in question["criteria"]}, 1.0))
        return TypeSafeResult(model, answers, {"input_tokens": 100, "output_tokens": 0}, 1)
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    configured._run_llm_analysis = AsyncMock(return_value=generator_result(LOW))
    result = await run_review(configured)
    assert result.success and result.findings[0]["severity"] == "P4"
    assert configured._run_llm_analysis.call_args.kwargs["review_route"] == LOW


async def test_provider_missing_model_identity_cannot_inherit_requested_model(configured, monkeypatch):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage()))
    response = generator_result(DEEP)
    response.usage.pop("model")
    configured._run_llm_analysis = AsyncMock(side_effect=lambda **_: generator_result(DEEP))
    # Every returned response lacks an identity; the deepest tier must still fail.
    async def missing(**kwargs):
        value = generator_result(kwargs["review_route"])
        value.usage.pop("model")
        return value
    configured._run_llm_analysis = AsyncMock(side_effect=missing)
    result = await run_review(configured)
    assert not result.success and result.failure_class == "cascade_model_mismatch"
    assert result.usage["cost_ledger"]["estimated_total_usd"] is None
    assert all(not row["identity_matches"] for row in result.usage["review_routing"]["routes"])


async def test_missing_sdk_model_is_a_failure_even_with_valid_json_and_usage():
    from omargate.analyze.llm.llm_client import LLMClient
    usage = SimpleNamespace(input_tokens=10, output_tokens=20,
        model_dump=lambda: {"input_tokens": 10, "output_tokens": 20})
    create = AsyncMock(return_value=SimpleNamespace(usage=usage, status="completed",
        output_text='{"no_findings":true}'))
    client = LLMClient("test-only", primary_model=LOW.model, fallback_model=LOW.model,
        reasoning_effort="max", allow_fallback=False, max_retries=1)
    client._client = SimpleNamespace(responses=SimpleNamespace(create=create))
    result = await client.analyze("review", "source")
    assert not result.success and result.usage.model == "unknown"
    assert result.usage.raw_usage["input_tokens"] == 10
    create.assert_awaited_once()
