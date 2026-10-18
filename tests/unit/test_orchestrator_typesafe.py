from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

import omargate.analyze.orchestrator as module
from omargate.analyze.orchestrator import AnalysisOrchestrator, LLMAnalysisResult
from omargate.analyze.typesafe_client import TypeSafeClient, TypeSafeResult
from omargate.analyze.typesafe_review import (
    ReviewDecision,
    ReviewPlan,
    RatedFinding,
    TypeSafeReviewIncomplete,
)
from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger


PIN = "jev-1.13.0"
GENERATOR = "gpt-5.3-codex"
ACTUAL_GENERATOR = "fixture-returned-generator-model"
DIFF = "diff --git a/source.py b/source.py\n--- a/source.py\n+++ b/source.py\n@@ -1 +1,2 @@\n-old\n+first\n+second\n"


def finding(source="deterministic", *, model=None):
    result = {
        "id": "det-fixture" if source == "deterministic" else "typed-fixture",
        "severity": "P2", "category": "fixture", "file_path": "source.py",
        "line_start": 1, "line_end": 1, "snippet": "first\n",
        "message": "A fixture finding is retained.",
        "recommendation": "Inspect the fixture source.", "source": source,
        "confidence": 0.8,
    }
    if model is not None:
        result["model_source"] = model
    return result


def outcome(*, success=True, provider="typesafe", model=PIN, findings=None, attempted=True):
    findings = [] if findings is None else findings
    return LLMAnalysisResult(
        findings=copy.deepcopy(findings), success=success,
        usage={"provider": provider, "model": model, "route": "fixture",
               "tokens_in": None, "tokens_out": None, "cost_usd": None,
               "latency_ms": 1},
        warning=None if success else "Fixture stage did not complete.",
        attempted=attempted, output_valid=success,
        no_findings_reported=success and not findings,
        reported_finding_count=len(findings),
        failure_class=None if success else "fixture_incomplete",
    )


def orchestrator(tmp_path, monkeypatch, *, fallback=True, codex=True, allow=True):
    (tmp_path / "source.py").write_text("first\nsecond\n", encoding="utf-8")
    config = OmarGateConfig(
        llm_provider="typesafe", typesafe_api_key="synthetic-typesafe-key",
        openai_api_key="synthetic-generator-key", typesafe_model=PIN,
        typesafe_fallback=fallback, use_codex=codex, model=GENERATOR,
        model_fallback=GENERATOR, codex_model=GENERATOR,
        run_harness=False, publish_github=False, telemetry=False,
        sentinelayer_spec_id="fixture", _env_file=None,
    )
    instance = AnalysisOrchestrator(config, OmarLogger("typesafe-fixture"), tmp_path, allow_llm=allow)
    quick = SimpleNamespace(source_doc=None, tech_stack=[], architecture="fixture", description="scaffold")
    monkeypatch.setattr(module, "extract_quick_learn_summary", lambda _: quick)
    monkeypatch.setattr(module, "is_boilerplate_description", lambda _: True)
    ingest = {"files": [{"path": "source.py", "lines": 2, "category": "source"}],
              "stats": {"total_files": 1, "in_scope_files": 1}, "hotspots": {}}
    monkeypatch.setattr(module, "run_ingest", lambda *_args, **_kwargs: copy.deepcopy(ingest))
    monkeypatch.setattr(instance, "_run_deterministic_scans", lambda _: [finding()])
    calls = []

    class UnexpectedSynopsis:
        def __init__(self, **kwargs):
            calls.append(kwargs)
            raise AssertionError("TypeSafe selection must not construct a summary generator")

    monkeypatch.setattr(module, "LLMClient", UnexpectedSynopsis)
    return instance, ingest, calls


def stages(instance, monkeypatch, *, typed, codex=None, generator=None):
    typed_call = AsyncMock(return_value=typed)
    codex_call = AsyncMock(return_value=codex if codex is not None else outcome(success=False, provider="openai", model=GENERATOR))
    generator_call = AsyncMock(return_value=generator if generator is not None else outcome(success=False, provider="openai", model=GENERATOR))
    monkeypatch.setattr(instance, "_run_typesafe_analysis", typed_call)
    monkeypatch.setattr(instance, "_run_codex_audit", codex_call)
    monkeypatch.setattr(instance, "_run_llm_analysis", generator_call)
    return typed_call, codex_call, generator_call


async def run(instance):
    return await instance.run(scan_mode="pr-diff", changed_files=["source.py"], diff_content=DIFF)


def assert_deterministic_retained(result):
    assert result.deterministic_count == 1
    assert any(row["id"] == "det-fixture" and row["source"] == "deterministic" for row in result.findings)


@pytest.mark.anyio
@pytest.mark.parametrize("fallback,codex", [(False, True), (True, True), (True, False)])
async def test_complete_empty_typed_review_is_success_and_skips_all_generators(tmp_path, monkeypatch, fallback, codex):
    instance, _, synopsis = orchestrator(tmp_path, monkeypatch, fallback=fallback, codex=codex)
    typed, cli, api = stages(instance, monkeypatch, typed=outcome())
    result = await run(instance)
    assert result.llm_success and result.llm_output_valid
    assert result.llm_no_findings_reported and result.llm_reported_finding_count == 0
    assert result.llm_count == 0 and result.llm_failure_class is None
    assert result.llm_usage["provider"] == "typesafe"
    assert result.llm_usage["model"] == PIN
    assert "fallback_chain" not in result.llm_usage
    assert typed.await_count == 1 and cli.await_count == api.await_count == 0
    assert synopsis == []
    assert_deterministic_retained(result)


@pytest.mark.anyio
async def test_no_fallback_flag_prevents_both_generator_routes_and_synopsis_on_typed_failure(tmp_path, monkeypatch):
    instance, _, synopsis = orchestrator(tmp_path, monkeypatch, fallback=False)
    typed, cli, api = stages(instance, monkeypatch, typed=outcome(success=False, attempted=False))
    result = await run(instance)
    assert not result.llm_success and not result.llm_output_valid
    assert not result.llm_attempted and result.llm_failure_class == "fixture_incomplete"
    assert typed.await_count == 1 and cli.await_count == api.await_count == 0
    assert synopsis == []
    assert_deterministic_retained(result)


@pytest.mark.anyio
async def test_limited_run_does_not_attempt_typed_cli_api_or_summary_generator(tmp_path, monkeypatch):
    instance, _, synopsis = orchestrator(tmp_path, monkeypatch, allow=False)
    typed, cli, api = stages(instance, monkeypatch, typed=outcome())
    result = await run(instance)
    assert typed.await_count == cli.await_count == api.await_count == 0
    assert not result.llm_attempted and not result.llm_success
    assert synopsis == []
    assert_deterministic_retained(result)


@pytest.mark.anyio
async def test_allowed_fallback_uses_codex_first_and_keeps_actual_returned_provenance(tmp_path, monkeypatch):
    instance, _, synopsis = orchestrator(tmp_path, monkeypatch)
    typed, cli, api = stages(
        instance, monkeypatch, typed=outcome(success=False),
        codex=outcome(provider="openai", model=GENERATOR),
    )
    result = await run(instance)
    assert result.llm_success and result.llm_output_valid
    assert typed.await_count == cli.await_count == 1 and api.await_count == 0
    assert result.llm_usage["provider"] == "openai" and result.llm_usage["model"] == GENERATOR
    assert result.llm_usage["typesafe_attempt"]["success"] is False
    assert result.llm_usage["fallback_chain"] == f"typesafe/{PIN} -> openai/{GENERATOR}"
    assert synopsis == []
    assert_deterministic_retained(result)


@pytest.mark.anyio
async def test_allowed_api_fallback_does_not_label_findings_with_requested_model(tmp_path, monkeypatch):
    instance, _, synopsis = orchestrator(tmp_path, monkeypatch, codex=False)
    generated = finding("llm")
    generated.update(category="fixture-generator", line_start=2, line_end=2, snippet="second\n")
    typed, cli, api = stages(
        instance, monkeypatch, typed=outcome(success=False, attempted=False),
        generator=outcome(provider="openai", model=ACTUAL_GENERATOR, findings=[generated]),
    )
    result = await run(instance)
    selected = next(row for row in result.findings if row["source"] == "llm")
    assert selected["model_source"] == ACTUAL_GENERATOR
    assert result.llm_usage["model"] == ACTUAL_GENERATOR
    assert result.llm_usage["fallback_chain"] == f"typesafe/{PIN} -> openai/{ACTUAL_GENERATOR}"
    assert typed.await_count == api.await_count == 1 and cli.await_count == 0
    assert synopsis == []
    assert_deterministic_retained(result)


@pytest.mark.anyio
async def test_failed_allowed_fallback_stays_failed_and_retains_deterministic(tmp_path, monkeypatch):
    instance, _, synopsis = orchestrator(tmp_path, monkeypatch)
    typed, cli, api = stages(instance, monkeypatch, typed=outcome(success=False))
    result = await run(instance)
    assert not result.llm_success and not result.llm_output_valid
    assert typed.await_count == cli.await_count == api.await_count == 1
    assert result.llm_attempted
    assert synopsis == []
    assert_deterministic_retained(result)


class FixturePolicy:
    policy_id = "fixture-only-policy"
    calibration_id = "fixture-only-calibration"

    def __init__(self, kind="noul"):
        self.kind = kind

    def plan(self, candidates):
        return ReviewPlan(
            questions={f"q{i}": {"type": self.kind, "instructions": "Return the fixture judgment."} for i, _ in enumerate(candidates)},
            question_candidates={f"q{i}": candidate.candidate_id for i, candidate in enumerate(candidates)},
        )

    def decide(self, candidates, answers):
        # No production threshold or security predicate is authored in this test.
        return ReviewDecision((), complete=True)


class FixtureClient:
    def __init__(self, *args, during=None, **kwargs):
        self.attempted = False
        self.calls = []
        self.during = during

    async def rate(self, *, state, questions, model):
        self.attempted = True
        self.calls.append({"model": model, "questions": questions})
        if self.during:
            self.during()
        return TypeSafeResult(model, {key: 0.5 for key in questions}, {"input_tokens": 7, "output_tokens": 0}, 1)


def real_stage_setup(tmp_path, monkeypatch, *, policy=None, client=None):
    instance, ingest, _ = orchestrator(tmp_path, monkeypatch, fallback=False)
    selected = FixtureClient() if client is None else client
    monkeypatch.setattr(module, "TypeSafeClient", lambda *args, **kwargs: selected)
    monkeypatch.setattr(module, "load_policy", lambda: FixturePolicy() if policy is None else policy)
    return instance, ingest, selected


async def real_stage(instance, ingest, *, run_dir=None, diff_content=DIFF):
    return await instance._run_typesafe_analysis(
        ingest=ingest, changed_files=["source.py"], scan_mode="pr-diff",
        deterministic_findings=[finding()], run_dir=run_dir, diff_content=diff_content,
    )


@pytest.mark.anyio
async def test_missing_policy_is_not_an_http_attempt_and_remains_failed(tmp_path, monkeypatch):
    instance, ingest, client = real_stage_setup(tmp_path, monkeypatch)

    def unavailable():
        raise TypeSafeReviewIncomplete("typesafe_policy_unavailable")

    monkeypatch.setattr(module, "load_policy", unavailable)
    result = await real_stage(instance, ingest)
    assert not result.success and not result.output_valid and not result.attempted
    assert result.failure_class == "typesafe_policy_unavailable"
    assert client.calls == []


@pytest.mark.anyio
async def test_context_preflight_failure_is_not_an_http_attempt(tmp_path, monkeypatch):
    instance, ingest, client = real_stage_setup(tmp_path, monkeypatch)
    text = "x" * 24_001
    (tmp_path / "source.py").write_text(text + "\n", encoding="utf-8")
    diff = f"diff --git a/source.py b/source.py\n--- a/source.py\n+++ b/source.py\n@@ -1 +1 @@\n-old\n+{text}\n"
    result = await real_stage(instance, ingest, diff_content=diff)
    assert not result.success and not result.output_valid and not result.attempted
    assert result.failure_class == "typed_context_budget_exceeded"
    assert client.calls == []


@pytest.mark.anyio
async def test_invalid_plan_coverage_stops_before_dispatch(tmp_path, monkeypatch):
    instance, ingest, client = real_stage_setup(tmp_path, monkeypatch)
    policy = FixturePolicy()
    monkeypatch.setattr(policy, "plan", lambda _: ReviewPlan({}, {}))
    monkeypatch.setattr(module, "load_policy", lambda: policy)
    result = await real_stage(instance, ingest)
    assert result.failure_class == "incomplete_question_coverage"
    assert not result.success and not result.attempted and client.calls == []


@pytest.mark.anyio
async def test_transport_prevalidation_failure_reports_no_http_attempt(tmp_path, monkeypatch):
    instance, ingest, _ = real_stage_setup(tmp_path, monkeypatch, policy=FixturePolicy("unknown-fixture-kind"))
    requests = []

    def forbidden(request):
        requests.append(request)
        raise AssertionError("Invalid typed question reached HTTP transport")

    async with httpx.AsyncClient(transport=httpx.MockTransport(forbidden)) as http:
        client = TypeSafeClient("synthetic-typesafe-key", client=http)
        monkeypatch.setattr(module, "TypeSafeClient", lambda *args, **kwargs: client)
        result = await real_stage(instance, ingest)
    assert not result.success and not result.output_valid
    assert not result.attempted and requests == []


@pytest.mark.anyio
async def test_real_mock_http_failure_reports_attempt_but_no_complete_review(tmp_path, monkeypatch):
    instance, ingest, _ = real_stage_setup(tmp_path, monkeypatch)
    requests = []

    def unavailable(request):
        requests.append(str(request.url))
        return httpx.Response(529, text="synthetic provider body must not be public")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as http:
        client = TypeSafeClient("synthetic-typesafe-key", client=http)
        monkeypatch.setattr(module, "TypeSafeClient", lambda *args, **kwargs: client)
        result = await real_stage(instance, ingest)
    assert not result.success and not result.output_valid and result.attempted
    assert result.failure_class == "typesafe_transport_failure"
    assert requests == ["https://api.typesafe.ai/v1/systemone"]
    assert "synthetic provider body" not in str(result)


@pytest.mark.anyio
async def test_real_empty_complete_review_records_model_scope_and_raw_usage(tmp_path, monkeypatch):
    instance, ingest, client = real_stage_setup(tmp_path, monkeypatch)
    run_dir = tmp_path / "artifacts"
    result = await real_stage(instance, ingest, run_dir=run_dir)
    assert result.success and result.output_valid and result.attempted
    assert result.no_findings_reported and result.findings == []
    assert result.reported_finding_count == 0
    assert result.usage["model"] == PIN and result.usage["provider"] == "typesafe"
    assert result.usage["typesafe_usage"] == {"input_tokens": 7, "output_tokens": 0}
    retained = json.loads((run_dir / "TYPESAFE_REVIEW.json").read_text(encoding="utf-8"))
    assert retained["complete"] is True and retained["model"] == PIN
    assert retained["source_hashes"] and len(client.calls) == 1


@pytest.mark.anyio
async def test_source_change_after_response_remains_failed_not_empty_success(tmp_path, monkeypatch):
    client = FixtureClient(during=lambda: (tmp_path / "source.py").write_text("changed\n", encoding="utf-8"))
    instance, ingest, _ = real_stage_setup(tmp_path, monkeypatch, client=client)
    result = await real_stage(instance, ingest)
    assert not result.success and not result.output_valid and result.attempted
    assert result.failure_class == "source_changed_during_review"
    assert len(client.calls) == 1 and not result.no_findings_reported


@pytest.mark.anyio
async def test_source_change_while_writer_waits_cannot_publish_stale_findings(tmp_path, monkeypatch):
    policy = FixturePolicy()

    def decision(candidates, answers):
        return ReviewDecision((RatedFinding(
            candidate_id=candidates[0].candidate_id, question_ids=("q0",),
            severity="P2", category="fixture", message="A fixed fixture verdict.",
            recommendation="Inspect the fixed fixture.", support_probability=0.5,
        ),), complete=True)

    monkeypatch.setattr(policy, "decide", decision)
    instance, ingest, client = real_stage_setup(tmp_path, monkeypatch, policy=policy)
    monkeypatch.setattr(module, "LLMClient", lambda **kwargs: object())

    async def writer(review, *, client):
        (tmp_path / "source.py").write_text("changed during writer\n", encoding="utf-8")
        return review

    writer_call = AsyncMock(side_effect=writer)
    monkeypatch.setattr(module, "explain_review", writer_call)
    result = await real_stage(instance, ingest)
    assert not result.success and not result.output_valid and result.attempted
    assert result.failure_class == "source_changed_during_review"
    assert len(client.calls) == writer_call.await_count == 1
    assert result.usage["model"] == PIN
    assert result.usage["typesafe_usage"] == {"input_tokens": 7, "output_tokens": 0}
    assert not any(row.get("id", "").startswith("typesafe-span-") for row in result.findings)
    assert result.usage["typesafe_assessment"]["complete"] is False
    assert result.usage["typesafe_assessment"]["typed_assessment_complete"] is True


@pytest.mark.anyio
async def test_evidence_write_failure_cannot_publish_successful_empty_review(tmp_path, monkeypatch):
    instance, ingest, client = real_stage_setup(tmp_path, monkeypatch)
    original = Path.write_text

    def deny_evidence(path, *args, **kwargs):
        if path.name == "TYPESAFE_REVIEW.json":
            raise OSError("synthetic evidence write failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", deny_evidence)
    result = await real_stage(instance, ingest, run_dir=tmp_path / "artifacts")
    assert not result.success and not result.output_valid and result.attempted
    assert result.failure_class == "typesafe_evidence_write_failed"
    assert not result.no_findings_reported and len(client.calls) == 1
    assert result.usage["model"] == PIN
    assert result.usage["typesafe_usage"] == {"input_tokens": 7, "output_tokens": 0}
    assert result.usage["typesafe_assessment"]["complete"] is False


@pytest.mark.anyio
async def test_generator_fallback_keeps_the_failed_typed_evidence(tmp_path, monkeypatch):
    instance, _, _ = orchestrator(tmp_path, monkeypatch, codex=False)
    typed = outcome(success=False)
    typed.usage["typesafe_assessment"] = {
        "complete": False, "failure_class": "fixture_uncertain",
        "answers": {"fixture-risk": 0.5},
    }
    typed.usage["typesafe_usage"] = {"input_tokens": 17}
    stages(instance, monkeypatch, typed=typed, generator=outcome(
        provider="openai", model=GENERATOR,
    ))
    result = await run(instance)
    assert result.llm_success
    assert result.llm_usage["provider"] == "openai"
    assert result.llm_usage["typesafe_assessment"] == typed.usage["typesafe_assessment"]
    assert result.llm_usage["typesafe_usage"] == {"input_tokens": 17}
    assert result.llm_usage["typesafe_attempt"]["success"] is False
