from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

import omargate.analyze.orchestrator as module
from omargate.analyze.codex.codex_runner import parse_codex_findings
from omargate.analyze.llm.response_parser import ResponseParser
from omargate.analyze.orchestrator import AnalysisOrchestrator, LLMAnalysisResult
from omargate.analyze.typesafe_client import TypeSafeClient, TypeSafeResult
from omargate.analyze.typesafe_review import (
    ReviewDecision,
    ReviewPlan,
    RatedFinding,
    TypeSafeReviewIncomplete,
)
from omargate.config import OmarGateConfig
from omargate.gate import evaluate_gate
from omargate.logging import OmarLogger
from omargate.main import _build_llm_evidence
from omargate.models import GateConfig, GateStatus
from omargate.packaging import write_findings_jsonl, write_pack_summary


PIN = "jev-1.13.0"
GENERATOR = "gpt-5.3-codex"
ACTUAL_GENERATOR = "fixture-returned-generator-model"
DIFF = "diff --git a/source.py b/source.py\n--- a/source.py\n+++ b/source.py\n@@ -1 +1,2 @@\n-old\n+first\n+second\n"


def finding(source="deterministic", *, model=None, rule_id=None):
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
    if rule_id is not None:
        result["rule_id"] = rule_id
    return result


def bind_typed_candidate(result):
    result["typed_candidate"] = {
        "candidate_id": "span-" + "0" * 64,
        "source_sha256": "1" * 64,
        "evidence_sha256": "2" * 64,
    }
    return result


def outcome(
    *,
    success=True,
    provider="typesafe",
    model=PIN,
    findings=None,
    attempted=True,
    output_valid=None,
    failure_class=None,
    no_findings_reported=None,
):
    findings = [] if findings is None else findings
    output_valid = success if output_valid is None else output_valid
    no_findings_reported = (
        success and not findings
        if no_findings_reported is None
        else no_findings_reported
    )
    return LLMAnalysisResult(
        findings=copy.deepcopy(findings), success=success,
        usage={"provider": provider, "model": model, "route": "fixture",
               "tokens_in": None, "tokens_out": None, "cost_usd": None,
               "latency_ms": 1},
        warning=None if success else "Fixture stage did not complete.",
        attempted=attempted, output_valid=output_valid,
        no_findings_reported=no_findings_reported,
        reported_finding_count=len(findings),
        failure_class=None if success else failure_class or "fixture_incomplete",
    )


def partial_typed_outcome():
    confirmed = bind_typed_candidate(finding("llm", model=PIN))
    confirmed.update(
        category="auth",
        line_start=2,
        line_end=2,
        snippet="second\n",
        typed_verdict={"severity": "P2", "category": "auth"},
    )
    result = outcome(
        success=False,
        findings=[confirmed],
        output_valid=True,
        failure_class="policy_review_incomplete",
    )
    result.usage["typesafe_assessment"] = {
        "complete": False,
        "policy_decision_complete": False,
        "decision_reason": "policy_review_incomplete",
        "unresolved_candidates": [{
            "candidate_id": "span-fixture-unresolved",
            "reason": "policy_risk_answer_ambiguous",
        }],
    }
    return result


def orchestrator(
    tmp_path,
    monkeypatch,
    *,
    fallback=True,
    codex=True,
    allow=True,
    failure_policy="block",
):
    (tmp_path / "source.py").write_text("first\nsecond\n", encoding="utf-8")
    config = OmarGateConfig(
        llm_provider="typesafe", typesafe_api_key="synthetic-typesafe-key",
        openai_api_key="synthetic-generator-key", typesafe_model=PIN,
        typesafe_fallback=fallback, use_codex=codex, model=GENERATOR,
        model_fallback=GENERATOR, codex_model=GENERATOR,
        run_harness=False, publish_github=False, telemetry=False,
        llm_failure_policy=failure_policy,
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
@pytest.mark.parametrize("codex", [True, False])
async def test_clean_typed_review_requires_successful_generator_confirmation(
    tmp_path,
    monkeypatch,
    codex,
):
    instance, _, synopsis = orchestrator(
        tmp_path, monkeypatch, fallback=True, codex=codex
    )
    typed_clean = outcome(
        success=False,
        output_valid=True,
        failure_class="typesafe_clean_requires_generator",
        no_findings_reported=True,
    )
    typed_clean.usage["typesafe_assessment"] = {
        "complete": False,
        "policy_decision_complete": True,
        "failure_class": "typesafe_clean_requires_generator",
    }
    generator = outcome(provider="openai", model=GENERATOR)
    typed, cli, api = stages(
        instance,
        monkeypatch,
        typed=typed_clean,
        codex=generator if codex else None,
        generator=generator,
    )

    result = await run(instance)

    assert result.llm_success and result.llm_output_valid
    assert result.llm_no_findings_reported and result.llm_reported_finding_count == 0
    assert result.llm_count == 0 and result.llm_failure_class is None
    assert result.llm_usage["provider"] == "openai"
    assert result.llm_usage["model"] == GENERATOR
    assert result.llm_usage["typesafe_attempt"]["success"] is False
    assert result.llm_usage["typesafe_assessment"]["complete"] is False
    assert typed.await_count == 1
    assert cli.await_count == int(codex)
    assert api.await_count == int(not codex)
    assert synopsis == []
    assert_deterministic_retained(result)


@pytest.mark.anyio
async def test_clean_typed_review_without_fallback_remains_incomplete(
    tmp_path,
    monkeypatch,
):
    instance, _, synopsis = orchestrator(tmp_path, monkeypatch, fallback=False)
    typed_clean = outcome(
        success=False,
        output_valid=True,
        failure_class="typesafe_clean_requires_generator",
        no_findings_reported=True,
    )
    typed, cli, api = stages(instance, monkeypatch, typed=typed_clean)

    result = await run(instance)

    assert not result.llm_success and result.llm_output_valid
    assert result.llm_attempted and result.llm_no_findings_reported
    assert result.llm_failure_class == "typesafe_clean_requires_generator"
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
async def test_real_empty_complete_policy_decision_requires_generator(tmp_path, monkeypatch):
    instance, ingest, client = real_stage_setup(tmp_path, monkeypatch)
    run_dir = tmp_path / "artifacts"
    result = await real_stage(instance, ingest, run_dir=run_dir)

    assert not result.success and result.output_valid and result.attempted
    assert result.no_findings_reported and result.findings == []
    assert result.reported_finding_count == 0
    assert result.failure_class == "typesafe_clean_requires_generator"
    assert result.usage["model"] == PIN and result.usage["provider"] == "typesafe"
    assert result.usage["typesafe_usage"] == {"input_tokens": 7, "output_tokens": 0}
    retained = json.loads((run_dir / "TYPESAFE_REVIEW.json").read_text(encoding="utf-8"))
    assert retained["complete"] is False and retained["model"] == PIN
    assert retained["policy_decision_complete"] is True
    assert retained["failure_class"] == "typesafe_clean_requires_generator"
    assert retained["source_hashes"] and len(client.calls) == 1


@pytest.mark.anyio
async def test_complete_mixed_typed_review_runs_generator_for_clean_span(
    tmp_path,
    monkeypatch,
):
    policy = FixturePolicy()

    def mixed_decision(candidates, answers):
        confirmed, _clean = candidates
        return ReviewDecision(
            (RatedFinding(
                candidate_id=confirmed.candidate_id,
                question_ids=("q0",),
                severity="P2",
                category="crypto",
                message="A fixed typed finding covers the first span only.",
                recommendation="Inspect the first source span.",
                support_probability=0.95,
            ),),
            complete=True,
            reason="policy_review_complete",
        )

    policy.decide = mixed_decision
    instance, ingest, _ = orchestrator(
        tmp_path,
        monkeypatch,
        fallback=True,
        codex=False,
    )
    source = "".join(f"line {index}\n" for index in range(1, 43))
    (tmp_path / "source.py").write_text(source, encoding="utf-8")
    ingest["files"][0]["lines"] = 42
    diff = (
        "diff --git a/source.py b/source.py\n"
        "--- /dev/null\n"
        "+++ b/source.py\n"
        "@@ -0,0 +1,42 @@\n"
        + "".join(f"+line {index}\n" for index in range(1, 43))
    )
    client = FixtureClient()
    monkeypatch.setattr(module, "TypeSafeClient", lambda *args, **kwargs: client)
    monkeypatch.setattr(module, "load_policy", lambda: policy)
    corroboration = finding(rule_id="SEC-016")
    corroboration.update(
        category="auth",
        line_start=41,
        line_end=41,
        snippet="line 41\n",
    )
    monkeypatch.setattr(
        instance,
        "_run_deterministic_scans",
        lambda _: [corroboration],
    )
    generator_finding = finding("llm", model=GENERATOR)
    generator_finding.update(
        id="generator-clean-span-p1",
        severity="P1",
        category="auth",
        line_start=41,
        line_end=41,
        snippet="line 41\n",
    )
    generator = AsyncMock(return_value=outcome(
        provider="openai",
        model=GENERATOR,
        findings=[generator_finding],
    ))
    monkeypatch.setattr(instance, "_run_llm_analysis", generator)

    result = await instance.run(
        scan_mode="pr-diff",
        changed_files=["source.py"],
        diff_content=diff,
    )

    assessment = result.llm_usage["typesafe_assessment"]
    clean_candidate, = assessment["generator_required_clean_candidates"]
    assert clean_candidate == assessment["candidates"][1]["candidate_id"]
    assert assessment["policy_decision_complete"] is True
    assert assessment["failure_class"] == "typesafe_clean_requires_generator"
    assert generator.await_count == 1
    assert result.llm_success and result.counts["P1"] == 1
    assert any(
        row["id"] == "generator-clean-span-p1"
        for row in result.findings
    )
    assert len(client.calls) == 1


@pytest.mark.anyio
async def test_real_partial_policy_result_is_valid_but_incomplete(tmp_path, monkeypatch):
    policy = FixturePolicy()

    def partial_decision(candidates, answers):
        confirmed, unresolved = candidates
        return ReviewDecision(
            (RatedFinding(
                candidate_id=confirmed.candidate_id,
                question_ids=("q0",),
                severity="P2",
                category="fixture",
                message="A fixed partial typed verdict.",
                recommendation="Inspect the fixed fixture source.",
                support_probability=0.8,
            ),),
            complete=False,
            reason="policy_review_incomplete",
            unresolved_candidates=((
                unresolved.candidate_id,
                "policy_risk_answer_ambiguous",
            ),),
        )

    policy.decide = partial_decision
    instance, ingest, client = real_stage_setup(
        tmp_path,
        monkeypatch,
        policy=policy,
    )
    source = "".join(f"line {index}\n" for index in range(1, 43))
    (tmp_path / "source.py").write_text(source, encoding="utf-8")
    ingest["files"][0]["lines"] = 42
    diff = (
        "diff --git a/source.py b/source.py\n"
        "--- /dev/null\n"
        "+++ b/source.py\n"
        "@@ -0,0 +1,42 @@\n"
        + "".join(f"+line {index}\n" for index in range(1, 43))
    )

    result = await real_stage(instance, ingest, diff_content=diff)

    finding_, = result.findings
    assert finding_["typed_verdict"]["category"] == "fixture"
    assert not result.success and result.output_valid and result.attempted
    assert result.failure_class == "policy_review_incomplete"
    assessment = result.usage["typesafe_assessment"]
    assert assessment["complete"] is False
    assert assessment["policy_decision_complete"] is False
    assert assessment["unresolved_candidates"] == [{
        "candidate_id": assessment["candidates"][1]["candidate_id"],
        "reason": "policy_risk_answer_ambiguous",
    }]
    assert len(client.calls) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("category", ["availability", "infrastructure"])
async def test_blocking_category_without_corroboration_producer_requires_generator(
    tmp_path,
    monkeypatch,
    category,
):
    policy = FixturePolicy()

    def availability_decision(candidates, answers):
        return ReviewDecision(
            (RatedFinding(
                candidate_id=candidates[0].candidate_id,
                question_ids=("q0",),
                severity="P1",
                category=category,
                message="A fixed generator-required verdict.",
                recommendation="Bound attacker-controlled work.",
                support_probability=0.95,
            ),),
            complete=True,
            reason="policy_review_complete",
        )

    policy.decide = availability_decision
    instance, ingest, client = real_stage_setup(
        tmp_path,
        monkeypatch,
        policy=policy,
    )

    result = await real_stage(instance, ingest)

    assert not result.success and result.output_valid and result.attempted
    assert result.failure_class == "typesafe_category_requires_generator"
    assert result.findings[0]["severity"] == "P1"
    assessment = result.usage["typesafe_assessment"]
    assert assessment["complete"] is False
    assert assessment["policy_decision_complete"] is True
    assert assessment["generator_required_categories"] == [category]
    assert len(client.calls) == 1


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


@pytest.mark.anyio
async def test_empty_successful_fallback_retains_confirmed_partial_typed_finding(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch, codex=False)
    typed_partial = partial_typed_outcome()
    typed, cli, api = stages(
        instance,
        monkeypatch,
        typed=typed_partial,
        generator=outcome(provider="openai", model=GENERATOR),
    )

    result = await run(instance)

    retained = [row for row in result.findings if row.get("typed_verdict")]
    assert len(retained) == 1
    assert retained[0]["category"] == "auth"
    assert result.llm_success and result.llm_output_valid
    assert result.llm_count == result.llm_reported_finding_count == 1
    assert result.llm_usage["typesafe_assessment"]["complete"] is False
    assert result.llm_usage["typesafe_attempt"]["success"] is False
    assert typed.await_count == api.await_count == 1 and cli.await_count == 0


@pytest.mark.anyio
@pytest.mark.parametrize("category", ["availability", "infrastructure"])
async def test_generator_fallback_cannot_promote_category_without_corroboration_producer(
    tmp_path,
    monkeypatch,
    category,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch, codex=False)
    typed_category_hold = partial_typed_outcome()
    typed_category_hold.findings[0].update(
        severity="P1",
        category=category,
        typed_verdict={"severity": "P1", "category": category},
    )
    typed_category_hold.failure_class = "typesafe_category_requires_generator"
    typed_category_hold.usage["typesafe_assessment"].update(
        generator_required_categories=[category],
        failure_class="typesafe_category_requires_generator",
    )
    typed, cli, api = stages(
        instance,
        monkeypatch,
        typed=typed_category_hold,
        generator=outcome(provider="openai", model=GENERATOR),
    )

    result = await run(instance)

    retained = [row for row in result.findings if row.get("typed_verdict")]
    assert len(retained) == 1
    assert retained[0]["severity"] == "P2"
    assert retained[0]["corroboration"]["reason"] == (
        "no_reviewed_deterministic_producer"
    )
    assert result.llm_success and result.llm_output_valid
    assert result.llm_usage["typesafe_assessment"]["complete"] is False
    assert typed.await_count == api.await_count == 1 and cli.await_count == 0


@pytest.mark.anyio
async def test_failed_fallback_retains_confirmed_partial_typed_finding(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch, codex=False)
    typed_partial = partial_typed_outcome()
    typed, cli, api = stages(
        instance,
        monkeypatch,
        typed=typed_partial,
        generator=outcome(success=False, provider="openai", model=GENERATOR),
    )

    result = await run(instance)

    retained = [row for row in result.findings if row.get("typed_verdict")]
    assert len(retained) == 1
    assert not result.llm_success and not result.llm_output_valid
    assert result.llm_count == result.llm_reported_finding_count == 1
    assert result.llm_usage["typesafe_assessment"]["complete"] is False
    assert typed.await_count == api.await_count == 1 and cli.await_count == 0


@pytest.mark.anyio
async def test_fallback_duplicate_does_not_replace_or_inflate_partial_typed_finding(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch, codex=False)
    typed_partial = partial_typed_outcome()
    duplicate = copy.deepcopy(typed_partial.findings[0])
    duplicate.pop("typed_verdict")
    duplicate.pop("typed_candidate")
    duplicate["id"] = "generator-duplicate"
    duplicate["message"] = "Generator duplicate must not replace the typed verdict."
    typed, cli, api = stages(
        instance,
        monkeypatch,
        typed=typed_partial,
        generator=outcome(
            provider="openai",
            model=GENERATOR,
            findings=[duplicate],
        ),
    )

    result = await run(instance)

    retained = [row for row in result.findings if row.get("typed_verdict")]
    assert len(retained) == 1
    assert retained[0].get("typed_verdict")
    assert retained[0]["message"] == "A fixture finding is retained."
    assert result.llm_count == result.llm_reported_finding_count == 1
    assert typed.await_count == api.await_count == 1 and cli.await_count == 0


@pytest.mark.parametrize(
    "typed_severity,generator_severity,expected_severity,expected_source",
    [
        ("P2", "P0", "P0", "codex"),
        ("P0", "P2", "P0", "llm"),
        ("P0", "P0", "P0", "llm"),
    ],
)
def test_llm_composition_keeps_strongest_guarded_severity_and_typed_provenance(
    typed_severity,
    generator_severity,
    expected_severity,
    expected_source,
):
    typed = bind_typed_candidate(finding("llm", model=PIN))
    typed.update(
        id="typed-collision",
        severity=typed_severity,
        category="auth",
        line_start=2,
        line_end=2,
        typed_verdict={"severity": typed_severity, "category": "auth"},
    )
    generator = finding("codex", model=GENERATOR)
    generator.update(
        id="generator-collision",
        severity=generator_severity,
        category="auth",
        line_start=2,
        line_end=2,
    )

    composed = AnalysisOrchestrator._compose_llm_findings([typed], [generator])

    assert len(composed) == 1
    winner = composed[0]
    assert winner["severity"] == expected_severity
    assert winner["source"] == expected_source
    assert {winner["id"]} | {
        record["id"] for record in winner["collision_provenance"]
    } == {
        "typed-collision",
        "generator-collision",
    }
    if expected_source == "llm":
        assert winner["typed_candidate"] == typed["typed_candidate"]
        assert winner["typed_verdict"] == typed["typed_verdict"]
    else:
        assert "typed_candidate" not in winner
        assert "typed_verdict" not in winner
        typed_alternate = next(
            record
            for record in winner["collision_provenance"]
            if "typed_candidate" in record
        )
        assert typed_alternate["typed_candidate"] == typed["typed_candidate"]
        assert typed_alternate["typed_verdict"] == typed["typed_verdict"]


def test_final_merge_is_order_independent_and_keeps_typed_p0_over_deterministic_p2(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    typed = bind_typed_candidate(finding("llm", model=PIN))
    typed.update(
        id="typed-p0",
        severity="P0",
        category="auth",
        line_start=2,
        line_end=2,
        typed_verdict={"severity": "P0", "category": "auth"},
    )
    deterministic = finding(rule_id="SEC-016")
    deterministic.update(
        id="deterministic-p2",
        severity="P2",
        category="auth",
        line_start=2,
        line_end=2,
    )

    forward = instance._merge_findings([deterministic], [typed])
    reverse = instance._merge_findings([typed], [deterministic])

    assert forward == reverse
    assert len(forward) == 1
    assert forward[0]["id"] == "typed-p0"
    assert forward[0]["severity"] == "P0"
    assert forward[0]["typed_candidate"] == typed["typed_candidate"]
    assert {forward[0]["id"]} | {
        record["id"] for record in forward[0]["collision_provenance"]
    } == {
        "typed-p0",
        "deterministic-p2",
    }


def test_equal_severity_duplicate_prefers_typed_provenance_in_both_input_orders(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    typed = bind_typed_candidate(finding("llm", model=PIN))
    typed.update(
        id="typed-equal",
        severity="P1",
        category="auth",
        typed_verdict={"severity": "P1", "category": "auth"},
    )
    generator = finding("codex", model=GENERATOR)
    generator.update(
        id="generator-equal",
        severity="P1",
        category="auth",
    )

    forward = instance._merge_findings([typed], [generator])
    reverse = instance._merge_findings([generator], [typed])

    assert forward == reverse
    assert len(forward) == 1
    assert forward[0]["id"] == "typed-equal"
    assert forward[0]["typed_candidate"] == typed["typed_candidate"]


def test_equal_severity_reviewed_producer_wins_and_retains_typed_alternate(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    typed = bind_typed_candidate(finding("llm", model=PIN))
    typed.update(
        id="typed-equal",
        severity="P1",
        category="auth",
        typed_verdict={"severity": "P1", "category": "auth"},
    )
    deterministic = finding(rule_id="SEC-016")
    deterministic.update(
        id="reviewed-producer-equal",
        severity="P1",
        category="auth",
    )

    forward = instance._merge_findings([deterministic], [typed])
    reverse = instance._merge_findings([typed], [deterministic])

    assert forward == reverse
    winner, = forward
    assert winner["id"] == "reviewed-producer-equal"
    assert "typed_candidate" not in winner
    typed_alternate = next(
        record
        for record in winner["collision_provenance"]
        if "typed_candidate" in record
    )
    assert typed_alternate["typed_candidate"] == typed["typed_candidate"]
    assert typed_alternate["typed_verdict"] == typed["typed_verdict"]


def test_distinct_same_start_spans_remain_stable_in_both_input_orders(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    short = finding(rule_id="SEC-016")
    short.update(id="short-span", category="auth", line_start=1, line_end=1)
    long = finding(rule_id="SEC-016")
    long.update(id="long-span", category="auth", line_start=1, line_end=2)

    forward = instance._merge_findings([short], [long])
    reverse = instance._merge_findings([long], [short])

    assert forward == reverse
    assert [row["id"] for row in forward] == ["short-span", "long-span"]


def test_collision_provenance_is_bounded_without_dropping_typed_evidence(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    typed = bind_typed_candidate(finding("llm", model=PIN))
    typed.update(
        id="z-typed-alternate",
        category="auth",
        typed_verdict={"severity": "P2", "category": "auth"},
    )
    winner = finding("codex", model=GENERATOR)
    winner.update(id="winner", severity="P0", category="auth")
    alternates = []
    for index in range(12):
        alternate = finding("codex", model=GENERATOR)
        alternate.update(id=f"alternate-{index:02d}", category="auth")
        alternates.append(alternate)

    forward = instance._merge_findings([], [winner, *alternates, typed])
    reverse = instance._merge_findings([], [typed, *reversed(alternates), winner])

    assert forward == reverse
    selected, = forward
    assert selected["id"] == "winner"
    assert len(selected["collision_provenance"]) == module._MAX_COLLISION_PROVENANCE
    assert selected["collision_provenance_truncated"] is True
    typed_alternate = next(
        record
        for record in selected["collision_provenance"]
        if "typed_candidate" in record
    )
    assert typed_alternate["typed_candidate"] == typed["typed_candidate"]
    assert typed_alternate["typed_verdict"] == typed["typed_verdict"]


@pytest.mark.anyio
async def test_guarded_fallback_p0_replaces_partial_typed_p2_without_losing_evidence(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch, codex=False)
    corroboration = finding(rule_id="SEC-016")
    corroboration.update(category="auth", line_start=2, line_end=2)
    monkeypatch.setattr(instance, "_run_deterministic_scans", lambda _: [corroboration])
    typed_partial = partial_typed_outcome()
    generator = finding("llm", model=GENERATOR)
    generator.update(
        id="generator-p0",
        severity="P0",
        category="auth",
        line_start=2,
        line_end=2,
        snippet="second\n",
    )
    stages(
        instance,
        monkeypatch,
        typed=typed_partial,
        generator=outcome(
            provider="openai",
            model=GENERATOR,
            findings=[generator],
        ),
    )

    result = await run(instance)

    assert result.counts["total"] == result.counts["P0"] == 1
    winner, = result.findings
    assert winner["id"] == "generator-p0"
    assert winner["severity"] == "P0"
    assert "typed_candidate" not in winner
    typed_alternate = next(
        record
        for record in winner["collision_provenance"]
        if "typed_candidate" in record
    )
    assert typed_alternate["typed_candidate"] == (
        typed_partial.findings[0]["typed_candidate"]
    )
    assert typed_alternate["typed_verdict"] == (
        typed_partial.findings[0]["typed_verdict"]
    )
    assert result.llm_count == result.llm_reported_finding_count == 1


@pytest.mark.anyio
async def test_run_keeps_distinct_same_start_spans_in_counts(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch, codex=False)
    deterministic = finding(rule_id="SEC-016")
    deterministic.update(category="auth", line_start=1, line_end=1)
    monkeypatch.setattr(instance, "_run_deterministic_scans", lambda _: [deterministic])
    typed_partial = partial_typed_outcome()
    typed_partial.findings[0].update(
        severity="P0",
        line_start=1,
        line_end=2,
        typed_verdict={"severity": "P0", "category": "auth"},
    )
    stages(
        instance,
        monkeypatch,
        typed=typed_partial,
        generator=outcome(provider="openai", model=GENERATOR),
    )

    result = await run(instance)

    assert result.counts["total"] == 2
    assert result.counts["P0"] == 1
    assert result.counts["P2"] == 1
    assert [(row["line_start"], row["line_end"]) for row in result.findings] == [
        (1, 2),
        (1, 1),
    ]


@pytest.mark.parametrize(
    "deterministic_start,deterministic_end,deterministic_category,expected_severity",
    [
        (35, 35, "auth", "P1"),
        (1, 15, "auth", "P1"),
        (45, 50, "auth", "P1"),
        (46, 50, "auth", "P2"),
        (35, 35, "privacy", "P2"),
        (35, 35, "", "P2"),
    ],
)
def test_corroboration_uses_complete_typed_and_deterministic_ranges_with_exact_category(
    tmp_path,
    monkeypatch,
    deterministic_start,
    deterministic_end,
    deterministic_category,
    expected_severity,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    typed = bind_typed_candidate(finding("llm"))
    typed.update(
        severity="P1",
        category="auth",
        line_start=20,
        line_end=40,
        message="A policy-owned authentication finding.",
    )
    deterministic = finding(rule_id="SEC-016")
    deterministic.update(
        category=deterministic_category,
        line_start=deterministic_start,
        line_end=deterministic_end,
    )

    guarded = instance._apply_llm_guardrails(
        llm_findings=[typed],
        non_llm_findings=[deterministic],
        ingest={"files": [{"path": "source.py", "lines": 100}]},
    )

    assert len(guarded) == 1
    assert guarded[0]["severity"] == expected_severity


def test_reviewed_corroboration_producer_census_is_explicit_and_rule_bound(
    tmp_path,
    monkeypatch,
):
    expected = {
        ("deterministic", "SEC-001", "secrets", "secrets"),
        ("deterministic", "SEC-002", "secrets", "secrets"),
        ("deterministic", "SEC-003", "secrets", "secrets"),
        ("deterministic", "SEC-004", "secrets", "secrets"),
        ("deterministic", "SEC-005", "secrets", "secrets"),
        ("deterministic", "SEC-006", "secrets", "secrets"),
        ("deterministic", "SEC-007", "misconfig", "misconfig"),
        ("deterministic", "SEC-008", "injection", "injection"),
        ("deterministic", "SEC-011", "crypto", "crypto"),
        ("deterministic", "SEC-013", "secrets", "secrets"),
        ("deterministic", "SEC-013", "ssrf", "ssrf"),
        ("deterministic", "SEC-015", "privacy", "privacy"),
        ("deterministic", "SEC-016", "auth", "auth"),
        ("deterministic", "SEC-ENTROPY", "secrets", "secrets"),
        ("deterministic", "CICD-001", "ci-cd", "ci-cd"),
        ("deterministic", "CICD-002", "ci-cd", "ci-cd"),
        ("deterministic", "CICD-003", "ci-cd", "ci-cd"),
        ("deterministic", "CICD-004", "ci-cd", "ci-cd"),
        ("deterministic", "CONF-ENV-001", "secrets", "secrets"),
        ("deterministic", "CONF-PKG-001", "supply-chain", "supply-chain"),
        ("deterministic", "CONF-DC-001", "misconfig", "misconfig"),
        ("deterministic", "CONF-DC-002", "exposure", "exposure"),
        ("deterministic", "EQ-022", "auth", "auth"),
        ("deterministic", "EQ-023", "auth", "auth"),
        (
            "harness",
            "HARNESS-NODE-IGNORE-SCRIPTS",
            "supply-chain",
            "supply-chain",
        ),
        ("harness", "HARNESS-DOCKER-COPY-ENV", "secrets", "secrets"),
        ("harness", "HARNESS-CICD-PERMS", "ci_cd", "ci-cd"),
        (
            "harness",
            "HARNESS-BUILD-LOCKFILE",
            "supply-chain",
            "supply-chain",
        ),
        (
            "harness",
            "HARNESS-BUILD-POSTINSTALL",
            "supply-chain",
            "supply-chain",
        ),
        (
            "harness",
            "HARNESS-BUILD-FLOATING-VERSIONS",
            "supply-chain",
            "supply-chain",
        ),
        ("harness", "HARNESS-NPM-AUDIT", "supply-chain", "supply-chain"),
        ("harness", "HARNESS-PIP-AUDIT", "supply-chain", "supply-chain"),
        ("harness", "HARNESS-CARGO-AUDIT", "supply-chain", "supply-chain"),
        ("harness", "SEC-004", "secrets", "secrets"),
        ("harness", "SEC-005", "secrets", "secrets"),
        ("harness", "SEC-013", "secrets", "secrets"),
        ("harness", "SEC-ENTROPY", "secrets", "secrets"),
    }
    actual = {
        (*producer, canonical)
        for producer, canonical in module._REVIEWED_CORROBORATION_PRODUCERS.items()
    }

    assert actual == expected
    assert not any(canonical == "infrastructure" for *_, canonical in actual)

    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    converted = instance._finding_to_dict(SimpleNamespace(
        id="producer-fixture",
        pattern_id="SEC-016",
        severity="P1",
        category="auth",
        file_path="source.py",
        line_start=1,
        line_end=1,
        snippet="first\n",
        message="Authentication policy bypass.",
        recommendation="Enforce authorization.",
        fix_plan="Enforce authorization.",
        confidence=1.0,
        source="deterministic",
    ))
    assert converted["rule_id"] == "SEC-016"


@pytest.mark.parametrize(
    (
        "typed_category,producer_source,rule_id,producer_category,"
        "expected_severity,expected_reason"
    ),
    [
        ("ci-cd", "harness", "HARNESS-CICD-PERMS", "ci_cd", "P1", None),
        ("csrf", "deterministic", "SEC-016", "auth", "P1", None),
        ("xss", "deterministic", "SEC-008", "injection", "P1", None),
        ("xxe", "deterministic", "SEC-008", "injection", "P1", None),
        ("path_traversal", "deterministic", "SEC-008", "injection", "P1", None),
        (
            "auth",
            "deterministic",
            "SEC-016",
            "csrf",
            "P2",
            "no_compatible_deterministic_finding",
        ),
        (
            "injection",
            "deterministic",
            "SEC-008",
            "xss",
            "P2",
            "no_compatible_deterministic_finding",
        ),
        (
            "auth",
            "deterministic",
            None,
            "auth",
            "P2",
            "no_compatible_deterministic_finding",
        ),
        (
            "auth",
            "deterministic",
            "SEC-999",
            "auth",
            "P2",
            "no_compatible_deterministic_finding",
        ),
        (
            "misconfig",
            "harness",
            "HARNESS-HTTP-HEADERS",
            "web",
            "P2",
            "no_compatible_deterministic_finding",
        ),
        (
            "availability",
            "deterministic",
            "UNREVIEWED",
            "availability",
            "P2",
            "no_reviewed_deterministic_producer",
        ),
        (
            "race-condition",
            "deterministic",
            "UNREVIEWED",
            "race-condition",
            "P2",
            "no_reviewed_deterministic_producer",
        ),
        (
            "other-security",
            "deterministic",
            "UNREVIEWED",
            "other-security",
            "P2",
            "no_reviewed_deterministic_producer",
        ),
        (
            "infrastructure",
            "deterministic",
            "EQ-018",
            "infrastructure",
            "P2",
            "no_reviewed_deterministic_producer",
        ),
        (
            "fixture",
            "deterministic",
            "UNREVIEWED",
            "fixture",
            "P2",
            "unsupported_category",
        ),
    ],
)
def test_corroboration_uses_only_reviewed_rule_bound_category_compatibility(
    tmp_path,
    monkeypatch,
    typed_category,
    producer_source,
    rule_id,
    producer_category,
    expected_severity,
    expected_reason,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    typed = bind_typed_candidate(finding("llm"))
    typed.update(
        severity="P1",
        category=typed_category,
        line_start=20,
        line_end=40,
    )
    producer = finding(producer_source, rule_id=rule_id)
    producer.update(
        category=producer_category,
        line_start=35,
        line_end=35,
    )

    guarded = instance._apply_llm_guardrails(
        llm_findings=[typed],
        non_llm_findings=[producer],
        ingest={"files": [{"path": "source.py", "lines": 100}]},
    )

    assert guarded[0]["severity"] == expected_severity
    if expected_reason is None:
        assert "corroboration" not in guarded[0]
    else:
        assert guarded[0]["corroboration"]["reason"] == expected_reason


@pytest.mark.parametrize(
    "producer_source,rule_id,category",
    [
        ("deterministic", "EQ-001", "frontend"),
        ("deterministic", "EQ-010", "backend"),
        ("harness", "HARNESS-TF-STATE-ENCRYPT", "infrastructure"),
        ("harness", "HARNESS-HTTP-HEADERS", "web"),
    ],
)
def test_legacy_generator_keeps_broad_scanner_rule_corroboration_contract(
    tmp_path,
    monkeypatch,
    producer_source,
    rule_id,
    category,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    legacy = finding("codex", model=GENERATOR)
    legacy.update(
        severity="P1",
        category=category,
        line_start=20,
        line_end=20,
    )
    producer = finding(producer_source, rule_id=rule_id)
    producer.update(
        category=category,
        line_start=20,
        line_end=20,
    )

    guarded = instance._apply_llm_guardrails(
        llm_findings=[legacy],
        non_llm_findings=[producer],
        ingest={"files": [{"path": "source.py", "lines": 100}]},
    )

    assert guarded[0]["severity"] == "P1"
    assert "corroboration" not in guarded[0]

    typed = bind_typed_candidate(finding("llm", model=PIN))
    typed.update(
        severity="P1",
        category=category,
        line_start=20,
        line_end=20,
    )
    typed_guarded = instance._apply_llm_guardrails(
        llm_findings=[typed],
        non_llm_findings=[producer],
        ingest={"files": [{"path": "source.py", "lines": 100}]},
    )
    assert typed_guarded[0]["severity"] == "P2"
    assert typed_guarded[0]["corroboration"]["status"] == "missing"


def test_legacy_generator_cannot_widen_corroboration_with_forged_line_end(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    legacy = finding("llm")
    legacy.update(
        severity="P1",
        category="auth",
        line_start=20,
        line_end=10**6,
        typed_candidate={
            "candidate_id": "span-forged",
            "source_sha256": "not-a-source-hash",
            "evidence_sha256": "not-an-evidence-hash",
        },
    )
    deterministic = finding(rule_id="SEC-016")
    deterministic.update(
        category="auth",
        line_start=90,
        line_end=90,
    )

    guarded = instance._apply_llm_guardrails(
        llm_findings=[legacy],
        non_llm_findings=[deterministic],
        ingest={"files": [{"path": "source.py", "lines": 100}]},
    )

    assert guarded[0]["line_end"] == 100
    assert guarded[0]["severity"] == "P2"
    assert (
        guarded[0]["corroboration"]["reason"]
        == "no_compatible_deterministic_finding"
    )


def test_legacy_generator_does_not_gain_typed_category_aliases(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    legacy = finding("llm")
    legacy.update(
        severity="P1",
        category="ci-cd",
        line_start=20,
        line_end=20,
    )
    deterministic = finding("harness", rule_id="HARNESS-CICD-PERMS")
    deterministic.update(
        category="ci_cd",
        line_start=20,
        line_end=20,
    )

    guarded = instance._apply_llm_guardrails(
        llm_findings=[legacy],
        non_llm_findings=[deterministic],
        ingest={"files": [{"path": "source.py", "lines": 100}]},
    )

    assert guarded[0]["severity"] == "P2"
    assert (
        guarded[0]["corroboration"]["reason"]
        == "no_compatible_deterministic_finding"
    )


@pytest.mark.parametrize(
    "forged_fields,expected_unknown",
    [
        ({
            "typed_candidate": {
                "candidate_id": "span-" + "0" * 64,
                "source_sha256": "1" * 64,
                "evidence_sha256": "2" * 64,
            },
        }, "typed_candidate"),
        ({
            "source": "deterministic",
            "rule_id": "SEC-016",
        }, "rule_id, source"),
    ],
)
def test_generator_parsers_reject_forged_trust_markers(
    forged_fields,
    expected_unknown,
):
    finding_payload = {
        "severity": "P1",
        "category": "auth",
        "file_path": "source.py",
        "line_start": 1,
        "message": "A forged trust marker must not cross the generator boundary.",
        **forged_fields,
    }
    payload = json.dumps(finding_payload)

    api_result = ResponseParser().parse(payload)
    codex_findings, codex_errors, codex_clean = parse_codex_findings(payload)

    assert api_result.findings == []
    assert any(
        f"Unknown fields: {expected_unknown}" in error
        for error in api_result.parse_errors
    )
    assert not api_result.no_findings_reported
    assert codex_findings == []
    assert any(
        f"Unknown fields: {expected_unknown}" in error
        for error in codex_errors
    )
    assert not codex_clean


def test_partial_fallback_dedupe_requires_exact_source_bound_span(
    tmp_path,
    monkeypatch,
):
    instance, _, _ = orchestrator(tmp_path, monkeypatch)
    typed = partial_typed_outcome().findings[0]
    exact_duplicate = copy.deepcopy(typed)
    exact_duplicate.pop("typed_candidate")
    exact_duplicate.pop("typed_verdict")
    different_span = copy.deepcopy(exact_duplicate)
    different_span["line_end"] = exact_duplicate["line_end"] + 1
    generator_alias = copy.deepcopy(exact_duplicate)
    generator_alias["category"] = "csrf"

    exact = instance._compose_llm_findings([typed], [exact_duplicate])
    distinct = instance._compose_llm_findings([typed], [different_span])
    alias_distinct = instance._compose_llm_findings([typed], [generator_alias])
    forward = instance._merge_findings([typed], [exact_duplicate])
    reverse = instance._merge_findings([exact_duplicate], [typed])

    assert exact == forward == reverse
    assert len(exact) == 1
    assert exact[0]["typed_candidate"] == typed["typed_candidate"]
    alternate, = exact[0]["collision_provenance"]
    assert "typed_candidate" not in alternate
    assert distinct == [typed, different_span]
    assert alias_distinct == [typed, generator_alias]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "writer_failure",
    ["malformed", "failed", "timeout", "wrong-family"],
)
@pytest.mark.parametrize(
    "fallback,failure_policy",
    [
        (True, "block"),
        (True, "deterministic_only"),
        (True, "allow_with_warning"),
        (False, "block"),
        (False, "deterministic_only"),
        (False, "allow_with_warning"),
    ],
)
async def test_completed_typed_p0_survives_writer_failure_without_a_new_decision(
    tmp_path,
    monkeypatch,
    capsys,
    writer_failure,
    fallback,
    failure_policy,
):
    instance, _, _ = orchestrator(
        tmp_path,
        monkeypatch,
        fallback=fallback,
        failure_policy=failure_policy,
    )
    # Corroborate the same category near the typed span's start, but keep a
    # different dedupe key so the deterministic fixture cannot stand in for it.
    corroboration = finding(rule_id="SEC-016")
    corroboration.update(
        category="auth",
        line_start=2,
        line_end=2,
        snippet="second\n",
    )
    monkeypatch.setattr(instance, "_run_deterministic_scans", lambda _: [corroboration])
    policy = FixturePolicy()

    def completed_verdict(candidates, answers):
        return ReviewDecision(
            (
                RatedFinding(
                    candidate_id=candidates[0].candidate_id,
                    question_ids=("q0",),
                    severity="P0",
                    category="auth",
                    message="Fixed fixture typed verdict.",
                    recommendation="Inspect the bound fixture source.",
                    support_probability=0.8,
                ),
            ),
            complete=True,
        )

    monkeypatch.setattr(policy, "decide", completed_verdict)
    monkeypatch.setattr(module, "load_policy", lambda: policy)
    typed_client = FixtureClient()
    monkeypatch.setattr(module, "TypeSafeClient", lambda *args, **kwargs: typed_client)
    usage = module.LLMUsage(GENERATOR, 10, 3, 0.0, 1, provider="openai")
    source_marker = "SOURCE_BEARING_WRITER_FIXTURE_MARKER"
    response = module.LLMResponse(f"not json: {source_marker}", usage, success=True)
    if writer_failure == "failed":
        response.success = False
    elif writer_failure == "wrong-family":
        response.usage.model = "gpt-4.1-mini"
    writer = SimpleNamespace(analyze=AsyncMock(return_value=response))
    if writer_failure == "timeout":
        writer.analyze.side_effect = TimeoutError(source_marker)
    writer_options = []

    def writer_factory(**kwargs):
        writer_options.append(kwargs)
        return writer

    monkeypatch.setattr(module, "LLMClient", writer_factory)
    clean_cli = AsyncMock(return_value=outcome(provider="openai", model=GENERATOR))
    clean_api = AsyncMock(return_value=outcome(provider="openai", model=GENERATOR))
    monkeypatch.setattr(instance, "_run_codex_audit", clean_cli)
    monkeypatch.setattr(instance, "_run_llm_analysis", clean_api)

    result = await run(instance)
    gate_dir = tmp_path / "gate"
    gate_dir.mkdir()
    findings_path = gate_dir / "FINDINGS.jsonl"
    write_findings_jsonl(findings_path, result.findings)
    write_pack_summary(
        gate_dir,
        "fixed-typed-verdict",
        True,
        findings_path,
        {key: result.counts[key] for key in ("P0", "P1", "P2", "P3")},
        {"action": "fixture"},
        ["deterministic", "llm"],
        llm_usage=result.llm_usage,
        llm_evidence=_build_llm_evidence(result, instance.config),
    )
    gate = evaluate_gate(
        gate_dir,
        GateConfig(
            severity_gate="P1",
            require_llm_success=failure_policy == "block",
        ),
    )
    typed = [row for row in result.findings if row.get("typed_verdict")]
    assert len(typed) == 1, {
        "counts": result.counts,
        "gate": gate.status.value,
        "cliCalls": clean_cli.await_count,
        "apiCalls": clean_api.await_count,
    }
    assert typed[0]["severity"] == typed[0]["typed_verdict"]["severity"] == "P0"
    assert typed[0]["message"] == "Fixed fixture typed verdict."
    assert (
        typed[0]["typed_reason"]
        == typed[0]["typed_verdict"]["reason"]
        == "Fixed fixture typed verdict."
    )
    assert typed[0]["recommendation"] == "Inspect the bound fixture source."
    assert typed[0]["file_path"] == "source.py" and typed[0]["line_start"] == 1
    assert typed[0]["model_source"] == PIN
    assert result.llm_success and result.llm_output_valid and result.llm_attempted
    assert result.llm_reported_finding_count == result.llm_count == 1
    assert result.counts["P0"] == 1 and result.counts["P2"] == 1
    assert gate.status == GateStatus.BLOCKED and gate.block_merge and gate.counts.p0 == 1
    assert clean_cli.await_count == clean_api.await_count == 0
    assert len(typed_client.calls) == writer.analyze.await_count == len(writer_options) == 1
    assert (
        writer_options[0]["primary_model"]
        == writer_options[0]["fallback_model"]
        == GENERATOR
    )
    writer_status = result.llm_usage["typesafe_assessment"]["writer"]
    assert writer_status["success"] is False
    assert writer_status["requested_model"] == GENERATOR
    assert re.fullmatch(r"[a-z][a-z0-9_]{0,95}", writer_status["failure_class"])
    assert any("writer" in warning.lower() for warning in result.warnings)
    assert source_marker not in json.dumps(
        {"warnings": result.warnings, "usage": result.llm_usage}
    )
    assert source_marker not in capsys.readouterr().err
