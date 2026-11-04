"""Shadow routing must never turn intent advice into merge authority."""
import json
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import ValidationError

from policy_fixture import FAKE_POLICY_JSON
from test_review_cascade import triage, generator_result, run_review
from test_scope_cascade import full as full, configured as configured, run_full
from omargate.analyze.orchestrator import AnalysisOrchestrator
from omargate.analyze.review_cascade import SHADOW
from omargate.analyze.typesafe_client import ChoiceAnswer
from omargate.comment import _review_chain_section
from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger

pytestmark = pytest.mark.anyio


def configuration(**overrides):
    values = dict(llm_provider="typesafe", review_routing="intent-shadow-v1",
                  typesafe_api_key="test-only", openai_api_key="test-only",
                  intent_model_pin="model-under-test-1.13.0", intent_policy=FAKE_POLICY_JSON,
                  intent_price_profile="typesafe-input-20261020", run_harness=False)
    values.update(overrides)
    return OmarGateConfig(**values)


@pytest.fixture
def shadow(tmp_path, monkeypatch):
    import os
    for key in list(os.environ):
        if key.startswith("INPUT_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    (tmp_path / "x.py").write_text("value = 1\n")
    runner = AnalysisOrchestrator(configuration(), OmarLogger("test-shadow"), tmp_path)
    runner._assess_cascade_policy = AsyncMock(side_effect=AssertionError("shadow must not adjudicate"))
    runner._run_llm_analysis = AsyncMock(return_value=generator_result(SHADOW))
    return runner


def test_shadow_owns_actual_model_and_refuses_weak_configuration():
    config = configuration()
    assert config.uses_intent_router
    assert {config.model, config.model_fallback, config.codex_model} == {"gpt-6.1-sol"}
    for overrides in ({"llm_failure_policy": "warn"}, {"llm_provider": "openai"},
                      {"model": "gpt-6-luna"}, {"codex_only": True},
                      {"intent_model_pin": "jev-latest"}, {"typesafe_api_key": ""},
                      {"sentinelayer_managed_llm": True}):
        with pytest.raises(ValidationError):
            configuration(**overrides)


@pytest.mark.parametrize("label", ["low", "review", "defect"])
async def test_proposed_route_never_changes_fixed_actual_review(shadow, monkeypatch, label, tmp_path):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage(label)))
    result = await run_review(shadow, run_dir=tmp_path / "evidence")
    shadow._assess_cascade_policy.assert_not_awaited()
    shadow._run_llm_analysis.assert_awaited_once()
    assert shadow._run_llm_analysis.call_args.kwargs["review_route"] == SHADOW
    assert result.success
    routing = result.usage["review_routing"]
    assert routing["routes"][0]["model"] == "gpt-6.1-sol"
    assert routing["routes"][0]["attempted"] is True
    assert routing["proposed_route"]["tier"] == {"low": "low", "review": "mid", "defect": "deep"}[label]
    assert result.usage["policy_assessment"] == {
        "complete": False, "status": "not_run", "reason_code": "shadow_router_only", "required_for_gate": False}
    artifact = json.loads((tmp_path / "evidence" / "REVIEW_ROUTING.json").read_text())
    assert artifact["routing"]["mode"] == "intent-shadow-v1"
    assert [r["stage"] for r in result.usage["cost_ledger"]["calls"]] == ["triage", "generator-shadow"]
    rendered = _review_chain_section({}, routing, "openai", "gpt-6.1-sol")
    assert "### Review chain" in rendered and "Proposed route (not executed)" in rendered
    assert "shadow; advice does not select" in rendered


@pytest.mark.parametrize("fault,reason", [
    ("missing", "typesafe_answers_invalid"), ("nan", "typesafe_response_invalid"),
    ("wrong-model", "typesafe_model_mismatch"), ("429", "typesafe_http_429"),
    ("timeout", "typesafe_timeout"), ("duplicate", "typesafe_response_invalid"),
])
async def test_invalid_intent_transport_preserves_sol_review_and_unknown_evidence(shadow, monkeypatch, fault, reason):
    original_client = httpx.AsyncClient
    calls = []
    def handler(request):
        calls.append(json.loads(request.content))
        if fault == "timeout":
            raise httpx.ReadTimeout("private transport detail", request=request)
        if fault == "429":
            return httpx.Response(429, text="private provider detail")
        if fault == "duplicate":
            return httpx.Response(200, content=b'{"model":"x","model":"y"}')
        if fault == "nan":
            return httpx.Response(200, content=b'{"unsafe":NaN}')
        answers = {name: a.as_dict() if isinstance(a, ChoiceAnswer) else {"type": "noul", "noul": a}
                   for name, a in triage().answers.items()}
        if fault == "missing":
            answers.pop("risk")
        return httpx.Response(200, json={"model": "wrong-1.0.0" if fault == "wrong-model" else calls[-1]["model"],
                                        "answers": answers, "usage": {"input_tokens": 42, "output_tokens": 9}})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs))
    result = await run_review(shadow)
    assert len(calls) == 1 and result.success
    assert shadow._run_llm_analysis.call_args.kwargs["review_route"] == SHADOW
    routing = result.usage["review_routing"]
    assert routing["triage_status"] == "unavailable_fixed_reviewer"
    assert routing["triage_failure_reason"] == reason
    assert routing["proposed_route"] is None and routing["answers"] == {}
    assert all(x["status"] == "unassessed" for x in result.usage["excellence"]["domains"])
    cost = result.usage["cost_ledger"]
    assert len(cost["calls"]) == 2
    if fault == "missing":
        assert cost["calls"][0]["input_tokens"] == 42
    else:
        assert cost["estimated_total_usd"] is None
    assert "private provider detail" not in json.dumps(result.usage)
    assert "private transport detail" not in json.dumps(result.usage)


@pytest.mark.parametrize("kind", ["provider-failure", "wrong-model", "missing-model"])
async def test_jev_cannot_green_a_missing_or_failed_real_reviewer(shadow, monkeypatch, kind):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage()))
    result = generator_result(SHADOW)
    if kind == "provider-failure":
        result.success = False
        result.output_valid = False
        result.failure_class = "provider_failure"
    else:
        result.usage["model"] = "gpt-6-luna" if kind == "wrong-model" else ""
    shadow._run_llm_analysis.return_value = result
    output = await run_review(shadow)
    assert not output.success
    assert len(output.usage["review_routing"]["routes"]) == 1
    assert output.failure_class == ("provider_failure" if kind == "provider-failure" else "cascade_model_mismatch")


async def test_shadow_keeps_generator_high_severity_finding(shadow, monkeypatch):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage()))
    finding = {"severity": "P1", "file_path": "x.py", "line_start": 1, "message": "source defect", "category": "auth", "source": "llm"}
    shadow._run_llm_analysis.return_value = generator_result(SHADOW, [finding])
    result = await run_review(shadow)
    assert result.findings[0]["severity"] == "P1"
    assert result.findings[0]["review_model"] == "gpt-6.1-sol"
    guarded = shadow._apply_llm_guardrails(llm_findings=result.findings, non_llm_findings=[],
                                          ingest={"files": [{"path": "x.py"}]})
    assert [f["severity"] for f in guarded] == ["P1"]


async def test_incomplete_source_prevents_both_providers(shadow, monkeypatch):
    (shadow.repo_root / "x.py").unlink()
    rate = AsyncMock(side_effect=AssertionError("no source must not leave runner"))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    result = await run_review(shadow)
    assert not result.success and not result.attempted
    rate.assert_not_awaited()
    shadow._run_llm_analysis.assert_not_awaited()
    assert result.usage["review_routing"]["proposed_route"] is None


async def test_source_change_during_intent_cannot_fall_back_to_generator(shadow, monkeypatch):
    async def mutate(**kwargs):
        (shadow.repo_root / "x.py").write_text("value = 2\n")
        return triage()
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(side_effect=mutate))
    result = await run_review(shadow)
    assert not result.success
    shadow._run_llm_analysis.assert_not_awaited()


async def test_full_source_shadow_preserves_partition_coverage_and_no_policy_success(request):
    runner = request.getfixturevalue("full")
    runner.config = configuration(typesafe_max_candidates=1)
    runner._assess_cascade_policy = AsyncMock(side_effect=AssertionError("must not run policy"))
    result = await run_full(runner)
    assert result.success
    assert len(result.usage["source_scope"]["reviewed_partition_ids"]) == 2
    assert result.usage["policy_assessment"]["complete"] is False
    assert result.usage["policy_assessment"]["status"] == "not_run"
    assert all(call.kwargs["review_route"] == SHADOW for call in runner._run_llm_analysis.call_args_list)
    runner._assess_cascade_policy.assert_not_awaited()


async def test_shadow_uses_real_openai_adapter_with_fixed_identity_and_effort(shadow, monkeypatch):
    from types import SimpleNamespace
    from omargate.analyze.llm.providers.openai_provider import OpenAIProvider
    usage = SimpleNamespace(model_dump=lambda: {"input_tokens": 20, "output_tokens": 8},
                            input_tokens=20, output_tokens=8)
    create = AsyncMock(return_value=SimpleNamespace(
        model="gpt-6.1-sol", output_text='{"no_findings":true}', usage=usage))
    monkeypatch.setattr(OpenAIProvider, "client", property(lambda self: SimpleNamespace(
        responses=SimpleNamespace(create=create))))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage()))
    shadow._run_llm_analysis = AnalysisOrchestrator._run_llm_analysis.__get__(shadow)
    result = await run_review(shadow)
    assert result.success and result.output_valid
    create.assert_awaited_once()
    assert create.call_args.kwargs["model"] == "gpt-6.1-sol"
    assert create.call_args.kwargs["reasoning"] == {"effort": "xhigh"}
    assert result.usage["review_routing"]["routes"][0]["reported_model"] == "gpt-6.1-sol"


async def test_credential_source_never_reaches_intent_or_generator(shadow, monkeypatch):
    source = 'api_key = "' + 'sk' + '-' + 'A' * 32 + '"\n'
    (shadow.repo_root / "x.py").write_text(source)
    rate = AsyncMock(side_effect=AssertionError("private source must stay local"))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    result = await shadow._run_cascade_analysis(
        ingest={"files": [{"path": "x.py"}]}, changed_files=["x.py"], scan_mode="pr-diff",
        deterministic_findings=[], quick_learn=None, spec_context=None, run_dir=None,
        diff_content="diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+" + source)
    assert not result.success and not result.attempted
    rate.assert_not_awaited()
    shadow._run_llm_analysis.assert_not_awaited()
    assert not result.usage["cost_ledger"]["calls"]


@pytest.mark.parametrize("case", ["clean", "p1", "provider-failure", "unknown-model", "snapshot-model"])
async def test_shadow_top_level_gate_and_report_contract(shadow, monkeypatch, tmp_path, case):
    """Exercise the public analysis entry, real SDK adapter/parser, artifact gate and renderer."""
    from types import SimpleNamespace
    from omargate.analyze.llm.providers.openai_provider import OpenAIProvider
    from omargate.comment import render_pr_comment
    from omargate.gate import evaluate_gate
    from omargate.main import _build_llm_evidence
    from omargate.models import GateConfig, GateStatus
    from omargate.packaging import write_findings_jsonl, write_pack_summary

    quick = SimpleNamespace(source_doc=None, tech_stack=[], architecture="fixture", description="fixture",
                            project_name="fixture", entry_points=[], raw_excerpt="")
    ingest = {"files": [{"path": "x.py", "lines": 1, "category": "source"}],
              "stats": {"total_files": 1, "in_scope_files": 1, "source_loc_total": 1}, "hotspots": {}}
    monkeypatch.setattr("omargate.analyze.orchestrator.extract_quick_learn_summary", lambda _: quick)
    monkeypatch.setattr("omargate.analyze.orchestrator.run_ingest", lambda *a, **kw: ingest)
    finding = {"severity": "P1", "file_path": "x.py", "line_start": 1,
               "line_end": 1, "message": "Source defect", "category": "auth",
               "recommendation": "Reject the unsafe operation.", "confidence": .99}
    monkeypatch.setattr(shadow, "_run_deterministic_scans", lambda _: [])
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage("low")))
    usage = SimpleNamespace(input_tokens=20, output_tokens=8,
                            model_dump=lambda: {"input_tokens": 20, "output_tokens": 8})
    model = {"unknown-model": "unknown", "snapshot-model": "gpt-6.1-sol-2026-10-01"}.get(case, "gpt-6.1-sol")
    output = json.dumps([finding]) if case == "p1" else '{"no_findings":true}'
    create = AsyncMock(return_value=SimpleNamespace(model=model, output_text=output, usage=usage))
    if case == "provider-failure":
        create.side_effect = RuntimeError("synthetic provider failure")
    monkeypatch.setattr(OpenAIProvider, "client", property(lambda self: SimpleNamespace(
        responses=SimpleNamespace(create=create))))
    # The real gate requires positive observed latency; deterministic SDK mocks
    # otherwise finish in zero milliseconds. Advance only the client's clock.
    from itertools import count
    clock = count(1, .125)
    monkeypatch.setattr("omargate.analyze.llm.llm_client.time", SimpleNamespace(time=lambda: next(clock)))
    shadow._run_llm_analysis = AnalysisOrchestrator._run_llm_analysis.__get__(shadow)
    run_dir = tmp_path / "gate"
    run_dir.mkdir()
    analysis = await shadow.run(scan_mode="pr-diff", changed_files=["x.py"], run_dir=run_dir,
        diff_content="diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+value = 1\n")
    llm_evidence = _build_llm_evidence(analysis, shadow.config)
    assert llm_evidence["fallback_used"] is False
    findings_path = run_dir / "FINDINGS.jsonl"
    write_findings_jsonl(findings_path, analysis.findings)
    write_pack_summary(run_dir, "shadow-contract", True, findings_path,
        {key: analysis.counts[key] for key in ("P0", "P1", "P2", "P3", "P4")},
        {"action": "fixture"}, ["deterministic", "llm"], llm_usage=analysis.llm_usage,
        llm_evidence=llm_evidence)
    gate = evaluate_gate(run_dir, GateConfig(severity_gate="P1", require_llm_success=True))
    if case in {"clean", "snapshot-model"}:
        assert gate.status == GateStatus.PASSED and not gate.block_merge
    else:
        assert gate.block_merge and gate.status != GateStatus.PASSED
    if case == "p1":
        assert gate.status == GateStatus.BLOCKED and gate.counts.p1 == 1
        assert analysis.findings[0]["severity"] == "P1"  # no deterministic corroboration needed
    if case in {"provider-failure", "unknown-model"}:
        assert not llm_evidence["success"]
    routing = analysis.llm_usage["review_routing"]
    assert routing["mode"] == "intent-shadow-v1"
    assert analysis.llm_usage["policy_assessment"]["status"] == "not_run"
    shadow._assess_cascade_policy.assert_not_awaited()
    comment = render_pr_comment(gate, "shadow-contract", "acme/demo", 42, None, None, .21, "fixture",
        findings=analysis.findings, scan_mode="pr-diff", llm_engine="openai", llm_model=model,
        actual_cost_usd=.21, llm_evidence=llm_evidence, review_routing=routing, codebase_snapshot=ingest)
    for required in ("<!-- sentinelayer:omar-gate:v1:acme/demo:42 -->", "## 🛡️ Omar Gate:",
                     "**Gate:**", "**Policy:**", "**Duration:**", "**LLM:** `openai`",
                     "Cost (usage)", "### Review chain", "| Severity | Count | Blocks Merge? |",
                     "P0 (Critical)", "P1 (High)", "P2 (Medium)", "P3 (Low)", "P4 (Informational)",
                     "Codebase Snapshot (Deterministic)", "Intent security policy: **not run**"):
        assert required in comment
    if case == "p1":
        for required in ("Top Findings", "Fix:", "Apply Fix:", "Coming soon."):
            assert required in comment
        assert "without a corroboration downgrade" in comment
        assert "automatically downgraded to P2" not in comment
    if case in {"provider-failure", "unknown-model"}:
        assert "✅ PASSED" not in comment
