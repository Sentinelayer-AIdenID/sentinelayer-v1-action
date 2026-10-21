import json
import subprocess
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest

from test_review_cascade import configured as configured, triage, generator_result
from omargate.analyze.review_cascade import LOW
from omargate.analyze.scope_context import plan_scope_requests, validate_scope_coverage
from omargate.analyze.source_scope import build_source_scope, verify_scope_partition
from omargate.analyze.typesafe_review import TypeSafeReviewIncomplete, load_policy
from omargate.analyze.typesafe_review import review_inventory as real_review_inventory
from omargate.analyze.typesafe_client import ChoiceAnswer, TypeSafeResult
from policy_fixture import FAKE_POLICY
from omargate.analyze.review_cascade import triage_questions

pytestmark = pytest.mark.anyio


@pytest.fixture
def full(request, monkeypatch):
    orchestrator = request.getfixturevalue("configured")
    root = orchestrator.repo_root
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "core.autocrlf", "false"], check=True)
    (root / "z.py").write_bytes(b"tail = 2\n")
    subprocess.run(["git", "-C", str(root), "add", "x.py", "z.py"], check=True)
    commit(root)
    orchestrator.config = orchestrator.config.model_copy(update={"typesafe_max_candidates": 1})
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage()))
    orchestrator._run_llm_analysis = AsyncMock(side_effect=lambda **kwargs: generator_result(kwargs["review_route"]))
    return orchestrator


def commit(root):
    subprocess.run(["git", "-C", str(root), "add", "-u"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "owned fixture"], check=True)


async def run_full(orchestrator, **kwargs):
    return await orchestrator._run_cascade_analysis(ingest={"files": [{"path": "x.py"}]},
        changed_files=None, scan_mode=kwargs.pop("scan_mode", "deep"), deterministic_findings=[],
        quick_learn=None, spec_context=None, diff_content=None, run_dir=kwargs.pop("run_dir", None))


@pytest.mark.parametrize("mode", ["deep", "nightly"])
async def test_real_full_scope_loop_reviews_tail_preserves_coordinates_and_counts_physical_calls(full, tmp_path, mode):
    result = await run_full(full, scan_mode=mode, run_dir=tmp_path / "evidence")
    assert result.success, result.usage
    assert full._run_llm_analysis.await_count == 2
    contexts = [json.loads(call.kwargs["source_context"]) for call in full._run_llm_analysis.call_args_list]
    assert [item["candidates"][0]["file_path"] for item in contexts] == ["x.py", "z.py"]
    assert contexts[-1]["candidates"][0]["line_start"] == 1
    assert contexts[-1]["candidates"][0]["evidence"] == "tail = 2\n"
    assert all(item["review_scope"]["scan_mode"] == mode for item in contexts)
    calls = result.usage["cost_ledger"]["calls"]
    assert len(calls) == 6
    assert len({call["partition_id"] for call in calls}) == 2
    assert [call["stage"] for call in calls] == ["triage", "source-policy", "generator-low"] * 2
    proof = json.loads((tmp_path / "evidence/SOURCE_SCOPE.json").read_text())
    assert proof["complete"] and proof["residual_partition_ids"] == []
    assert proof["cost_ledger"] == result.usage["cost_ledger"]


async def test_late_redaction_refuses_entire_plan_without_spending_on_earlier_partition(full):
    (full.repo_root / "z.py").write_text("password = '" + "not-" + "a-credential'\n")
    commit(full.repo_root)
    result = await run_full(full)
    full._run_llm_analysis.assert_not_awaited()
    assert not result.success
    assert result.usage["source_scope"]["reason_code"] == "redacted_source"
    assert result.usage["cost_ledger"]["calls"] == []


async def test_failed_first_partition_is_unknown_with_explicit_unreviewed_tail(full):
    full._run_llm_analysis = AsyncMock(return_value=generator_result(LOW, success=False))
    result = await run_full(full)
    proof = result.usage["source_scope"]
    assert not result.success and not proof["complete"]
    assert len(proof["partitions"]) == 1 and len(proof["residual_partition_ids"]) == 1
    assert len(result.usage["cost_ledger"]["calls"]) == 4  # triage/policy + low + deep


async def test_mutation_after_generator_keeps_paid_usage_and_blocks(full):
    async def change(**kwargs):
        (full.repo_root / "z.py").write_text("changed = True\n")
        return generator_result(kwargs["review_route"])
    full._run_llm_analysis = AsyncMock(side_effect=change)
    result = await run_full(full)
    assert not result.success and len(result.usage["cost_ledger"]["calls"]) == 3
    assert result.usage["source_scope"]["complete"] is False


@pytest.mark.parametrize("key", ["truncated", "too_large", "read_failures"])
async def test_incomplete_native_census_refuses_before_models(full, key):
    result = await full._run_cascade_analysis(ingest={"stats": {key: 1}}, scan_mode="deep", changed_files=None,
        deterministic_findings=[], quick_learn=None, spec_context=None, diff_content=None, run_dir=None)
    full._run_llm_analysis.assert_not_awaited()
    assert result.usage["source_scope"]["reason_code"] == "deterministic_inventory_incomplete"
    assert result.usage["cost_ledger"]["calls"] == []


async def test_oversize_tail_refuses_complete_plan_before_first_provider(full):
    (full.repo_root / "z.py").write_bytes(b"content = '" + b"a" * 100_000 + b"'\n")
    commit(full.repo_root)
    result = await run_full(full)
    full._run_llm_analysis.assert_not_awaited()
    assert not result.success and result.usage["cost_ledger"]["calls"] == []
    assert result.usage["source_scope"]["reason_code"].endswith("budget_exceeded")


async def test_real_source_policy_still_independently_blocks_after_clean_partition_generators(full, monkeypatch):
    monkeypatch.setattr("omargate.analyze.orchestrator.review_inventory", real_review_inventory)
    policy_calls = []
    async def rate(self, *, state, questions, model):
        if "risk" in questions:
            return triage()
        policy_calls.append(state)
        assert state["scope"] == "deep"
        answers = {}
        for name, question in questions.items():
            selected = "P1" if name.startswith("severity::") else "auth"
            answers[name] = (1.0 if question["type"] == "noul" else
                ChoiceAnswer(selected, {key: float(key == selected) for key in question["criteria"]}, 1.0))
        return TypeSafeResult(model, answers, {"input_tokens": 100, "output_tokens": 0}, 1)
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    result = await run_full(full)
    assert len(policy_calls) == 2, result.usage
    assert result.success and result.usage["policy_assessment"]["complete"]
    assert {item["file_path"] for item in result.findings} == {"x.py", "z.py"}
    assert all(item["severity"] == "P1" for item in result.findings)
    assert all(item["review_tier"] == "intent-policy" for item in result.findings)
    assert all(call.kwargs["review_route"].tier == "deep" for call in full._run_llm_analysis.call_args_list)


def test_missing_duplicate_and_forged_partition_spans_cannot_pass(full):
    scope = build_source_scope(full.repo_root, "deep")
    requests = plan_scope_requests(scope, [], load_policy(
        full.config.intent_policy.get_secret_value()), triage_questions(FAKE_POLICY), max_candidates=1)
    for bad in (requests[:-1], (*requests, requests[-1]), tuple(reversed(requests))):
        with pytest.raises(TypeSafeReviewIncomplete, match="partition_coverage"):
            validate_scope_coverage(scope, bad)
    forged = replace(requests[0].inventory.candidates[0], evidence="forged\n")
    with pytest.raises(TypeSafeReviewIncomplete, match="unbound_source_partition"):
        verify_scope_partition(full.repo_root, scope, replace(requests[0].inventory, candidates=(forged,)))
