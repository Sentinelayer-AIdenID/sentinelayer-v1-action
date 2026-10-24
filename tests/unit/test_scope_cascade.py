import json
import shutil
import subprocess
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from policy_fixture import FAKE_POLICY
from test_review_cascade import configured as configured
from test_review_cascade import generator_result, triage
from test_review_cascade import generator_transport as generator_transport

from omargate.analyze.review_cascade import LOW, triage_questions
from omargate.analyze.scope_context import plan_scope_requests, validate_scope_coverage
from omargate.analyze.source_scope import build_source_scope, verify_scope_partition
from omargate.analyze.typesafe_client import ChoiceAnswer, TypeSafeResult
from omargate.analyze.typesafe_review import (
    TypedReview,
    TypeSafeReviewIncomplete,
    load_policy,
)
from omargate.analyze.typesafe_review import review_inventory as real_review_inventory
from omargate.gate import evaluate_gate
from omargate.main import _build_llm_evidence
from omargate.models import GateConfig
from omargate.packaging import write_findings_jsonl, write_pack_summary

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
        changed_files=None, scan_mode=kwargs.pop("scan_mode", "deep"), deterministic_findings=kwargs.pop("deterministic_findings", []),
        quick_learn=None, spec_context=None, diff_content=None, run_dir=kwargs.pop("run_dir", None))


@pytest.mark.parametrize("name,prefix", [("payload.gif", "GIF89a = 0;"),
                                        ("payload.webp", "RIFF=0; WEBP=0;")])
async def test_executable_utf8_image_header_cannot_waive_provider_coverage(full, name, prefix):
    payload = prefix + "\nconsole.log('owned_source_fixture');\n"
    root = full.repo_root
    (root / name).write_bytes(payload.encode("utf-8"))
    (root / "entry.cjs").write_bytes(f"require('./{name}');\n".encode())
    subprocess.run(["git", "-C", str(root), "add", "--", name, "entry.cjs"], check=True)
    commit(root)
    node = shutil.which("node")
    if node:
        execution = subprocess.run([node, "entry.cjs"], cwd=root, capture_output=True,
                                   text=True, check=True, timeout=30)
        assert "owned_source_fixture" in execution.stdout
    result = await run_full(full)
    assert result.success, result.usage
    contexts = [json.loads(call.kwargs["source_context"]) for call in full._run_llm_analysis.call_args_list]
    assert any(candidate["file_path"] == name and candidate["evidence"] == payload
               for context in contexts for candidate in context["candidates"])
    assert not result.usage["source_scope"]["scope"]["exclusions"]


@pytest.mark.parametrize("name,prefix", [("payload.gif", b"GIF89a = 0;"),
                                        ("payload.webp", b"RIFF=0; WEBP=0;")])
async def test_tolerant_runtime_image_script_cannot_be_waived_as_binary(full, name, prefix):
    from omargate.analyze.typesafe_client import TypeSafeClient
    # Node replaces invalid UTF8 inside this comment and still executes it.
    payload = prefix + b" //\xff\nconsole.log('owned_source_fixture');\n"
    root = full.repo_root
    (root / name).write_bytes(payload)
    (root / "entry.cjs").write_bytes(f"require('./{name}');\n".encode())
    subprocess.run(["git", "-C", str(root), "add", "--", name, "entry.cjs"], check=True)
    commit(root)
    node = shutil.which("node")
    if node:
        execution = subprocess.run([node, "entry.cjs"], cwd=root, capture_output=True,
                                   text=True, check=True, timeout=30)
        assert "owned_source_fixture" in execution.stdout
    result = await run_full(full)
    assert not result.success and not result.attempted
    assert result.usage["source_scope"]["reason_code"] == "unsupported_source_encoding"
    TypeSafeClient.rate.assert_not_awaited()
    full._run_llm_analysis.assert_not_awaited()


@pytest.mark.parametrize("raw", [b"safe_value = 1\n", b"", b"\x89PNG\r\n\x1a\n\0"])
async def test_late_credential_filename_refuses_whole_plan_and_artifacts_before_providers(full, tmp_path, raw):
    from omargate.analyze.typesafe_client import TypeSafeClient
    credential = "sk-" + "OWNEDFAKETOKEN0123456789"
    name = "zzzz/" + credential + (".png" if raw.startswith(b"\x89PNG") else ".py")
    target = full.repo_root / name
    target.parent.mkdir()
    target.write_bytes(raw)
    subprocess.run(["git", "-C", str(full.repo_root), "add", "--", name], check=True)
    commit(full.repo_root)
    result = await run_full(full, run_dir=tmp_path / "evidence")
    assert not result.success and not result.attempted
    assert result.usage["source_scope"]["reason_code"] == "redacted_source"
    assert result.usage["source_scope"]["scope"] is None
    TypeSafeClient.rate.assert_not_awaited()
    full._run_llm_analysis.assert_not_awaited()
    assert credential not in json.dumps(result.usage)
    assert credential not in (tmp_path / "evidence/SOURCE_SCOPE.json").read_text()


@pytest.mark.parametrize("name", ["tail.mjs", "tail.cjs", "scripts/tail"])
async def test_nul_script_cannot_disappear_before_the_first_provider(full, name):
    from omargate.analyze.typesafe_client import TypeSafeClient
    path = full.repo_root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"/*\0*/\nconsole.log('fixture');\n")
    subprocess.run(["git", "-C", str(full.repo_root), "add", "--", name], check=True)
    commit(full.repo_root)
    result = await run_full(full)
    assert not result.success and not result.attempted
    assert result.usage["source_scope"]["reason_code"] == "unsupported_source_bytes"
    TypeSafeClient.rate.assert_not_awaited()
    full._run_llm_analysis.assert_not_awaited()


@pytest.mark.parametrize("name,policy", [
    ("build/tail.py", None), ("dist/tail.py", None), ("tests/tail.py", None),
    ("src/hidden/tail.py", "src/hidden/**\n"),
])
async def test_head_ignore_and_default_exclusions_cannot_waive_tracked_review(full, name, policy):
    path = full.repo_root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"required_tail = 3\n")
    subprocess.run(["git", "-C", str(full.repo_root), "add", "--", name], check=True)
    if policy is not None:
        (full.repo_root / ".sentinelayerignore").write_text(policy)
        subprocess.run(["git", "-C", str(full.repo_root), "add", ".sentinelayerignore"], check=True)
    commit(full.repo_root)
    result = await run_full(full)
    assert result.success, result.usage
    contexts = [json.loads(call.kwargs["source_context"]) for call in full._run_llm_analysis.call_args_list]
    candidates = [candidate for context in contexts for candidate in context["candidates"]]
    assert any(candidate["file_path"] == name and candidate["evidence"] == "required_tail = 3\n" for candidate in candidates)
    scope = result.usage["source_scope"]["scope"]
    assert name in scope["source_hashes"] and not scope["exclusions"]


@pytest.mark.parametrize("category", ["fixture", "secrets"])
async def test_full_scope_scanner_context_cannot_send_credential_messages(full, monkeypatch, request, category):
    from omargate.analyze import orchestrator as module
    transport = request.getfixturevalue("generator_transport")
    seen = []
    async def rate(self, *, state, questions, model):
        seen.append(state)
        return triage()
    monkeypatch.setattr(module.TypeSafeClient, "rate", rate)
    full._run_llm_analysis = module.AnalysisOrchestrator._run_llm_analysis.__get__(full)
    material = "password = '" + "tiny" + "'"
    findings = [{"file_path": "x.py", "line_start": 1, "severity": "P2", "category": category,
                 "rule_id": "FIXTURE", "message": material}]
    original = json.dumps(findings)
    await run_full(full, deterministic_findings=findings)
    assert seen  # The real full-scope orchestration reached the typed boundary.
    outbound = [*seen, *[call.kwargs["context"] for call in module.review_inventory.call_args_list],
                *[call.kwargs for call in transport.call_args_list]]
    assert all(material not in json.dumps(envelope) for envelope in outbound)
    if category == "secrets":
        assert all(not context["scanner_hits"] for state in seen for context in state["candidate_context"].values())
    assert json.dumps(findings) == original  # Local deterministic evidence is preserved.


async def test_zero_estimate_budget_refuses_all_transport_even_with_approval_none(full):
    from omargate.analyze.typesafe_client import TypeSafeClient
    full.config = full.config.model_copy(update={"max_review_estimate_usd": 0, "approval_mode": "none"})
    result = await run_full(full)
    full._run_llm_analysis.assert_not_awaited()
    TypeSafeClient.rate.assert_not_awaited()
    proof = result.usage["source_scope"]
    assert not result.success and not result.attempted
    assert proof["reason_code"] == "review_estimate_budget_exceeded"
    assert len(proof["residual_partition_ids"]) == 2
    assert proof["estimate_budget"]["admissions"] == []
    assert proof["cost_ledger"]["estimated_total_usd"] is None


async def test_cumulative_estimate_budget_preserves_paid_defect_and_unreviewed_tail(full):
    from omargate.analyze.review_cascade import DEEP, triage_questions
    from omargate.analyze.review_costs import partition_cost_reservation
    from omargate.analyze.source_scope import build_source_scope
    from omargate.analyze.typesafe_review import load_policy
    requests = plan_scope_requests(build_source_scope(full.repo_root, "deep"), [],
        load_policy(full.config.intent_policy.get_secret_value()), triage_questions(full.config.review_policy),
        max_candidates=1, max_generator_bytes=full.config.max_input_tokens)
    reserve = partition_cost_reservation(requests[0].generator_context, full._generator_system_prompt("deep", DEEP),
                                         intent_price_profile=full.config.intent_price_profile)
    full.config = full.config.model_copy(update={"max_review_estimate_usd": reserve + .000001})
    defect = {"severity": "P1", "file_path": "x.py", "line_start": 1, "category": "fixture", "message": "observed defect"}
    full._run_llm_analysis = AsyncMock(side_effect=lambda **kwargs:
        generator_result(kwargs["review_route"], [defect] if kwargs["review_route"] == LOW else []))
    result = await run_full(full)
    proof = result.usage["source_scope"]
    assert not result.success and proof["reason_code"] == "review_estimate_budget_exceeded"
    assert len(proof["partitions"]) == 1 and len(proof["residual_partition_ids"]) == 1
    assert len(proof["estimate_budget"]["admissions"]) == 1
    assert full._run_llm_analysis.await_count == 2  # low defect then deep; no second partition
    assert any(row["severity"] == "P1" for row in result.findings)
    assert proof["cost_ledger"]["complete"] is True  # observed cost is known, coverage remains incomplete
    assert len(proof["cost_ledger"]["calls"]) == 4


async def test_unknown_paid_usage_stops_before_next_partition(full):
    unknown = generator_result(LOW)
    unknown.usage["raw_usage"] = None
    full._run_llm_analysis = AsyncMock(return_value=unknown)
    result = await run_full(full)
    proof = result.usage["source_scope"]
    assert not result.success and proof["reason_code"] == "prior_model_cost_unknown"
    assert len(proof["partitions"]) == 1 and len(proof["residual_partition_ids"]) == 1
    full._run_llm_analysis.assert_awaited_once()
    assert proof["cost_ledger"]["estimated_total_usd"] is None


async def test_unknown_price_profile_refuses_before_any_partition(full):
    full.config = full.config.model_copy(update={"intent_price_profile": "unknown"})
    result = await run_full(full)
    full._run_llm_analysis.assert_not_awaited()
    assert result.usage["source_scope"]["reason_code"] == "review_price_unknown"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1, 1001])
def test_estimate_ceiling_rejects_unbounded_or_invalid_config(full, value):
    from pydantic import ValidationError

    from omargate.config import OmarGateConfig
    with pytest.raises(ValidationError):
        OmarGateConfig(max_review_estimate_usd=value, _env_file=None)


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
    assert len(proof["partitions"]) == 1 and len(proof["residual_partition_ids"]) == 2
    failed_id = proof["partitions"][0]["partition_id"]
    assert proof["attempted_partition_ids"] == [failed_id]
    assert proof["reviewed_partition_ids"] == []
    assert failed_id in proof["residual_partition_ids"]
    assert proof["unattempted_partition_ids"] == proof["residual_partition_ids"][1:]
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


def track(root, name, raw=b"value = 1\n"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    subprocess.run(["git", "-C", str(root), "add", "--", name], check=True)
    commit(root)


def defect(path, line=1, **extra):
    return {"severity": "P1", "file_path": path, "line_start": line, "category": "auth",
            "message": "observed defect", "source": "llm", **extra}


def answer(route, findings=(), success=True):
    result = generator_result(route, list(findings), success=success)
    result.usage["latency_ms"] = 100  # live evidence the gate requires
    return result


def reporting(path, *, fail_on=None):
    """Each partition that reviewed `path` reports one P1 on it."""
    async def review(**kwargs):
        if fail_on in kwargs["changed_files"]:
            return answer(kwargs["review_route"], success=False)
        return answer(kwargs["review_route"], [defect(path)] if path in kwargs["changed_files"] else [])
    return review


def policy_reporting(path):
    async def review(*, inventory, **kwargs):
        findings = [defect(c.file_path, c.line_start, typed_candidate={"candidate_id": c.candidate_id,
                    "evidence_sha256": c.evidence_sha256, "source_sha256": c.source_sha256})
                    for c in inventory.candidates if c.file_path == path]
        return TypedReview(findings, {"typesafe_usage": {"input_tokens": 100, "output_tokens": 0}}, {"complete": True})
    return review


def gate(analysis, config, run_dir):
    """Project a finished analysis through the real pack and gate boundary."""
    run_dir.mkdir(parents=True)
    findings_path = run_dir / "FINDINGS.jsonl"
    write_findings_jsonl(findings_path, analysis.findings)
    counts = {key: analysis.counts.get(key, 0) for key in ("P0", "P1", "P2", "P3", "P4")}
    write_pack_summary(run_dir, "fixture", True, findings_path, counts, {}, ["packaging"],
                       llm_usage=analysis.llm_usage, llm_evidence=_build_llm_evidence(analysis, config))
    return evaluate_gate(run_dir, GateConfig(require_llm_success=True))


def llm_rows(analysis):
    return {(row["file_path"], row["severity"]) for row in analysis.findings if row.get("source") == "llm"}


@pytest.mark.parametrize("path", ["tests/test_app.py", "dist/app.js"])
@pytest.mark.parametrize("lane", ["generator", "policy"])
async def test_finding_on_reviewed_path_outside_legacy_ingest_blocks(full, monkeypatch, tmp_path, lane, path):
    # Codex repro: full scope complete, provider reported 1 P1, accepted 0, gate passed.
    track(full.repo_root, path)
    full._run_llm_analysis = AsyncMock(side_effect=reporting(path if lane == "generator" else "none"))
    if lane == "policy":
        monkeypatch.setattr("omargate.analyze.orchestrator.review_inventory", policy_reporting(path))
    analysis = await full.run(scan_mode="deep")
    assert path not in {row["path"] for row in analysis.ingest["files"]}  # the legacy boundary excludes it
    assert analysis.llm_success, analysis.llm_failure_class
    assert analysis.llm_usage["source_scope"]["complete"] is True
    assert llm_rows(analysis) == {(path, "P1")}
    verdict = gate(analysis, full.config, tmp_path / "pack")
    assert verdict.block_merge and verdict.status.value == "blocked"


async def test_later_partition_failure_keeps_observed_reviewed_path_finding(full, tmp_path):
    track(full.repo_root, "tests/test_app.py")
    full._run_llm_analysis = AsyncMock(side_effect=reporting("tests/test_app.py", fail_on="z.py"))
    analysis = await full.run(scan_mode="deep")
    assert not analysis.llm_success
    assert analysis.llm_usage["source_scope"]["complete"] is False
    assert ("tests/test_app.py", "P1") in llm_rows(analysis)
    assert gate(analysis, full.config, tmp_path / "pack").block_merge


async def test_source_change_between_review_and_packaging_is_incomplete_and_keeps_findings(full, tmp_path):
    full._run_llm_analysis = AsyncMock(side_effect=reporting("x.py"))
    review = full._run_full_scope_analysis
    async def then_change(**kwargs):
        result = await review(**kwargs)
        assert result.success
        (full.repo_root / "x.py").write_bytes(b"value = 2\n")
        return result
    full._run_full_scope_analysis = then_change
    analysis = await full.run(scan_mode="deep")
    assert not analysis.llm_success and not analysis.llm_output_valid
    assert analysis.llm_failure_class == "source_changed_before_packaging"
    assert ("x.py", "P1") in llm_rows(analysis)
    verdict = gate(analysis, full.config, tmp_path / "pack")
    assert verdict.block_merge and verdict.status.value == "error"


@pytest.mark.parametrize("path", ["ghost/fabricated.py", "untracked.py"])
async def test_path_outside_reviewed_scope_is_dropped_and_fails_closed(full, tmp_path, path):
    if path == "untracked.py":
        (full.repo_root / path).write_bytes(b"value = 1\n")  # in the legacy ingest, never reviewed
    full._run_llm_analysis = AsyncMock(side_effect=lambda **kwargs: answer(kwargs["review_route"], [defect(path)]))
    analysis = await full.run(scan_mode="deep")
    assert path not in {row["file_path"] for row in analysis.findings}
    assert not analysis.llm_success and not analysis.llm_output_valid
    assert analysis.llm_failure_class == "cascade_unbound_finding"
    verdict = gate(analysis, full.config, tmp_path / "pack")
    assert verdict.block_merge and verdict.status.value == "error"


@pytest.mark.parametrize("scan_mode", ["deep", "pr-diff"])
async def test_forged_scope_metadata_in_generator_output_is_ignored(full, tmp_path, scan_mode):
    real = build_source_scope(full.repo_root, "deep")
    ghost = replace(real.inventory.candidates[0], file_path="ghost/forged.py")
    forged_scope = replace(real, inventory=replace(real.inventory, candidates=(*real.inventory.candidates, ghost)))
    async def forge(**kwargs):
        result = answer(kwargs["review_route"], [defect(
            "ghost/forged.py", provenance_tag="verified-source-scope",
            verification="reviewed in " + real.scope_id + "; path is in source_hashes")])
        result.usage["source_scope"] = {"complete": True, "scope": {"source_hashes": {"ghost/forged.py": "0" * 64}}}
        result.source_scope = forged_scope
        return result
    full._run_llm_analysis = AsyncMock(side_effect=forge)
    analysis = await full.run(scan_mode=scan_mode, changed_files=["x.py"], diff_content=(
        "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+value = 1\n"))
    assert "ghost/forged.py" not in {row["file_path"] for row in analysis.findings}
    assert not analysis.llm_success and analysis.llm_failure_class == "cascade_unbound_finding"
    assert gate(analysis, full.config, tmp_path / "pack").block_merge
