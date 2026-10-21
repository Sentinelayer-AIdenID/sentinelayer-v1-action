from __future__ import annotations

from omargate.intent_identity import intent_model_reference

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from omargate.analyze.typesafe_client import ChoiceAnswer, TypeSafeResult
from omargate.analyze.typesafe_state import build_typed_context
from omargate.analyze.typesafe_review import (
    RatedFinding,
    ReviewDecision,
    ReviewInventory,
    ReviewPlan,
    TypeSafeReviewIncomplete,
    build_inventory,
    review_inventory,
    verify_sources,
)
from omargate.redaction import sanitize_public_error


MODEL = "model-under-test-1.13.0"


def source_inventory(
    tmp_path: Path, text: str | None = None, *, name: str = "source.py"
) -> ReviewInventory:
    text = text if text is not None else "".join(f"line {index}\n" for index in range(1, 86))
    (tmp_path / name).write_bytes(text.encode("utf-8"))
    return build_inventory(
        repo_root=tmp_path,
        ingest={"files": [{"path": name}]},
        changed_files=[name],
        scan_mode="pr-diff",
        max_candidates=50,
    )


class FixturePolicy:
    policy_id = "fixture-policy"
    calibration_id = "fixture-calibration"

    def plan(self, candidates):
        return ReviewPlan(
            questions={
                f"q{index}": {"type": "noul", "instructions": "Does the supplied candidate support this fixture claim?"}
                for index, _ in enumerate(candidates)
            },
            question_candidates={f"q{index}": candidate.candidate_id for index, candidate in enumerate(candidates)},
        )

    def decide(self, candidates, answers):
        # A test policy supplies the interpretation explicitly; no production
        # threshold, severity calibration or confidence inference is defined here.
        return ReviewDecision((self.finding(candidates),), complete=True)

    def finding(self, candidates):
        return RatedFinding(
            candidate_id=candidates[0].candidate_id,
            question_ids=("q0",),
            severity="P2",
            category="fixture",
            message="The fixture policy selected this source span.",
            recommendation="Inspect the bound fixture evidence.",
            support_probability=0.61,
        )


class FakeClient:
    def __init__(self, *, answers=None, during=None):
        self.calls = []
        self.answers = answers
        self.during = during

    async def rate(self, *, state, questions, model):
        self.calls.append({"state": state, "questions": questions, "model": model})
        if self.during:
            self.during()
        answers = self.answers if self.answers is not None else {name: 0.87 for name in questions}
        return TypeSafeResult(
            model=model,
            answers=answers,
            usage={"input_tokens": 13, "output_tokens": 0, "fixture_meter": "reported"},
            latency_ms=9,
        )


async def review(tmp_path, inventory, *, policy=None, client=None):
    return await review_inventory(
        repo_root=tmp_path,
        inventory=inventory,
        policy=policy if policy is not None else FixturePolicy(),
        client=client if client is not None else FakeClient(),
        model=MODEL,
    )


def test_inventory_covers_complete_files_in_stable_forty_line_spans(tmp_path: Path):
    inventory = source_inventory(tmp_path)
    assert [(candidate.line_start, candidate.line_end) for candidate in inventory.candidates] == [
        (1, 40), (41, 80), (81, 85)
    ]
    raw = (tmp_path / "source.py").read_bytes()
    assert "".join(candidate.evidence for candidate in inventory.candidates).encode() == raw
    assert inventory.source_hashes == (("source.py", hashlib.sha256(raw).hexdigest()),)
    for candidate in inventory.candidates:
        assert candidate.source_sha256 == hashlib.sha256(raw).hexdigest()
        assert candidate.evidence_sha256 == hashlib.sha256(candidate.evidence.encode()).hexdigest()
    repeated = build_inventory(
        repo_root=tmp_path,
        ingest={"files": [{"path": "source.py"}]},
        changed_files=["source.py", "source.py"],
        scan_mode="pr-diff",
        max_candidates=3,
    )
    assert inventory == repeated
    verify_sources(tmp_path, inventory)
    modified = source_inventory(tmp_path, raw.decode().replace("line 85", "changed 85"))
    assert {candidate.candidate_id for candidate in inventory.candidates}.isdisjoint(
        candidate.candidate_id for candidate in modified.candidates
    )


@pytest.mark.parametrize("kind", ["deleted", "binary", "invalid-utf8", "oversize", "unknown"])
def test_inventory_refuses_unreadable_or_unrepresented_source(tmp_path: Path, kind: str):
    path = tmp_path / "source.py"
    if kind == "binary":
        path.write_bytes(b"first\x00second")
    elif kind == "invalid-utf8":
        path.write_bytes(b"\xff\xfe")
    elif kind == "oversize":
        path.write_bytes(b"x" * 1_000_001)
    elif kind == "unknown":
        path.write_bytes(b"present but absent from ingest\n")
    known = [] if kind == "unknown" else [{"path": "source.py"}]
    with pytest.raises(TypeSafeReviewIncomplete):
        build_inventory(repo_root=tmp_path, ingest={"files": known}, changed_files=["source.py"],
                        scan_mode="pr-diff", max_candidates=50)


@pytest.mark.parametrize("path", ["../outside.py", "nested/../source.py", "/absolute.py", "a\\b.py", "C:outside.py"])
def test_inventory_refuses_path_escape_spellings(tmp_path: Path, path: str):
    with pytest.raises(TypeSafeReviewIncomplete):
        build_inventory(repo_root=tmp_path, ingest={"files": [{"path": path}]}, changed_files=[path],
                        scan_mode="pr-diff", max_candidates=50)


def test_inventory_refuses_symlink_outside_repository(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("outside source\n", encoding="utf-8")
    try:
        (repo / "linked.py").symlink_to(outside)
    except OSError as error:
        pytest.skip(f"OS cannot create fixture symlink: {error.winerror if hasattr(error, 'winerror') else error.errno}")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_unavailable"):
        build_inventory(repo_root=repo, ingest={"files": [{"path": "linked.py"}]}, changed_files=["linked.py"],
                        scan_mode="pr-diff", max_candidates=50)


def test_inventory_never_silently_truncates_to_candidate_budget(tmp_path: Path):
    source_inventory(tmp_path)
    with pytest.raises(TypeSafeReviewIncomplete, match="candidate_budget_exceeded"):
        build_inventory(repo_root=tmp_path, ingest={"files": [{"path": "source.py"}]}, changed_files=["source.py"],
                        scan_mode="pr-diff", max_candidates=2)


@pytest.mark.parametrize("mode,changed", [("deep", ["source.py"]), ("pr-diff", []), ("pr-diff", None)])
def test_inventory_requires_explicit_supported_source_scope(tmp_path: Path, mode, changed):
    with pytest.raises(TypeSafeReviewIncomplete, match="source_scope_unavailable"):
        build_inventory(repo_root=tmp_path, ingest={"files": [{"path": "source.py"}]}, changed_files=changed,
                        scan_mode=mode, max_candidates=50)


def test_credential_coordinates_are_refused_in_inventory_and_candidate_state(tmp_path):
    name = "sk-" + "OWNEDFAKETOKEN0123456789" + ".py"
    (tmp_path / name).write_bytes(b"safe_value = 1\n")
    with pytest.raises(TypeSafeReviewIncomplete, match="redacted_source"):
        build_inventory(repo_root=tmp_path, ingest={"files": [{"path": name}]},
                        changed_files=[name], scan_mode="pr-diff", max_candidates=50)
    candidate = source_inventory(tmp_path, "safe_value = 1\n").candidates[0]
    with pytest.raises(TypeSafeReviewIncomplete, match="redacted_source"):
        replace(candidate, file_path=name).state()


@pytest.mark.anyio
@pytest.mark.parametrize("forgery", ["quote", "line", "id", "source-hash", "evidence-hash", "gap"])
async def test_forged_inventory_refuses_before_client(tmp_path: Path, forgery: str):
    inventory = source_inventory(tmp_path)
    first = inventory.candidates[0]
    changes = {
        "quote": {"evidence": "forged source"},
        "line": {"line_start": 2},
        "id": {"candidate_id": "span-invented"},
        "source-hash": {"source_sha256": "0" * 64},
        "evidence-hash": {"evidence_sha256": "0" * 64},
    }
    candidates = (
        (inventory.candidates[0], inventory.candidates[2])
        if forgery == "gap"
        else (replace(first, **changes[forgery]), *inventory.candidates[1:])
    )
    client = FakeClient()
    with pytest.raises(TypeSafeReviewIncomplete):
        await review(tmp_path, replace(inventory, candidates=candidates), client=client)
    assert client.calls == []


@pytest.mark.anyio
async def test_source_mutated_during_client_cannot_produce_review(tmp_path: Path):
    inventory = source_inventory(tmp_path)
    client = FakeClient(during=lambda: (tmp_path / "source.py").write_text("changed during review\n", encoding="utf-8"))
    with pytest.raises(TypeSafeReviewIncomplete, match="source_changed_during_review"):
        await review(tmp_path, inventory, client=client)
    assert len(client.calls) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["uncovered-candidate", "missing-question-map", "unknown-candidate"])
async def test_policy_plan_must_bind_every_candidate_before_client(tmp_path: Path, kind: str):
    inventory = source_inventory(tmp_path)
    policy = FixturePolicy()
    plan = policy.plan(inventory.candidates)
    if kind == "uncovered-candidate":
        plan = ReviewPlan({"q0": plan.questions["q0"]}, {"q0": inventory.candidates[0].candidate_id})
    elif kind == "missing-question-map":
        plan = ReviewPlan(plan.questions, {"q0": inventory.candidates[0].candidate_id})
    else:
        plan = ReviewPlan(plan.questions, {**plan.question_candidates, "q0": "invented"})
    policy.plan = lambda candidates: plan
    client = FakeClient()
    with pytest.raises(TypeSafeReviewIncomplete, match="incomplete_question_coverage"):
        await review(tmp_path, inventory, policy=policy, client=client)
    assert client.calls == []


@pytest.mark.anyio
@pytest.mark.parametrize("answers", [{}, {"q0": True}, {"q0": float("nan")}, {"q0": 1.1}, {"q0": 0.8, "extra": 0.7}])
async def test_missing_or_invalid_answers_never_reach_policy_decision(tmp_path: Path, answers):
    inventory = source_inventory(tmp_path, "one line\n")
    policy = FixturePolicy()
    decided = []
    policy.decide = lambda candidates, result: decided.append(result)
    client = FakeClient(answers=answers)
    with pytest.raises(TypeSafeReviewIncomplete, match="incomplete_typed_answers"):
        await review(tmp_path, inventory, policy=policy, client=client)
    assert len(client.calls) == 1
    assert decided == []


@pytest.mark.anyio
async def test_uncertain_policy_is_not_a_clean_review(tmp_path: Path):
    inventory = source_inventory(tmp_path, "one line\n")
    policy = FixturePolicy()
    policy.decide = lambda candidates, answers: ReviewDecision((), complete=False, reason="fixture uncertainty")
    with pytest.raises(TypeSafeReviewIncomplete, match="typed_review_incomplete"):
        await review(tmp_path, inventory, policy=policy)


@pytest.mark.anyio
async def test_partial_policy_retains_only_bound_confirmed_findings(tmp_path: Path):
    inventory = source_inventory(
        tmp_path,
        "".join(f"line {index}\n" for index in range(1, 43)),
    )
    confirmed, unresolved = inventory.candidates
    policy = FixturePolicy()
    policy.decide = lambda candidates, answers: ReviewDecision(
        (policy.finding(candidates),),
        complete=False,
        reason="policy_review_incomplete",
        unresolved_candidates=((unresolved.candidate_id, "policy_risk_answer_ambiguous"),),
    )

    result = await review(tmp_path, inventory, policy=policy)

    finding, = result.findings
    assert finding["file_path"] == confirmed.file_path
    assert finding["line_start"] == confirmed.line_start
    assert result.assessment["complete"] is False
    assert result.assessment["decision_reason"] == "policy_review_incomplete"
    assert result.assessment["unresolved_candidates"] == [{
        "candidate_id": unresolved.candidate_id,
        "reason": "policy_risk_answer_ambiguous",
    }]


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["cross-question", "invalid-severity"])
async def test_partial_policy_still_validates_every_retained_finding(
    tmp_path: Path,
    kind: str,
):
    inventory = source_inventory(
        tmp_path,
        "".join(f"line {index}\n" for index in range(1, 43)),
    )
    policy = FixturePolicy()
    finding = policy.finding(inventory.candidates)
    if kind == "cross-question":
        finding = replace(finding, question_ids=("q1",))
        expected = "unbound_typed_finding"
    else:
        finding = replace(finding, severity="P9")
        expected = "invalid_typed_finding"
    policy.decide = lambda candidates, answers: ReviewDecision(
        (finding,),
        complete=False,
        reason="policy_review_incomplete",
        unresolved_candidates=((candidates[1].candidate_id, "policy_risk_answer_ambiguous"),),
    )

    with pytest.raises(TypeSafeReviewIncomplete, match=expected):
        await review(tmp_path, inventory, policy=policy)


@pytest.mark.anyio
async def test_partial_policy_rejects_unbounded_unresolved_reason(tmp_path: Path):
    inventory = source_inventory(tmp_path, "one line\n")
    policy = FixturePolicy()
    policy.decide = lambda candidates, answers: ReviewDecision(
        (),
        complete=False,
        reason="policy_review_incomplete",
        unresolved_candidates=((candidates[0].candidate_id, "unsafe reason with source text"),),
    )

    with pytest.raises(TypeSafeReviewIncomplete, match="invalid_unresolved_candidate"):
        await review(tmp_path, inventory, policy=policy)


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["invented-candidate", "missing-reference", "unknown-question", "other-candidate-question"])
async def test_finding_must_reference_its_own_candidate_questions(tmp_path: Path, kind: str):
    inventory = source_inventory(tmp_path)
    policy = FixturePolicy()
    finding = policy.finding(inventory.candidates)
    if kind == "invented-candidate":
        finding = replace(finding, candidate_id="invented")
    elif kind == "missing-reference":
        finding = replace(finding, question_ids=())
    else:
        finding = replace(finding, question_ids=("unknown" if kind == "unknown-question" else "q1",))
    policy.decide = lambda candidates, answers: ReviewDecision((finding,), complete=True)
    with pytest.raises(TypeSafeReviewIncomplete, match="unbound_typed_finding"):
        await review(tmp_path, inventory, policy=policy)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "changes",
    [{"severity": "P9"}, {"category": ""}, {"message": None}, {"recommendation": " "},
     {"support_probability": True}, {"support_probability": float("nan")}, {"support_probability": -0.1}],
)
async def test_policy_cannot_emit_malformed_findings(tmp_path: Path, changes):
    inventory = source_inventory(tmp_path, "one line\n")
    policy = FixturePolicy()
    finding = replace(policy.finding(inventory.candidates), **changes)
    policy.decide = lambda candidates, answers: ReviewDecision((finding,), complete=True)
    with pytest.raises(TypeSafeReviewIncomplete, match="invalid_"):
        await review(tmp_path, inventory, policy=policy)


@pytest.mark.anyio
async def test_budget_refusal_happens_before_client_without_clipping(tmp_path: Path):
    inventory = source_inventory(tmp_path, "a" * 24_001 + "\n")
    client = FakeClient()
    with pytest.raises(TypeSafeReviewIncomplete, match="typed_context_budget_exceeded"):
        await review(tmp_path, inventory, client=client)
    assert client.calls == []


@pytest.mark.anyio
async def test_question_budget_refuses_before_client(tmp_path: Path):
    inventory = source_inventory(tmp_path, "one line\n")
    policy = FixturePolicy()
    policy.plan = lambda candidates: ReviewPlan(
        {"q0": {"type": "noul", "instructions": "x" * 48_001}},
        {"q0": candidates[0].candidate_id},
    )
    client = FakeClient()
    with pytest.raises(TypeSafeReviewIncomplete, match="typed_question_budget_exceeded"):
        await review(tmp_path, inventory, policy=policy, client=client)
    assert client.calls == []


@pytest.mark.anyio
async def test_review_preserves_source_binding_and_reports_only_actual_usage(tmp_path: Path):
    secret = "".join(('sk', '-fixture-secret-123456789'))
    inventory = source_inventory(tmp_path, f'api_key = "{secret}"\nprint("ordinary source")\n')
    candidate = inventory.candidates[0]
    client = FakeClient()
    result = await review(tmp_path, inventory, client=client)
    assert len(client.calls) == 1
    sent = client.calls[0]
    assert sent["model"] == MODEL
    assert secret not in json.dumps(sent)
    sent_candidate = sent["state"]["candidates"][0]
    assert sent_candidate["evidence_redacted"] is True
    assert any(marker in sent_candidate["evidence"] for marker in (
        "[redacted]", "[redacted-secret]", "[secret-bearing source excluded]",
    ))
    assert sent_candidate["source_sha256"] == candidate.source_sha256
    assert sent_candidate["evidence_sha256"] == hashlib.sha256(candidate.evidence.encode()).hexdigest()
    assert result.assessment["source_hashes"] == {"source.py": candidate.source_sha256}
    assert result.assessment["question_candidates"] == {"q0": candidate.candidate_id}
    assert result.assessment["answers"] == {"q0": 0.87}
    finding, = result.findings
    assert (finding["file_path"], finding["line_start"], finding["line_end"]) == ("source.py", 1, 2)
    assert finding["snippet"] == sent_candidate["evidence"]
    assert finding["confidence"] == 0.61  # The fixture policy's interpretation, not the raw 0.87 Noul.
    assert finding["model_source"] == intent_model_reference(MODEL)
    assert finding["typed_candidate"] == {
        "candidate_id": candidate.candidate_id,
        "evidence_sha256": candidate.evidence_sha256,
        "source_sha256": candidate.source_sha256,
    }
    assert secret not in json.dumps(result.findings)
    assert result.usage == {
        "provider": "typesafe", "model": intent_model_reference(MODEL), "route": "typed-review",
        "tokens_in": None, "tokens_out": None, "cost_usd": None,
        "latency_ms": 9,
        "typesafe_usage": {"input_tokens": 13, "output_tokens": 0, "fixture_meter": "reported"},
        "typesafe_assessment": result.assessment,
    }


@pytest.mark.anyio
async def test_review_excludes_comment_and_private_key_material_before_client(tmp_path: Path):
    aws_secret = "AKIA" + "1234567890ABCDEF"
    private_body = "private-body-must-never-cross-the-provider-boundary"
    inventory = source_inventory(
        tmp_path,
        "# historical credential " + aws_secret + "".join(('\n-----', 'BEGIN PRIVATE KEY-----\n'))
        + private_body
        + "".join(('\n-----', 'END PRIVATE KEY-----\nordinary = 1\n')),
    )
    candidate = inventory.candidates[0]
    client = FakeClient()

    result = await review(tmp_path, inventory, client=client)

    sent = json.dumps(client.calls[0], sort_keys=True)
    retained = json.dumps(
        {"findings": result.findings, "assessment": result.assessment, "usage": result.usage},
        sort_keys=True,
    )
    assert aws_secret not in sent + retained
    assert private_body not in sent + retained
    assert "[secret-bearing source excluded]" in sent
    assert client.calls[0]["state"]["candidates"][0]["evidence_redacted"] is True
    assert result.assessment["source_hashes"] == {"source.py": candidate.source_sha256}
    assert result.assessment["candidates"][0]["evidence_sha256"] == candidate.evidence_sha256


@pytest.mark.anyio
async def test_review_excludes_entire_sensitive_source_file_before_client(tmp_path: Path):
    secret = "value-that-has-no-recognizable-secret-shape"
    inventory = source_inventory(tmp_path, f"ORDINARY_NAME={secret}\n", name=".env.production")
    client = FakeClient()

    result = await review(tmp_path, inventory, client=client)

    sent = json.dumps(client.calls[0], sort_keys=True)
    assert secret not in sent
    assert "ORDINARY_NAME" not in sent
    assert "[secret-bearing source excluded]" in sent
    assert secret not in json.dumps(result.findings, sort_keys=True)


class MixedFixturePolicy(FixturePolicy):
    def plan(self, candidates):
        questions = {}
        bindings = {}
        for index, candidate in enumerate(candidates):
            questions[f"risk{index}"] = {"type": "noul", "instructions": "Does the bound fixture claim apply?"}
            questions[f"severity{index}"] = {
                "type": "choice", "instructions": "Select the fixture severity label.",
                "criteria": {"P0": None, "P1": None, "P2": None, "P3": None, "none": None},
            }
            questions[f"category{index}"] = {
                "type": "choice", "instructions": "Select the fixture category label.",
                "criteria": {"quality": None, "security": None, "none": None},
            }
            for kind in ("risk", "severity", "category"):
                bindings[f"{kind}{index}"] = candidate.candidate_id
        return ReviewPlan(questions, bindings)

    def finding(self, candidates):
        return replace(
            super().finding(candidates),
            question_ids=("risk0", "severity0", "category0"),
            category="quality",
            message="Explicit fixture decision over the supplied source evidence.",
        )


class MixedFakeClient(FakeClient):
    @staticmethod
    def mixed_answers(questions):
        answers = {}
        for name, question in questions.items():
            if question["type"] == "noul":
                answers[name] = 0.81
            elif name.startswith("severity"):
                answers[name] = ChoiceAnswer("P2", {"P0": 0.03, "P1": 0.02, "P2": 0.85, "P3": 0.05, "none": 0.05}, 0.72)
            else:
                answers[name] = ChoiceAnswer("quality", {"quality": 0.9, "security": 0.1, "none": 0}, 0.8)
        return answers

    async def rate(self, *, state, questions, model):
        if self.answers is None:
            self.answers = self.mixed_answers(questions)
        return await super().rate(state=state, questions=questions, model=model)


def bound_fixture_context(tmp_path, inventory, *, scanner_message="Fixture scanner observation"):
    diff = (
        "diff --git a/source.py b/source.py\n"
        "--- a/source.py\n"
        "+++ b/source.py\n"
        "@@ -1,2 +1,2 @@\n"
        " before = 1\n"
        "-result = before + 1\n"
        "+result = before + 2\n"
    )
    return build_typed_context(
        repo_root=tmp_path,
        inventory=inventory,
        diff_content=diff,
        ingest={"files": [{"path": "source.py", "language": "python"}]},
        deterministic_findings=[{
            "id": "fixture-hit", "rule_id": "fixture-rule", "file_path": "source.py",
            "line_start": 2, "line_end": 2, "category": "fixture", "severity": "P3",
            "message": scanner_message,
        }],
    )


@pytest.mark.anyio
async def test_mixed_review_retains_choices_verdict_and_source_bound_context(tmp_path: Path):
    inventory = source_inventory(tmp_path, "before = 1\nresult = before + 2\n")
    candidate, = inventory.candidates
    context = bound_fixture_context(tmp_path, inventory)
    client = MixedFakeClient()
    result = await review_inventory(
        repo_root=tmp_path, inventory=inventory, policy=MixedFixturePolicy(), client=client,
        model=MODEL, context=context,
    )
    assert len(client.calls) == 1
    assert client.calls[0]["state"]["context"] == result.assessment["context"] == context
    assert context["diff_head_lines_verified"] is True
    assert context["removed_lines_verified"] is False
    details = context["candidate_context"][candidate.candidate_id]
    assert details["language"] == "python"
    hunk, = details["diff_hunks"]
    assert (hunk["file_path"], hunk["line_start"], hunk["line_end"]) == ("source.py", 1, 2)
    assert hunk["diff_hunk_sha256"] == hashlib.sha256(hunk["diff_hunk"].encode()).hexdigest()
    hit, = details["deterministic_scanner_hits"]
    assert (hit["rule_id"], hit["file_path"], hit["line_start"]) == ("fixture-rule", "source.py", 2)
    assert result.assessment["candidates"] == [{
        "candidate_id": candidate.candidate_id, "file_path": "source.py",
        "line_start": 1, "line_end": 2,
        "evidence_sha256": hashlib.sha256(candidate.evidence.encode()).hexdigest(),
        "source_sha256": hashlib.sha256((tmp_path / "source.py").read_bytes()).hexdigest(),
        "evidence_redacted": False,
    }]
    answers = result.assessment["answers"]
    assert answers["risk0"] == 0.81
    assert answers["severity0"] == client.answers["severity0"].as_dict()
    assert answers["category0"] == client.answers["category0"].as_dict()
    assert answers["severity0"]["confidence"] == 0.72
    assert answers["severity0"]["probabilities"]["P2"] == 0.85
    assert json.loads(json.dumps(result.assessment)) == result.assessment
    finding, = result.findings
    assert finding["typed_verdict"] == {
        "severity": "P2", "category": "quality",
        "question_ids": ["risk0", "severity0", "category0"],
        "support_probability": 0.61,
        "reason": "Explicit fixture decision over the supplied source evidence.",
    }
    assert finding["file_path"] == candidate.file_path


@pytest.mark.anyio
async def test_mixed_review_rejects_cross_candidate_choice_reference(tmp_path: Path):
    inventory = source_inventory(tmp_path)
    policy = MixedFixturePolicy()
    finding = replace(policy.finding(inventory.candidates), question_ids=("risk0", "severity0", "category1"))
    policy.decide = lambda candidates, answers: ReviewDecision((finding,), complete=True)
    client = MixedFakeClient()
    with pytest.raises(TypeSafeReviewIncomplete, match="unbound_typed_finding"):
        await review(tmp_path, inventory, policy=policy, client=client)
    assert len(client.calls) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["missing-choice", "invalid-distribution"])
async def test_mixed_review_invalid_choice_stops_before_policy_decide(tmp_path: Path, kind: str):
    inventory = source_inventory(tmp_path, "one line\n")
    policy = MixedFixturePolicy()
    answers = MixedFakeClient.mixed_answers(policy.plan(inventory.candidates).questions)
    if kind == "missing-choice":
        del answers["severity0"]
    else:
        answers["severity0"] = ChoiceAnswer("P2", {"P0": 0, "P1": 0, "P2": 0.7, "P3": 0, "none": 0}, 0.72)
    decisions = []
    policy.decide = lambda candidates, values: decisions.append(values) or ReviewDecision((), complete=True)
    client = MixedFakeClient(answers=answers)
    with pytest.raises(TypeSafeReviewIncomplete, match="incomplete_typed_answers"):
        await review(tmp_path, inventory, policy=policy, client=client)
    assert len(client.calls) == 1
    assert decisions == []


@pytest.mark.anyio
async def test_bound_diff_scanner_context_counts_toward_budget_without_clipping(tmp_path: Path):
    inventory = source_inventory(tmp_path, "before = 1\nresult = before + 2\n")
    context = bound_fixture_context(tmp_path, inventory, scanner_message="x" * 24_001)
    client = MixedFakeClient()
    with pytest.raises(TypeSafeReviewIncomplete, match="typed_context_budget_exceeded"):
        await review_inventory(
            repo_root=tmp_path, inventory=inventory, policy=MixedFixturePolicy(), client=client,
            model=MODEL, context=context,
        )
    assert client.calls == []


@pytest.mark.anyio
async def test_none_choice_does_not_override_uncertain_fixture_policy(tmp_path: Path):
    inventory = source_inventory(tmp_path, "one line\n")
    policy = MixedFixturePolicy()
    answers = {
        "risk0": 0.02,
        "severity0": ChoiceAnswer("none", {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "none": 1}, 1),
        "category0": ChoiceAnswer("none", {"quality": 0, "security": 0, "none": 1}, 1),
    }
    policy.decide = lambda candidates, values: ReviewDecision((), complete=False, reason="Fixture needs evidence")
    client = MixedFakeClient(answers=answers)
    with pytest.raises(TypeSafeReviewIncomplete, match="typed_review_incomplete"):
        await review(tmp_path, inventory, policy=policy, client=client)
    assert len(client.calls) == 1


@pytest.mark.anyio
async def test_policy_prose_reuses_existing_redactor_with_bound_source_and_verdict(tmp_path: Path):
    secret = "".join(('sk', '-synthetic-policy-fixture-123456789'))
    message = f"The fixture policy reason repeated {secret}."
    recommendation = f"Remove the fixture policy value {secret}."
    assert secret not in sanitize_public_error(message)
    inventory = source_inventory(tmp_path, "ordinary fixture source\n")
    candidate, = inventory.candidates
    policy = FixturePolicy()
    proposed = replace(policy.finding(inventory.candidates), message=message, recommendation=recommendation)
    policy.finding = lambda candidates: proposed

    result = await review(tmp_path, inventory, policy=policy)

    serialized = json.dumps({
        "findings": result.findings, "assessment": result.assessment, "usage": result.usage,
    })
    assert secret not in serialized
    finding, = result.findings
    assert finding["message"] == sanitize_public_error(message)
    assert finding["recommendation"] == finding["fix_plan"] == sanitize_public_error(recommendation)
    assert finding["typed_verdict"] == {
        "severity": proposed.severity, "category": proposed.category,
        "question_ids": list(proposed.question_ids),
        "support_probability": proposed.support_probability,
        "reason": sanitize_public_error(message),
    }
    assert finding["file_path"] == candidate.file_path
    assert (finding["line_start"], finding["line_end"]) == (candidate.line_start, candidate.line_end)
    assert finding["snippet"] == candidate.evidence
    assert finding["model_source"] == intent_model_reference(MODEL)
    assert result.assessment["source_hashes"] == dict(inventory.source_hashes)
