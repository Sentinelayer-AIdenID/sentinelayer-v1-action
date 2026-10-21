"""Preflight complete request budgets without clipping source or rubric inputs."""
from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path

from ..redaction import sanitize_public_error
from .source_scope import SourceScope
from .typesafe_review import MAX_STATE_BYTES, ReviewInventory, TypeSafeReviewIncomplete


def build_scope_context(scope: SourceScope, inventory: ReviewInventory, findings: list[dict]) -> dict:
    candidates = [candidate.state() for candidate in inventory.candidates]
    if any(candidate["evidence_redacted"] for candidate in candidates):
        raise TypeSafeReviewIncomplete("redacted_source")
    context = {}
    for candidate in inventory.candidates:
        hits = []
        for finding in findings:
            start = finding.get("line_start")
            end = finding.get("line_end") or start
            if (finding.get("file_path") == candidate.file_path and type(start) is int
                    and type(end) is int and end >= candidate.line_start and start <= candidate.line_end):
                hits.append({key: sanitize_public_error(str(finding.get(key, "")))
                             for key in ("rule_id", "severity", "category", "message")})
        context[candidate.candidate_id] = {
            "language": Path(candidate.file_path).suffix.lstrip(".") or "unknown",
            "scanner_hits": hits,
        }
    return {"scope_id": scope.scope_id, "scan_mode": scope.scan_mode,
            "source_coordinates": "original_file_and_line_numbers",
            "coverage": "this_partition_only", "cross_partition_relationships": "not_proven",
            "candidate_context": context}


def validate_scope_request_budgets(inventory: ReviewInventory, context: dict, policy, routing_questions: dict) -> str:
    candidates = [candidate.state() for candidate in inventory.candidates]
    triage = {"state": {"candidates": candidates, **context}, "questions": routing_questions}
    if len(json.dumps(triage).encode("utf-8")) > MAX_STATE_BYTES:
        raise TypeSafeReviewIncomplete("triage_budget_exceeded")
    state = {"scope": context["scan_mode"], "policy_id": policy.policy_id,
             "calibration_id": policy.calibration_id, "candidates": candidates, "context": context}
    if len(json.dumps(state, ensure_ascii=False).encode("utf-8")) > MAX_STATE_BYTES:
        raise TypeSafeReviewIncomplete("typed_context_budget_exceeded")
    plan = policy.plan(inventory.candidates)
    if len(json.dumps({"state": state, "questions": plan.questions}, ensure_ascii=False).encode("utf-8")) > 48_000:
        raise TypeSafeReviewIncomplete("typed_question_budget_exceeded")
    # Each original span and coordinate appears verbatim once. No whole-file
    # reread, synthesized paths, truncation, or renamed line offsets.
    return json.dumps({"review_scope": context, "candidates": candidates}, ensure_ascii=False)


@dataclass(frozen=True)
class ScopeRequest:
    partition_id: str
    inventory: ReviewInventory
    context: dict
    generator_context: str


def plan_scope_requests(scope: SourceScope, findings: list[dict], policy, routing_questions: dict,
                        *, max_candidates: int, max_partitions: int = 512,
                        max_generator_bytes: int = 80_000) -> tuple[ScopeRequest, ...]:
    """Plan every provider envelope before the first paid request."""
    if (type(max_candidates) is not int or not 1 <= max_candidates <= 200
            or type(max_partitions) is not int or max_partitions < 1):
        raise TypeSafeReviewIncomplete("invalid_partition_budget")
    hashes = dict(scope.inventory.source_hashes)
    def request(candidates):
        paths = sorted({candidate.file_path for candidate in candidates})
        inventory = ReviewInventory(tuple(candidates), tuple((path, hashes[path]) for path in paths), "pr-diff")
        context = build_scope_context(scope, inventory, findings)
        source = validate_scope_request_budgets(inventory, context, policy, routing_questions)
        if len(source.encode("utf-8")) > max_generator_bytes:
            raise TypeSafeReviewIncomplete("generator_partition_budget_exceeded")
        identity = scope.scope_id + "|" + "|".join(candidate.candidate_id for candidate in candidates)
        return ScopeRequest("partition-" + hashlib.sha256(identity.encode()).hexdigest(), inventory, context, source)
    planned = []
    current = []
    for candidate in scope.inventory.candidates:
        try:
            if len(current) + 1 > max_candidates:
                raise TypeSafeReviewIncomplete("partition_candidate_budget_exceeded")
            request([*current, candidate])
        except TypeSafeReviewIncomplete as exc:
            if not current or not str(exc).endswith("budget_exceeded"):
                raise
            planned.append(request(current))
            current = []
            request([candidate])  # A single oversize span refuses the complete plan.
        current.append(candidate)
        if len(planned) >= max_partitions:
            raise TypeSafeReviewIncomplete("partition_count_budget_exceeded")
    if current:
        planned.append(request(current))
    validate_scope_coverage(scope, tuple(planned))
    return tuple(planned)


def validate_scope_coverage(scope: SourceScope, requests: tuple[ScopeRequest, ...]) -> None:
    expected = tuple(scope.inventory.candidates)
    actual = tuple(candidate for request in requests for candidate in request.inventory.candidates)
    if not requests or actual != expected or len({r.partition_id for r in requests}) != len(requests):
        raise TypeSafeReviewIncomplete("incomplete_partition_coverage")
