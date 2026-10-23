"""Source-bound typed review. Policy is supplied separately from transport.

The provider never invents a file, line, quote or explanation. A policy maps typed
answers to templated findings over this exact inventory. Incomplete inventory,
missing policy and uncertain decisions are explicit generator-fallback reasons.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from ..intent_identity import intent_model_reference, redact_intent_pin
from ..redaction import redact_secret_source, sanitize_public_error
from .typesafe_client import (
    ChoiceAnswer,
    TypeSafeClient,
    TypeSafeError,
    validate_answers,
)

MAX_FILE_BYTES = 1_000_000
MAX_STATE_BYTES = 24_000
LINES_PER_CANDIDATE = 40


class TypeSafeReviewIncomplete(ValueError):
    """A bounded reason, safe to retain without source or credential bodies."""


def verify_source_path_privacy(relative: str) -> None:
    # Coordinates are source too. Refuse instead of rewriting a path and
    # breaking its binding to the committed file/line evidence.
    if redact_secret_source(relative, code_context=False)[1]:
        raise TypeSafeReviewIncomplete("redacted_source")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class ReviewCandidate:
    candidate_id: str
    file_path: str
    line_start: int
    line_end: int
    evidence: str
    evidence_sha256: str
    source_sha256: str

    def state(self) -> dict[str, Any]:
        verify_source_path_privacy(self.file_path)
        # Source privacy is credential-only. Public-error identifier scrubbing
        # must not alter ordinary source or its coverage/verification decision.
        source_safe, source_redacted = redact_secret_source(
            self.evidence, file_path=self.file_path
        )
        safe = source_safe
        return {
            "candidate_id": self.candidate_id,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "evidence": safe,
            "evidence_redacted": source_redacted,
            "evidence_sha256": self.evidence_sha256,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class ReviewInventory:
    candidates: tuple[ReviewCandidate, ...]
    source_hashes: tuple[tuple[str, str], ...]
    scan_mode: str
    policy_excluded: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ReviewPlan:
    questions: dict[str, dict[str, Any]]
    question_candidates: dict[str, str]


@dataclass(frozen=True)
class RatedFinding:
    candidate_id: str
    question_ids: tuple[str, ...]
    severity: str
    category: str
    message: str
    recommendation: str
    support_probability: float


@dataclass(frozen=True)
class ReviewDecision:
    findings: tuple[RatedFinding, ...]
    complete: bool
    reason: str = ""
    unresolved_candidates: tuple[tuple[str, str], ...] = ()


class ReviewPolicy(Protocol):
    """Owned security catalogue/calibration; transport does not define policy."""

    @property
    def policy_id(self) -> str: ...

    @property
    def calibration_id(self) -> str: ...

    def plan(self, candidates: tuple[ReviewCandidate, ...]) -> ReviewPlan: ...

    def decide(
        self, candidates: tuple[ReviewCandidate, ...], answers: dict[str, float | ChoiceAnswer]
    ) -> ReviewDecision: ...


@dataclass(frozen=True)
class TypedReview:
    findings: list[dict[str, Any]]
    usage: dict[str, Any]
    assessment: dict[str, Any]


def _source_path(repo_root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
        raise TypeSafeReviewIncomplete("unsupported_source_path")
    logical = PurePosixPath(relative)
    if logical.is_absolute() or any(part in {".", ".."} for part in relative.split("/")):
        raise TypeSafeReviewIncomplete("unsupported_source_path")
    verify_source_path_privacy(relative)
    target = (repo_root / relative).resolve()
    if not target.is_relative_to(repo_root.resolve()) or not target.is_file():
        raise TypeSafeReviewIncomplete("source_unavailable")
    return target


def _is_lockfile(relative: str) -> bool:
    """Recognise generated lockfiles that the dependency audit covers.

    The dependency audit (dep_audit.py) audits these exact lockfiles:
    npm: package-lock.json, npm-shrinkwrap.json
    pip: Pipfile.lock, poetry.lock, uv.lock, pdm.lock
    cargo: Cargo.lock
    Also recognises pylock.* (pip lock inputs that the audit covers)."""
    name = PurePosixPath(relative).name
    return name in {
        "package-lock.json", "npm-shrinkwrap.json",
        "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock",
        "Cargo.lock",
    } or (name.startswith("pylock.") and len(name) > len("pylock."))


def build_inventory(
    *, repo_root: Path, ingest: dict, changed_files: list[str] | None,
    scan_mode: str, max_candidates: int,
) -> ReviewInventory:
    """Cover complete changed source files, without silently truncating a scope.

    Forty-line spans are bounded candidates, not claimed exact fault locations.
    Unsupported scopes and deleted/binary/oversize required files refuse review;
    they cannot silently fall back to an incomplete generator context.
    """
    if scan_mode != "pr-diff" or not changed_files:
        raise TypeSafeReviewIncomplete("source_scope_unavailable")
    if any(not isinstance(path, str) or not path for path in changed_files):
        raise TypeSafeReviewIncomplete("unsupported_source_path")
    if type(max_candidates) is not int or not 1 <= max_candidates <= 200:
        raise TypeSafeReviewIncomplete("invalid_candidate_budget")
    candidates: list[ReviewCandidate] = []
    hashes: list[tuple[str, str]] = []
    policy_excluded: list[tuple[str, str]] = []
    for relative in sorted(set(changed_files)):
        path = _source_path(repo_root, relative)
        if path.stat().st_size > MAX_FILE_BYTES:
            raise TypeSafeReviewIncomplete("source_budget_exceeded")
        raw = path.read_bytes()
        if len(raw) > MAX_FILE_BYTES or b"\0" in raw:
            raise TypeSafeReviewIncomplete("unsupported_source_bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise TypeSafeReviewIncomplete("unsupported_source_encoding") from None
        if _is_lockfile(relative):
            policy_excluded.append((relative, "policy-excluded: covered by dependency audit"))
            continue
        lines = text.splitlines(keepends=True)
        if not lines:
            raise TypeSafeReviewIncomplete("empty_source_scope")
        source_hash = _digest(raw)
        hashes.append((relative, source_hash))
        for offset in range(0, len(lines), LINES_PER_CANDIDATE):
            end = min(offset + LINES_PER_CANDIDATE, len(lines))
            evidence = "".join(lines[offset:end])
            evidence_hash = _digest(evidence.encode("utf-8"))
            identity = f"{relative}\0{offset + 1}\0{end}\0{source_hash}\0{evidence_hash}"
            candidates.append(ReviewCandidate(
                candidate_id="span-" + _digest(identity.encode("utf-8")),
                file_path=relative, line_start=offset + 1, line_end=end,
                evidence=evidence, evidence_sha256=evidence_hash,
                source_sha256=source_hash,
            ))
            if len(candidates) > max_candidates:
                raise TypeSafeReviewIncomplete("candidate_budget_exceeded")
    return ReviewInventory(tuple(candidates), tuple(hashes), scan_mode, tuple(policy_excluded))


def verify_sources(repo_root: Path, inventory: ReviewInventory) -> None:
    expected_hashes = dict(inventory.source_hashes)
    if (
        inventory.scan_mode != "pr-diff"
        or not expected_hashes
        or len(expected_hashes) != len(inventory.source_hashes)
        or {candidate.file_path for candidate in inventory.candidates} != set(expected_hashes)
    ):
        raise TypeSafeReviewIncomplete("incomplete_source_inventory")
    for relative, expected in inventory.source_hashes:
        path = _source_path(repo_root, relative)
        if path.stat().st_size > MAX_FILE_BYTES:
            raise TypeSafeReviewIncomplete("source_changed_during_review")
        raw = path.read_bytes()
        if len(raw) > MAX_FILE_BYTES or _digest(raw) != expected:
            raise TypeSafeReviewIncomplete("source_changed_during_review")
        try:
            lines = raw.decode("utf-8").splitlines(keepends=True)
        except UnicodeDecodeError:
            raise TypeSafeReviewIncomplete("unsupported_source_encoding") from None
        ordered = sorted(
            (candidate for candidate in inventory.candidates if candidate.file_path == relative),
            key=lambda candidate: candidate.line_start,
        )
        cursor = 1
        for candidate in ordered:
            if (
                type(candidate.line_start) is not int
                or type(candidate.line_end) is not int
                or candidate.line_start != cursor
                or not candidate.line_start <= candidate.line_end <= len(lines)
            ):
                raise TypeSafeReviewIncomplete("incomplete_source_span_coverage")
            evidence = "".join(lines[candidate.line_start - 1:candidate.line_end])
            evidence_hash = _digest(evidence.encode("utf-8"))
            identity = f"{relative}\0{candidate.line_start}\0{candidate.line_end}\0{expected}\0{evidence_hash}"
            if (
                candidate.evidence != evidence
                or candidate.evidence_sha256 != evidence_hash
                or candidate.source_sha256 != expected
                or candidate.candidate_id != "span-" + _digest(identity.encode("utf-8"))
            ):
                raise TypeSafeReviewIncomplete("unbound_source_evidence")
            cursor = candidate.line_end + 1
        if cursor != len(lines) + 1:
            raise TypeSafeReviewIncomplete("incomplete_source_span_coverage")


def load_policy(raw: str) -> ReviewPolicy:
    from ..private_policy import load_private_policy
    from .typesafe_policy import SecurityReviewPolicy
    return SecurityReviewPolicy(load_private_policy(raw))


async def review_inventory(
    *, repo_root: Path, inventory: ReviewInventory, policy: ReviewPolicy,
    client: TypeSafeClient, model: str,
    context: dict[str, Any] | None = None,
    source_scope=None,
) -> TypedReview:
    if not inventory.candidates or not policy.policy_id or not policy.calibration_id:
        raise TypeSafeReviewIncomplete("review_policy_or_coverage_unavailable")
    def verify():
        if source_scope is None:
            verify_sources(repo_root, inventory)
        else:
            from .source_scope import verify_scope_partition
            verify_scope_partition(repo_root, source_scope, inventory)
    verify()
    by_id = {candidate.candidate_id: candidate for candidate in inventory.candidates}
    if len(by_id) != len(inventory.candidates):
        raise TypeSafeReviewIncomplete("duplicate_source_candidate")
    plan = policy.plan(inventory.candidates)
    if (
        not plan.questions
        or set(plan.questions) != set(plan.question_candidates)
        or set(plan.question_candidates.values()) != set(by_id)
    ):
        raise TypeSafeReviewIncomplete("incomplete_question_coverage")
    state = {
        "scope": source_scope.scan_mode if source_scope is not None else inventory.scan_mode,
        "policy_id": policy.policy_id,
        "calibration_id": policy.calibration_id,
        "candidates": [candidate.state() for candidate in inventory.candidates],
        "context": context or {},
    }
    # Conservative byte budgets supplement server token limits; nothing is clipped.
    if len(json.dumps(state, ensure_ascii=False).encode("utf-8")) > MAX_STATE_BYTES:
        raise TypeSafeReviewIncomplete("typed_context_budget_exceeded")
    request_bytes = json.dumps({"state": state, "questions": plan.questions}, ensure_ascii=False).encode("utf-8")
    if len(request_bytes) > 48_000:
        raise TypeSafeReviewIncomplete("typed_question_budget_exceeded")
    response = await client.rate(state=state, questions=plan.questions, model=model)
    verify()
    try:
        validate_answers(response.answers, plan.questions)
    except TypeSafeError:
        raise TypeSafeReviewIncomplete("incomplete_typed_answers")
    decision = policy.decide(inventory.candidates, response.answers)
    if (
        not isinstance(decision, ReviewDecision)
        or type(decision.findings) is not tuple
        or type(decision.complete) is not bool
        or type(decision.unresolved_candidates) is not tuple
    ):
        raise TypeSafeReviewIncomplete("invalid_typed_decision")
    emitted: list[dict[str, Any]] = []
    finding_candidates: set[str] = set()
    for finding in decision.findings:
        candidate = by_id.get(finding.candidate_id)
        if candidate is None or not finding.question_ids or any(
            plan.question_candidates.get(question) != finding.candidate_id
            for question in finding.question_ids
        ):
            raise TypeSafeReviewIncomplete("unbound_typed_finding")
        if finding.severity not in {"P0", "P1", "P2", "P3", "P4"} or not all(
            isinstance(value, str) and value.strip()
            for value in (finding.category, finding.message, finding.recommendation)
        ):
            raise TypeSafeReviewIncomplete("invalid_typed_finding")
        if (
            isinstance(finding.support_probability, bool)
            or not isinstance(finding.support_probability, (int, float))
            or not math.isfinite(finding.support_probability)
            or not 0 <= finding.support_probability <= 1
        ):
            raise TypeSafeReviewIncomplete("invalid_finding_support_probability")
        if finding.candidate_id in finding_candidates:
            raise TypeSafeReviewIncomplete("duplicate_typed_finding_candidate")
        finding_candidates.add(finding.candidate_id)
        emitted.append({
            "id": f"typesafe-{finding.candidate_id}-{finding.category}",
            "severity": finding.severity, "category": finding.category,
            "file_path": candidate.file_path,
            "line_start": candidate.line_start, "line_end": candidate.line_end,
            "snippet": candidate.state()["evidence"],
            "message": sanitize_public_error(finding.message),
            "recommendation": sanitize_public_error(finding.recommendation),
            "fix_plan": sanitize_public_error(finding.recommendation),
            # Legacy finding field: explicitly interpreted by the policy owner,
            # never inferred as a separate Noul confidence by the transport.
            "confidence": finding.support_probability,
            "source": "llm", "model_source": intent_model_reference(response.model),
            "typed_candidate": {
                "candidate_id": candidate.candidate_id,
                "evidence_sha256": candidate.evidence_sha256,
                "source_sha256": candidate.source_sha256,
            },
            "typed_verdict": {
                "severity": finding.severity, "category": finding.category,
                "question_ids": list(finding.question_ids),
                "support_probability": finding.support_probability,
                "reason": sanitize_public_error(finding.message),
            },
        })
    unresolved: list[dict[str, str]] = []
    unresolved_ids: set[str] = set()
    for record in decision.unresolved_candidates:
        if type(record) is not tuple or len(record) != 2:
            raise TypeSafeReviewIncomplete("invalid_unresolved_candidate")
        candidate_id, reason = record
        if (
            not isinstance(candidate_id, str)
            or candidate_id not in by_id
            or candidate_id in unresolved_ids
            or candidate_id in finding_candidates
            or not isinstance(reason, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,95}", reason) is None
        ):
            raise TypeSafeReviewIncomplete("invalid_unresolved_candidate")
        unresolved_ids.add(candidate_id)
        unresolved.append({"candidate_id": candidate_id, "reason": reason})
    if decision.complete is True:
        if unresolved:
            raise TypeSafeReviewIncomplete("invalid_typed_decision")
        decision_reason = (
            decision.reason
            if isinstance(decision.reason, str)
            and re.fullmatch(r"[a-z][a-z0-9_]{0,95}", decision.reason)
            else "policy_review_complete"
        )
    else:
        if not unresolved:
            raise TypeSafeReviewIncomplete("typed_review_incomplete")
        decision_reason = (
            decision.reason
            if isinstance(decision.reason, str)
            and re.fullmatch(r"[a-z][a-z0-9_]{0,95}", decision.reason)
            else "policy_review_incomplete"
        )
    assessment = {
        "provider": "typesafe", "model": intent_model_reference(response.model),
        "policy_id": policy.policy_id, "calibration_id": policy.calibration_id,
        "source_hashes": dict(inventory.source_hashes),
        "policy_excluded": [
            {"path": path, "reason": reason}
            for path, reason in inventory.policy_excluded
        ],
        "candidates": [{
            "candidate_id": candidate.candidate_id,
            "file_path": candidate.file_path,
            "line_start": candidate.line_start,
            "line_end": candidate.line_end,
            "evidence_sha256": candidate.evidence_sha256,
            "source_sha256": candidate.source_sha256,
            "evidence_redacted": candidate.state()["evidence_redacted"],
        } for candidate in inventory.candidates],
        "question_candidates": dict(plan.question_candidates),
        "answers": {
            key: answer.as_dict() if isinstance(answer, ChoiceAnswer) else answer
            for key, answer in response.answers.items()
        },
        "decision_reason": decision_reason,
        "unresolved_candidates": unresolved,
        "complete": decision.complete,
        "context": context or {},
    }
    assessment = redact_intent_pin(assessment, model)
    return TypedReview(redact_intent_pin(emitted, model), redact_intent_pin({
        "provider": "typesafe", "model": intent_model_reference(response.model), "route": "typed-review",
        "tokens_in": None, "tokens_out": None, "cost_usd": None,
        "latency_ms": response.latency_ms, "typesafe_usage": response.usage,
        "typesafe_assessment": assessment,
    }, model), assessment)
