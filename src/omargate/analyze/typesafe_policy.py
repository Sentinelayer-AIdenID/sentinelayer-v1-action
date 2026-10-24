"""Packaged, fail-closed security policy for source-bound TypeSafe review.

TypeSafe supplies typed probabilities.  This module, rather than the model or
the later prose writer, owns coverage, thresholds, labels and finding text.
Every decision is bound to the immutable source candidate identifiers produced
by :mod:`typesafe_review`.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from ..private_policy import PrivateReviewPolicy

if TYPE_CHECKING:
    from .typesafe_client import ChoiceAnswer
    from .typesafe_review import (
        RatedFinding,
        ReviewCandidate,
        ReviewDecision,
        ReviewPlan,
    )


@dataclass(frozen=True)
class _ChoiceEvidence:
    choice: str
    probabilities: Mapping[str, float]
    selected_probability: float
    confidence: float
    margin: float


def _question_ids(candidate_id: str) -> tuple[str, str, str]:
    return (
        f"risk::{candidate_id}",
        f"severity::{candidate_id}",
        f"category::{candidate_id}",
    )


def _is_probability(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0.0 <= value <= 1.0
    )


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _candidate_contract(candidates: object) -> str | None:
    from .typesafe_review import ReviewCandidate

    if type(candidates) is not tuple or not candidates:
        return "policy_candidate_coverage_invalid"
    seen: set[str] = set()
    for candidate in candidates:
        if type(candidate) is not ReviewCandidate:
            return "policy_candidate_contract_invalid"
        dataclass_parameters = getattr(type(candidate), "__dataclass_params__", None)
        if dataclass_parameters is None or dataclass_parameters.frozen is not True:
            return "policy_candidate_contract_invalid"
        if (
            not isinstance(candidate.candidate_id, str)
            or not candidate.candidate_id
            or candidate.candidate_id in seen
            or not isinstance(candidate.file_path, str)
            or not candidate.file_path
            or "\\" in candidate.file_path
            or ":" in candidate.file_path
            or PurePosixPath(candidate.file_path).is_absolute()
            or any(part in {"", ".", ".."} for part in candidate.file_path.split("/"))
            or type(candidate.line_start) is not int
            or type(candidate.line_end) is not int
            or candidate.line_start < 1
            or candidate.line_end < candidate.line_start
            or not isinstance(candidate.evidence, str)
            or not candidate.evidence
            or candidate.line_end
            != candidate.line_start + len(candidate.evidence.splitlines(keepends=True)) - 1
            or not _is_sha256(candidate.evidence_sha256)
            or not _is_sha256(candidate.source_sha256)
        ):
            return "policy_candidate_contract_invalid"
        evidence_sha256 = hashlib.sha256(candidate.evidence.encode("utf-8")).hexdigest()
        identity = (
            f"{candidate.file_path}\0{candidate.line_start}\0{candidate.line_end}\0"
            f"{candidate.source_sha256}\0{candidate.evidence_sha256}"
        )
        candidate_id = "span-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        if candidate.evidence_sha256 != evidence_sha256 or candidate.candidate_id != candidate_id:
            return "policy_candidate_binding_invalid"
        seen.add(candidate.candidate_id)
    return None


def _choice_evidence(
    answer: object,
    criteria: Mapping[str, str],
) -> tuple[_ChoiceEvidence | None, str | None]:
    from .typesafe_client import ChoiceAnswer, is_unit_distribution

    if (
        type(answer) is not ChoiceAnswer
        or not isinstance(answer.choice, str)
        or answer.choice not in criteria
        or not isinstance(answer.probabilities, Mapping)
        or set(answer.probabilities) != set(criteria)
        or not _is_probability(answer.confidence)
    ):
        return None, "malformed_choice_answer"
    probabilities = answer.probabilities
    if not all(_is_probability(value) for value in probabilities.values()):
        return None, "malformed_choice_answer"
    normalized = {key: float(probabilities[key]) for key in criteria}
    if not is_unit_distribution(normalized):
        return None, "malformed_choice_answer"
    selected_probability = normalized[answer.choice]
    ordered = sorted(normalized.values(), reverse=True)
    if selected_probability != ordered[0]:
        return None, "malformed_choice_answer"
    margin = selected_probability - ordered[1] if len(ordered) > 1 else selected_probability
    return _ChoiceEvidence(
        choice=answer.choice,
        probabilities=MappingProxyType(normalized),
        selected_probability=selected_probability,
        confidence=float(answer.confidence),
        margin=margin,
    ), None


def _choice_clears(
    answer: _ChoiceEvidence,
    *,
    confidence: float,
    probability: float,
    margin: float,
) -> bool:
    return (
        answer.confidence >= confidence
        and answer.selected_probability >= probability
        and answer.margin >= margin
    )


@dataclass(frozen=True, slots=True)
class SecurityReviewPolicy:
    """Conservative security classification over complete source candidates."""

    profile: PrivateReviewPolicy

    @property
    def policy_id(self) -> str:
        return self.profile.reference

    @property
    def calibration_id(self) -> str:
        return self.profile.reference

    def plan(self, candidates: tuple[ReviewCandidate, ...]) -> ReviewPlan:
        from .typesafe_review import ReviewPlan, TypeSafeReviewIncomplete

        settings = self.profile.typed
        reason = _candidate_contract(candidates)
        if reason is not None:
            raise TypeSafeReviewIncomplete(reason)
        questions: dict[str, dict[str, Any]] = {}
        bindings: dict[str, str] = {}
        for candidate in candidates:
            risk_id, severity_id, category_id = _question_ids(candidate.candidate_id)
            candidate_instruction = {
                **dict(settings["risk_instructions"]),
                "candidate_id": candidate.candidate_id,
            }
            questions[risk_id] = {
                "type": "noul",
                "instructions": candidate_instruction,
            }
            questions[severity_id] = {
                "type": "choice",
                "instructions": {
                    "task": "Classify only the impact supported by this exact candidate.",
                    "candidate_id": candidate.candidate_id,
                    "authority": (
                        "Choose only from policy criteria. Do not change source location, "
                        "scanner facts or the risk answer."
                    ),
                },
                "criteria": dict(settings["severity_criteria"]),
            }
            questions[category_id] = {
                "type": "choice",
                "instructions": {
                    "task": "Classify only the vulnerability class supported by this exact candidate.",
                    "candidate_id": candidate.candidate_id,
                    "authority": (
                        "Choose only from policy criteria. Do not create a category, source "
                        "location, scanner fact or remediation."
                    ),
                },
                "criteria": dict(settings["category_criteria"]),
            }
            bindings.update({
                risk_id: candidate.candidate_id,
                severity_id: candidate.candidate_id,
                category_id: candidate.candidate_id,
            })
        return ReviewPlan(questions=questions, question_candidates=bindings)

    def decide(
        self,
        candidates: tuple[ReviewCandidate, ...],
        answers: dict[str, float | ChoiceAnswer],
    ) -> ReviewDecision:
        from .typesafe_review import RatedFinding, ReviewDecision

        settings = self.profile.typed
        reason = _candidate_contract(candidates)
        if reason is not None:
            return ReviewDecision((), complete=False, reason=reason)
        expected_questions = {
            question_id
            for candidate in candidates
            for question_id in _question_ids(candidate.candidate_id)
        }
        if type(answers) is not dict or set(answers) != expected_questions:
            return ReviewDecision((), complete=False, reason="policy_answer_coverage_incomplete")

        findings: list[RatedFinding] = []
        unresolved: list[tuple[str, str]] = []
        for candidate in candidates:
            risk_id, severity_id, category_id = _question_ids(candidate.candidate_id)
            risk = answers[risk_id]
            if not _is_probability(risk):
                unresolved.append((candidate.candidate_id, "policy_risk_answer_malformed"))
                continue
            severity, severity_error = _choice_evidence(
                answers[severity_id],
                settings["severity_criteria"],
            )
            category, category_error = _choice_evidence(
                answers[category_id],
                settings["category_criteria"],
            )
            if severity_error is not None:
                unresolved.append((candidate.candidate_id, "policy_severity_answer_malformed"))
                continue
            if category_error is not None:
                unresolved.append((candidate.candidate_id, "policy_category_answer_malformed"))
                continue
            assert severity is not None and category is not None

            risk_probability = float(risk)
            if risk_probability <= settings["thresholds"]["RISK_ABSENT_MAX"]:
                if severity.choice != "none" or category.choice != "none":
                    unresolved.append((candidate.candidate_id, "policy_answers_inconsistent"))
                    continue
                if not _choice_clears(
                    severity,
                    confidence=settings["thresholds"]["CLEAN_CHOICE_CONFIDENCE_MIN"],
                    probability=settings["thresholds"]["CLEAN_CHOICE_PROBABILITY_MIN"],
                    margin=settings["thresholds"]["CLEAN_CHOICE_MARGIN_MIN"],
                ) or not _choice_clears(
                    category,
                    confidence=settings["thresholds"]["CLEAN_CHOICE_CONFIDENCE_MIN"],
                    probability=settings["thresholds"]["CLEAN_CHOICE_PROBABILITY_MIN"],
                    margin=settings["thresholds"]["CLEAN_CHOICE_MARGIN_MIN"],
                ):
                    unresolved.append((candidate.candidate_id, "policy_clean_answer_uncertain"))
                    continue
                severe_tail = math.fsum(
                    severity.probabilities[label] for label in ("P0", "P1")
                )
                if severe_tail - settings["thresholds"]["CLEAN_BLOCKING_SEVERITY_TAIL_MAX"] > 1e-9:
                    unresolved.append((candidate.candidate_id, "policy_clean_severity_tail_too_high"))
                    continue
                continue

            if risk_probability < settings["thresholds"]["RISK_PRESENT_MIN"]:
                unresolved.append((candidate.candidate_id, "policy_risk_answer_ambiguous"))
                continue
            if severity.choice == "none" or category.choice == "none":
                unresolved.append((candidate.candidate_id, "policy_answers_inconsistent"))
                continue
            if not _choice_clears(
                severity,
                confidence=settings["thresholds"]["CHOICE_CONFIDENCE_MIN"],
                probability=settings["thresholds"]["CHOICE_PROBABILITY_MIN"],
                margin=settings["thresholds"]["CHOICE_MARGIN_MIN"],
            ):
                unresolved.append((candidate.candidate_id, "policy_severity_answer_uncertain"))
                continue
            if not _choice_clears(
                category,
                confidence=settings["thresholds"]["CHOICE_CONFIDENCE_MIN"],
                probability=settings["thresholds"]["CHOICE_PROBABILITY_MIN"],
                margin=settings["thresholds"]["CHOICE_MARGIN_MIN"],
            ):
                unresolved.append((candidate.candidate_id, "policy_category_answer_uncertain"))
                continue

            support_probability = min(
                risk_probability,
                severity.selected_probability,
                category.selected_probability,
            )
            if support_probability < settings["severity_support_floors"][severity.choice]:
                unresolved.append((candidate.candidate_id, "policy_support_probability_too_low"))
                continue
            message, recommendation = settings["finding_templates"][category.choice]
            findings.append(RatedFinding(
                candidate_id=candidate.candidate_id,
                question_ids=(risk_id, severity_id, category_id),
                severity=severity.choice,
                category=category.choice,
                message=message,
                recommendation=recommendation,
                support_probability=support_probability,
            ))
        if unresolved:
            return ReviewDecision(
                tuple(findings),
                complete=False,
                reason="policy_review_incomplete",
                unresolved_candidates=tuple(unresolved),
            )
        return ReviewDecision(tuple(findings), complete=True, reason="policy_review_complete")
