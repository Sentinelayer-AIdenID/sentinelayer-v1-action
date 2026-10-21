"""Bounded private configuration. Public code owns validation, not the rubric."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import re


class PrivatePolicyError(ValueError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy field")
        result[key] = value
    return result


def _probability(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1


def _text(value):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 8192


def _text_map(value):
    return isinstance(value, dict) and 1 <= len(value) <= 64 and all(
        isinstance(key, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,95}", key)
        and _text(item) for key, item in value.items())


@dataclass(frozen=True, repr=False)
class PrivateReviewPolicy:
    _canonical: bytes = field(repr=False)

    @property
    def reference(self):
        return "private-policy:" + hashlib.sha256(self._canonical).hexdigest()[:16]

    @property
    def routing(self):
        return json.loads(self._canonical)["routing"]

    @property
    def typed(self):
        return json.loads(self._canonical)["typed"]

    @property
    def generator_instructions(self):
        return json.loads(self._canonical)["generator_instructions"]


def load_private_policy(raw: str) -> PrivateReviewPolicy:
    """Reject missing, ambiguous and malformed input without echoing its contents."""
    try:
        if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > 65536:
            raise ValueError("policy size")
        data = json.loads(raw, object_pairs_hook=_unique)
        if not isinstance(data, dict) or set(data) != {"schema", "routing", "typed", "generator_instructions"}:
            raise ValueError("policy shape")
        if data["schema"] != "omargate.private-review-policy.v1" or not _text(data["generator_instructions"]):
            raise ValueError("policy version")
        routing, typed = data["routing"], data["typed"]
        if not isinstance(routing, dict) or set(routing) != {"domains", "questions", "critical_path_tokens", "critical_path_groups", "thresholds"}:
            raise ValueError("routing shape")
        domains = routing["domains"]
        if not isinstance(domains, dict) or not 1 <= len(domains) <= 32:
            raise ValueError("domains")
        for name, descriptor in domains.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) or not isinstance(descriptor, list) or len(descriptor) != 2:
                raise ValueError("domain shape")
            weight, criterion = descriptor
            if type(weight) is not int or not 1 <= weight <= 100 or not _text(criterion):
                raise ValueError("domain data")
        if sum(row[0] for row in domains.values()) != 100:
            raise ValueError("domain weights")
        thresholds = routing["thresholds"]
        required = {"defect_confidence_min", "defect_probability_min", "sensitive_max", "low_confidence_min", "low_probability_min", "hazard_max"}
        if not isinstance(thresholds, dict) or set(thresholds) != required or not all(_probability(value) for value in thresholds.values()):
            raise ValueError("routing thresholds")
        tokens, groups = routing["critical_path_tokens"], routing["critical_path_groups"]
        if not isinstance(tokens, list) or not 1 <= len(tokens) <= 128 or not all(isinstance(value, str) and re.fullmatch(r"[a-z0-9_.-]{1,96}", value) for value in tokens):
            raise ValueError("path tokens")
        if not isinstance(groups, list) or len(groups) > 32 or not all(isinstance(group, list) and 1 <= len(group) <= 8 and all(isinstance(value, str) and re.fullmatch(r"[a-z0-9_.-]{1,96}", value) for value in group) for group in groups):
            raise ValueError("path groups")
        questions = routing["questions"]
        from .analyze.typesafe_client import _validate_questions
        _validate_questions(questions)
        if set(questions) != {"risk", "sensitive", "structural", "spaghetti"} | {"gap_" + name for name in domains}:
            raise ValueError("routing questions")
        if questions["risk"].get("type") != "choice" or set(questions["risk"].get("criteria", {})) != {"low", "review", "defect"}:
            raise ValueError("risk choices")
        if any(value.get("type") != "noul" for name, value in questions.items() if name != "risk"):
            raise ValueError("hazard question type")
        required_typed = {"policy_id", "calibration_id", "thresholds", "severity_support_floors", "severity_criteria", "category_criteria", "finding_templates", "risk_instructions"}
        if not isinstance(typed, dict) or set(typed) != required_typed:
            raise ValueError("typed shape")
        if not _text(typed["policy_id"]) or not _text(typed["calibration_id"]):
            raise ValueError("typed identity")
        required_thresholds = {"RISK_PRESENT_MIN", "RISK_ABSENT_MAX", "CHOICE_CONFIDENCE_MIN", "CHOICE_PROBABILITY_MIN", "CHOICE_MARGIN_MIN", "CLEAN_CHOICE_CONFIDENCE_MIN", "CLEAN_CHOICE_PROBABILITY_MIN", "CLEAN_CHOICE_MARGIN_MIN", "CLEAN_BLOCKING_SEVERITY_TAIL_MAX"}
        numbers = typed["thresholds"]
        if not isinstance(numbers, dict) or set(numbers) != required_thresholds or not all(_probability(value) for value in numbers.values()) or numbers["RISK_ABSENT_MAX"] >= numbers["RISK_PRESENT_MIN"]:
            raise ValueError("typed thresholds")
        severity, category = typed["severity_criteria"], typed["category_criteria"]
        if not _text_map(severity) or not {"P0", "P1", "P2", "P3", "none"} <= set(severity) <= {"P0", "P1", "P2", "P3", "P4", "none"}:
            raise ValueError("severity criteria")
        if not _text_map(category) or "none" not in category or not _text_map(typed["risk_instructions"]):
            raise ValueError("category criteria")
        floors, templates = typed["severity_support_floors"], typed["finding_templates"]
        if not isinstance(floors, dict) or set(floors) != set(severity) - {"none"} or not all(_probability(value) for value in floors.values()):
            raise ValueError("severity floors")
        if not isinstance(templates, dict) or set(templates) != set(category) - {"none"} or not all(isinstance(value, list) and len(value) == 2 and all(_text(item) for item in value) for value in templates.values()):
            raise ValueError("finding templates")
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        return PrivateReviewPolicy(canonical)
    except Exception:
        raise PrivatePolicyError("Private review policy is missing or invalid; review is unknown") from None
