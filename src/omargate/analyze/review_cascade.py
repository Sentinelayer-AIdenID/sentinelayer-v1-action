"""Routing mechanics. Rubrics and calibration belong to private configuration."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any

from ..private_policy import PrivateReviewPolicy
from .typesafe_client import ChoiceAnswer, TypeSafeResult, validate_answers

POLICY_VERSION = "omargate.intent-cascade.v1"
CALIBRATION = "operator-policy-not-validated-here"


@dataclass(frozen=True)
class ReviewRoute:
    tier: str
    model: str
    effort: str
    reason: str

    def evidence(self, policy_reference: str = "unknown") -> dict:
        return {**self.__dict__, "policy_version": POLICY_VERSION,
                "policy_reference": policy_reference, "calibration": CALIBRATION}


LOW = ReviewRoute("low", "gpt-6-luna", "max", "complete_low_risk")
MID = ReviewRoute("mid", "gpt-6.1-sol", "xhigh", "uncertain_or_complex")
DEEP = ReviewRoute("deep", "gpt-6-sol", "max", "critical_or_incomplete")


def cascade_generator_system_prompt(base_prompt: str, policy: PrivateReviewPolicy) -> str:
    """Use one prompt construction for review and its preflight cost envelope."""
    dimensions = [criterion for _, criterion in policy.routing["domains"].values()]
    return (base_prompt + "\n" + policy.generator_instructions + "\nReview dimensions: "
            + json.dumps(dimensions) + "\nReport source defects; do not quote private configuration.")


def response_model_matches(actual: str, expected: str) -> bool:
    if not isinstance(actual, str) or not isinstance(expected, str):
        return False
    if actual == expected:
        return True
    suffix = actual.removeprefix(expected + "-")
    if not actual.startswith(expected + "-") or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", suffix):
        return False
    try:
        date.fromisoformat(suffix)
        return True
    except ValueError:
        return False


def triage_questions(policy: PrivateReviewPolicy) -> dict[str, dict]:
    return policy.routing["questions"]


def critical_paths(policy: PrivateReviewPolicy, paths: list[str] | None) -> bool:
    config = policy.routing
    tokens = set(config["critical_path_tokens"])
    for raw in paths or []:
        path = PurePosixPath(raw.replace("\\", "/").lower())
        parts = set(path.parts)
        if parts & tokens or any(path.stem == token or path.stem.startswith(token + "_") for token in tokens):
            return True
        if any(set(group) <= parts for group in config["critical_path_groups"]):
            return True
    return False


def choose_route(policy: PrivateReviewPolicy, result: TypeSafeResult, *, paths: list[str], findings: list[dict]) -> ReviewRoute:
    answers = validate_answers(result.answers, triage_questions(policy))
    thresholds = policy.routing["thresholds"]
    risk = answers["risk"]
    assert isinstance(risk, ChoiceAnswer)
    if critical_paths(policy, paths) or any(f.get("severity") in {"P0", "P1"} for f in findings):
        return DEEP
    if risk.choice == "defect" and risk.confidence >= thresholds["defect_confidence_min"] and risk.probabilities["defect"] >= thresholds["defect_probability_min"]:
        return ReviewRoute("deep", DEEP.model, DEEP.effort, "high_confidence_defect")
    if answers["sensitive"] > thresholds["sensitive_max"]:
        return DEEP
    hazards = [value for name, value in answers.items() if name != "risk"]
    if (risk.choice == "low" and risk.confidence >= thresholds["low_confidence_min"]
            and risk.probabilities["low"] >= thresholds["low_probability_min"]
            and all(value <= thresholds["hazard_max"] for value in hazards)
            and not any(f.get("severity") in {"P0", "P1", "P2"} for f in findings)):
        return LOW
    return MID


def excellence_coverage(policy: PrivateReviewPolicy, answers: dict[str, Any] | None) -> dict:
    # Public evidence identifies dimensions without publishing their rubric/weights.
    domains = policy.routing["domains"]
    return {"framework_reference": policy.reference, "kind": "review_signals_not_verified_scores",
            "domains": [{"dimension": f"dimension-{index}",
                "criterion_reference": hashlib.sha256((name + "\0" + criterion).encode()).hexdigest()[:16],
                "gap_probability": (answers or {}).get("gap_" + name),
                "status": "assessed_source_only" if answers else "unassessed"}
                for index, (name, (_, criterion)) in enumerate(domains.items(), start=1)]}
