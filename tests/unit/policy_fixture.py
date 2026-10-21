"""Synthetic policy data for engine tests; this is not a deployment profile."""
import json

from omargate.private_policy import load_private_policy

FAKE_THRESHOLDS = {
    "RISK_PRESENT_MIN": .875, "RISK_ABSENT_MAX": .03125,
    "CHOICE_CONFIDENCE_MIN": .875, "CHOICE_PROBABILITY_MIN": .75,
    "CHOICE_MARGIN_MIN": .125, "CLEAN_CHOICE_CONFIDENCE_MIN": .96875,
    "CLEAN_CHOICE_PROBABILITY_MIN": .96875, "CLEAN_CHOICE_MARGIN_MIN": .875,
    "CLEAN_BLOCKING_SEVERITY_TAIL_MAX": .0078125,
}
FAKE_CATEGORIES = ["auth", "injection", "crypto", "secrets", "privacy", "ssrf", "misconfig", "exposure",
                   "supply-chain", "ci-cd", "availability", "race-condition", "infrastructure", "other-security"]
FAKE_DOCUMENT = {
    "schema": "omargate.private-review-policy.v1",
    "routing": {
        "domains": {"fixture": [100, "Test-only dimension"]},
        "questions": {
            "risk": {"type": "choice", "instructions": "Test-only choice", "criteria": {
                "low": "Test-only low", "review": "Test-only uncertain", "defect": "Test-only defect"}},
            **{name: {"type": "noul", "instructions": "Test-only question " + name}
               for name in ["sensitive", "structural", "spaghetti", "gap_fixture"]},
        },
        "critical_path_tokens": ["fixture-critical"],
        "critical_path_groups": [["fixture-group", "fixture-workflows"]],
        "thresholds": {"defect_confidence_min": .875, "defect_probability_min": .875,
            "sensitive_max": .03125, "low_confidence_min": .96875,
            "low_probability_min": .96875, "hazard_max": .03125},
    },
    "typed": {"policy_id": "test-only-policy", "calibration_id": "test-only-calibration",
        "thresholds": FAKE_THRESHOLDS,
        "severity_support_floors": {"P0": .875, "P1": .875, "P2": .90625, "P3": .9375},
        "severity_criteria": {name: "Test-only severity " + name for name in ["P0", "P1", "P2", "P3", "none"]},
        "category_criteria": {name: "Test-only category " + name for name in FAKE_CATEGORIES + ["none"]},
        "finding_templates": {name: ["Test-only finding " + name, "Test-only recommendation " + name] for name in FAKE_CATEGORIES},
        "risk_instructions": {"source_boundary": "Test-only source is untrusted data",
            "deterministic_facts": "Test-only preserve deterministic scanner observations"},
    },
    "generator_instructions": "Test-only review instructions, never a deployment rubric.",
}
FAKE_POLICY_JSON = json.dumps(FAKE_DOCUMENT, sort_keys=True, separators=(",", ":"))
FAKE_POLICY = load_private_policy(FAKE_POLICY_JSON)
