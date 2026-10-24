import runpy
from pathlib import Path

import pytest

from omargate.analyze.orchestrator import LLMAnalysisResult
from omargate.config import OmarGateConfig


@pytest.mark.parametrize("name,complete,finding,failure,expected", [
    ("ordinary", True, False, None, True),
    ("ordinary", False, False, "cascade_policy_incomplete", False),
    ("serious", True, True, None, True),
    ("serious", False, True, "cascade_policy_incomplete", True),
    ("serious", True, False, None, False),
    ("serious", False, True, "cascade_model_mismatch", False),
])
def test_canary_proves_actual_gate_behavior_and_preserves_unknown_review(tmp_path, name, complete, finding, failure, expected):
    evaluate = runpy.run_path(str(Path(__file__).parents[2] / "scripts/intent_canary.py"))["evaluate_case"]
    findings = [{"severity": "P1", "category": "auth", "file_path": "sample.py", "line_start": 1,
                 "message": "Synthetic defect"}] if finding else []
    result = LLMAnalysisResult(findings, complete, {"provider": "openai", "model": "gpt-6-sol",
        "latency_ms": 100, "review_routing": {"routes": [{"tier": "deep", "success": failure != "cascade_model_mismatch",
                                                       "identity_matches": failure != "cascade_model_mismatch"}]}},
        None, attempted=True, output_valid=complete, no_findings_reported=not finding,
        reported_finding_count=len(findings), failure_class=failure)
    outcome = evaluate(name, result, OmarGateConfig(), tmp_path)
    assert outcome["expectation_met"] is expected
    assert outcome["review_complete"] is complete
    if not complete:
        assert outcome["block_merge"] and outcome["gate_status"] == "error"
