from types import SimpleNamespace

import pytest

from omargate.analyze.review_costs import cost_ledger, estimate_usage
from omargate.main import _llm_display_cost
from omargate.models import Counts, GateResult, GateStatus
from omargate.telemetry_runtime import _write_github_outputs


def test_typed_only_usage_is_not_reported_as_zero_when_generator_context_refuses():
    ledger = cost_ledger([estimate_usage('typesafe', 'model-under-test-1.13.0',
                                       {'input_tokens': 1000, 'output_tokens': 0},
                                       intent_price_profile='typesafe-input-20261020')])
    analysis = SimpleNamespace(llm_attempted=False, llm_success=False, llm_usage={'cost_ledger': ledger})
    assert _llm_display_cost(analysis) == ledger['estimated_total_usd'] > 0
    ledger['estimated_total_usd'] = None
    assert _llm_display_cost(analysis) is None


@pytest.mark.parametrize('cost,expected', [(None, 'unknown'), (0.00000025, '0.00000025'), (0.0, '0.00000000')])
def test_actual_cost_output_keeps_unknown_and_small_paid_estimates(tmp_path, monkeypatch, cost, expected):
    path = tmp_path / 'outputs'
    monkeypatch.setenv('GITHUB_OUTPUT', str(path))
    _write_github_outputs(run_id='cost-output', idem_key='', findings_path=tmp_path / 'FINDINGS.jsonl',
                          pack_summary_path=tmp_path / 'PACK_SUMMARY.json',
                          gate_result=GateResult(GateStatus.PASSED, 'complete', False, Counts()),
                          estimated_cost_usd=cost)
    assert 'estimated_cost_usd=' + expected + '\n' in path.read_text()
