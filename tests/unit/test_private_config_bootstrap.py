import json
from unittest.mock import AsyncMock, Mock

import pytest
from policy_fixture import FAKE_POLICY_JSON

from omargate.gate import evaluate_gate
from omargate.models import GateConfig


def configure(monkeypatch, tmp_path):
    values = {
        'INPUT_LLM_PROVIDER': 'typesafe', 'INPUT_REVIEW_ROUTING': 'intent-cascade-v1',
        'INPUT_INTENT_MODEL_PIN': 'model-under-test-1.13.0', 'INPUT_INTENT_POLICY': FAKE_POLICY_JSON,
        'INPUT_TYPESAFE_API_KEY': 'fixture-typed-auth', 'INPUT_OPENAI_API_KEY': 'fixture-generator-auth',
        'INPUT_MODEL': 'gpt-6-sol', 'INPUT_MODEL_FALLBACK': 'gpt-6-sol', 'INPUT_CODEX_MODEL': 'gpt-6-sol',
        'INPUT_USE_CODEX': 'false', 'INPUT_TELEMETRY': 'false',
        'SENTINELAYER_RUNS_DIR': str(tmp_path / 'runs'), 'GITHUB_WORKSPACE': str(tmp_path),
        'GITHUB_OUTPUT': str(tmp_path / 'outputs'), 'GITHUB_STEP_SUMMARY': str(tmp_path / 'summary'),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize('provider', ['anthropic', 'google', 'xai'])
def test_other_explicit_providers_refuse_whitespace_only_keys(provider):
    from omargate.config import OmarGateConfig
    with pytest.raises(ValueError):
        OmarGateConfig(llm_provider=provider, **{provider + '_api_key': ' \t\n'})


@pytest.mark.anyio
@pytest.mark.parametrize('name', ['TYPESAFE_API_KEY', 'OPENAI_API_KEY', 'INTENT_MODEL_PIN', 'INTENT_POLICY'])
@pytest.mark.parametrize('mode', ['unset', 'empty', 'whitespace'])
async def test_unavailable_private_config_refuses_with_unknown_artifacts_before_any_review(monkeypatch, tmp_path, capsys, name, mode):
    from omargate import main
    configure(monkeypatch, tmp_path)
    if mode == 'unset':
        monkeypatch.delenv('INPUT_' + name)
    else:
        monkeypatch.setenv('INPUT_' + name, '' if mode == 'empty' else ' \t\n')
    context = Mock(side_effect=AssertionError('configuration refusal must precede context'))
    github = Mock(side_effect=AssertionError('configuration refusal must precede GitHub'))
    engine = Mock(side_effect=AssertionError('configuration refusal must precede providers'))
    monkeypatch.setattr(main.GitHubContext, 'from_environment', context)
    monkeypatch.setattr(main, 'GitHubClient', github)
    monkeypatch.setattr(main, 'AnalysisOrchestrator', engine)
    monkeypatch.setattr(main, '_upload_telemetry_always', AsyncMock())
    assert await main.async_main() == 2
    context.assert_not_called()
    github.assert_not_called()
    engine.assert_not_called()
    summaries = list((tmp_path / 'runs').glob('*/PACK_SUMMARY.json'))
    assert len(summaries) == 1
    summary = json.loads(summaries[0].read_text())
    assert summary['review_verdict'] == 'UNKNOWN'
    assert summary['writer_complete'] is False
    assert summary['llm_usage']['cost_ledger']['estimated_total_usd'] is None
    assert evaluate_gate(summaries[0].parent, GateConfig()).block_merge is True
    outputs = (tmp_path / 'outputs').read_text()
    assert 'gate_status=error\n' in outputs
    assert 'review_verdict=UNKNOWN\n' in outputs
    assert 'estimated_cost_usd=unknown\n' in outputs
    assert 'UNKNOWN' in (tmp_path / 'summary').read_text()
    captured = capsys.readouterr()
    assert 'fixture-typed-auth' not in captured.out + captured.err
    assert 'fixture-generator-auth' not in captured.out + captured.err


@pytest.mark.anyio
async def test_complete_private_config_reaches_context_instead_of_bootstrap_refusal(monkeypatch, tmp_path):
    from omargate import main
    configure(monkeypatch, tmp_path)
    context = Mock(side_effect=RuntimeError('test stops after successful private configuration'))
    monkeypatch.setattr(main.GitHubContext, 'from_environment', context)
    monkeypatch.setattr(main, '_upload_telemetry_always', AsyncMock())
    assert await main.async_main() == 2
    context.assert_called_once()
    assert not list((tmp_path / 'runs').glob('*/PACK_SUMMARY.json'))
