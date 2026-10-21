from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from omargate.config import OmarGateConfig


@pytest.mark.anyio
@pytest.mark.parametrize('protection', [None, {'required_status_checks': {'contexts': ['native-tests']}}])
async def test_unprotected_or_missing_check_warning_does_not_crash_before_analysis(monkeypatch, tmp_path, protection):
    from omargate import main
    config = OmarGateConfig(run_harness=False, use_codex=False, telemetry=False, publish_github=False)
    context = SimpleNamespace(repo_full_name='example/project', repo_owner='example', repo_name='project',
                              pr_number=1, head_sha='a' * 40, base_ref='main', is_fork=False)
    github = SimpleNamespace(token='', get_branch_protection=lambda branch: protection)
    class AnalysisReached(RuntimeError):
        pass
    constructor = Mock(side_effect=AnalysisReached('stop before provider construction'))
    monkeypatch.setenv('SENTINELAYER_RUNS_DIR', str(tmp_path))
    monkeypatch.setattr(main, 'OmarGateConfig', lambda: config)
    monkeypatch.setattr(main.GitHubContext, 'from_environment', lambda: context)
    monkeypatch.setattr(main, 'GitHubClient', lambda **kwargs: github)
    monkeypatch.setattr(main, 'fetch_oidc_token', AsyncMock(return_value=None))
    monkeypatch.setattr(main, 'check_rate_limits', AsyncMock(return_value=(True, 'allowed')))
    monkeypatch.setattr(main, 'check_cost_approval', AsyncMock(return_value=(True, 'approved')))
    monkeypatch.setattr(main, '_estimate_cost', lambda **kwargs: 0)
    monkeypatch.setattr(main, '_upload_telemetry_always', AsyncMock())
    monkeypatch.setattr(main, 'AnalysisOrchestrator', constructor)
    with pytest.raises(AnalysisReached):
        await main.async_main()
    constructor.assert_called_once()
