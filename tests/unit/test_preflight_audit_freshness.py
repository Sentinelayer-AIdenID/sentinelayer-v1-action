from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from omargate.config import OmarGateConfig
from omargate.idempotency import compute_idempotency_key


@pytest.mark.anyio
@pytest.mark.parametrize("limit", ["cooldown", "daily_cap"])
@pytest.mark.parametrize("prior_contract", ["legacy", "previous_day", "disabled", "ignore_ids"])
async def test_rate_limit_cannot_replay_success_from_another_audit_contract(
    monkeypatch, tmp_path, limit, prior_contract
) -> None:
    from omargate import main as om

    now = datetime.now(UTC)
    config = OmarGateConfig(
        run_harness=True,
        github_token="fixture-token",
        publish_github=False,
        min_scan_interval_minutes=60 if limit == "cooldown" else 0,
        max_daily_scans=1 if limit == "daily_cap" else 0,
    )
    prior_fields = {
        "repo": "acme/app", "pr_number": 123, "head_sha": "same-head",
        "scan_mode": config.scan_mode, "policy_pack": config.policy_pack,
        "policy_pack_version": config.policy_pack_version,
        "action_major_version": om.ACTION_IDEMPOTENCY_VERSION,
        "comment_tag": config.comment_tag,
        "audit_contract_version": om.DEPENDENCY_AUDIT_CONTRACT_VERSION,
        "run_harness": True, "pip_audit_ignore_ids": "",
        "audit_freshness_epoch": now.date().isoformat(),
    }
    if prior_contract == "legacy":
        prior_fields["audit_contract_version"] = "1.0"
    elif prior_contract == "previous_day":
        prior_fields["audit_freshness_epoch"] = (now - timedelta(days=1)).date().isoformat()
    elif prior_contract == "disabled":
        prior_fields["run_harness"] = False
    else:
        prior_fields["pip_audit_ignore_ids"] = "CVE-FIXTURE-IGNORE"
    prior_key = compute_idempotency_key(**prior_fields)
    prior = {
        "external_id": prior_key, "status": "completed", "conclusion": "success",
        "completed_at": now.isoformat(), "output": {"summary": "Old successful scan"},
    }
    uploaded = []
    summaries = []

    class FixtureGH:
        def __init__(self, token, repo):
            self.token = token

        def find_check_run_by_external_id(self, _head, key, _name):
            return prior if key == prior_key else None

        def list_check_runs(self, *_args):
            return [prior]

        def get_pull_request(self, _number):
            return {"head": {"sha": "same-head"}}

    async def no_oidc(**_kwargs):
        return None

    async def capture_upload(payload, **_kwargs):
        uploaded.append(payload)
        return True

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(om, "OmarGateConfig", lambda: config)
    monkeypatch.setattr(om, "GitHubClient", FixtureGH)
    monkeypatch.setattr(om.GitHubContext, "from_environment", classmethod(lambda cls: SimpleNamespace(
        repo_full_name="acme/app", pr_number=123, head_sha="same-head", is_fork=False,
    )))
    monkeypatch.setattr(om, "fetch_oidc_token", no_oidc)
    monkeypatch.setattr(om, "upload_telemetry", capture_upload)
    monkeypatch.setattr(om, "dependency_audit_freshness_epoch", lambda: now.date().isoformat())
    monkeypatch.setattr(om, "_estimate_cost", lambda **_kwargs: 0.0)
    monkeypatch.setattr(om, "write_step_summary", lambda **kwargs: summaries.append(kwargs))

    exit_code = await om.async_main()

    assert exit_code == 13
    assert len(summaries) == 1
    result = summaries[0]["gate_result"]
    assert result.status == om.GateStatus.NEEDS_APPROVAL
    assert result.block_merge is True
    assert result.dedupe_key != prior_key
    assert "dependency audit" in result.reason.lower()
    assert len(list(tmp_path.glob("*/PACK_SUMMARY.json"))) == 1
    assert len(uploaded) == 1
    assert uploaded[0]["run"]["exit_code"] == 13
    assert uploaded[0]["run"]["exit_reason"] == "rate_limit"


@pytest.mark.anyio
@pytest.mark.parametrize("history", ["empty", "unavailable"])
async def test_required_audit_rate_limit_without_history_still_blocks(
    monkeypatch, tmp_path, history
) -> None:
    from omargate import main as om

    config = OmarGateConfig(run_harness=True, github_token="fixture-token", publish_github=False)
    summaries = []

    class FixtureGH:
        def __init__(self, token, repo):
            self.token = token

        def find_check_run_by_external_id(self, *_args):
            return None

        def list_check_runs(self, *_args):
            if history == "unavailable":
                raise RuntimeError("fixture history unavailable")
            return []

    async def no_oidc(**_kwargs):
        return None

    async def blocked_rate(*_args, **_kwargs):
        return False, "daily_cap_exceeded"

    async def no_upload(*_args, **_kwargs):
        return False

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(om, "OmarGateConfig", lambda: config)
    monkeypatch.setattr(om, "GitHubClient", FixtureGH)
    monkeypatch.setattr(om.GitHubContext, "from_environment", classmethod(lambda cls: SimpleNamespace(
        repo_full_name="acme/app", pr_number=123, head_sha="same-head", is_fork=False,
    )))
    monkeypatch.setattr(om, "fetch_oidc_token", no_oidc)
    monkeypatch.setattr(om, "upload_telemetry", no_upload)
    monkeypatch.setattr(om, "check_rate_limits", blocked_rate)
    monkeypatch.setattr(om, "_estimate_cost", lambda **_kwargs: 0.0)
    monkeypatch.setattr(om, "write_step_summary", lambda **kwargs: summaries.append(kwargs))

    assert await om.async_main() == 13
    assert summaries[0]["gate_result"].status == om.GateStatus.NEEDS_APPROVAL
    assert summaries[0]["gate_result"].block_merge is True


def _configure_compatibility_preflight(monkeypatch, tmp_path, om, config, gh_type):
    """Keep real preflight/selection/artifact code, with no external effects."""
    summaries = []
    final_calls = []

    async def no_oidc(**_kwargs):
        return None

    async def capture_finally(**kwargs):
        # Capture the actual main-scope result, including the neutral branch
        # that does not call the Step Summary writer. Do not upload telemetry.
        final_calls.append(kwargs)

    def refuse_analysis(*_args, **_kwargs):
        raise AssertionError("preflight must return before analysis starts")

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path))
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setattr(om, "OmarGateConfig", lambda: config)
    monkeypatch.setattr(om, "GitHubClient", gh_type)
    monkeypatch.setattr(
        om.GitHubContext,
        "from_environment",
        classmethod(lambda cls: SimpleNamespace(
            repo_full_name="acme/app",
            pr_number=123,
            head_sha="same-head",
            is_fork=False,
        )),
    )
    monkeypatch.setattr(om, "fetch_oidc_token", no_oidc)
    monkeypatch.setattr(om, "_upload_telemetry_always", capture_finally)
    monkeypatch.setattr(om, "_estimate_cost", lambda **_kwargs: 0.0)
    monkeypatch.setattr(
        om, "write_step_summary", lambda **kwargs: summaries.append(kwargs)
    )
    monkeypatch.setattr(om, "AnalysisOrchestrator", refuse_analysis)
    return summaries, final_calls


def _compatibility_audit_key(om, config, now, **overrides):
    fields = {
        "repo": "acme/app",
        "pr_number": 123,
        "head_sha": "same-head",
        "scan_mode": config.scan_mode,
        "policy_pack": config.policy_pack,
        "policy_pack_version": config.policy_pack_version,
        "action_major_version": om.ACTION_IDEMPOTENCY_VERSION,
        "comment_tag": config.comment_tag,
        "audit_contract_version": om.DEPENDENCY_AUDIT_CONTRACT_VERSION,
        "run_harness": config.run_harness,
        "pip_audit_ignore_ids": config.pip_audit_ignore_ids,
        "audit_freshness_epoch": (
            now.date().isoformat() if config.run_harness else None
        ),
    }
    fields.update(overrides)
    return compute_idempotency_key(**fields)


@pytest.mark.anyio
@pytest.mark.parametrize("conclusion", ["success", "failure"])
async def test_even_current_key_check_metadata_cannot_skip_fresh_review(
    monkeypatch, tmp_path, conclusion
) -> None:
    from omargate import main as om

    now = datetime.now(UTC)
    config = OmarGateConfig(
        run_harness=True,
        github_token="fixture-token",
        publish_github=False,
        min_scan_interval_minutes=60,
        max_daily_scans=1,
    )
    current_key = _compatibility_audit_key(om, config, now)
    wrong_key = _compatibility_audit_key(
        om, config, now, pip_audit_ignore_ids="CVE-FIXTURE-OTHER"
    )
    assert current_key != wrong_key
    current = {
        "external_id": current_key,
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": (now - timedelta(minutes=2)).isoformat(),
        "output": {"summary": "Exact-current-key outcome"},
    }
    newer_wrong = {
        "external_id": wrong_key,
        "status": "completed",
        "conclusion": "success",
        "completed_at": (now - timedelta(minutes=1)).isoformat(),
        "output": {"summary": "Newer wrong-key success"},
    }
    rate_calls = []

    class FixtureGH:
        def __init__(self, token, repo):
            self.token = token

        def find_check_run_by_external_id(self, head, key, _name):
            assert head == "same-head"
            return current if key == current_key else None

        def list_check_runs(self, *_args):
            # Latest-result selection would choose the wrong success, so a
            # failing exact-key result proves the dedupe selector is retained.
            return [newer_wrong, current]

    async def refuse_rate_check(*_args, **_kwargs):
        rate_calls.append(True)
        return False, "daily_cap_exceeded"

    summaries, final_calls = _configure_compatibility_preflight(
        monkeypatch, tmp_path, om, config, FixtureGH
    )
    monkeypatch.setattr(
        om, "dependency_audit_freshness_epoch", lambda: now.date().isoformat()
    )
    monkeypatch.setattr(om, "check_rate_limits", refuse_rate_check)

    assert await om.async_main() == 13
    assert rate_calls == [True]
    assert len(summaries) == 1
    result = summaries[0]["gate_result"]
    assert result.status == om.GateStatus.NEEDS_APPROVAL and result.block_merge
    assert "fresh review" in result.reason
    assert "Exact-current-key outcome" not in result.reason
    assert len(list(tmp_path.glob("*/PACK_SUMMARY.json"))) == 1
    assert final_calls[0]["gate_result"] == result
    collector = final_calls[0]["collector"]
    assert collector.gate_status == "needs_approval"
    assert collector.exit_reason == "rate_limit" and collector.exit_code == 13


@pytest.mark.anyio
@pytest.mark.parametrize("limit", ["cooldown", "daily_cap"])
@pytest.mark.parametrize("mirror_history", ["latest_success", "empty"])
async def test_harness_off_rate_limit_cannot_mirror_or_allow_an_unverified_check(
    monkeypatch, tmp_path, limit, mirror_history
) -> None:
    from omargate import main as om

    now = datetime.now(UTC)
    config = OmarGateConfig(
        run_harness=False,
        github_token="fixture-token",
        publish_github=False,
        min_scan_interval_minutes=60 if limit == "cooldown" else 0,
        max_daily_scans=1 if limit == "daily_cap" else 0,
    )
    prior = {
        "external_id": "different-key",
        "status": "completed",
        "conclusion": "success",
        "completed_at": now.isoformat(),
        "output": {"summary": "Latest harness-off compatibility result"},
    }
    history_reads = []

    class FixtureGH:
        def __init__(self, token, repo):
            self.token = token

        def find_check_run_by_external_id(self, *_args):
            return None

        def get_pull_request(self, _number):
            return {"head": {"sha": "same-head"}}

        def list_check_runs(self, *_args):
            history_reads.append(True)
            # The real dedupe and rate helpers first see the prior run. The
            # mirror's later read may be empty, modeling a history-read race
            # while still exercising a real cooldown/daily-cap refusal.
            if len(history_reads) <= 2 or mirror_history == "latest_success":
                return [prior]
            return []

    summaries, final_calls = _configure_compatibility_preflight(
        monkeypatch, tmp_path, om, config, FixtureGH
    )

    assert await om.async_main() == 13
    assert len(history_reads) == 1  # rate enforcement only; no dedupe or mirror reads
    assert len(final_calls) == 1 and len(summaries) == 1
    result = summaries[0]["gate_result"]
    assert result.status == om.GateStatus.NEEDS_APPROVAL and result.block_merge
    assert "fresh review" in result.reason
    assert "Latest harness-off compatibility result" not in result.reason
    assert final_calls[0]["gate_result"] == result
    collector = final_calls[0]["collector"]
    assert collector.gate_status == "needs_approval"
    assert collector.exit_reason == "rate_limit" and collector.exit_code == 13
    assert collector.preflight_exits == [{"reason": "rate_limit", "exit_code": 13}]


@pytest.mark.anyio
async def test_explicit_harness_off_missing_token_closed_requires_approval(
    monkeypatch, tmp_path
) -> None:
    from omargate import main as om

    config = OmarGateConfig(
        run_harness=False,
        github_token="",
        publish_github=False,
        min_scan_interval_minutes=5,
        max_daily_scans=1,
        rate_limit_fail_mode="closed",
    )
    unsafe_api_calls = []

    class FixtureGH:
        def __init__(self, token, repo):
            self.token = token

        def find_check_run_by_external_id(self, *_args):
            return None

        def list_check_runs(self, *_args):
            return []

        def get_pull_request(self, _number):
            unsafe_api_calls.append(True)
            raise AssertionError("a missing token must be refused before API use")

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    summaries, final_calls = _configure_compatibility_preflight(
        monkeypatch, tmp_path, om, config, FixtureGH
    )

    assert await om.async_main() == 13

    assert unsafe_api_calls == []
    assert len(summaries) == 1
    result = summaries[0]["gate_result"]
    assert result.status == om.GateStatus.NEEDS_APPROVAL
    assert result.block_merge is True
    assert "approval required" in result.reason.lower()
    skip_files = list(tmp_path.glob("*/SKIP.md"))
    assert len(skip_files) == 1
    assert "rate_limit:missing_github_token_require_approval" in (
        skip_files[0].read_text()
    )
    assert len(final_calls) == 1
    assert final_calls[0]["collector"].exit_reason == "rate_limit"
    assert final_calls[0]["collector"].exit_code == 13
