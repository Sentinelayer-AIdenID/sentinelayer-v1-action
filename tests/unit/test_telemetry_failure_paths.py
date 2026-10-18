from __future__ import annotations

from dataclasses import dataclass

import pytest


@dataclass
class _DummyCtx:
    repo_owner: str = "acme"
    repo_name: str = "app"
    repo_full_name: str = "acme/app"
    pr_number: int | None = 123
    head_sha: str = "abc123"
    base_sha: str | None = None
    head_ref: str | None = None
    base_ref: str | None = None
    is_fork: bool = False
    fork_owner: str | None = None
    actor: str = "tester"


@pytest.mark.anyio
async def test_preflight_exit_dedupe_uploads_telemetry(monkeypatch, tmp_path) -> None:
    from omargate import main as om

    uploaded: list[dict] = []
    idempotency_kwargs: dict = {}

    async def fake_upload(payload: dict, **_kwargs) -> bool:
        uploaded.append(payload)
        return True

    async def fake_check_dedupe(*_args, **_kwargs):
        return True, None

    async def fake_fetch_oidc_token(*_args, **_kwargs):
        return None

    def fake_compute_idempotency_key(**kwargs) -> str:
        idempotency_kwargs.update(kwargs)
        return "test-idempotency-key"

    class DummyGH:
        def __init__(self, token: str, repo: str):
            self.token = token
            self.repo = repo

    dummy_ctx = _DummyCtx()

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(om, "upload_telemetry", fake_upload)
    monkeypatch.setattr(om, "fetch_oidc_token", fake_fetch_oidc_token)
    monkeypatch.setattr(om, "compute_idempotency_key", fake_compute_idempotency_key)
    monkeypatch.setattr(
        om,
        "dependency_audit_freshness_epoch",
        lambda: "2026-10-18",
    )
    monkeypatch.setattr(om, "check_dedupe", fake_check_dedupe)
    monkeypatch.setattr(om, "_estimate_cost", lambda *_args, **_kwargs: 0.0)
    monkeypatch.setattr(om, "_short_circuit_mirror_prior_check_run", lambda **_kwargs: 0)
    monkeypatch.setattr(om.GitHubContext, "from_environment", classmethod(lambda cls: dummy_ctx))
    monkeypatch.setattr(om, "GitHubClient", DummyGH)

    exit_code = await om.async_main()
    assert exit_code == 0

    assert len(uploaded) == 1
    payload = uploaded[0]
    assert payload["tier"] == 1
    assert payload["run"]["exit_reason"] == "dedupe"
    assert payload["run"]["exit_code"] == 0
    assert payload["gate"]["preflight_exits"] == [{"reason": "dedupe", "exit_code": 0}]
    assert idempotency_kwargs["audit_contract_version"] == (
        om.DEPENDENCY_AUDIT_CONTRACT_VERSION
    )
    assert idempotency_kwargs["run_harness"] is True
    assert idempotency_kwargs["pip_audit_ignore_ids"] == ""
    assert idempotency_kwargs["audit_freshness_epoch"] == "2026-10-18"


@pytest.mark.anyio
async def test_analysis_exception_uploads_telemetry_before_raising(monkeypatch, tmp_path) -> None:
    from omargate import main as om

    uploaded: list[dict] = []

    async def fake_upload(payload: dict, **_kwargs) -> bool:
        uploaded.append(payload)
        return True

    async def fake_check_dedupe(*_args, **_kwargs):
        return False, None

    async def fake_check_rate_limits(*_args, **_kwargs):
        return True, "ok"

    async def fake_check_cost_approval(*_args, **_kwargs):
        return True, "approved"

    async def fake_fetch_oidc_token(*_args, **_kwargs):
        return None

    class DummyGH:
        def __init__(self, token: str, repo: str):
            self.token = token
            self.repo = repo

    class DummyOrchestrator:
        def __init__(self, *args, **kwargs):
            pass

        async def run(self, **_kwargs):
            raise RuntimeError("llm fail")

    dummy_ctx = _DummyCtx()

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path))
    monkeypatch.setenv("INPUT_SCAN_MODE", "deep")  # avoid diff fetch
    monkeypatch.setattr(om, "upload_telemetry", fake_upload)
    monkeypatch.setattr(om, "fetch_oidc_token", fake_fetch_oidc_token)
    monkeypatch.setattr(om, "_estimate_cost", lambda *_args, **_kwargs: 0.0)
    monkeypatch.setattr(om, "check_dedupe", fake_check_dedupe)
    monkeypatch.setattr(om, "check_fork_policy", lambda *_args, **_kwargs: (True, "full", "not_fork"))
    monkeypatch.setattr(om, "check_rate_limits", fake_check_rate_limits)
    monkeypatch.setattr(om, "check_cost_approval", fake_check_cost_approval)
    monkeypatch.setattr(om, "check_branch_protection", lambda *_args, **_kwargs: (True, "ok"))
    monkeypatch.setattr(om.GitHubContext, "from_environment", classmethod(lambda cls: dummy_ctx))
    monkeypatch.setattr(om, "GitHubClient", DummyGH)
    monkeypatch.setattr(om, "AnalysisOrchestrator", DummyOrchestrator)

    with pytest.raises(RuntimeError, match="llm fail"):
        await om.async_main()

    assert len(uploaded) == 1
    payload = uploaded[0]
    assert payload["tier"] == 1
    assert payload["run"]["exit_reason"] == "unhandled"
    assert payload["run"]["exit_code"] == 2
    assert "analysis" in payload["errors"]
    assert "unhandled" in payload["errors"]


@pytest.mark.anyio
async def test_unhandled_exception_uploads_telemetry_before_raising(monkeypatch, tmp_path) -> None:
    from omargate import main as om

    uploaded: list[dict] = []

    async def fake_upload(payload: dict, **_kwargs) -> bool:
        uploaded.append(payload)
        return True

    async def fake_fetch_oidc_token(*_args, **_kwargs):
        return None

    dummy_ctx = _DummyCtx()

    monkeypatch.setenv("SENTINELAYER_RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(om, "upload_telemetry", fake_upload)
    monkeypatch.setattr(om, "fetch_oidc_token", fake_fetch_oidc_token)
    monkeypatch.setattr(om.GitHubContext, "from_environment", classmethod(lambda cls: dummy_ctx))
    monkeypatch.setattr(om, "compute_idempotency_key", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(RuntimeError, match="boom"):
        await om.async_main()

    assert len(uploaded) == 1
    payload = uploaded[0]
    assert payload["tier"] == 1
    assert payload["run"]["exit_reason"] == "unhandled"
    assert payload["run"]["exit_code"] == 2
    assert "unhandled" in payload["errors"]

