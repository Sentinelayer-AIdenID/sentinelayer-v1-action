from __future__ import annotations

from pathlib import Path

import pytest

from omargate.analyze.llm.context_builder import BuiltContext
from omargate.analyze.llm.llm_client import LLMClient, LLMResponse, LLMUsage
from omargate.analyze.codex.codex_runner import CodexResult, CodexRunner
from omargate.analyze.orchestrator import AnalysisOrchestrator, LLMAnalysisResult
from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger


def _orchestrator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AnalysisOrchestrator:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    return AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=False,
    )


def _stub_llm_context(
    orchestrator: AnalysisOrchestrator, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator.context_builder,
        "build_context",
        lambda **_kwargs: BuiltContext(
            content="scan this",
            token_count=3,
            files_included=[],
            files_truncated=[],
            files_skipped=[],
            hotspots_included=[],
        ),
    )


def _successful_usage() -> LLMUsage:
    return LLMUsage(
        model="gpt-5.3-codex",
        tokens_in=10,
        tokens_out=5,
        cost_usd=0.01,
        latency_ms=25,
        provider="openai",
        route="byo",
    )


def test_byo_openai_managed_flag_allows_capacity_fallback_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_SENTINELAYER_TOKEN", "sl_test_token")
    monkeypatch.setenv("INPUT_SENTINELAYER_MANAGED_LLM", "true")
    monkeypatch.setenv("INPUT_LLM_PROVIDER", "openai")
    config = OmarGateConfig()
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=OmarLogger("test-run"),
        repo_root=tmp_path,
        allow_llm=True,
    )

    assert orchestrator._should_use_managed_proxy_for_llm_analysis() is False
    assert orchestrator._should_allow_managed_capacity_fallback() is True


def test_llm_p1_without_corroboration_is_downgraded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    ingest = {"files": [{"path": "src/auth.py", "lines": 200}]}
    llm_findings = [
        {
            "severity": "P1",
            "category": "auth",
            "file_path": "src/auth.py",
            "line_start": 48,
            "line_end": 49,
            "message": "OAuth callback does not validate state",
            "confidence": 0.95,
            "source": "codex",
        }
    ]

    guarded = orchestrator._apply_llm_guardrails(
        llm_findings=llm_findings,
        non_llm_findings=[],
        ingest=ingest,
    )

    assert len(guarded) == 1
    assert guarded[0]["severity"] == "P2"
    assert "LLM-only" in guarded[0]["message"]


def test_llm_p1_with_corroboration_stays_blocking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    ingest = {"files": [{"path": "src/auth.py", "lines": 200}]}
    llm_findings = [
        {
            "severity": "P1",
            "category": "auth",
            "file_path": "src/auth.py",
            "line_start": 50,
            "line_end": 50,
            "message": "State parameter not validated",
            "confidence": 0.9,
            "source": "codex",
        }
    ]
    deterministic_findings = [
        {
            "severity": "P1",
            "category": "auth",
            "file_path": "src/auth.py",
            "line_start": 53,
            "line_end": 53,
            "message": "Auth flow guard missing",
            "source": "deterministic",
            "rule_id": "SEC-016",
        }
    ]

    guarded = orchestrator._apply_llm_guardrails(
        llm_findings=llm_findings,
        non_llm_findings=deterministic_findings,
        ingest=ingest,
    )

    assert len(guarded) == 1
    assert guarded[0]["severity"] == "P1"


def test_llm_findings_for_unknown_files_are_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    ingest = {"files": [{"path": "src/known.py", "lines": 10}]}
    llm_findings = [
        {
            "severity": "P1",
            "category": "backend",
            "file_path": "src/missing.py",
            "line_start": 999,
            "message": "Missing timeout",
            "source": "llm",
        }
    ]

    guarded = orchestrator._apply_llm_guardrails(
        llm_findings=llm_findings,
        non_llm_findings=[],
        ingest=ingest,
    )

    assert guarded == []


def test_system_findings_are_preserved_even_without_repo_file_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    orchestrator = _orchestrator(tmp_path, monkeypatch)
    ingest = {"files": [{"path": "src/known.py", "lines": 10}]}
    llm_findings = [
        {
            "severity": "P0",
            "category": "LLM Failure",
            "file_path": "<system>",
            "line_start": 0,
            "line_end": 0,
            "message": "LLM analysis failed and must block merge",
            "source": "system",
        }
    ]

    guarded = orchestrator._apply_llm_guardrails(
        llm_findings=llm_findings,
        non_llm_findings=[],
        ingest=ingest,
    )

    assert len(guarded) == 1
    assert guarded[0]["source"] == "system"
    assert guarded[0]["severity"] == "P0"
    assert guarded[0]["file_path"] == "<system>"


def test_should_run_llm_with_managed_proxy_when_byo_key_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INPUT_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("INPUT_SENTINELAYER_TOKEN", "sl_test_token")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )

    assert orchestrator._should_run_llm() is True


def test_byo_openai_key_takes_precedence_over_managed_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_SENTINELAYER_TOKEN", "sl_test_token")
    monkeypatch.setenv("INPUT_SENTINELAYER_MANAGED_LLM", "true")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )

    assert orchestrator._should_run_llm() is True
    assert orchestrator._should_use_managed_proxy_for_llm_analysis() is False
    assert orchestrator._should_allow_managed_capacity_fallback() is True


def test_managed_proxy_used_when_byo_openai_key_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INPUT_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("INPUT_SENTINELAYER_TOKEN", "sl_test_token")
    monkeypatch.setenv("INPUT_SENTINELAYER_MANAGED_LLM", "true")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )

    assert orchestrator._should_run_llm() is True
    assert orchestrator._should_use_managed_proxy_for_llm_analysis() is True


@pytest.mark.anyio
async def test_api_explicit_clean_result_is_valid_live_llm_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_USE_CODEX", "false")
    monkeypatch.setenv("INPUT_RUN_HARNESS", "false")
    orchestrator = AnalysisOrchestrator(
        config=OmarGateConfig(),
        logger=OmarLogger("test-run"),
        repo_root=tmp_path,
        allow_llm=True,
    )
    _stub_llm_context(orchestrator, monkeypatch)

    async def _fake_analyze(*_args, **_kwargs):
        return LLMResponse(
            content='{"no_findings": true}',
            usage=_successful_usage(),
            success=True,
            error=None,
        )

    monkeypatch.setattr(LLMClient, "analyze", _fake_analyze)

    result = await orchestrator._run_llm_analysis(
        ingest={},
        deterministic_findings=[],
        quick_learn=None,
        spec_context=None,
        scan_mode="deep",
        diff_content=None,
        changed_files=None,
    )

    assert result.success is True
    assert result.attempted is True
    assert result.output_valid is True
    assert result.no_findings_reported is True
    assert result.reported_finding_count == 0
    assert result.parse_error_count == 0
    assert result.failure_class is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("content", "expected_parse_errors", "expected_reported", "expected_clean"),
    [
        ("", 1, 0, False),
        (
            '[{"severity":"P2","category":"auth","file_path":"src/a.py",'
            '"line_start":3,"message":"missing guard"},{"unexpected":true}]',
            1,
            1,
            False,
        ),
        (
            '[{"severity":"P2","category":"auth","file_path":"src/a.py",'
            '"line_start":3,"message":"missing guard"},{"no_findings":true}]',
            1,
            1,
            False,
        ),
    ],
)
async def test_api_invalid_structured_output_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
    expected_parse_errors: int,
    expected_reported: int,
    expected_clean: bool,
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_USE_CODEX", "false")
    monkeypatch.setenv("INPUT_RUN_HARNESS", "false")
    monkeypatch.setenv("INPUT_LLM_FAILURE_POLICY", "block")
    orchestrator = AnalysisOrchestrator(
        config=OmarGateConfig(),
        logger=OmarLogger("test-run"),
        repo_root=tmp_path,
        allow_llm=True,
    )
    _stub_llm_context(orchestrator, monkeypatch)

    async def _fake_analyze(*_args, **_kwargs):
        return LLMResponse(
            content=content,
            usage=_successful_usage(),
            success=True,
            error=None,
        )

    monkeypatch.setattr(LLMClient, "analyze", _fake_analyze)

    result = await orchestrator._run_llm_analysis(
        ingest={},
        deterministic_findings=[],
        quick_learn=None,
        spec_context=None,
        scan_mode="deep",
        diff_content=None,
        changed_files=None,
    )

    assert result.success is False
    assert result.attempted is True
    assert result.output_valid is False
    assert result.failure_class == "invalid_output"
    assert result.parse_error_count == expected_parse_errors
    assert result.reported_finding_count == expected_reported
    assert result.no_findings_reported is expected_clean
    assert any(
        finding["severity"] == "P0" and finding["category"] == "LLM Failure"
        for finding in result.findings
    )


@pytest.mark.anyio
async def test_codex_contradictory_clean_and_findings_output_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_LLM_FAILURE_POLICY", "block")
    orchestrator = AnalysisOrchestrator(
        config=OmarGateConfig(),
        logger=OmarLogger("test-run"),
        repo_root=tmp_path,
        allow_llm=True,
    )

    async def _fake_run_audit(*_args, **_kwargs):
        return CodexResult(
            findings=[
                {
                    "severity": "P2",
                    "category": "auth",
                    "file_path": "src/a.py",
                    "line_start": 3,
                    "line_end": 3,
                    "message": "missing guard",
                    "recommendation": "add guard",
                    "source": "codex",
                }
            ],
            raw_output="",
            success=True,
            duration_ms=25,
            parse_errors=[],
            no_findings_reported=True,
        )

    monkeypatch.setattr(CodexRunner, "run_audit", _fake_run_audit)

    result = await orchestrator._run_codex_audit(
        ingest={"files": [], "hotspots": {}},
        deterministic_findings=[],
        quick_learn=None,
        scan_mode="deep",
        diff_content=None,
    )

    assert result.success is False
    assert result.output_valid is False
    assert result.failure_class == "invalid_output"
    assert result.reported_finding_count == 1
    assert result.no_findings_reported is True
    assert any(finding["severity"] == "P0" for finding in result.findings)


@pytest.mark.anyio
async def test_codex_only_disables_api_fallback_on_codex_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_USE_CODEX", "true")
    monkeypatch.setenv("INPUT_CODEX_ONLY", "true")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )

    def _fake_det(_self, _ingest):
        return []

    async def _fake_codex(*_args, **_kwargs):
        return LLMAnalysisResult(
            findings=[],
            success=False,
            usage=None,
            warning="codex failed",
        )

    called = {"llm": False}

    async def _fake_llm(*_args, **_kwargs):
        called["llm"] = True
        return LLMAnalysisResult(
            findings=[],
            success=True,
            usage=None,
            warning=None,
        )

    monkeypatch.setattr(AnalysisOrchestrator, "_run_deterministic_scans", _fake_det)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_codex_audit", _fake_codex)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_llm_analysis", _fake_llm)

    result = await orchestrator.run(scan_mode="deep")

    # Parallel scan runs 2 Codex CLIs — no LLM API fallback
    assert called["llm"] is False
    assert any("codex failed" in warning for warning in result.warnings)


@pytest.mark.anyio
async def test_codex_failure_runs_llm_fallback_when_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_USE_CODEX", "true")
    monkeypatch.setenv("INPUT_CODEX_ONLY", "false")
    monkeypatch.setenv("INPUT_RUN_HARNESS", "false")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )

    def _fake_det(_self, _ingest):
        return []

    async def _fake_codex(*_args, **_kwargs):
        return LLMAnalysisResult(
            findings=[],
            success=False,
            usage=None,
            warning="codex failed",
        )

    called = {"llm": False}

    async def _fake_llm(*_args, **_kwargs):
        called["llm"] = True
        return LLMAnalysisResult(
            findings=[
                {
                    "severity": "P0",
                    "category": "LLM Failure",
                    "file_path": "<system>",
                    "line_start": 0,
                    "line_end": 0,
                    "message": "Managed LLM fallback executed",
                    "source": "system",
                }
            ],
            success=True,
            usage={"model": "gpt-5.3-codex", "tokens_in": 10, "tokens_out": 5},
            warning=None,
        )

    monkeypatch.setattr(AnalysisOrchestrator, "_run_deterministic_scans", _fake_det)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_codex_audit", _fake_codex)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_llm_analysis", _fake_llm)

    result = await orchestrator.run(scan_mode="deep")

    assert called["llm"] is True
    assert result.llm_success is True
    assert result.llm_count == 1
    assert result.llm_usage == {"model": "gpt-5.3-codex", "tokens_in": 10, "tokens_out": 5}
    assert any("codex failed" in warning for warning in result.warnings)


@pytest.mark.anyio
async def test_failed_llm_attempt_preserves_usage_for_comment_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_MODEL", "gpt-4.1-mini")
    monkeypatch.setenv("INPUT_MODEL_FALLBACK", "gpt-4.1-mini")
    monkeypatch.setenv("INPUT_RUN_HARNESS", "false")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )
    monkeypatch.setattr(
        orchestrator.context_builder,
        "build_context",
        lambda **_kwargs: BuiltContext(
            content="scan this",
            token_count=3,
            files_included=[],
            files_truncated=[],
            files_skipped=[],
            hotspots_included=[],
        ),
    )

    async def _fake_analyze(*_args, **_kwargs):
        return LLMResponse(
            content="",
            usage=LLMUsage(
                model="gpt-4.1-mini",
                tokens_in=0,
                tokens_out=0,
                cost_usd=0.0,
                latency_ms=12,
                provider="openai",
                route="managed_after_byo_capacity_failed",
                fallback_chain=(
                    "primary:openai/gpt-5.3-codex:capacity_failed"
                    "->fallback:google/gemini-2.5-flash:capacity_failed"
                    "->managed:openai/gpt-5.3-codex:failed"
                ),
            ),
            success=False,
            error="insufficient_quota",
        )

    monkeypatch.setattr(LLMClient, "analyze", _fake_analyze)

    result = await orchestrator._run_llm_analysis(
        ingest={},
        deterministic_findings=[],
        quick_learn=None,
        spec_context=None,
        scan_mode="deep",
        diff_content=None,
        changed_files=None,
    )

    assert result.success is False
    assert result.usage == {
        "model": "gpt-4.1-mini",
        "provider": "openai",
        "tokens_in": 0,
        "tokens_out": 0,
        "cost_usd": 0.0,
        "latency_ms": 12,
        "route": "managed_after_byo_capacity_failed",
        "fallback_chain": (
            "primary:openai/gpt-5.3-codex:capacity_failed"
            "->fallback:google/gemini-2.5-flash:capacity_failed"
            "->managed:openai/gpt-5.3-codex:failed"
        ),
    }


@pytest.mark.anyio
async def test_codex_skip_runs_managed_llm_fallback_without_byo_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INPUT_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("INPUT_SENTINELAYER_TOKEN", "sl_test_token")
    monkeypatch.setenv("INPUT_SENTINELAYER_MANAGED_LLM", "true")
    monkeypatch.setenv("INPUT_USE_CODEX", "true")
    monkeypatch.setenv("INPUT_CODEX_ONLY", "false")
    monkeypatch.setenv("INPUT_RUN_HARNESS", "false")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )

    def _fake_det(_self, _ingest):
        return []

    called = {"llm": False}

    async def _fake_llm(*_args, **_kwargs):
        called["llm"] = True
        return LLMAnalysisResult(
            findings=[],
            success=True,
            usage={"provider": "sentinelayer-managed"},
            warning=None,
        )

    monkeypatch.setattr(AnalysisOrchestrator, "_run_deterministic_scans", _fake_det)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_llm_analysis", _fake_llm)

    result = await orchestrator.run(scan_mode="deep")

    assert called["llm"] is True
    assert result.llm_success is True
    assert not any("Codex" in warning for warning in result.warnings)


@pytest.mark.anyio
async def test_use_codex_false_runs_llm_analysis_directly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_USE_CODEX", "false")
    monkeypatch.setenv("INPUT_RUN_HARNESS", "false")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )

    def _fake_det(_self, _ingest):
        return []

    async def _fake_codex(*_args, **_kwargs):
        raise AssertionError("Codex should not run when INPUT_USE_CODEX=false")

    called = {"llm": False}

    async def _fake_llm(*_args, **_kwargs):
        called["llm"] = True
        return LLMAnalysisResult(
            findings=[],
            success=True,
            usage=None,
            warning=None,
        )

    monkeypatch.setattr(AnalysisOrchestrator, "_run_deterministic_scans", _fake_det)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_codex_audit", _fake_codex)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_llm_analysis", _fake_llm)

    result = await orchestrator.run(scan_mode="deep")

    assert called["llm"] is True
    assert result.llm_success is True


@pytest.mark.anyio
async def test_codex_skip_is_silent_in_managed_mode_without_openai_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INPUT_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("INPUT_SENTINELAYER_TOKEN", "sl_test_token")
    monkeypatch.setenv("INPUT_SENTINELAYER_MANAGED_LLM", "true")
    config = OmarGateConfig()
    logger = OmarLogger("test-run")
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=logger,
        repo_root=tmp_path,
        allow_llm=True,
    )

    result = await orchestrator._run_codex_audit(
        ingest={"hotspots": {}},
        deterministic_findings=[],
        quick_learn=None,
        scan_mode="deep",
        diff_content=None,
    )

    assert result.success is False
    assert result.warning is None


@pytest.mark.anyio
async def test_missing_codex_and_fallback_credentials_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INPUT_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("INPUT_SENTINELAYER_TOKEN", raising=False)
    monkeypatch.setenv("INPUT_SENTINELAYER_MANAGED_LLM", "false")
    monkeypatch.setenv("INPUT_USE_CODEX", "true")
    monkeypatch.setenv("INPUT_CODEX_ONLY", "false")
    monkeypatch.setenv("INPUT_RUN_HARNESS", "false")
    monkeypatch.setenv("INPUT_LLM_FAILURE_POLICY", "block")
    orchestrator = AnalysisOrchestrator(
        config=OmarGateConfig(),
        logger=OmarLogger("test-run"),
        repo_root=tmp_path,
        allow_llm=True,
    )
    monkeypatch.setattr(
        AnalysisOrchestrator,
        "_run_deterministic_scans",
        lambda _self, _ingest: [],
    )

    result = await orchestrator.run(scan_mode="deep")

    assert result.llm_success is False
    assert result.llm_attempted is False
    assert result.llm_output_valid is False
    assert result.llm_failure_class == "missing_credentials"
    assert result.counts["P0"] == 1
    assert any(
        finding["category"] == "LLM Failure" and finding["source"] == "system"
        for finding in result.findings
    )


@pytest.mark.anyio
async def test_codex_and_api_fallback_failures_leave_blocking_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_USE_CODEX", "true")
    monkeypatch.setenv("INPUT_CODEX_ONLY", "false")
    monkeypatch.setenv("INPUT_RUN_HARNESS", "false")
    monkeypatch.setenv("INPUT_LLM_FAILURE_POLICY", "block")
    orchestrator = AnalysisOrchestrator(
        config=OmarGateConfig(),
        logger=OmarLogger("test-run"),
        repo_root=tmp_path,
        allow_llm=True,
    )
    monkeypatch.setattr(
        AnalysisOrchestrator,
        "_run_deterministic_scans",
        lambda _self, _ingest: [],
    )

    async def _fake_codex(*_args, **_kwargs):
        return LLMAnalysisResult(
            findings=[],
            success=False,
            usage=None,
            warning="codex failed",
            attempted=True,
            failure_class="codex_failure",
        )

    fallback_called = {"value": False}

    async def _fake_fallback(*_args, **_kwargs):
        fallback_called["value"] = True
        return orchestrator._llm_failure_result(
            deterministic_findings=[],
            attempted=True,
            failure_class="provider_failure",
            public_error="fallback provider failed",
            usage={
                "engine": "api",
                "provider": "openai",
                "model": "gpt-5.3-codex",
                "latency_ms": 25,
            },
        )

    monkeypatch.setattr(AnalysisOrchestrator, "_run_codex_audit", _fake_codex)
    monkeypatch.setattr(AnalysisOrchestrator, "_run_llm_analysis", _fake_fallback)

    result = await orchestrator.run(scan_mode="deep")

    assert fallback_called["value"] is True
    assert result.llm_success is False
    assert result.llm_attempted is True
    assert result.llm_output_valid is False
    assert result.llm_failure_class == "provider_failure"
    assert result.counts["P0"] == 1
