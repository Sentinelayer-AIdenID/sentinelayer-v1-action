"""Integration tests for complete analysis pipeline."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from omargate.analyze import AnalysisOrchestrator
from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger


@pytest.fixture
def test_repo(tmp_path):
    """Create a test repository with known vulnerabilities."""
    auth_file = tmp_path / "src" / "auth.py"
    auth_file.parent.mkdir(parents=True, exist_ok=True)
    api_key_value = "sk_test_" + ("a" * 20)
    auth_file.write_text(
        
            "# Authentication module\n"
            'API_KEY = "' + api_key_value + '"  # SEC-001: Hardcoded API key\n\n'
            "def login(username, password):\n"
            "    # TODO: Add rate limiting  # QUAL-001\n"
            "    query = f\"SELECT * FROM users WHERE username = '{username}'\"  # SEC-008: SQL injection\n"
            "    return execute(query)\n"
        
    )

    utils_file = tmp_path / "src" / "utils.py"
    utils_file.write_text(
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n"
    )

    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "test", "dependencies": {}}')

    return tmp_path


@pytest.fixture
def mock_config():
    """Create mock config."""
    with patch.dict(
        os.environ,
        {
            "INPUT_OPENAI_API_KEY": "sk_test_dummy",
            "INPUT_SCAN_MODE": "deep",
            "INPUT_SEVERITY_GATE": "P1",
        },
        clear=False,
    ):
        return OmarGateConfig()


@pytest.mark.anyio
async def test_full_pipeline_detects_vulnerabilities(test_repo, mock_config):
    """Full pipeline detects deterministic vulnerabilities."""
    logger = OmarLogger("test-run")

    with patch("omargate.analyze.orchestrator.LLMClient") as mock_llm:
        mock_instance = AsyncMock()
        mock_instance.analyze.return_value = MagicMock(
            success=True,
            content='{"no_findings": true}',
            usage=MagicMock(
                model="gpt-4o",
                tokens_in=100,
                tokens_out=50,
                cost_usd=0.01,
                latency_ms=500,
            ),
        )
        mock_llm.return_value = mock_instance

        orchestrator = AnalysisOrchestrator(
            config=mock_config,
            logger=logger,
            repo_root=test_repo,
        )

        result = await orchestrator.run(scan_mode="deep")

    assert result.deterministic_count > 0
    assert result.counts["P1"] > 0 or result.counts["P0"] > 0

    api_key_finding = next(
        (
            f
            for f in result.findings
            if "API" in f["category"] or "secret" in f["category"].lower()
        ),
        None,
    )
    assert api_key_finding is not None
    assert all(str(f.get("fix_plan") or "").strip() for f in result.findings)


@pytest.mark.anyio
async def test_pipeline_handles_llm_failure(test_repo, mock_config):
    """Pipeline gracefully handles LLM failure."""
    logger = OmarLogger("test-run")

    with patch("omargate.analyze.orchestrator.LLMClient") as mock_llm:
        mock_instance = AsyncMock()
        mock_instance.analyze.return_value = MagicMock(
            success=False,
            content="",
            error="API rate limited",
            usage=MagicMock(
                model="gpt-4o",
                tokens_in=0,
                tokens_out=0,
                cost_usd=0,
                latency_ms=0,
            ),
        )
        mock_llm.return_value = mock_instance

        orchestrator = AnalysisOrchestrator(
            config=mock_config,
            logger=logger,
            repo_root=test_repo,
        )

        result = await orchestrator.run(scan_mode="deep")

    assert result.deterministic_count > 0
    assert not result.llm_success
    assert len(result.warnings) > 0


@pytest.mark.anyio
async def test_pipeline_merges_findings_without_duplicates(test_repo, mock_config):
    """Pipeline deduplicates findings from different sources."""
    logger = OmarLogger("test-run")

    with patch("omargate.analyze.orchestrator.LLMClient") as mock_llm:
        mock_instance = AsyncMock()
        mock_instance.analyze.return_value = MagicMock(
            success=True,
            content=(
                '{"severity": "P1", "category": "secrets", "file_path": "src/auth.py", '
                '"line_start": 2, "message": "Hardcoded key", "recommendation": "Use env var", '
                '"confidence": 0.9}'
            ),
            usage=MagicMock(
                model="gpt-4o",
                tokens_in=100,
                tokens_out=50,
                cost_usd=0.01,
                latency_ms=500,
            ),
        )
        mock_llm.return_value = mock_instance

        orchestrator = AnalysisOrchestrator(
            config=mock_config,
            logger=logger,
            repo_root=test_repo,
        )

        result = await orchestrator.run(scan_mode="deep")

    line_findings = [
        f
        for f in result.findings
        if f["file_path"] == "src/auth.py" and f["line_start"] == 2
    ]

    assert len(line_findings) <= 1


@pytest.mark.anyio
async def test_pipeline_counts_severities_correctly(test_repo, mock_config):
    """Pipeline correctly counts findings by severity."""
    logger = OmarLogger("test-run")

    with patch("omargate.analyze.orchestrator.LLMClient") as mock_llm:
        mock_instance = AsyncMock()
        mock_instance.analyze.return_value = MagicMock(
            success=True,
            content='{"no_findings": true}',
            usage=MagicMock(
                model="gpt-4o",
                tokens_in=100,
                tokens_out=50,
                cost_usd=0.01,
                latency_ms=500,
            ),
        )
        mock_llm.return_value = mock_instance

        orchestrator = AnalysisOrchestrator(
            config=mock_config,
            logger=logger,
            repo_root=test_repo,
        )

        result = await orchestrator.run(scan_mode="deep")

    total_from_counts = (
        result.counts["P0"]
        + result.counts["P1"]
        + result.counts["P2"]
        + result.counts["P3"]
    )
    assert total_from_counts == result.counts["total"]
    assert total_from_counts == len(result.findings)
