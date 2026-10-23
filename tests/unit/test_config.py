from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from omargate.config import OmarGateConfig


def test_config_loads_defaults_and_masks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    cfg = OmarGateConfig()

    assert cfg.scan_mode == "pr-diff"
    assert cfg.severity_gate == "P1"
    assert cfg.run_harness is True
    assert cfg.pip_audit_ignore_ids == ""
    assert "sk_test_dummy" not in repr(cfg)


def test_config_parses_booleans(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_RUN_DETERMINISTIC_FIX", "true")
    monkeypatch.setenv("INPUT_TRAINING_OPT_IN", "true")
    monkeypatch.setenv("INPUT_TELEMETRY", "false")
    monkeypatch.setenv("INPUT_SHARE_METADATA", "true")
    monkeypatch.setenv("INPUT_SHARE_ARTIFACTS", "true")
    monkeypatch.setenv("INPUT_PUBLISH_GITHUB", "false")
    cfg = OmarGateConfig()

    assert cfg.run_deterministic_fix is True
    assert cfg.training_opt_in is True
    assert cfg.telemetry is False
    assert cfg.share_metadata is True
    assert cfg.share_artifacts is True
    assert cfg.publish_github is False


def test_invalid_severity_gate_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_SEVERITY_GATE", "P9")

    with pytest.raises(ValidationError):
        OmarGateConfig()


def test_config_is_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    cfg = OmarGateConfig()

    # Pydantic 2.x raises ValidationError for frozen models
    with pytest.raises((TypeError, ValidationError)):
        cfg.scan_mode = "deep"


def test_managed_llm_auto_enables_without_openai_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("INPUT_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("INPUT_SENTINELAYER_TOKEN", "sl_test_token")
    cfg = OmarGateConfig()
    assert cfg.use_managed_llm_proxy() is True


def test_managed_llm_explicit_requires_sentinelayer_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("INPUT_SENTINELAYER_TOKEN", raising=False)
    monkeypatch.setenv("INPUT_SENTINELAYER_MANAGED_LLM", "true")
    with pytest.raises(ValidationError):
        OmarGateConfig()


def test_config_normalizes_sentinelayer_spec_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_SENTINELAYER_SPEC_ID", "A" * 64)
    cfg = OmarGateConfig()
    assert cfg.sentinelayer_spec_id == "a" * 64


def test_config_auto_detects_sentinelayer_spec_id_from_workflow(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / "omar-gate.yml").write_text(
        "jobs:\n"
        "  gate:\n"
        "    with:\n"
        "      sentinelayer_spec_id: " + ("b" * 64) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.delenv("INPUT_SENTINELAYER_SPEC_ID", raising=False)

    cfg = OmarGateConfig()
    assert cfg.sentinelayer_spec_id == "b" * 64


def test_config_sanitizes_comment_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_COMMENT_TAG", "  Gemini !@# Provider  ")
    cfg = OmarGateConfig()
    assert cfg.comment_tag == "gemini-provider"


@pytest.mark.parametrize(("raw", "expected"), [("", ""), ("max", "max"), (" XHigh ", "xhigh"), ("low", "low")])
def test_reasoning_effort_accepts_known_values(monkeypatch: pytest.MonkeyPatch, raw: str, expected: str) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_REASONING_EFFORT", raw)

    assert OmarGateConfig().reasoning_effort == expected


def test_reasoning_effort_rejects_unknown_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "sk_test_dummy")
    monkeypatch.setenv("INPUT_REASONING_EFFORT", "ultra")

    with pytest.raises(ValidationError):
        OmarGateConfig()


def test_reasoning_effort_requires_byo_openai_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INPUT_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("INPUT_LLM_PROVIDER", "openai")
    monkeypatch.setenv("INPUT_SENTINELAYER_MANAGED_LLM", "true")
    monkeypatch.setenv("INPUT_REASONING_EFFORT", "max")

    with pytest.raises(ValidationError, match="requires a BYO openai_api_key"):
        OmarGateConfig()
