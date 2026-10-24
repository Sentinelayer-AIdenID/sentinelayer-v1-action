from pathlib import Path

import yaml

from omargate.analyze.llm.providers import detect_provider_from_model
from omargate.config import OmarGateConfig


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/security-review.yml"


def _workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_omar_review_uses_only_pinned_sol_with_no_provider_fallback():
    workflow = _workflow()
    jobs = workflow["jobs"]
    assert {"quality-gates", "build-provenance", "secret-scanning", "omar-review"} <= set(jobs)
    review = jobs["omar-review"]
    assert set(review["needs"]) == {"quality-gates", "build-provenance", "secret-scanning"}
    steps = review["steps"]
    step = next(step for step in steps if step.get("name") == "Omar Gate (Host Runner)")
    env = step["env"]
    assert env["INPUT_LLM_PROVIDER"] == "openai"
    assert env["INPUT_MODEL"] == "gpt-6.1-sol"
    assert env["INPUT_CODEX_MODEL"] == "gpt-6.1-sol"
    assert env["INPUT_MODEL_FALLBACK"] == "gpt-6.1-sol"
    assert env["INPUT_REVIEW_ROUTING"] == "legacy"
    assert env["INPUT_USE_CODEX"] == "false"
    assert env["INPUT_CODEX_ONLY"] == "false"
    assert env["INPUT_LLM_FAILURE_POLICY"] == "block"
    assert env["INPUT_SENTINELAYER_MANAGED_LLM"] == "false"
    assert {"INPUT_ANTHROPIC_API_KEY", "INPUT_GOOGLE_API_KEY", "INPUT_XAI_API_KEY"}.isdisjoint(env)
    assert all("claude" not in str(step).lower() for step in steps)
    assert all("codex" not in str(step).lower() for step in steps if step.get("name") != "Omar Gate (Host Runner)")
    assert all("npm" not in str(step).lower() for step in steps)
    assert "OPENAI_API_KEY" in next(step for step in steps if step.get("name") == "Require OPENAI_API_KEY for OpenAI review")["env"]


def test_pinned_workflow_environment_selects_only_openai_api(monkeypatch):
    review = _workflow()["jobs"]["omar-review"]
    env = next(step for step in review["steps"] if step.get("name") == "Omar Gate (Host Runner)")["env"]
    for name, value in env.items():
        if name.startswith("INPUT_") and isinstance(value, str) and "${{" not in value:
            monkeypatch.setenv(name, value)
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("INPUT_SENTINELAYER_TOKEN", "test-sentinelayer-token")

    config = OmarGateConfig()

    assert config.llm_provider == "openai"
    assert config.model == config.model_fallback == config.codex_model == "gpt-6.1-sol"
    assert config.review_routing == "legacy"
    assert detect_provider_from_model(config.model, default_provider=config.llm_provider) == "openai"
    assert config.use_codex is False
    assert config.codex_only is False
    assert config.sentinelayer_managed_llm is False
    assert config.use_managed_llm_proxy() is False
    assert config.llm_failure_policy == "block"


def test_legacy_intent_canary_fails_without_model_call():
    trial = _workflow()["jobs"]["intent-canary"]
    assert "workflow_dispatch" in trial["if"]
    executable_steps = [step for step in trial["steps"] if "run" in step]
    assert len(executable_steps) == 1
    assert "exit 1" in executable_steps[0]["run"]
    assert all("INPUT_TYPESAFE_API_KEY" not in str(step) for step in trial["steps"])
