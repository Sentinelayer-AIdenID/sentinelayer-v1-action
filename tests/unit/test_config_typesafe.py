from __future__ import annotations

import os
from pathlib import Path
import re

import pytest
from pydantic import SecretStr, ValidationError

from omargate.config import OmarGateConfig


def _action_contract() -> tuple[dict, dict]:
    """Read this action's literal input defaults and Omar env, using stdlib only.

    This asserts the repository's quoted-scalar contract, not general YAML
    parsing. Unexpected formatting fails explicitly instead of skipping checks.
    """
    text = (Path(__file__).resolve().parents[2] / "action.yml").read_text(encoding="utf-8")
    section = text.split("\ninputs:\n", 1)[1].split("\noutputs:\n", 1)[0]
    starts = list(re.finditer(r"^  ([a-z][a-z0-9_]*):\s*$", section, re.MULTILINE))
    assert starts, "Action must declare inputs"
    inputs = {}
    for index, start in enumerate(starts):
        block = section[start.end():starts[index + 1].start() if index + 1 < len(starts) else len(section)]
        default = re.search(r"^    default: '([^\n]*)'\s*$", block, re.MULTILINE)
        required = re.search(r"^    required: (true|false)\s*$", block, re.MULTILINE)
        assert default and required, f"Expected literal default/required for {start[1]}"
        inputs[start[1]] = {"default": default[1].replace("''", "'"), "required": required[1] == "true"}
    execute = re.search(
        r"^    - name: [^\n]+\n      id: omar\n(.*?)(?=^    - |\Z)",
        text, re.MULTILINE | re.DOTALL,
    )
    assert execute, "Action must declare the Omar execution step"
    env = dict(re.findall(r"^        (INPUT_[A-Z_]+): (.+)$", execute[1], re.MULTILINE))
    return inputs, env


@pytest.fixture(autouse=True)
def isolated_inputs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in list(os.environ):
        if name.upper().startswith("INPUT_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))


def test_typesafe_defaults_preserve_legacy_generator_settings() -> None:
    config = OmarGateConfig()

    assert config.llm_provider == "openai"
    assert config.typesafe_api_key.get_secret_value() == ""
    assert config.intent_model_pin.get_secret_value() == ""
    assert config.typesafe_timeout == 30
    assert config.typesafe_max_candidates == 50
    assert config.typesafe_fallback is True
    assert config.model == config.model_fallback == "gpt-4.1-mini"
    assert config.use_codex is True
    assert config.llm_failure_policy == "block"


def test_typesafe_inputs_load_with_funded_generator_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "LLM_PROVIDER": " TypeSafe ",
        "TYPESAFE_API_KEY": "typesafe-test-only",
        "OPENAI_API_KEY": "writer-test-only",
        "INTENT_MODEL_PIN": "model-under-test-1.14.0",
        "TYPESAFE_TIMEOUT": "12",
        "TYPESAFE_MAX_CANDIDATES": "7",
        "TYPESAFE_FALLBACK": "false",
        "MODEL": "gpt-5.3-codex",
        "MODEL_FALLBACK": "gpt-5.3-codex",
        "CODEX_MODEL": "gpt-5.3-codex",
    }
    for name, value in values.items():
        monkeypatch.setenv("INPUT_" + name, value)

    config = OmarGateConfig()
    assert config.llm_provider == "typesafe"
    assert isinstance(config.typesafe_api_key, SecretStr)
    assert config.typesafe_api_key.get_secret_value() == "typesafe-test-only"
    assert "typesafe-test-only" not in repr(config)
    assert "typesafe-test-only" not in config.model_dump_json()
    assert "writer-test-only" not in repr(config)
    assert "writer-test-only" not in config.model_dump_json()
    assert config.intent_model_pin.get_secret_value() == "model-under-test-1.14.0"
    assert config.typesafe_timeout == 12
    assert config.typesafe_max_candidates == 7
    assert config.typesafe_fallback is False
    assert config.model == config.model_fallback == config.codex_model == "gpt-5.3-codex"
    assert config.use_managed_llm_proxy() is False


@pytest.mark.parametrize("key", ["", " ", "\t\n"])
def test_typesafe_requires_nonblank_key(key: str) -> None:
    with pytest.raises(ValidationError, match="typesafe_api_key is required"):
        OmarGateConfig(
            llm_provider="typesafe", typesafe_api_key=key, openai_api_key="writer-test-only"
        , intent_model_pin="model-under-test-1.13.0")


@pytest.mark.parametrize(
    "model",
    ["model-under-test-latest", "model-under-test-preview", "model-under-test-1.13", "model-under-test-1.13.0-preview", "model-under-test-1.13.0\n", " model-under-test-1.13.0"],
)
def test_typesafe_requires_exact_pinned_model(model: str) -> None:
    with pytest.raises(ValidationError, match="intent_model_pin must be a pinned version"):
        OmarGateConfig(
            llm_provider="typesafe", typesafe_api_key="test-only",
            openai_api_key="writer-test-only", intent_model_pin=model,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("typesafe_timeout", 0),
        ("typesafe_timeout", 121),
        ("typesafe_timeout", 1.5),
        ("typesafe_max_candidates", 0),
        ("typesafe_max_candidates", 201),
        ("typesafe_max_candidates", 2.5),
    ],
)
def test_typesafe_limits_reject_out_of_range_or_fractional_values(field: str, value: float) -> None:
    with pytest.raises(ValidationError):
        OmarGateConfig(
            llm_provider="typesafe", typesafe_api_key="test-only",
            openai_api_key="writer-test-only", **{field: value},
         intent_model_pin="model-under-test-1.13.0")


@pytest.mark.parametrize(
    ("field", "value"),
    [("typesafe_timeout", 1), ("typesafe_timeout", 120), ("typesafe_max_candidates", 1), ("typesafe_max_candidates", 200)],
)
def test_typesafe_limits_accept_boundaries(field: str, value: int) -> None:
    config = OmarGateConfig(
        llm_provider="typesafe", typesafe_api_key="test-only",
        openai_api_key="writer-test-only", **{field: value},
     intent_model_pin="model-under-test-1.13.0")
    assert getattr(config, field) == value


def test_typesafe_rejects_codex_only() -> None:
    with pytest.raises(ValidationError, match="codex_only cannot be true"):
        OmarGateConfig(
            llm_provider="typesafe", typesafe_api_key="test-only",
            openai_api_key="writer-test-only", codex_only=True,
         intent_model_pin="model-under-test-1.13.0")


def test_typesafe_keeps_existing_managed_proxy_restriction() -> None:
    with pytest.raises(ValidationError, match="currently supports only llm_provider=openai"):
        OmarGateConfig(
            llm_provider="typesafe",
            typesafe_api_key="test-only",
            openai_api_key="writer-test-only",
            sentinelayer_managed_llm=True,
            sentinelayer_token="test-only",
         intent_model_pin="model-under-test-1.13.0")


@pytest.mark.parametrize("provider", ["anthropic", "google", "xai"])
def test_legacy_explicit_provider_key_checks_remain(provider: str) -> None:
    with pytest.raises(ValidationError, match=provider + "_api_key is required"):
        OmarGateConfig(llm_provider=provider)


def test_action_forwards_typesafe_inputs_with_matching_defaults() -> None:
    inputs, env = _action_contract()
    defaults = {
        "typesafe_api_key": "",
        "intent_model_pin": "",
        "typesafe_timeout": "30",
        "typesafe_max_candidates": "50",
        "typesafe_fallback": "true",
    }
    for name, default in defaults.items():
        assert inputs[name]["default"] == default
        assert inputs[name]["required"] is False
        assert env["INPUT_" + name.upper()] == "${{ inputs." + name + " }}"
    assert env["INPUT_MODEL"] == "${{ inputs.model }}"
    assert env["INPUT_MODEL_FALLBACK"] == "${{ inputs.model_fallback }}"
    assert inputs["model"]["default"] == ""
    assert inputs["model_fallback"]["default"] == ""
    assert inputs["codex_model"]["default"] == "gpt-5.3-codex"
    assert inputs["llm_failure_policy"]["default"] == "block"


@pytest.mark.parametrize("use_codex", [True, False])
@pytest.mark.parametrize("typesafe_fallback", [True, False])
def test_typesafe_defaults_all_generator_paths_to_funded_model(
    use_codex: bool, typesafe_fallback: bool,
) -> None:
    config = OmarGateConfig(
        llm_provider="typesafe", typesafe_api_key="typed-test-only",
        openai_api_key="writer-test-only", use_codex=use_codex,
        typesafe_fallback=typesafe_fallback,
     intent_model_pin="model-under-test-1.13.0")
    assert config.model == config.model_fallback == config.codex_model == "gpt-5.3-codex"
    assert config.llm_provider == "typesafe"
    assert config.use_managed_llm_proxy() is False


@pytest.mark.parametrize("key", ["", " ", "\t\n"])
@pytest.mark.parametrize("disable_optional_paths", [False, True])
def test_typesafe_requires_openai_writer_key_even_without_optional_fallback(
    key: str, disable_optional_paths: bool,
) -> None:
    with pytest.raises(ValidationError, match="openai_api_key is required for the writer"):
        OmarGateConfig(
            llm_provider="typesafe", typesafe_api_key="typed-test-only",
            openai_api_key=key, use_codex=not disable_optional_paths,
            typesafe_fallback=not disable_optional_paths,
            sentinelayer_token="token-cannot-fund-writer",
         intent_model_pin="model-under-test-1.13.0")


@pytest.mark.parametrize("field", ["model", "model_fallback", "codex_model"])
@pytest.mark.parametrize(
    "model",
    ["gpt-4.1-mini", "anthropic/claude", "google/gemini", "xai/grok", "gpt-5.3-codex-preview"],
)
def test_typesafe_rejects_conflicting_generator_model_overrides(field: str, model: str) -> None:
    with pytest.raises(ValidationError, match=field + " must be gpt-5.3-codex"):
        OmarGateConfig(
            llm_provider="typesafe", typesafe_api_key="typed-test-only",
            openai_api_key="writer-test-only", **{field: model},
         intent_model_pin="model-under-test-1.13.0")


@pytest.mark.parametrize("field", ["model", "model_fallback", "codex_model"])
def test_typesafe_rejects_conflicting_environment_models(
    monkeypatch: pytest.MonkeyPatch, field: str,
) -> None:
    monkeypatch.setenv("INPUT_" + field.upper(), "gpt-4.1-mini")
    with pytest.raises(ValidationError, match=field + " must be gpt-5.3-codex"):
        OmarGateConfig(
            llm_provider="typesafe", typesafe_api_key="typed-test-only",
            openai_api_key="writer-test-only",
         intent_model_pin="model-under-test-1.13.0")


def test_typesafe_accepts_only_exact_funded_explicit_models() -> None:
    config = OmarGateConfig(
        llm_provider="typesafe", typesafe_api_key="typed-test-only",
        openai_api_key="writer-test-only", model="gpt-5.3-codex",
        model_fallback="gpt-5.3-codex", codex_model="gpt-5.3-codex",
     intent_model_pin="model-under-test-1.13.0")
    assert config.model == config.model_fallback == config.codex_model == "gpt-5.3-codex"
    assert {"model", "model_fallback", "codex_model"} <= config.model_fields_set


@pytest.mark.parametrize("blank", ["", " ", "\t\n"])
def test_blank_automatic_generator_inputs_select_typesafe_defaults(blank: str) -> None:
    config = OmarGateConfig(
        llm_provider="typesafe", typesafe_api_key="typed-test-only",
        openai_api_key="writer-test-only", model=blank, model_fallback=blank,
     intent_model_pin="model-under-test-1.13.0")
    assert config.model == config.model_fallback == "gpt-5.3-codex"
    assert {"model", "model_fallback"}.isdisjoint(config.model_fields_set)


@pytest.mark.parametrize("model", ["", " gpt-5.3-codex", "gpt-5.3-codex "])
def test_typesafe_codex_model_must_match_exactly(model: str) -> None:
    with pytest.raises(ValidationError, match="codex_model must be gpt-5.3-codex"):
        OmarGateConfig(
            llm_provider="typesafe", typesafe_api_key="typed-test-only",
            openai_api_key="writer-test-only", codex_model=model,
         intent_model_pin="model-under-test-1.13.0")


@pytest.mark.parametrize("provider", ["openai", "anthropic", "google", "xai", "typesafe"])
def test_action_automatic_inputs_preserve_effective_provider_defaults(
    monkeypatch: pytest.MonkeyPatch, provider: str,
) -> None:
    inputs, _env = _action_contract()
    for name, definition in inputs.items():
        monkeypatch.setenv("INPUT_" + name.upper(), str(definition.get("default", "")))
    monkeypatch.setenv("INPUT_LLM_PROVIDER", provider)
    monkeypatch.setenv("INPUT_OPENAI_API_KEY", "writer-test-only")
    monkeypatch.setenv("INPUT_TYPESAFE_API_KEY", "typed-test-only")
    monkeypatch.setenv("INPUT_INTENT_MODEL_PIN", "model-under-test-1.13.0")
    if provider in {"anthropic", "google", "xai"}:
        monkeypatch.setenv("INPUT_" + provider.upper() + "_API_KEY", "alternate-test-only")

    config = OmarGateConfig()

    expected = "gpt-5.3-codex" if provider == "typesafe" else "gpt-4.1-mini"
    assert config.model == config.model_fallback == expected
    assert config.codex_model == "gpt-5.3-codex"
    assert config.llm_provider == provider


@pytest.mark.parametrize("provider", ["openai", "anthropic", "google", "xai"])
def test_other_providers_keep_explicit_generator_model_overrides(provider: str) -> None:
    keys = {provider + "_api_key": "provider-test-only"}
    config = OmarGateConfig(
        llm_provider=provider, model="existing-primary", model_fallback="existing-fallback",
        codex_model="existing-codex", **keys,
    )
    assert config.model == "existing-primary"
    assert config.model_fallback == "existing-fallback"
    assert config.codex_model == "existing-codex"
