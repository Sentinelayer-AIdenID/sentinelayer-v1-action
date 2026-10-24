from __future__ import annotations

import builtins
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from omargate.analyze.llm.llm_client import LLMClient
from omargate.analyze.llm.providers import detect_provider_from_model
from omargate.analyze.llm.providers.anthropic_provider import AnthropicProvider
from omargate.analyze.llm.providers.base import ProviderResponse
from omargate.analyze.llm.providers.gemini_provider import GeminiProvider
from omargate.analyze.llm.providers.openai_provider import OpenAIProvider
from omargate.analyze.llm.providers.xai_provider import XAIProvider


@pytest.mark.anyio
async def test_openai_provider_calls_responses_create() -> None:
    response = SimpleNamespace(
        usage=SimpleNamespace(input_tokens=12, output_tokens=3),
        output_text="hello",
    )
    create_mock = AsyncMock(return_value=response)
    fake_client = SimpleNamespace(responses=SimpleNamespace(create=create_mock))

    provider = OpenAIProvider(api_key="".join(('sk', '-test')), client_getter=lambda: fake_client)
    out = await provider.call(
        model="gpt-4.1",
        system="SYS",
        user="USER",
        max_tokens=123,
        temperature=0.2,
        timeout=10,
    )

    create_mock.assert_awaited_once()
    kwargs = create_mock.call_args.kwargs
    assert kwargs["model"] == "gpt-4.1"
    assert kwargs["instructions"] == "SYS"
    assert kwargs["input"] == "USER"
    assert kwargs["max_output_tokens"] == 123
    assert kwargs["temperature"] == 0.2
    assert out.content == "hello"
    assert out.input_tokens == 12
    assert out.output_tokens == 3


@pytest.mark.anyio
async def test_funded_codex_uses_responses_defaults_and_retains_reported_model() -> None:
    create = AsyncMock(return_value=SimpleNamespace(
        model="gpt-5.3-codex", usage=SimpleNamespace(input_tokens=12, output_tokens=3),
        output_text="explanation",
    ))
    provider = OpenAIProvider(
        api_key="fixture", client_getter=lambda: SimpleNamespace(responses=SimpleNamespace(create=create)),
    )
    out = await provider.call(
        model="gpt-5.3-codex", system="fixed verdicts", user="bound evidence",
        max_tokens=123, temperature=0.1, timeout=10,
    )
    assert create.call_args.kwargs == {
        "model": "gpt-5.3-codex", "instructions": "fixed verdicts",
        "input": "bound evidence", "max_output_tokens": 123,
    }
    assert out.model == "gpt-5.3-codex"


@pytest.mark.anyio
async def test_openai_provider_retains_actual_returned_model() -> None:
    create = AsyncMock(return_value=SimpleNamespace(
        model="fixture-returned-model", usage=None, output_text="text",
    ))
    provider = OpenAIProvider(
        api_key="fixture", client_getter=lambda: SimpleNamespace(responses=SimpleNamespace(create=create)),
    )
    result = await provider.call(
        model="gpt-5.3-codex", system="s", user="u", max_tokens=1,
        temperature=0.1, timeout=10,
    )
    assert result.model == "fixture-returned-model"


@pytest.mark.anyio
async def test_llm_client_usage_retains_reported_model_across_openai_boundary(monkeypatch) -> None:
    reported_model = "fixture-returned-model"
    create = AsyncMock(return_value=SimpleNamespace(
        model=reported_model, usage=SimpleNamespace(input_tokens=12, output_tokens=3),
        output_text="bound explanation",
    ))
    provider = OpenAIProvider(
        api_key="fixture", client_getter=lambda: SimpleNamespace(responses=SimpleNamespace(create=create)),
    )
    estimate = Mock(return_value=0.125)
    monkeypatch.setattr(provider, "estimate_cost", estimate)
    client = LLMClient(
        api_key="fixture", primary_model="gpt-5.3-codex",
        fallback_model="gpt-5.3-codex", llm_provider="openai",
    )
    monkeypatch.setattr(client, "_get_provider", lambda name: provider)

    result = await client.analyze("fixed verdicts", "bound evidence")

    assert result.success and result.content == "bound explanation"
    assert create.await_count == 1
    assert create.call_args.kwargs["model"] == "gpt-5.3-codex"
    assert "temperature" not in create.call_args.kwargs
    assert result.usage.model == reported_model
    assert result.usage.provider == "openai"
    assert result.usage.tokens_in == 12 and result.usage.tokens_out == 3
    estimate.assert_called_once_with(reported_model, 12, 3)
    assert result.usage.cost_usd == 0.125  # Synthetic estimate, not measured billing.


@pytest.mark.anyio
async def test_anthropic_provider_calls_messages_create(monkeypatch: pytest.MonkeyPatch) -> None:
    # Fake anthropic module with AsyncAnthropic client.
    messages_create = AsyncMock(
        return_value=SimpleNamespace(
            content=[SimpleNamespace(text="ok")],
            usage=SimpleNamespace(input_tokens=10, output_tokens=4),
        )
    )

    class _AsyncAnthropic:
        def __init__(self, api_key: str):
            self.messages = SimpleNamespace(create=messages_create)

    fake_anthropic = types.SimpleNamespace(AsyncAnthropic=_AsyncAnthropic)
    monkeypatch.setitem(__import__("sys").modules, "anthropic", fake_anthropic)

    provider = AnthropicProvider(api_key="anthropic-key")
    out = await provider.call(
        model="claude-sonnet-4-5-20250929",
        system="SYS",
        user="USER",
        max_tokens=321,
        temperature=0.1,
        timeout=10,
    )

    messages_create.assert_awaited_once()
    kwargs = messages_create.call_args.kwargs
    assert kwargs["model"] == "claude-sonnet-4-5-20250929"
    assert kwargs["system"] == "SYS"
    assert kwargs["max_tokens"] == 321
    assert kwargs["temperature"] == 0.1
    assert kwargs["messages"] == [{"role": "user", "content": "USER"}]
    assert out.content == "ok"
    assert out.input_tokens == 10
    assert out.output_tokens == 4


def test_missing_anthropic_sdk_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "anthropic":
            raise ImportError("nope")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    provider = AnthropicProvider(api_key="x")
    with pytest.raises(RuntimeError, match=r"Install `anthropic` package"):
        _ = provider.client


@pytest.mark.anyio
async def test_gemini_provider_calls_generate_content(monkeypatch: pytest.MonkeyPatch) -> None:
    generate_content = Mock()
    response_obj = SimpleNamespace(
        text="gemini-ok",
        usage_metadata=SimpleNamespace(prompt_token_count=7, candidates_token_count=2),
    )

    class _Models:
        def generate_content(self, **kwargs):
            # GeminiProvider runs this in a worker thread (sync API).
            generate_content(**kwargs)
            return response_obj

    class _Client:
        def __init__(self, api_key: str):
            self.models = _Models()

    fake_genai = types.SimpleNamespace(Client=_Client)
    fake_google = types.SimpleNamespace(genai=fake_genai)
    monkeypatch.setitem(__import__("sys").modules, "google", fake_google)
    monkeypatch.setitem(__import__("sys").modules, "google.genai", fake_genai)

    provider = GeminiProvider(api_key="google-key")
    out = await provider.call(
        model="gemini-2.5-flash",
        system="SYS",
        user="USER",
        max_tokens=111,
        temperature=0.3,
        timeout=10,
    )

    assert generate_content.call_count == 1
    kwargs = generate_content.call_args.kwargs
    assert kwargs["model"] == "gemini-2.5-flash"
    assert kwargs["contents"] == "USER"
    assert kwargs["config"]["system_instruction"] == "SYS"
    assert kwargs["config"]["max_output_tokens"] == 111
    assert kwargs["config"]["temperature"] == 0.3
    assert out.content == "gemini-ok"
    assert out.input_tokens == 7
    assert out.output_tokens == 2


def test_missing_google_sdk_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "google":
            raise ImportError("nope")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    provider = GeminiProvider(api_key="x")
    with pytest.raises(RuntimeError, match=r"Install `google-genai` package"):
        _ = provider.client


def test_xai_provider_uses_custom_base_url() -> None:
    with patch("openai.AsyncOpenAI") as async_openai:
        fake_create = AsyncMock(
            return_value=SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="xai-ok"))],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=2),
            )
        )
        fake_client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=fake_create)))
        async_openai.return_value = fake_client

        provider = XAIProvider(api_key="xai-key")

        # Force client initialization
        _ = provider.client
        async_openai.assert_called_once()
        assert async_openai.call_args.kwargs["base_url"] == "https://api.x.ai/v1"


def test_provider_auto_detection_from_model_name() -> None:
    assert detect_provider_from_model("claude-sonnet-4-5-20250929") == "anthropic"
    assert detect_provider_from_model("gemini-2.5-flash") == "google"
    assert detect_provider_from_model("grok-3") == "xai"
    assert detect_provider_from_model("gpt-4.1") == "openai"


@pytest.mark.anyio
async def test_cross_provider_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    client = LLMClient(
        api_key="openai-key",
        primary_model="claude-sonnet-4-5-20250929",
        fallback_model="gpt-4.1",
        llm_provider="anthropic",
        anthropic_api_key="anthropic-key",
    )

    anthropic = SimpleNamespace(
        call=AsyncMock(side_effect=RuntimeError("boom")),
        estimate_cost=lambda *_args, **_kwargs: 0.0,
    )
    openai = SimpleNamespace(
        call=AsyncMock(
            return_value=ProviderResponse(
                content="fallback-ok",
                input_tokens=1,
                output_tokens=1,
                model="gpt-4.1",
            )
        ),
        estimate_cost=lambda *_args, **_kwargs: 0.0,
    )

    # Override provider factory so we don't need real SDKs.
    def fake_get_provider(name: str):
        return anthropic if name == "anthropic" else openai

    monkeypatch.setattr(client, "_get_provider", fake_get_provider)

    result = await client.analyze("SYS", "USER")
    assert result.success is True
    assert result.content == "fallback-ok"
    assert result.usage.model == "gpt-4.1"
    assert result.usage.provider == "openai"


def test_cost_estimation_per_provider() -> None:
    openai = OpenAIProvider(api_key="x")
    assert abs(openai.estimate_cost("gpt-4o", 10000, 1000) - ((10 * 0.005) + (1 * 0.015))) < 1e-6

    anthropic = AnthropicProvider(api_key="x")
    assert abs(anthropic.estimate_cost("claude-sonnet-4-5-20250929", 1_000_000, 1_000_000) - 18.0) < 1e-6

    gemini = GeminiProvider(api_key="x")
    assert abs(gemini.estimate_cost("gemini-2.5-flash", 1_000_000, 1_000_000) - 0.75) < 1e-6

    xai = XAIProvider(api_key="x")
    assert abs(xai.estimate_cost("grok-3", 1_000_000, 1_000_000) - 18.0) < 1e-6
