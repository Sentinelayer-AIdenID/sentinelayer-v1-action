from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from omargate.analyze.llm.llm_client import LLMClient, LLMResponse, LLMUsage


def _make_response(content: str = "ok", input_tokens: int = 10, output_tokens: int = 5):
    usage = SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens)
    return SimpleNamespace(usage=usage, output_text=content, model="gpt-5.3-codex")


@pytest.mark.anyio
async def test_llm_client_success() -> None:
    """Successful API call returns content and usage."""
    client = LLMClient(api_key="test", max_retries=1)
    response = _make_response("hello", 12, 3)

    fake_client = SimpleNamespace(
        responses=SimpleNamespace(create=AsyncMock(return_value=response))
    )
    client._client = fake_client

    result = await client.analyze("system", "user")

    assert result.success is True
    assert result.content == "hello"
    assert result.usage.tokens_in == 12
    assert result.usage.tokens_out == 3
    assert result.usage.model == client.primary_model


@pytest.mark.anyio
async def test_llm_client_retry_on_timeout() -> None:
    """Client retries on timeout, then succeeds."""
    client = LLMClient(api_key="test", max_retries=2)
    response = _make_response("ok", 5, 2)

    create_mock = AsyncMock(side_effect=[asyncio.TimeoutError(), response])
    fake_client = SimpleNamespace(
        responses=SimpleNamespace(create=create_mock)
    )
    client._client = fake_client

    with patch("omargate.analyze.llm.llm_client.asyncio.sleep", new=AsyncMock()) as sleep_mock:
        result = await client.analyze("system", "user")

    assert result.success is True
    assert create_mock.call_count == 2
    sleep_mock.assert_awaited_once_with(1)


@pytest.mark.anyio
async def test_llm_client_fallback_to_secondary_model() -> None:
    """Falls back to secondary model when primary fails."""
    client = LLMClient(api_key="test")

    primary_fail = LLMResponse(
        content="",
        usage=LLMUsage(model=client.primary_model, tokens_in=0, tokens_out=0, cost_usd=0.0, latency_ms=0),
        success=False,
        error="primary failed",
    )
    fallback_success = LLMResponse(
        content="fallback",
        usage=LLMUsage(model=client.fallback_model, tokens_in=1, tokens_out=1, cost_usd=0.0, latency_ms=1),
        success=True,
    )

    with patch.object(
        client,
        "_call_with_retry",
        new=AsyncMock(side_effect=[primary_fail, fallback_success]),
    ) as retry_mock:
        result = await client.analyze("system", "user")

    assert result.success is True
    assert result.content == "fallback"
    assert retry_mock.call_count == 2
    assert retry_mock.call_args_list[0].args[0] == client.primary_model
    assert retry_mock.call_args_list[1].args[0] == client.fallback_model


@pytest.mark.anyio
async def test_llm_client_returns_error_when_both_fail() -> None:
    """Returns error response when both models fail."""
    client = LLMClient(api_key="test")

    primary_fail = LLMResponse(
        content="",
        usage=LLMUsage(model=client.primary_model, tokens_in=0, tokens_out=0, cost_usd=0.0, latency_ms=0),
        success=False,
        error="primary error",
    )
    fallback_fail = LLMResponse(
        content="",
        usage=LLMUsage(model=client.fallback_model, tokens_in=0, tokens_out=0, cost_usd=0.0, latency_ms=0),
        success=False,
        error="fallback error",
    )

    with patch.object(
        client,
        "_call_with_retry",
        new=AsyncMock(side_effect=[primary_fail, fallback_fail]),
    ):
        result = await client.analyze("system", "user")

    assert result.success is False
    assert result.error is not None
    assert "Primary failed" in result.error
    assert "Fallback failed" in result.error


@pytest.mark.anyio
async def test_llm_client_redacts_provider_payloads_in_combined_error() -> None:
    client = LLMClient(api_key="test", fallback_model="gemini-2.5-flash")

    primary_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.primary_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=0,
        ),
        success=False,
        error="".join(('Error code: 429 - insufficient_quota sk', '-testtesttesttest')),
    )
    fallback_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.fallback_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=0,
            provider="google",
        ),
        success=False,
        error="403 PERMISSION_DENIED consumer projects/123456789012 suspended",
    )

    with patch.object(
        client,
        "_call_with_retry",
        new=AsyncMock(side_effect=[primary_fail, fallback_fail]),
    ):
        result = await client.analyze("system", "user")

    assert result.success is False
    assert result.error is not None
    assert "Primary failed" in result.error
    assert "Fallback failed" in result.error
    assert "insufficient_quota" in result.error
    assert "PERMISSION_DENIED" in result.error
    assert "123456789012" not in result.error
    assert "".join(('sk', '-testtesttesttest')) not in result.error


@pytest.mark.anyio
async def test_managed_capacity_fallback_runs_once_after_byo_quota_failures() -> None:
    client = LLMClient(
        api_key="".join(('sk', '-byo')),
        primary_model="gpt-5.3-codex",
        fallback_model="gemini-2.5-flash",
        google_api_key="google-byo",
        managed_capacity_fallback=True,
        sentinelayer_token="sl_test_token",
        max_retries=1,
    )
    primary_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.primary_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=0,
            provider="openai",
        ),
        success=False,
        error="Error code: 429 - insufficient_quota",
    )
    fallback_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.fallback_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=0,
            provider="google",
        ),
        success=False,
        error="429 RESOURCE_EXHAUSTED generate_content_free_tier_requests",
    )
    managed_success = LLMResponse(
        content="managed-ok",
        usage=LLMUsage(
            model=client.primary_model,
            tokens_in=12,
            tokens_out=4,
            cost_usd=0.02,
            latency_ms=31,
            provider="openai",
            route="managed_after_byo_capacity",
        ),
        success=True,
    )

    with (
        patch.object(
            client,
            "_call_with_retry",
            new=AsyncMock(side_effect=[primary_fail, fallback_fail]),
        ) as retry_mock,
        patch.object(
            client,
            "_call_managed_proxy",
            new=AsyncMock(return_value=managed_success),
        ) as managed_mock,
    ):
        result = await client.analyze("system", "user", max_tokens=256)

    assert result.success is True
    assert result.content == "managed-ok"
    assert retry_mock.call_count == 2
    managed_mock.assert_awaited_once()
    assert managed_mock.await_args.kwargs["model"] == client.primary_model
    assert managed_mock.await_args.kwargs["route"] == "managed_after_byo_capacity"
    assert result.usage.route == "managed_after_byo_capacity"
    assert result.usage.fallback_chain is not None
    assert "primary:openai/gpt-5.3-codex:capacity_failed" in result.usage.fallback_chain
    assert "fallback:google/gemini-2.5-flash:capacity_failed" in result.usage.fallback_chain
    assert "managed:openai/gpt-5.3-codex:success" in result.usage.fallback_chain


@pytest.mark.anyio
async def test_managed_capacity_fallback_does_not_run_for_non_capacity_errors() -> None:
    client = LLMClient(
        api_key="".join(('sk', '-byo')),
        primary_model="gpt-5.3-codex",
        fallback_model="gpt-4.1-mini",
        managed_capacity_fallback=True,
        sentinelayer_token="sl_test_token",
        max_retries=1,
    )
    primary_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.primary_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=0,
            provider="openai",
        ),
        success=False,
        error="Error code: 429 - insufficient_quota",
    )
    fallback_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.fallback_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=0,
            provider="openai",
        ),
        success=False,
        error="response did not match Omar JSON schema",
    )

    with (
        patch.object(
            client,
            "_call_with_retry",
            new=AsyncMock(side_effect=[primary_fail, fallback_fail]),
        ),
        patch.object(client, "_call_managed_proxy", new=AsyncMock()) as managed_mock,
    ):
        result = await client.analyze("system", "user", max_tokens=256)

    assert result.success is False
    assert "Primary failed" in str(result.error)
    assert "Fallback failed" in str(result.error)
    managed_mock.assert_not_awaited()


@pytest.mark.anyio
async def test_managed_capacity_fallback_failure_fails_closed() -> None:
    client = LLMClient(
        api_key="".join(('sk', '-byo')),
        primary_model="gpt-5.3-codex",
        fallback_model="gemini-2.5-flash",
        google_api_key="google-byo",
        managed_capacity_fallback=True,
        sentinelayer_token="sl_test_token",
        max_retries=1,
    )
    primary_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.primary_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=0,
            provider="openai",
        ),
        success=False,
        error="Error code: 429 - insufficient_quota",
    )
    fallback_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.fallback_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=0,
            provider="google",
        ),
        success=False,
        error="429 RESOURCE_EXHAUSTED generate_content_free_tier_requests",
    )
    managed_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.primary_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=20,
            provider="openai",
            route="managed_after_byo_capacity",
        ),
        success=False,
        error="Managed LLM proxy timeout",
    )

    with (
        patch.object(
            client,
            "_call_with_retry",
            new=AsyncMock(side_effect=[primary_fail, fallback_fail]),
        ),
        patch.object(
            client,
            "_call_managed_proxy",
            new=AsyncMock(return_value=managed_fail),
        ) as managed_mock,
    ):
        result = await client.analyze("system", "user", max_tokens=256)

    assert result.success is False
    assert "Primary failed" in str(result.error)
    assert "Fallback failed" in str(result.error)
    assert "Managed fallback failed" in str(result.error)
    managed_mock.assert_awaited_once()
    assert result.usage.route == "managed_after_byo_capacity_failed"
    assert result.usage.fallback_chain is not None
    assert "managed:openai/gpt-5.3-codex:failed" in result.usage.fallback_chain


def test_cost_estimation() -> None:
    """Cost estimation matches expected pricing."""
    client = LLMClient(api_key="test")
    cost = client.estimate_cost("gpt-4o", tokens_in=10000, tokens_out=1000)
    expected = (10000 / 1000 * 0.005) + (1000 / 1000 * 0.015)
    assert abs(cost - expected) < 0.001


@pytest.mark.anyio
async def test_managed_proxy_path_is_used_when_enabled() -> None:
    client = LLMClient(
        api_key="",
        llm_provider="openai",
        managed_llm=True,
        sentinelayer_token="sl_test_token",
    )

    managed_success = LLMResponse(
        content="managed",
        usage=LLMUsage(
            model=client.primary_model,
            tokens_in=42,
            tokens_out=10,
            cost_usd=0.01,
            latency_ms=100,
            provider="openai",
        ),
        success=True,
    )

    with patch.object(
        client,
        "_call_managed_proxy",
        new=AsyncMock(return_value=managed_success),
    ) as proxy_mock:
        result = await client._call_with_retry(client.primary_model, "system", "user", 256)

    assert result.success is True
    assert result.content == "managed"
    proxy_mock.assert_awaited()


@pytest.mark.anyio
async def test_managed_proxy_error_propagates() -> None:
    client = LLMClient(
        api_key="",
        llm_provider="openai",
        managed_llm=True,
        sentinelayer_token="sl_test_token",
        max_retries=1,
    )

    managed_fail = LLMResponse(
        content="",
        usage=LLMUsage(
            model=client.primary_model,
            tokens_in=0,
            tokens_out=0,
            cost_usd=0.0,
            latency_ms=12,
            provider="openai",
        ),
        success=False,
        error="Free trial expired — add your own API key",
    )

    with patch.object(
        client,
        "_call_managed_proxy",
        new=AsyncMock(return_value=managed_fail),
    ):
        result = await client._call_with_retry(client.primary_model, "system", "user", 256)

    assert result.success is False
    assert "Free trial expired" in str(result.error)


@pytest.mark.anyio
async def test_managed_oidc_request_overrides_existing_audience(monkeypatch) -> None:
    client = LLMClient(
        api_key="",
        llm_provider="openai",
        managed_llm=True,
        sentinelayer_token="sl_test_token",
    )

    monkeypatch.setenv(
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "https://token.actions.githubusercontent.com/id?audience=sts.amazonaws.com&foo=bar",
    )
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-token")
    monkeypatch.setenv("SENTINELAYER_OIDC_AUDIENCE", "sentinelayer")

    requested_urls: list[str] = []

    class _FakeResponse:
        status_code = 200

        @staticmethod
        def json() -> dict:
            return {"value": "oidc-jwt"}

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url: str, headers: dict):
            requested_urls.append(url)
            return _FakeResponse()

    monkeypatch.setattr("omargate.analyze.llm.llm_client.httpx.AsyncClient", _FakeAsyncClient)

    token = await client._fetch_managed_oidc_token()

    assert token == "oidc-jwt"
    assert len(requested_urls) == 1
    assert "audience=sentinelayer" in requested_urls[0]
    assert "audience=sts.amazonaws.com" not in requested_urls[0]
