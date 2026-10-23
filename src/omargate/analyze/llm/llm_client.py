from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from .providers import (
    AnthropicProvider,
    GeminiProvider,
    OpenAIProvider,
    XAIProvider,
    detect_provider_from_model,
)
from ...redaction import sanitize_public_error


@dataclass
class LLMUsage:
    model: str
    tokens_in: int | None  # None: no response reported usage, which stays unknown
    tokens_out: int | None
    cost_usd: float | None
    latency_ms: int
    provider: str = "openai"
    route: str = "byo"
    fallback_chain: Optional[str] = None
    raw_usage: Optional[dict] = None


def _unreturned_usage(provider: str, latency_ms: int = 0, **fields) -> LLMUsage:
    """A call without a response reports no model, and its billed usage is unknown, not zero."""
    return LLMUsage("unknown", None, None, None, latency_ms, provider=provider, **fields)


@dataclass
class LLMResponse:
    content: str
    usage: LLMUsage
    success: bool
    error: Optional[str] = None


class LLMClient:
    """LLM SDK wrapper with retry and fallback across providers."""

    def __init__(
        self,
        api_key: str,
        primary_model: str = "gpt-5.3-codex",
        fallback_model: str = "gpt-5.2-codex",
        llm_provider: str = "openai",
        anthropic_api_key: str = "",
        google_api_key: str = "",
        xai_api_key: str = "",
        timeout_seconds: int = 120,
        max_retries: int = 2,
        managed_llm: bool = False,
        managed_capacity_fallback: bool = False,
        sentinelayer_token: str = "",
        managed_api_url: str = "https://api.sentinelayer.com",
        reasoning_effort: str | None = None,
        allow_fallback: bool = True,
    ) -> None:
        # Back-compat: api_key is the OpenAI key used for OpenAI calls and fallback.
        self.api_key = api_key
        self.primary_model = primary_model
        self.fallback_model = fallback_model
        self.llm_provider = llm_provider
        self.anthropic_api_key = anthropic_api_key
        self.google_api_key = google_api_key
        self.xai_api_key = xai_api_key
        self.timeout = timeout_seconds
        self.max_retries = max_retries
        self.managed_llm = managed_llm
        self.managed_capacity_fallback = managed_capacity_fallback
        self.sentinelayer_token = sentinelayer_token
        self.managed_api_url = managed_api_url
        self.reasoning_effort = reasoning_effort
        self.allow_fallback = allow_fallback
        self._client = None
        self._providers: dict[str, object] = {}
        self._managed_oidc_token: Optional[str] = None

    @property
    def client(self):
        """Lazy initialize OpenAI client."""
        if self._client is None:
            from openai import AsyncOpenAI

            self._client = AsyncOpenAI(api_key=self.api_key, **({"max_retries": 0} if self.reasoning_effort else {}))
        return self._client

    def _get_provider(self, provider_name: str):
        if provider_name in self._providers:
            return self._providers[provider_name]

        if provider_name == "openai":
            provider = OpenAIProvider(
                api_key=self.api_key,
                client_getter=lambda: self.client,
                reasoning_effort=self.reasoning_effort,
            )
        elif provider_name == "anthropic":
            provider = AnthropicProvider(api_key=self.anthropic_api_key)
        elif provider_name == "google":
            provider = GeminiProvider(api_key=self.google_api_key)
        elif provider_name == "xai":
            provider = XAIProvider(api_key=self.xai_api_key)
        else:
            raise ValueError(f"Unknown LLM provider: {provider_name}")

        self._providers[provider_name] = provider
        return provider

    async def _fetch_managed_oidc_token(self) -> str:
        if self._managed_oidc_token is not None:
            return self._managed_oidc_token

        request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        if not request_url or not request_token:
            self._managed_oidc_token = ""
            return ""

        audience = (os.environ.get("SENTINELAYER_OIDC_AUDIENCE") or "sentinelayer").strip()
        if audience:
            parsed = urlparse(request_url)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query["audience"] = audience
            request_url = urlunparse(parsed._replace(query=urlencode(query)))

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    request_url,
                    headers={
                        "Authorization": f"Bearer {request_token}",
                        "Accept": "application/json",
                    },
                )
            if response.status_code != 200:
                self._managed_oidc_token = ""
                return ""
            payload = response.json()
            token = str(payload.get("value") or payload.get("id_token") or "")
            self._managed_oidc_token = token
            return token
        except Exception:
            self._managed_oidc_token = ""
            return ""

    def _should_use_managed_proxy(self, provider_name: str) -> bool:
        return (
            provider_name == "openai"
            and self.managed_llm
            and bool(self.sentinelayer_token)
        )

    async def _call_managed_proxy(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
        route: str = "managed",
        fallback_chain: Optional[str] = None,
    ) -> LLMResponse:
        if self.reasoning_effort:
            # The managed proxy contract (POST /api/v1/proxy/llm) carries no reasoning effort. A request that asked for one
            # is refused here, explicitly, instead of being served silently at the provider default.
            return LLMResponse(
                content="",
                usage=_unreturned_usage("openai", 0, route=route, fallback_chain=fallback_chain),
                success=False,
                error=f"Managed LLM proxy cannot apply reasoning_effort={self.reasoning_effort}; not sent",
            )
        endpoint = f"{self.managed_api_url.rstrip('/')}/api/v1/proxy/llm"

        headers = {
            "Authorization": f"Bearer {self.sentinelayer_token}",
            "Content-Type": "application/json",
        }

        oidc_token = await self._fetch_managed_oidc_token()
        if oidc_token:
            headers["X-Sentinelayer-OIDC-Token"] = oidc_token

        repo_full_name = os.environ.get("GITHUB_REPOSITORY", "")
        owner, name = "", ""
        if "/" in repo_full_name:
            owner, name = repo_full_name.split("/", 1)

        payload = {
            "model": model,
            "system_prompt": system,
            "user_content": user,
            "max_tokens": int(max_tokens),
            "temperature": float(temperature),
            "repo_owner": owner,
            "repo_name": name,
        }

        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(endpoint, json=payload, headers=headers)
        except httpx.TimeoutException:
            return LLMResponse(
                content="",
                usage=_unreturned_usage("openai", int((time.time() - start) * 1000), route=route, fallback_chain=fallback_chain),
                success=False,
                error=f"Managed LLM proxy timeout after {self.timeout}s",
            )
        except Exception as exc:
            return LLMResponse(
                content="",
                usage=_unreturned_usage("openai", int((time.time() - start) * 1000), route=route, fallback_chain=fallback_chain),
                success=False,
                error=f"Managed LLM proxy request failed: {exc}",
            )

        latency_ms = int((time.time() - start) * 1000)

        if response.status_code != 200:
            error_message = f"Managed LLM proxy failed ({response.status_code}) at {endpoint}"
            if response.status_code == 404:
                error_message = (
                    f"Managed LLM proxy endpoint not found at {endpoint}. "
                    "Deploy API route /api/v1/proxy/llm."
                )
            try:
                payload = response.json()
                if isinstance(payload, dict):
                    err = payload.get("error")
                    if isinstance(err, dict):
                        msg = str(err.get("message") or "").strip()
                        if msg:
                            error_message = msg
            except Exception:
                pass
            return LLMResponse(
                content="",
                usage=_unreturned_usage("openai", latency_ms, route=route, fallback_chain=fallback_chain),
                success=False,
                error=error_message,
            )

        try:
            payload = response.json()
            usage_data = payload.get("usage", {}) if isinstance(payload, dict) else {}
            tokens_in = int(usage_data.get("tokens_in", 0) or 0)
            tokens_out = int(usage_data.get("tokens_out", 0) or 0)
            cost_usd = float(usage_data.get("cost_usd", 0.0) or 0.0)
            provider_name = str(usage_data.get("provider") or "openai")
            content = str(payload.get("content") or "")
        except Exception as exc:
            return LLMResponse(
                content="",
                usage=_unreturned_usage("openai", latency_ms, route=route, fallback_chain=fallback_chain),
                success=False,
                error=f"Managed LLM proxy response parsing failed: {exc}",
            )

        return LLMResponse(
            content=content,
            usage=LLMUsage(
                model=model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost_usd,
                latency_ms=latency_ms,
                provider=provider_name,
                route=route,
                fallback_chain=fallback_chain,
            ),
            success=True,
        )

    @staticmethod
    def _is_capacity_error(error: Optional[str]) -> bool:
        message = str(error or "").strip().lower()
        if not message:
            return False
        markers = (
            "429",
            "insufficient_quota",
            "resource_exhausted",
            "quota",
            "rate limit",
            "rate_limit",
            "generate_content_free_tier_requests",
        )
        return any(marker in message for marker in markers)

    @classmethod
    def _all_failures_are_capacity(cls, *responses: LLMResponse) -> bool:
        errors = [response.error for response in responses if not response.success]
        return bool(errors) and all(cls._is_capacity_error(error) for error in errors)

    def _managed_capacity_fallback_model(self) -> str:
        primary_provider = detect_provider_from_model(
            self.primary_model, default_provider=self.llm_provider
        )
        if primary_provider == "openai":
            return self.primary_model
        fallback_provider = detect_provider_from_model(
            self.fallback_model, default_provider=self.llm_provider
        )
        if fallback_provider == "openai":
            return self.fallback_model
        return "gpt-4.1-mini"

    def _should_try_managed_capacity_fallback(
        self,
        *,
        primary_response: LLMResponse,
        fallback_response: LLMResponse,
    ) -> bool:
        return (
            self.managed_capacity_fallback
            and not self.managed_llm
            and bool(self.sentinelayer_token)
            and self._all_failures_are_capacity(primary_response, fallback_response)
        )

    def _capacity_fallback_chain(
        self,
        *,
        primary_response: LLMResponse,
        fallback_response: LLMResponse,
        managed_model: str,
        managed_status: str,
    ) -> str:
        primary_provider = primary_response.usage.provider
        fallback_provider = fallback_response.usage.provider
        return "->".join(
            [
                f"primary:{primary_provider}/{self.primary_model}:capacity_failed",
                f"fallback:{fallback_provider}/{self.fallback_model}:capacity_failed",
                f"managed:openai/{managed_model}:{managed_status}",
            ]
        )

    async def analyze(
        self,
        system_prompt: str,
        user_content: str,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """
        Run analysis with automatic retry and fallback.

        Flow:
        1. Try primary_model (up to max_retries)
        2. On failure, try fallback_model (up to max_retries)
        3. Return error response if both fail
        """
        primary_response = await self._call_with_retry(
            self.primary_model,
            system_prompt,
            user_content,
            max_tokens,
        )
        if primary_response.success or not self.allow_fallback:
            return primary_response

        fallback_response = await self._call_with_retry(
            self.fallback_model,
            system_prompt,
            user_content,
            max_tokens,
        )
        if fallback_response.success:
            return fallback_response

        managed_error: Optional[str] = None
        if self._should_try_managed_capacity_fallback(
            primary_response=primary_response,
            fallback_response=fallback_response,
        ):
            managed_model = self._managed_capacity_fallback_model()
            fallback_chain = self._capacity_fallback_chain(
                primary_response=primary_response,
                fallback_response=fallback_response,
                managed_model=managed_model,
                managed_status="attempt",
            )
            managed_response = await self._call_managed_proxy(
                model=managed_model,
                system=system_prompt,
                user=user_content,
                max_tokens=max_tokens,
                temperature=0.1,
                route="managed_after_byo_capacity",
                fallback_chain=fallback_chain,
            )
            managed_response.usage.fallback_chain = self._capacity_fallback_chain(
                primary_response=primary_response,
                fallback_response=fallback_response,
                managed_model=managed_model,
                managed_status="success" if managed_response.success else "failed",
            )
            if managed_response.success:
                return managed_response
            managed_error = managed_response.error or "unknown error"
            fallback_response.usage.route = "managed_after_byo_capacity_failed"
            fallback_response.usage.fallback_chain = managed_response.usage.fallback_chain

        primary_error = sanitize_public_error(primary_response.error or "unknown error")
        fallback_error = sanitize_public_error(fallback_response.error or "unknown error")
        combined_error = f"Primary failed: {primary_error}; Fallback failed: {fallback_error}"
        if managed_error:
            combined_error = (
                f"{combined_error}; Managed fallback failed: "
                f"{sanitize_public_error(managed_error)}"
            )
        return LLMResponse(
            content="",
            usage=fallback_response.usage,
            success=False,
            error=combined_error,
        )

    async def _call_with_retry(
        self,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
    ) -> LLMResponse:
        """Call provider API with retry on transient failures."""
        last_error: Optional[str] = None

        provider_name = detect_provider_from_model(model, default_provider=self.llm_provider)
        use_managed_proxy = self._should_use_managed_proxy(provider_name)
        provider = None if use_managed_proxy else self._get_provider(provider_name)

        for attempt in range(self.max_retries):
            try:
                if use_managed_proxy:
                    response = await self._call_managed_proxy(
                        model=model,
                        system=system,
                        user=user,
                        max_tokens=max_tokens,
                        temperature=0.1,
                    )
                    if response.success:
                        return response
                    last_error = sanitize_public_error(response.error)
                else:
                    start = time.time()
                    response = await provider.call(
                        model=model,
                        system=system,
                        user=user,
                        max_tokens=max_tokens,
                        temperature=0.1,
                        timeout=self.timeout,
                    )
                    latency_ms = int((time.time() - start) * 1000)
                    input_tokens = int(getattr(response, "input_tokens", 0) or 0)
                    output_tokens = int(getattr(response, "output_tokens", 0) or 0)
                    reported_model = getattr(response, "model", None)
                    identity_valid = isinstance(reported_model, str) and bool(reported_model.strip())
                    usage = LLMUsage(
                        model=reported_model if identity_valid else "unknown",
                        tokens_in=input_tokens,
                        tokens_out=output_tokens,
                        cost_usd=provider.estimate_cost(
                            reported_model, input_tokens, output_tokens
                        ) if identity_valid else 0.0,
                        latency_ms=latency_ms,
                        provider=provider_name,
                        raw_usage=getattr(response, "raw_usage", None),
                    )
                    content = getattr(response, "content", "") or ""
                    return LLMResponse(
                        content=content,
                        usage=usage,
                        success=identity_valid and getattr(response, "completed", True),
                        error=("Provider response did not report model identity" if not identity_valid else
                               None if getattr(response, "completed", True) else "Provider response did not complete"),
                    )
            except asyncio.TimeoutError:
                last_error = f"Timeout after {self.timeout}s"
            except Exception as exc:
                last_error = sanitize_public_error(exc)

            if attempt < self.max_retries - 1:
                await asyncio.sleep(2**attempt)

        return LLMResponse(
            content="",
            usage=_unreturned_usage(provider_name),
            success=False,
            error=last_error,
        )

    def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        """Estimate cost in USD based on model pricing."""
        provider_name = detect_provider_from_model(model, default_provider=self.llm_provider)
        provider = self._get_provider(provider_name)
        return provider.estimate_cost(model, tokens_in, tokens_out)
