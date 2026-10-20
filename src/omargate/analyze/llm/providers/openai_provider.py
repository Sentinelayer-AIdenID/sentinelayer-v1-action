from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .base import LLMProvider, ProviderResponse


@dataclass
class _OpenAIUsage:
    input_tokens: int
    output_tokens: int


class OpenAIProvider(LLMProvider):
    """OpenAI Responses API provider."""

    def __init__(self, api_key: str, *, client_getter: Optional[Callable[[], Any]] = None, reasoning_effort: str | None = None) -> None:
        self.api_key = api_key
        self._client_getter = client_getter
        self._client = None
        self.reasoning_effort = reasoning_effort

    @property
    def client(self):
        if self._client_getter is not None:
            return self._client_getter()
        if self._client is None:
            from openai import AsyncOpenAI

            self._client = AsyncOpenAI(api_key=self.api_key, **({"max_retries": 0} if self.reasoning_effort else {}))
        return self._client

    async def call(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> ProviderResponse:
        request = dict(
            model=model, instructions=system, input=user,
            max_output_tokens=max_tokens,
        )
        # Use the reasoning model's API defaults. Sampling controls are optional
        # and the funded Codex writer does not require a sampling override.
        if self.reasoning_effort:
            request["reasoning"] = {"effort": self.reasoning_effort}
        elif model != "gpt-5.3-codex" and not model.startswith("gpt-6"):
            request["temperature"] = temperature
        response = await asyncio.wait_for(
            self.client.responses.create(**request),
            timeout=timeout,
        )
        usage = getattr(response, "usage", None)
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0) if usage else 0
        output_tokens = int(getattr(usage, "output_tokens", 0) or 0) if usage else 0
        content = getattr(response, "output_text", "") or ""
        return ProviderResponse(
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=getattr(response, "model", None) or model,
            raw_usage=usage.model_dump() if hasattr(usage, "model_dump") else None,
            completed=getattr(response, "status", "completed") == "completed",
        )

    def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        from ...review_costs import estimate_usage
        current = estimate_usage("openai", model, {"input_tokens": tokens_in, "output_tokens": tokens_out})
        if current["estimated_usd"] is not None:
            return current["estimated_usd"]
        pricing = {
            "gpt-5.3-codex-spark": {"input": 0.00075, "output": 0.003},
            "gpt-5.3-codex": {"input": 0.00175, "output": 0.014},
            "gpt-5.2-codex": {"input": 0.00175, "output": 0.014},
            "gpt-4.1": {"input": 0.002, "output": 0.008},
            "gpt-4.1-mini": {"input": 0.0004, "output": 0.0016},
            "gpt-4.1-nano": {"input": 0.0001, "output": 0.0004},
            "gpt-4o": {"input": 0.005, "output": 0.015},
            "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
        }
        rates = pricing.get(model, {"input": 0.002, "output": 0.008})
        return (tokens_in / 1000 * rates["input"]) + (tokens_out / 1000 * rates["output"])

