from __future__ import annotations

from .anthropic_provider import AnthropicProvider
from .base import LLMProvider, ProviderResponse
from .gemini_provider import GeminiProvider
from .openai_provider import OpenAIProvider
from .xai_provider import XAIProvider

PROVIDERS: dict[str, type[LLMProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "google": GeminiProvider,
    "xai": XAIProvider,
}


def detect_provider_from_model(model: str, *, default_provider: str = "openai") -> str:
    """Infer provider from model name (used for cross-provider fallback)."""
    m = (model or "").strip()
    lower = m.lower()

    if lower.startswith("claude-"):
        return "anthropic"
    if lower.startswith("gemini-"):
        return "google"
    if lower.startswith("grok-"):
        return "xai"
    if lower.startswith(("gpt-", "o1-", "o3-")):
        return "openai"

    return default_provider


__all__ = [
    "PROVIDERS",
    "AnthropicProvider",
    "GeminiProvider",
    "LLMProvider",
    "OpenAIProvider",
    "ProviderResponse",
    "XAIProvider",
    "detect_provider_from_model",
]

