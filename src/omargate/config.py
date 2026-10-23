from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, conint, confloat, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import (
    ApprovalMode,
    ForkPolicy,
    LLMFailurePolicy,
    LLMProviderType,
    RateLimitFailMode,
    ScanMode,
    SeverityGate,
)


TYPESAFE_GENERATOR_MODEL = "gpt-5.3-codex"
REASONING_EFFORTS = frozenset({"", "none", "minimal", "low", "medium", "high", "xhigh", "max"})


class OmarGateConfig(BaseSettings):
    """Configuration loaded from GitHub Actions inputs."""

    model_config = SettingsConfigDict(
        env_prefix="INPUT_",
        frozen=True,
        extra="ignore",
        protected_namespaces=(),  # Allow fields starting with 'model_'
        hide_input_in_errors=True,
    )

    # Required
    openai_api_key: SecretStr = Field(
        default="",
        description="OpenAI API key (BYO); required for the writer and fallback when llm_provider=typesafe.",
    )

    # LLM provider selection + keys (BYO)
    llm_provider: LLMProviderType = Field(
        default="openai",
        description="LLM provider: openai, anthropic, google, xai, typesafe",
    )
    anthropic_api_key: SecretStr = Field(
        default="",
        description="Anthropic API key (required if llm_provider=anthropic)",
    )
    google_api_key: SecretStr = Field(
        default="",
        description="Google AI API key (required if llm_provider=google)",
    )
    xai_api_key: SecretStr = Field(
        default="",
        description="xAI API key (required if llm_provider=xai)",
    )
    typesafe_api_key: SecretStr = Field(
        default="",
        description="TypeSafe API key (required if llm_provider=typesafe)",
    )
    intent_model_pin: SecretStr = Field(
        default="",
        description="Pinned TypeSafe model version for typed candidate assessments",
    )
    typesafe_timeout: conint(ge=1, le=120) = Field(default=30)
    typesafe_max_candidates: conint(ge=1, le=200) = Field(default=50)
    typesafe_fallback: bool = Field(
        default=True,
        description="Allow gpt-5.3-codex fallback when typed candidate review cannot complete",
    )
    intent_price_profile: Literal["", "typesafe-input-20261020"] = Field(default="")
    intent_policy: SecretStr = Field(default="", description="Private review policy JSON; no packaged rubric default")
    review_routing: Literal["legacy", "intent-cascade-v1"] = Field(default="legacy")

    # Codex CLI path (OpenAI-only); wiring added later.
    use_codex: bool = Field(default=True, description="Use Codex CLI for deep audit (falls back to API)")
    codex_only: bool = Field(
        default=False,
        description="When true, disable API fallback and use Codex CLI as the only LLM path",
    )
    codex_model: str = Field(default="gpt-5.3-codex", description="Model for Codex CLI")
    reasoning_effort: str = Field(
        default="",
        description="Reasoning effort for the non-routed LLM call and Codex CLI; empty keeps the provider default",
    )
    codex_timeout: conint(ge=60) = Field(
        default=300, description="Codex timeout in seconds for Codex execution"
    )
    run_harness: bool = Field(default=True, description="Run security test harness")
    pip_audit_ignore_ids: str = Field(
        default="",
        description="Comma-separated vulnerability IDs to ignore in pip-audit",
    )

    # GitHub integration (recommended)
    github_token: SecretStr = Field(default="", description="GitHub token used for API calls")
    comment_tag: str = Field(
        default="",
        description="Optional provider tag to isolate PR comments/check runs",
    )
    publish_github: bool = Field(
        default=True,
        description="Publish GitHub PR comments and check runs",
    )

    # Sentinelayer integration (optional)
    sentinelayer_token: SecretStr = Field(default="", description="Sentinelayer API token")
    sentinelayer_spec_id: str = Field(
        default="",
        description="Sentinelayer spec hash for spec-aware reviews",
    )
    sentinelayer_managed_llm: bool = Field(
        default=False,
        description=(
            "Use Sentinelayer-managed LLM proxy. If false, managed mode auto-enables "
            "when openai_api_key is empty and sentinelayer_token is provided."
        ),
    )
    telemetry_tier: conint(ge=0, le=3) = Field(
        default=1,
        description="Telemetry tier: 0=off, 1=aggregate, 2=metadata, 3=full artifacts",
    )
    telemetry: bool = Field(
        default=True,
        description="Enable anonymous telemetry (opt-out)",
    )
    share_metadata: bool = Field(
        default=False,
        description="Opt-in to Tier 2 metadata (repo identity + finding metadata)",
    )
    share_artifacts: bool = Field(
        default=False,
        description="Opt-in to Tier 3 artifacts upload",
    )
    training_opt_in: bool = Field(default=False, description="Optional training consent")

    # Scan configuration
    scan_mode: ScanMode = Field(default="pr-diff")
    severity_gate: SeverityGate = Field(default="P1")

    # Model settings
    # Primary model for LLM API fallback path (when Codex CLI is unavailable).
    # Codex CLI model is configured separately via codex_model.
    # TypeSafe resolves omitted model fields to its funded writer model below.
    model: str = Field(default="gpt-4.1-mini")
    model_fallback: str = Field(default="gpt-4.1-mini")
    llm_failure_policy: LLMFailurePolicy = Field(default="block")

    # Rate limiting / cost control
    max_daily_scans: conint(ge=0) = Field(default=20)
    min_scan_interval_minutes: conint(ge=0) = Field(default=0)
    rate_limit_fail_mode: RateLimitFailMode = Field(
        default="closed",
        description="On GitHub API errors during rate limit enforcement: open or closed",
    )
    max_input_tokens: conint(ge=0) = Field(default=100000)
    require_cost_confirmation: confloat(ge=0) = Field(default=5.00)
    max_review_estimate_usd: confloat(ge=0, le=1000, allow_inf_nan=False) = Field(default=5.00)
    approval_mode: ApprovalMode = Field(default="pr_label")
    approval_label: str = Field(default="sentinelayer:approved")

    # Fork handling
    fork_policy: ForkPolicy = Field(default="block")

    # Fixer options
    run_deterministic_fix: bool = Field(default=False)
    run_llm_fix: bool = Field(default=False)
    auto_commit_fixes: bool = Field(default=False)

    # Policy pack controls
    policy_pack: str = Field(default="omar")
    policy_pack_version: str = Field(default="v1")

    @model_validator(mode="before")
    @classmethod
    def _automatic_generator_defaults(cls, values: object) -> object:
        # Empty action inputs mean automatic. Remove them before Pydantic records
        # explicit fields, so TypeSafe can distinguish defaults from overrides.
        if not isinstance(values, dict):
            return values
        return {
            name: value
            for name, value in values.items()
            if not (
                name in {"model", "model_fallback"}
                and isinstance(value, str)
                and not value.strip()
            )
        }

    @model_validator(mode="after")
    def _validate_review_routing(self) -> "OmarGateConfig":
        if self.review_routing == "intent-cascade-v1":
            if self.llm_provider != "typesafe":
                raise ValueError("intent-cascade-v1 requires llm_provider=typesafe")
            if self.llm_failure_policy != "block":
                raise ValueError("intent-cascade-v1 requires llm_failure_policy=block")
        return self

    @field_validator("severity_gate", mode="before")
    @classmethod
    def _normalize_severity_gate(cls, value: str) -> str:
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.lower() == "none":
                return "none"
            return trimmed.upper()
        return value

    @field_validator("reasoning_effort", mode="before")
    @classmethod
    def _validate_reasoning_effort(cls, value: str) -> str:
        effort = value.strip().lower() if isinstance(value, str) else value
        if effort not in REASONING_EFFORTS:
            raise ValueError(f"reasoning_effort must be one of {sorted(REASONING_EFFORTS - {''})} or empty")
        return effort

    @field_validator("sentinelayer_spec_id", mode="before")
    @classmethod
    def _normalize_spec_hash(cls, value: str) -> str:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("intent_model_pin")
    @classmethod
    def _validate_intent_model_pin(cls, value: SecretStr) -> SecretStr:
        pin = value.get_secret_value()
        if pin and (len(pin) > 128 or re.fullmatch(r"[a-z][a-z0-9-]*-[0-9]+\.[0-9]+\.[0-9]+", pin) is None):
            raise ValueError("intent_model_pin must be a pinned version")
        return value

    @property
    def intent_model_reference(self) -> str:
        from .intent_identity import intent_model_reference
        return intent_model_reference(self.intent_model_pin.get_secret_value())

    @property
    def review_policy(self):
        from .private_policy import load_private_policy
        return load_private_policy(self.intent_policy.get_secret_value())

    @field_validator("comment_tag", mode="before")
    @classmethod
    def _normalize_comment_tag(cls, value: str) -> str:
        tag = str(value or "").strip().lower()
        if not tag:
            return ""
        sanitized = re.sub(r"[^a-z0-9_-]+", "-", tag)
        sanitized = re.sub(r"-{2,}", "-", sanitized).strip("-_")
        return sanitized[:32]

    @field_validator(
        "scan_mode",
        "llm_failure_policy",
        "approval_mode",
        "fork_policy",
        "rate_limit_fail_mode",
        "llm_provider",
        mode="before",
    )
    @classmethod
    def _normalize_lowercase(cls, value: str) -> str:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @model_validator(mode="after")
    def _validate_provider_keys(self) -> "OmarGateConfig":
        """
        Cross-field validation for provider keys.

        We validate non-OpenAI providers strictly (they are always explicit).
        OpenAI is allowed to be empty so deterministic-only runs and fork handling
        can still execute without failing config parsing.
        """
        # Note: use_codex=true without openai_api_key is allowed at config time.
        # CodexRunner fails gracefully and the orchestrator falls back to LLM API.

        provider = self.llm_provider
        if self.reasoning_effort and provider == "openai" and not self.openai_api_key.get_secret_value().strip():
            # without a BYO key the managed proxy would serve every call, and its contract carries no effort
            raise ValueError("reasoning_effort requires a BYO openai_api_key; the managed LLM proxy cannot apply it")
        if provider == "anthropic" and not self.anthropic_api_key.get_secret_value().strip():
            raise ValueError("anthropic_api_key is required when llm_provider=anthropic")
        if provider == "google" and not self.google_api_key.get_secret_value().strip():
            raise ValueError("google_api_key is required when llm_provider=google")
        if provider == "xai" and not self.xai_api_key.get_secret_value().strip():
            raise ValueError("xai_api_key is required when llm_provider=xai")
        if provider == "typesafe":
            if not self.typesafe_api_key.get_secret_value().strip():
                raise ValueError("typesafe_api_key is required when llm_provider=typesafe")
            if not self.openai_api_key.get_secret_value().strip():
                raise ValueError(
                    "openai_api_key is required for the writer and fallback when llm_provider=typesafe"
                )
            if not self.intent_model_pin.get_secret_value():
                raise ValueError("intent_model_pin is required; intent model is unknown")
            self.review_policy  # validate the private policy before any provider call
            if self.codex_only:
                raise ValueError("codex_only cannot be true when llm_provider=typesafe")
            if self.review_routing == "intent-cascade-v1":
                for name in ("model", "model_fallback", "codex_model"):
                    if name in self.model_fields_set and getattr(self, name) not in {"", "gpt-6-sol"}:
                        raise ValueError("intent-cascade-v1 owns model selection; remove model overrides")
                    object.__setattr__(self, name, "gpt-6-sol")
                return self
            for name in ("model", "model_fallback", "codex_model"):
                if name in self.model_fields_set and getattr(self, name) != TYPESAFE_GENERATOR_MODEL:
                    raise ValueError(
                        f"{name} must be {TYPESAFE_GENERATOR_MODEL} when llm_provider=typesafe"
                    )
                object.__setattr__(self, name, TYPESAFE_GENERATOR_MODEL)

        if self.sentinelayer_managed_llm:
            if provider != "openai":
                raise ValueError("sentinelayer_managed_llm currently supports only llm_provider=openai")
            if not self.sentinelayer_token.get_secret_value():
                raise ValueError(
                    "sentinelayer_token is required when sentinelayer_managed_llm=true"
                )

        return self

    @model_validator(mode="after")
    def _auto_detect_sentinelayer_spec_id(self) -> "OmarGateConfig":
        if self.sentinelayer_spec_id:
            return self

        workspace = os.environ.get("GITHUB_WORKSPACE", ".")
        candidates = [
            Path(workspace) / ".github" / "workflows" / "omar-gate.yml",
            Path(workspace) / ".github" / "workflows" / "omar-gate.yaml",
        ]
        pattern = re.compile(r"sentinelayer_spec_id:\s*([0-9a-fA-F]{64})")
        for path in candidates:
            try:
                if not path.is_file():
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            match = pattern.search(content)
            if match:
                object.__setattr__(self, "sentinelayer_spec_id", match.group(1).lower())
                break
        return self

    def use_managed_llm_proxy(self) -> bool:
        """
        Whether to use Sentinelayer-managed OpenAI proxy for LLM analysis.

        Explicit enable takes priority.
        Implicit enable supports 48-hour trial UX when BYO key is absent.
        """
        if self.llm_provider != "openai":
            return False

        if self.sentinelayer_managed_llm:
            return bool(self.sentinelayer_token.get_secret_value())

        has_openai = bool(self.openai_api_key.get_secret_value())
        has_sentinelayer = bool(self.sentinelayer_token.get_secret_value())
        return (not has_openai) and has_sentinelayer
