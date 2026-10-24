from __future__ import annotations

from ..config import OmarGateConfig
from ..context import GitHubContext
from ..github import GitHubClient


def estimate_cost(
    file_count: int,
    total_lines: int,
    model: str,
) -> float:
    """Estimate LLM cost in USD."""
    estimated_tokens = total_lines * 12
    cost_per_1k = {
        "gpt-5.3-codex": 0.00175,
        "gpt-5.2-codex": 0.00175,
        "gpt-4.1": 0.002,
        "gpt-4.1-mini": 0.0004,
        "gpt-4.1-nano": 0.0001,
        "gpt-4o": 0.005,
        "gpt-4o-mini": 0.00015,
    }.get(model, 0.002)
    return (estimated_tokens / 1000) * cost_per_1k


async def check_cost_approval(
    estimated_cost: float,
    config: OmarGateConfig,
    ctx: GitHubContext,
    gh: GitHubClient,
) -> tuple[bool, str]:
    """
    Check if cost approval is required and granted.

    Returns:
        (approved, status)
    """
    if estimated_cost <= config.require_cost_confirmation:
        return True, "below_threshold"

    if config.approval_mode == "none":
        return True, "approval_not_required"

    if config.approval_mode == "workflow_dispatch":
        return (
            ctx.event_name == "workflow_dispatch",
            "workflow_dispatch" if ctx.event_name == "workflow_dispatch" else "requires_workflow_dispatch",
        )

    if config.approval_mode == "pr_label":
        if ctx.pr_number is None:
            return False, "label_missing_pr"
        try:
            approved = gh.has_label(ctx.pr_number, config.approval_label)
        except Exception:
            return False, "api_error_require_approval"
        return (approved, "label_approved" if approved else "label_missing")

    return False, "approval_required"
