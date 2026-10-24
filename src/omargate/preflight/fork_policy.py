from __future__ import annotations

from ..config import OmarGateConfig
from ..context import GitHubContext


def check_fork_policy(
    ctx: GitHubContext,
    config: OmarGateConfig,
) -> tuple[bool, str, str]:
    """
    Check fork policy.

    Returns:
        (should_proceed, mode, reason)
        mode: "full", "limited", "blocked"
    """
    if not ctx.is_fork:
        return True, "full", "not_fork"

    if config.fork_policy == "block":
        return False, "blocked", "fork_pr_blocked_by_policy"
    if config.fork_policy == "limited":
        return True, "limited", "fork_pr_limited_mode"
    return True, "full", "fork_pr_allowed"
