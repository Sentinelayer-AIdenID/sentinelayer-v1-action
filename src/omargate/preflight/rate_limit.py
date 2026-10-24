from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ..config import OmarGateConfig
from ..github import GitHubClient
from ..logging import OmarLogger
from ..utils import parse_iso8601


async def check_rate_limits(
    gh: GitHubClient,
    pr_number: int | None,
    config: OmarGateConfig,
    logger: OmarLogger,
    check_name: str = "Omar Gate",
) -> tuple[bool, str]:
    """
    Check cooldown and daily limits.

    Returns:
        (should_proceed, reason_if_blocked)

    FAIL MODE (GitHub API errors):
    - rate_limit_fail_mode=open: skip enforcement and allow the scan to proceed (cost-risky, but avoids blocking).
    - rate_limit_fail_mode=closed: require approval (fail-closed) when enforcement cannot be performed.

    Missing token follows the configured fail mode:
    - open: allow scan (skip limits)
    - closed: require approval (fail-closed)
    """
    if config.max_daily_scans == 0 and config.min_scan_interval_minutes == 0:
        return True, "limits_disabled"

    if not pr_number:
        return True, "not_pr"

    if not getattr(gh, "token", ""):
        logger.warning("rate_limit_missing_token", mode=config.rate_limit_fail_mode)
        if config.rate_limit_fail_mode == "open":
            return True, "missing_github_token_skip_limits"
        return False, "missing_github_token_require_approval"

    def _on_api_error(reason: str, error: str | None = None) -> tuple[bool, str]:
        logger.warning("rate_limit_api_error", reason=reason, error=error or "")
        if config.rate_limit_fail_mode == "open":
            return True, "api_error_skip_limits"
        return False, "api_error_require_approval"

    try:
        pr = gh.get_pull_request(pr_number)
        head_sha = (pr.get("head") or {}).get("sha")
        if not head_sha:
            return _on_api_error("missing_head_sha")
        runs = gh.list_check_runs(head_sha, check_name)
    except Exception as exc:
        return _on_api_error("exception", error=str(exc))

    now = datetime.now(UTC)
    completed_times = [
        ts for ts in (parse_iso8601(r.get("completed_at")) for r in runs) if ts
    ]

    if completed_times:
        latest = max(completed_times)
        cooldown = timedelta(minutes=config.min_scan_interval_minutes)
        if cooldown.total_seconds() > 0 and (now - latest) < cooldown:
            return False, "cooldown_not_met"

    if config.max_daily_scans > 0:
        cutoff = now - timedelta(days=1)
        daily_count = sum(1 for ts in completed_times if ts >= cutoff)
        if daily_count >= config.max_daily_scans:
            return False, "daily_cap_exceeded"

    return True, "ok"
