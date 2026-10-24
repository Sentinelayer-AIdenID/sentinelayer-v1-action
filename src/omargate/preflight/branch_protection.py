from __future__ import annotations

from typing import Any

from ..context import GitHubContext
from ..github import GitHubClient


def _required_check_names(protection: dict[str, Any]) -> set[str]:
    required = protection.get("required_status_checks") or {}
    contexts = set(required.get("contexts") or [])
    checks = required.get("checks") or []
    for check in checks:
        context = check.get("context")
        if context:
            contexts.add(context)
    return contexts


def check_branch_protection(
    gh: GitHubClient,
    ctx: GitHubContext,
    check_name: str = "Omar Gate",
) -> tuple[bool, str]:
    """
    Best-effort verification that branch protection requires this check.

    Returns:
        (is_required, status)
        status: required | missing_required_check | not_protected | not_applicable | api_error
    """
    if not ctx.base_ref:
        return True, "not_applicable"

    try:
        protection = gh.get_branch_protection(ctx.base_ref)
    except Exception:
        return True, "api_error"

    if not protection:
        return False, "not_protected"

    required_checks = _required_check_names(protection)
    if check_name in required_checks:
        return True, "required"
    return False, "missing_required_check"
