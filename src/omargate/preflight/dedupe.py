from __future__ import annotations

from ..github import GitHubClient


async def check_dedupe(
    gh: GitHubClient,
    head_sha: str,
    dedupe_key: str,
    check_name: str = "Omar Gate",
) -> tuple[bool, str | None]:
    """
    Remote check metadata is not an authenticated reusable gate receipt.

    Returns:
        (should_skip, existing_run_url)
    """
    # Check names, external IDs and summary markers can be forged by another
    # check producer. Do fresh work until a separately authenticated receipt
    # contract binds source, configuration, producer and successful completion.
    return False, None
