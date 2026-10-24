"""Bind a PR patch to the event's exact Git base and checked-out head."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from threading import Timer

from .analyze.typesafe_state import MAX_BOUND_DIFF_BYTES


_SHA = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}\Z")
_HUNK_HEADING = re.compile(
    r"(@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@)[^\r\n]*(\r?\n)?\Z"
)
FETCH_DEPTH = 128
GIT_TIMEOUT_SECONDS = 45


class PRDiffIncomplete(RuntimeError):
    """A bounded fail-closed reason for a PR patch whose source is unproved."""


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", *args], cwd=repo_root, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=GIT_TIMEOUT_SECONDS,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PRDiffIncomplete("pr_diff_git_unavailable") from None


def _merge_base(repo_root: Path, base_sha: str, head_sha: str) -> str | None:
    for sha in (base_sha, head_sha):
        if _git(repo_root, "cat-file", "-e", f"{sha}^{{commit}}").returncode:
            return None
    result = _git(repo_root, "merge-base", "--all", base_sha, head_sha)
    if result.returncode:
        return None
    bases = result.stdout.decode("ascii", errors="ignore").splitlines()
    if len(bases) != 1 or not _SHA.fullmatch(bases[0]):
        raise PRDiffIncomplete("pr_diff_ambiguous_merge_base")
    return bases[0]


def _bounded_diff(repo_root: Path, merge_base: str, head_sha: str, max_bytes: int) -> str:
    try:
        process = subprocess.Popen(
            ["git", "-c", "core.quotePath=false", "diff", "--no-ext-diff",
             "--no-textconv", "--no-renames", "--full-index", "--unified=3",
             merge_base, head_sha, "--"],
            cwd=repo_root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except OSError:
        raise PRDiffIncomplete("pr_diff_git_unavailable") from None
    timed_out = False

    def stop_timeout() -> None:
        nonlocal timed_out
        timed_out = True
        process.kill()

    timer = Timer(GIT_TIMEOUT_SECONDS, stop_timeout)
    timer.start()
    try:
        assert process.stdout is not None
        data = process.stdout.read(max_bytes + 1)
        if len(data) > max_bytes:
            process.kill()
            raise PRDiffIncomplete("pr_diff_oversize")
        process.wait(timeout=5)
        if timed_out or process.returncode:
            raise PRDiffIncomplete("pr_diff_git_unavailable")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise PRDiffIncomplete("pr_diff_encoding_unsupported") from None
    except subprocess.TimeoutExpired:
        process.kill()
        raise PRDiffIncomplete("pr_diff_git_unavailable") from None
    finally:
        timer.cancel()
        process.stdout.close()
        process.wait()


def _without_index_lines(diff: str) -> str:
    # GitHub abbreviates blob IDs and may label a hunk with a different nearby
    # symbol than local git. Preserve the complete numeric hunk ranges, mode,
    # path and content lines while dropping only these display-only labels.
    rows: list[str] = []
    for row in diff.splitlines(keepends=True):
        if row.startswith("index "):
            continue
        if row.startswith("@@ "):
            heading = _HUNK_HEADING.fullmatch(row)
            if heading is not None:
                row = heading.group(1) + (heading.group(2) or "")
        rows.append(row)
    return "".join(rows)


def attest_pr_diff(
    repo_root: Path, *, base_sha: str | None, head_sha: str,
    supplied_diff: str, max_bytes: int = MAX_BOUND_DIFF_BYTES,
) -> str:
    """Return the complete local patch only when it matches GitHub's patch.

    A bounded fetch may fill a shallow checkout. A missing merge base, wrong
    checkout head, stale GitHub payload, or clipped patch refuses review.
    """
    if (not isinstance(base_sha, str) or not _SHA.fullmatch(base_sha)
            or not isinstance(head_sha, str) or not _SHA.fullmatch(head_sha)):
        raise PRDiffIncomplete("pr_diff_event_refs_unavailable")
    if (not isinstance(max_bytes, int) or isinstance(max_bytes, bool)
            or not 0 < max_bytes <= MAX_BOUND_DIFF_BYTES):
        raise PRDiffIncomplete("pr_diff_invalid_budget")
    if not isinstance(supplied_diff, str) or len(supplied_diff.encode("utf-8")) > max_bytes:
        raise PRDiffIncomplete("pr_diff_oversize")
    checkout = _git(repo_root, "rev-parse", "--verify", "HEAD")
    if checkout.returncode:
        raise PRDiffIncomplete("pr_diff_git_unavailable")
    if checkout.stdout.decode("ascii", errors="ignore").strip().lower() != head_sha.lower():
        raise PRDiffIncomplete(
            "pr_head_checkout_mismatch: checkout pull_request.head.sha for source-bound review"
        )
    merge_base = _merge_base(repo_root, base_sha, head_sha)
    if merge_base is None:
        fetched = _git(
            repo_root, "fetch", "--no-tags", "--depth", str(FETCH_DEPTH),
            f"--filter=blob:limit={MAX_BOUND_DIFF_BYTES}", "origin", base_sha, head_sha,
        )
        if fetched.returncode:
            raise PRDiffIncomplete("pr_diff_history_unavailable")
        merge_base = _merge_base(repo_root, base_sha, head_sha)
    if merge_base is None:
        raise PRDiffIncomplete("pr_diff_history_unavailable")
    local = _bounded_diff(repo_root, merge_base, head_sha, max_bytes)
    if _without_index_lines(local) != _without_index_lines(supplied_diff):
        raise PRDiffIncomplete("pr_diff_mismatch")
    return local
