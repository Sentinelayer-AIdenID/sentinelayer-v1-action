from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _load_event() -> dict[str, Any]:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return {}
    try:
        return json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _workflow_dispatch_pr_number(event_name: str) -> int | None:
    if event_name != "workflow_dispatch":
        return None

    raw_value = os.environ.get("INPUT_PR_NUMBER", "").strip()
    if not raw_value:
        return None
    if not raw_value.isascii() or not raw_value.isdecimal():
        raise RuntimeError("Invalid INPUT_PR_NUMBER; expected a positive decimal integer")

    pr_number = int(raw_value)
    if pr_number < 1:
        raise RuntimeError("Invalid INPUT_PR_NUMBER; expected a positive decimal integer")
    return pr_number


def _detect_fork(event: dict[str, Any]) -> tuple[bool, str | None]:
    """Detect if PR is from a fork and return fork owner."""
    pr = event.get("pull_request", {})
    head = pr.get("head", {})
    base = pr.get("base", {})

    head_repo = head.get("repo", {})
    base_repo = base.get("repo", {})

    if head_repo.get("full_name") and base_repo.get("full_name"):
        if head_repo.get("full_name") != base_repo.get("full_name"):
            return True, head_repo.get("owner", {}).get("login")

    return False, None


@dataclass(frozen=True)
class GitHubContext:
    """Immutable GitHub Actions context."""

    # Repository
    repo_owner: str
    repo_name: str
    repo_full_name: str  # "owner/name"

    # Event
    event_name: str  # pull_request, push, workflow_dispatch

    # PR-specific (None if not a PR)
    pr_number: int | None
    pr_title: str | None
    head_sha: str
    base_sha: str | None
    head_ref: str | None
    base_ref: str | None

    # Fork detection
    is_fork: bool
    fork_owner: str | None

    # Actor
    actor: str

    @classmethod
    def from_environment(cls) -> GitHubContext:
        """Load context from GitHub Actions environment."""
        event = _load_event()

        repo_full_name = (
            os.environ.get("GITHUB_REPOSITORY")
            or event.get("repository", {}).get("full_name")
            or ""
        )
        if not repo_full_name or "/" not in repo_full_name:
            raise RuntimeError("Missing or invalid GITHUB_REPOSITORY")

        repo_owner, repo_name = repo_full_name.split("/", 1)

        event_name = os.environ.get("GITHUB_EVENT_NAME") or ""
        if not event_name:
            raise RuntimeError("Missing GITHUB_EVENT_NAME")

        actor = os.environ.get("GITHUB_ACTOR", "")

        pr = event.get("pull_request") or {}
        if pr:
            pr_number = _coerce_int(event.get("number") or pr.get("number"))
            pr_title = pr.get("title")
            head_sha = (pr.get("head") or {}).get("sha") or os.environ.get("GITHUB_SHA", "")
            base_sha = (pr.get("base") or {}).get("sha")
            head_ref = (pr.get("head") or {}).get("ref")
            base_ref = (pr.get("base") or {}).get("ref")
            is_fork, fork_owner = _detect_fork(event)
        else:
            pr_number = _workflow_dispatch_pr_number(event_name)
            pr_title = None
            head_sha = event.get("after") or os.environ.get("GITHUB_SHA", "")
            base_sha = None
            head_ref = event.get("ref") or os.environ.get("GITHUB_REF")
            base_ref = None
            is_fork = False
            fork_owner = None

        if not head_sha:
            raise RuntimeError("Missing head SHA in GitHub context")

        return cls(
            repo_owner=repo_owner,
            repo_name=repo_name,
            repo_full_name=repo_full_name,
            event_name=event_name,
            pr_number=pr_number,
            pr_title=pr_title,
            head_sha=head_sha,
            base_sha=base_sha,
            head_ref=head_ref,
            base_ref=base_ref,
            is_fork=is_fork,
            fork_owner=fork_owner,
            actor=actor,
        )

    @property
    def dedupe_components(self) -> dict[str, str | int | None]:
        """Components used for dedupe key computation."""
        return {
            "repo": self.repo_full_name,
            "pr": self.pr_number,
            "head_sha": self.head_sha,
        }
