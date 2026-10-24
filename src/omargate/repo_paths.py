"""Reading a repository path whose content may reach a provider, a comment or an artifact.

Ingest walks the checkout without following links, so the paths it lists are already
vetted. Every other read of a named repository path (a changed file ingest skipped, a
README or manifest chosen by quick learn, a well-known infra file) goes through
``plain_repo_file``: a pull request controls the checkout, and a symlink there can point
at the runner's environment, ``.git/config`` or any file outside the repository.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def plain_repo_file(repo_root: Optional[Path], rel_path: object) -> Optional[Path]:
    """The path, only if it names a regular file inside repo_root, outside .git/,
    with no symlink at any component (a symlinked parent directory escapes too)."""
    if repo_root is None or not isinstance(rel_path, str) or not rel_path:
        return None
    if "\\" in rel_path or ":" in rel_path or rel_path.startswith("/"):
        return None
    parts = rel_path.split("/")
    # casefold: on a case-insensitive filesystem (Windows, default macOS) ".GIT" is .git
    if any(part in {"", ".", ".."} or part.casefold() == ".git" for part in parts):
        return None
    current = Path(repo_root)
    for part in parts:
        current = current / part
        if current.is_symlink():
            return None
    try:
        resolved = current.resolve(strict=True)
        root = Path(repo_root).resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_relative_to(root) or not resolved.is_file():
        return None
    if any(part.casefold() == ".git" for part in resolved.relative_to(root).parts):
        return None
    return current
