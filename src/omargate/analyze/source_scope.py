"""Immutable, explicitly bounded tracked-text scopes for whole-repository review."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess

from ..ingest.ingest_runner import _load_ignore_patterns, _matches_ignore
from ..ingest.file_classifier import classify_file
from .typesafe_review import (
    MAX_FILE_BYTES, ReviewInventory, TypeSafeReviewIncomplete, _source_path,
    build_inventory, verify_sources,
)


@dataclass(frozen=True)
class SourceScope:
    inventory: ReviewInventory
    scan_mode: str
    tracked_paths: tuple[str, ...]
    source_hashes: tuple[tuple[str, str], ...]
    exclusions: tuple[tuple[str, str], ...]
    ignore_patterns: tuple[str, ...]
    total_bytes: int
    scope_id: str

    def manifest(self) -> dict:
        return {
            "scope_id": self.scope_id, "scan_mode": self.scan_mode,
            "coverage": "all tracked text within the declared ignore policy",
            "untracked_files": "outside_declared_scope",
            "source_hashes": dict(self.source_hashes),
            "exclusions": [{"file_path": path, "reason": reason} for path, reason in self.exclusions],
            "ignore_patterns": list(self.ignore_patterns), "total_bytes": self.total_bytes,
            "candidate_count": len(self.inventory.candidates),
            "cross_partition_relationships": "not independently proven",
        }


def _tracked_paths(repo_root: Path) -> tuple[str, ...]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "--cached", "-z"],
            capture_output=True, check=True, timeout=30,
        )
        paths = result.stdout.decode("utf-8").split("\0")
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
        raise TypeSafeReviewIncomplete("tracked_source_inventory_unavailable") from None
    names = paths[:-1] if paths and paths[-1] == "" else paths
    if not names or len(names) != len(set(names)):
        raise TypeSafeReviewIncomplete("invalid_tracked_source_inventory")
    return tuple(sorted(names))


def build_source_scope(
    repo_root: Path, scan_mode: str, *, max_total_bytes: int = 8_000_000,
    max_candidates: int = 10_000,
) -> SourceScope:
    if scan_mode not in {"deep", "nightly"}:
        raise TypeSafeReviewIncomplete("unsupported_full_source_mode")
    if type(max_total_bytes) is not int or max_total_bytes < 1 or type(max_candidates) is not int or max_candidates < 1:
        raise TypeSafeReviewIncomplete("invalid_full_source_budget")
    tracked = _tracked_paths(repo_root)
    ignores = tuple(_load_ignore_patterns(repo_root))
    candidates, required_hashes, hashes, excluded = [], [], [], []
    total = 0
    for relative in tracked:
        if _matches_ignore(relative, list(ignores)):
            excluded.append((relative, "declared_ignore_policy"))
            continue
        path = _source_path(repo_root, relative)
        if path.is_symlink() or (repo_root / relative).is_symlink():
            raise TypeSafeReviewIncomplete("unsupported_source_symlink")
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise TypeSafeReviewIncomplete("source_budget_exceeded")
            raw = path.read_bytes()
        except OSError:
            raise TypeSafeReviewIncomplete("source_unavailable") from None
        if len(raw) > MAX_FILE_BYTES:
            raise TypeSafeReviewIncomplete("source_budget_exceeded")
        if b"\0" in raw:
            if classify_file(relative).category != "other":
                raise TypeSafeReviewIncomplete("unsupported_source_bytes")
            excluded.append((relative, "binary_non_text"))
            continue
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            # Unlike a declared binary, an undecodable required text file may
            # contain code. It cannot silently disappear from the review.
            raise TypeSafeReviewIncomplete("unsupported_source_encoding") from None
        total += len(raw)
        if total > max_total_bytes:
            raise TypeSafeReviewIncomplete("full_source_byte_budget_exceeded")
        hashes.append((relative, hashlib.sha256(raw).hexdigest()))
        if not raw:
            continue  # Empty files remain hash-bound, with no source lines to review.
        item = build_inventory(repo_root=repo_root, ingest={"files": [{"path": relative}]},
                               changed_files=[relative], scan_mode="pr-diff", max_candidates=200)
        candidates.extend(item.candidates)
        required_hashes.extend(item.source_hashes)
        if len(candidates) > max_candidates:
            raise TypeSafeReviewIncomplete("full_source_candidate_budget_exceeded")
    if not candidates:
        raise TypeSafeReviewIncomplete("empty_source_scope")
    inventory = ReviewInventory(tuple(candidates), tuple(required_hashes), "pr-diff")
    identity = json.dumps([scan_mode, tracked, hashes, excluded, ignores], ensure_ascii=False).encode("utf-8")
    scope = SourceScope(inventory, scan_mode, tracked, tuple(hashes), tuple(excluded), ignores,
                        total, "scope-" + hashlib.sha256(identity).hexdigest())
    verify_source_scope(repo_root, scope)
    return scope


def verify_source_scope(repo_root: Path, scope: SourceScope) -> None:
    if _tracked_paths(repo_root) != scope.tracked_paths or tuple(_load_ignore_patterns(repo_root)) != scope.ignore_patterns:
        raise TypeSafeReviewIncomplete("source_scope_changed")
    for relative, expected in scope.source_hashes:
        try:
            path = _source_path(repo_root, relative)
            if (repo_root / relative).is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                raise TypeSafeReviewIncomplete("source_changed_during_review")
            raw = path.read_bytes()
        except OSError:
            raise TypeSafeReviewIncomplete("source_unavailable") from None
        if hashlib.sha256(raw).hexdigest() != expected:
            raise TypeSafeReviewIncomplete("source_changed_during_review")
    # A binary exclusion cannot be replaced with code between provider calls.
    for relative, reason in scope.exclusions:
        if reason == "binary_non_text":
            try:
                path = _source_path(repo_root, relative)
                if path.stat().st_size > MAX_FILE_BYTES or b"\0" not in path.read_bytes():
                    raise TypeSafeReviewIncomplete("source_scope_changed")
            except OSError:
                raise TypeSafeReviewIncomplete("source_unavailable") from None
    verify_sources(repo_root, scope.inventory)


def verify_scope_partition(repo_root: Path, scope: SourceScope, inventory: ReviewInventory) -> None:
    """A subset must be byte-identical to the complete verified source manifest."""
    verify_source_scope(repo_root, scope)
    expected = {candidate.candidate_id: candidate for candidate in scope.inventory.candidates}
    ids = [candidate.candidate_id for candidate in inventory.candidates]
    paths = {candidate.file_path for candidate in inventory.candidates}
    hashes = dict(scope.inventory.source_hashes)
    if (not ids or len(ids) != len(set(ids)) or inventory.scan_mode != "pr-diff"
            or any(expected.get(candidate.candidate_id) != candidate for candidate in inventory.candidates)
            or inventory.source_hashes != tuple((path, hashes[path]) for path in sorted(paths))):
        raise TypeSafeReviewIncomplete("unbound_source_partition")
