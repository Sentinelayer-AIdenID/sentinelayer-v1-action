"""Immutable, explicitly bounded tracked-text scopes for whole-repository review."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess

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
    source_head: str
    git_blobs: tuple[tuple[str, str], ...]

    def manifest(self) -> dict:
        return {
            "scope_id": self.scope_id, "scan_mode": self.scan_mode,
            "source_head": self.source_head,
            "coverage": "all tracked text; ignore patterns cannot waive coverage",
            "ignore_policy": "no_tracked_text_exemptions",
            "binary_exclusion_policy": "image-extension-and-magic-v1",
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


def _committed_tree(repo_root: Path) -> tuple[str, tuple[tuple[str, str], ...]]:
    try:
        head = subprocess.check_output(["git", "-C", str(repo_root), "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, timeout=30).decode().strip()
        tree = subprocess.check_output(["git", "-C", str(repo_root), "ls-tree", "-r", "-z", "HEAD"], timeout=30).decode("utf-8")
        blobs = []
        for row in tree.rstrip("\0").split("\0"):
            info, path = row.split("\t", 1)
            _, kind, digest = info.split(" ")
            if kind != "blob":
                raise TypeSafeReviewIncomplete("unsupported_tracked_source_type")
            blobs.append((path, digest))
        return head, tuple(sorted(blobs))
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError):
        raise TypeSafeReviewIncomplete("committed_source_inventory_unavailable") from None


def _verify_blob(raw: bytes, expected: str) -> None:
    blob = b"blob " + str(len(raw)).encode() + b"\0" + raw
    actual = hashlib.sha1(blob, usedforsecurity=False).hexdigest() if len(expected) == 40 else hashlib.sha256(blob).hexdigest()
    if actual != expected:
        raise TypeSafeReviewIncomplete("source_differs_from_committed_blob")


def _declared_image(relative: str, raw: bytes) -> bool:
    """A NUL alone never establishes that executable source is a binary asset."""
    suffix = Path(relative).suffix.lower()
    if suffix == ".png":
        return raw.startswith(b"\x89PNG\r\n\x1a\n")
    if suffix in {".jpg", ".jpeg"}:
        return raw.startswith(b"\xff\xd8\xff")
    if suffix == ".gif":
        return raw.startswith((b"GIF87a", b"GIF89a"))
    if suffix == ".webp":
        return raw.startswith(b"RIFF") and raw[8:12] == b"WEBP"
    if suffix == ".ico":
        return raw.startswith(b"\x00\x00\x01\x00")
    return False


def build_source_scope(
    repo_root: Path, scan_mode: str, *, max_total_bytes: int = 8_000_000,
    max_candidates: int = 10_000,
) -> SourceScope:
    if scan_mode not in {"deep", "nightly"}:
        raise TypeSafeReviewIncomplete("unsupported_full_source_mode")
    if type(max_total_bytes) is not int or max_total_bytes < 1 or type(max_candidates) is not int or max_candidates < 1:
        raise TypeSafeReviewIncomplete("invalid_full_source_budget")
    tracked = _tracked_paths(repo_root)
    head, git_blobs = _committed_tree(repo_root)
    blobs = dict(git_blobs)
    if tracked != tuple(path for path, _ in git_blobs):
        raise TypeSafeReviewIncomplete("source_scope_changed")
    # A whole-source completeness claim cannot be narrowed by PR-controlled
    # ignore rules or generic defaults such as tests/build/dist. Tracked ignore
    # files are ordinary reviewed text; untracked files remain outside scope.
    ignores: tuple[str, ...] = ()
    candidates, required_hashes, hashes, excluded = [], [], [], []
    total = 0
    for relative in tracked:
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
        _verify_blob(raw, blobs[relative])
        hashes.append((relative, hashlib.sha256(raw).hexdigest()))
        if _declared_image(relative, raw):
            excluded.append((relative, "binary_non_text"))
            continue
        if b"\0" in raw:
            raise TypeSafeReviewIncomplete("unsupported_source_bytes")
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            # Unlike a declared binary, an undecodable required text file may
            # contain code. It cannot silently disappear from the review.
            raise TypeSafeReviewIncomplete("unsupported_source_encoding") from None
        total += len(raw)
        if total > max_total_bytes:
            raise TypeSafeReviewIncomplete("full_source_byte_budget_exceeded")
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
    identity = json.dumps([head, scan_mode, tracked, hashes, excluded, ignores], ensure_ascii=False).encode("utf-8")
    scope = SourceScope(inventory, scan_mode, tracked, tuple(hashes), tuple(excluded), ignores,
                        total, "scope-" + hashlib.sha256(identity).hexdigest(), head, git_blobs)
    verify_source_scope(repo_root, scope)
    return scope


def verify_source_scope(repo_root: Path, scope: SourceScope) -> None:
    if _committed_tree(repo_root) != (scope.source_head, scope.git_blobs):
        raise TypeSafeReviewIncomplete("source_scope_changed")
    if _tracked_paths(repo_root) != scope.tracked_paths or scope.ignore_patterns != ():
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
    # The hash loop binds binary exclusions too: retaining a magic header or
    # another NUL cannot conceal a change between provider calls.
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
