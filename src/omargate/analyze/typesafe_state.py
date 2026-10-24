"""Bind typed-review context to the actual changed source and scanner evidence."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from ..redaction import redact_secret_source, sanitize_public_error
from .typesafe_review import ReviewInventory, TypeSafeReviewIncomplete

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_METADATA = re.compile(r"(?:index [a-fA-F0-9]{4,64}\.\.[a-fA-F0-9]{4,64}(?: [0-7]{6})?|(?:old|new|new file|deleted file) mode [0-7]{6})")


def build_typed_context(
    *, repo_root: Path, inventory: ReviewInventory, diff_content: str | None,
    ingest: dict, deterministic_findings: list[dict],
) -> dict:
    """Reject unsupported/partial diffs; never silently clip the review state.

    Added/context lines are checked against the current file. Removed lines are
    patch context only: they are not claimed as verified head-source quotations.
    """
    if not diff_content or len(diff_content.encode("utf-8")) > 100_000:
        raise TypeSafeReviewIncomplete("typed_diff_unavailable_or_oversize")
    expected = dict(inventory.source_hashes)
    excluded_paths = frozenset(path for path, _ in inventory.policy_excluded)
    all_known = frozenset(expected) | excluded_paths
    if len(expected) + len(excluded_paths) != len(all_known):
        raise TypeSafeReviewIncomplete("incomplete_typed_diff_file_coverage")
    headers = {f"diff --git a/{path} b/{path}" for path in all_known}
    headers.update("--- a/" + path for path in all_known)
    headers.update("+++ b/" + path for path in all_known)
    headers.add("--- /dev/null")
    lines = diff_content.splitlines()
    hunks = []
    current = None
    index = 0
    touched = set()
    diff_paths_seen: set[str] = set()
    while index < len(lines):
        line = lines[index]
        if line.startswith(("rename from ", "rename to ", "copy from ", "copy to ",
                            "GIT binary patch", "Binary files ")):
            raise TypeSafeReviewIncomplete("unsupported_typed_diff_path")
        if line.startswith("diff --git "):
            current = None
        if line.startswith("+++ "):
            path = line[4:]
            # Quoted paths, binary patches, deletion-only and renames are not
            # approximated by this bounded first implementation.
            if not path.startswith("b/") or path[2:] not in all_known:
                raise TypeSafeReviewIncomplete("unsupported_typed_diff_path")
            current = path[2:]
            if current in diff_paths_seen:
                raise TypeSafeReviewIncomplete("unsupported_typed_diff_path")
            diff_paths_seen.add(current)
        match = _HUNK.match(line)
        if not match:
            # Generator context includes the complete original patch. Arbitrary
            # preamble/tail prose cannot be ignored here and then inherit code
            # reference exemptions in the assembled outbound context.
            if line and line not in headers and not _DIFF_METADATA.fullmatch(line):
                raise TypeSafeReviewIncomplete("unbound_typed_diff_record")
            if current is not None and line.startswith(("+", "-", " ")) and not line.startswith("+++ "):
                raise TypeSafeReviewIncomplete("invalid_typed_diff_counts")
            index += 1
            continue
        if current is None:
            raise TypeSafeReviewIncomplete("unbound_typed_diff_hunk")
        # Policy-excluded files: accept diff record but withhold content
        if current in excluded_paths:
            touched.add(current)
            # Skip hunk body lines; advance past @@ header and content
            index += 1
            while index < len(lines):
                body = lines[index]
                if body.startswith("\\ No newline at end of file"):
                    index += 1
                    continue
                if not body or body[0] not in {" ", "+", "-"}:
                    break
                index += 1
            continue
        start = int(match[3])
        old_count = int(match[2]) if match[2] is not None else 1
        new_count = int(match[4]) if match[4] is not None else 1
        try:
            source = (repo_root / current).read_bytes()
        except OSError:
            raise TypeSafeReviewIncomplete("source_unavailable") from None
        if hashlib.sha256(source).hexdigest() != expected[current]:
            raise TypeSafeReviewIncomplete("source_changed_during_review")
        source_lines = source.decode("utf-8").splitlines()
        hunk = [line]
        index += 1
        old_seen = new_seen = 0
        while index < len(lines):
            body = lines[index]
            if body.startswith("\\ No newline at end of file"):
                hunk.append(body)
                index += 1
                continue
            if old_seen == old_count and new_seen == new_count:
                break
            if not body or body[0] not in {" ", "+", "-"}:
                raise TypeSafeReviewIncomplete("incomplete_typed_diff_hunk")
            if body[0] in {" ", "+"}:
                at = start - 1 + new_seen
                if at < 0 or at >= len(source_lines) or body[1:] != source_lines[at]:
                    raise TypeSafeReviewIncomplete("typed_diff_source_mismatch")
                new_seen += 1
            if body[0] in {" ", "-"}:
                old_seen += 1
            if old_seen > old_count or new_seen > new_count:
                raise TypeSafeReviewIncomplete("invalid_typed_diff_counts")
            hunk.append(body)
            index += 1
        if old_seen != old_count or new_seen != new_count:
            raise TypeSafeReviewIncomplete("incomplete_typed_diff_hunk")
        touched.add(current)
        text = "\n".join(hunk)
        # Patch '+'/'-' markers are not identifier bytes. Inspect the source
        # payload so a removed '-SECRET_KEY=...' cannot evade the field scanner.
        payload = "\n".join(row[1:] for row in hunk[1:] if row and row[0] in {" ", "+", "-"})
        safe_text, source_redacted = redact_secret_source(payload, file_path=current)
        safe_hunk = hunk[0] + "\n" + safe_text if source_redacted else text
        hunks.append({
            "file_path": current, "line_start": start,
            "line_end": start + max(0, new_count - 1),
            "diff_hunk": safe_hunk,
            # Bind the display-safe hunk to the exact local source without
            # retaining its credential bytes in the provider state.
            "diff_hunk_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "source_redacted": source_redacted,
        })
    if touched != set(all_known):
        raise TypeSafeReviewIncomplete("incomplete_typed_diff_file_coverage")
    metadata = {row.get("path"): row for row in ingest.get("files", []) if isinstance(row, dict)}
    candidates = {}
    for candidate in inventory.candidates:
        file = metadata.get(candidate.file_path, {})
        language = file.get("language") or Path(candidate.file_path).suffix.lstrip(".") or "unknown"
        hits = []
        for finding in deterministic_findings:
            if finding.get("file_path") != candidate.file_path:
                continue
            line_start = finding.get("line_start")
            line_end = finding.get("line_end") or line_start
            if type(line_start) is not int or type(line_end) is not int:
                raise TypeSafeReviewIncomplete("invalid_deterministic_location")
            if line_end < candidate.line_start or line_start > candidate.line_end:
                continue
            hit = {}
            for key in (
                "id", "rule_id", "category", "severity", "file_path",
                "line_start", "line_end", "message",
            ):
                value = finding.get(key)
                if isinstance(value, str):
                    if key == "message":
                        value, _ = redact_secret_source(value)
                    value = sanitize_public_error(value)
                hit[key] = value
            if str(finding.get("category", "")).lower() == "secrets":
                hit["message"] = "Secret-bearing scanner evidence excluded"
            hits.append(hit)
        candidates[candidate.candidate_id] = {
            "language": sanitize_public_error(language),
            "diff_hunks": [hunk for hunk in hunks if hunk["file_path"] == candidate.file_path
                           and hunk["line_end"] >= candidate.line_start
                           and hunk["line_start"] <= candidate.line_end],
            "deterministic_scanner_hits": hits,
        }
    return {"candidate_context": candidates, "diff_head_lines_verified": True,
            "removed_lines_verified": False}
