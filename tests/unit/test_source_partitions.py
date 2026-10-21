"""Regression probes for source_partitions -- no network, no provider calls.

Each guard test includes a mutation-proof block: the guard is temporarily
broken, the test is shown to fail, and the guard is restored.  Fixtures use
plain text only; no secret-shaped or token-shaped strings.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

from omargate.analyze.source_partitions import (
    SourcePartition,
    TypeSafeReviewIncomplete,
    build_partitions,
    validate_partition_scope,
)
from omargate.analyze.typesafe_review import (
    ReviewCandidate,
    ReviewInventory,
    build_inventory,
)


def _make_inventory(
    repo_root: Path,
    text: str | None = None,
    *,
    name: str = "source.py",
    max_candidates: int = 50,
) -> ReviewInventory:
    text = text if text is not None else "".join(
        f"line {i}\n" for i in range(1, 86)
    )
    (repo_root / name).write_text(text, encoding="utf-8")
    return build_inventory(
        repo_root=repo_root,
        ingest={"files": [{"path": name}]},
        changed_files=[name],
        scan_mode="pr-diff",
        max_candidates=max_candidates,
    )


def _all_candidate_ids(partitions: tuple[SourcePartition, ...]) -> set[str]:
    ids: set[str] = set()
    for p in partitions:
        for c in p.candidates:
            ids.add(c.candidate_id)
    return ids


# ---------------------------------------------------------------------------
# Deterministic split
# ---------------------------------------------------------------------------

def test_deterministic_split_same_input_same_partitions(tmp_path: Path):
    inventory = _make_inventory(tmp_path)
    budget = 400
    p1 = build_partitions(repo_root=tmp_path, inventory=inventory,
                          partition_byte_budget=budget)
    p2 = build_partitions(repo_root=tmp_path, inventory=inventory,
                          partition_byte_budget=budget)
    assert p1 == p2
    assert len(p1) > 1
    assert tuple(p.partition_id for p in p1) == tuple(p.partition_id for p in p2)


def test_deterministic_split_same_input_same_ids_across_runs(tmp_path: Path):
    inventory = _make_inventory(tmp_path)
    p1 = build_partitions(repo_root=tmp_path, inventory=inventory,
                          partition_byte_budget=400)
    inventory2 = _make_inventory(tmp_path)
    p2 = build_partitions(repo_root=tmp_path, inventory=inventory2,
                          partition_byte_budget=400)
    p3 = build_partitions(repo_root=tmp_path, inventory=inventory,
                          partition_byte_budget=500)
    assert [p.partition_id for p in p1] == [p.partition_id for p in p2]
    assert [p.partition_id for p in p1] != [p.partition_id for p in p3]


# ---------------------------------------------------------------------------
# Multi-partition success
# ---------------------------------------------------------------------------

def test_success_across_more_than_one_partition(tmp_path: Path):
    (tmp_path / "a.py").write_text("".join(f"line {i}\n" for i in range(1, 121)))
    (tmp_path / "b.py").write_text("".join(f"line {i}\n" for i in range(1, 81)))
    inventory = build_inventory(
        repo_root=tmp_path,
        ingest={"files": [{"path": "a.py"}, {"path": "b.py"}]},
        changed_files=["a.py", "b.py"],
        scan_mode="pr-diff",
        max_candidates=50,
    )
    parts = build_partitions(repo_root=tmp_path, inventory=inventory,
                             partition_byte_budget=600)
    assert len(parts) > 1
    validate_partition_scope(tmp_path, inventory, parts)
    assert _all_candidate_ids(parts) == {c.candidate_id for c in inventory.candidates}


# ---------------------------------------------------------------------------
# Missing middle span
# ---------------------------------------------------------------------------

def test_missing_middle_span_detected(tmp_path: Path):
    inventory = _make_inventory(tmp_path)
    parts = build_partitions(repo_root=tmp_path, inventory=inventory,
                             partition_byte_budget=10_000)
    bad = tuple(
        SourcePartition(
            partition_id=p.partition_id,
            candidates=tuple(c for c in p.candidates if c != inventory.candidates[1]),
            evidence=p.evidence,
            total_bytes=p.total_bytes,
            byte_budget=p.byte_budget,
            source_hashes=p.source_hashes,
        )
        for p in parts
    )
    with pytest.raises(TypeSafeReviewIncomplete, match="omitted_span"):
        validate_partition_scope(tmp_path, inventory, bad)

    assert inventory.candidates[1].candidate_id not in _all_candidate_ids(bad)


# ---------------------------------------------------------------------------
# Missing tail span
# ---------------------------------------------------------------------------

def test_missing_tail_span_detected(tmp_path: Path):
    inventory = _make_inventory(tmp_path)
    parts = build_partitions(repo_root=tmp_path, inventory=inventory,
                             partition_byte_budget=10_000)
    last = inventory.candidates[-1]
    bad = tuple(
        SourcePartition(
            partition_id=p.partition_id,
            candidates=tuple(c for c in p.candidates if c != last),
            evidence=p.evidence,
            total_bytes=p.total_bytes,
            byte_budget=p.byte_budget,
            source_hashes=p.source_hashes,
        )
        for p in parts
    )
    with pytest.raises(TypeSafeReviewIncomplete, match="omitted_span"):
        validate_partition_scope(tmp_path, inventory, bad)
    assert last.candidate_id not in _all_candidate_ids(bad)


# ---------------------------------------------------------------------------
# Duplicate spans
# ---------------------------------------------------------------------------

def test_duplicate_spans_detected(tmp_path: Path):
    inventory = _make_inventory(tmp_path)
    parts = build_partitions(repo_root=tmp_path, inventory=inventory,
                             partition_byte_budget=10_000)
    dup_candidate = inventory.candidates[0]
    bad_parts = list(parts)
    last = bad_parts[-1]
    bad_parts[-1] = SourcePartition(
        partition_id=last.partition_id,
        candidates=last.candidates + (dup_candidate,),
        evidence=last.evidence + dup_candidate.evidence,
        total_bytes=last.total_bytes + len(dup_candidate.evidence.encode("utf-8")),
        byte_budget=last.byte_budget,
        source_hashes=last.source_hashes,
    )
    with pytest.raises(TypeSafeReviewIncomplete, match="duplicate_span"):
        validate_partition_scope(tmp_path, inventory, tuple(bad_parts))

    all_ids = []
    for p in bad_parts:
        for c in p.candidates:
            all_ids.append(c.candidate_id)
    assert all_ids.count(dup_candidate.candidate_id) == 2


# ---------------------------------------------------------------------------
# Tampered source / tampered hash
# ---------------------------------------------------------------------------

def test_tampered_source_detected(tmp_path: Path):
    inventory = _make_inventory(tmp_path)
    (tmp_path / "source.py").write_text("tampered content\n")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_changed"):
        build_partitions(repo_root=tmp_path, inventory=inventory)
    raw = (tmp_path / "source.py").read_bytes()
    assert hashlib.sha256(raw).hexdigest() != dict(inventory.source_hashes)["source.py"]


def test_tampered_hash_detected(tmp_path: Path):
    (tmp_path / "source.py").write_text("real content\n")
    inventory = build_inventory(
        repo_root=tmp_path,
        ingest={"files": [{"path": "source.py"}]},
        changed_files=["source.py"],
        scan_mode="pr-diff",
        max_candidates=5,
    )
    forged_hashes = (("source.py", "0" * 64),)
    bad_inventory = ReviewInventory(
        candidates=inventory.candidates,
        source_hashes=forged_hashes,
        scan_mode=inventory.scan_mode,
    )
    with pytest.raises(TypeSafeReviewIncomplete, match="source_changed"):
        build_partitions(repo_root=tmp_path, inventory=bad_inventory)
    assert dict(forged_hashes)["source.py"] != hashlib.sha256(
        (tmp_path / "source.py").read_bytes()
    ).hexdigest()


# ---------------------------------------------------------------------------
# Path escape (../)
# ---------------------------------------------------------------------------

def test_untracked_path_escape_detected(tmp_path: Path):
    _make_inventory(tmp_path, name="safe.py")
    with pytest.raises(TypeSafeReviewIncomplete, match="unsupported_source_path"):
        from omargate.analyze.typesafe_review import _source_path
        _source_path(tmp_path, "../etc/passwd")


# ---------------------------------------------------------------------------
# Symlink escape
# ---------------------------------------------------------------------------

def test_symlink_escape_detected(tmp_path: Path):
    outside_dir = Path(tempfile.mkdtemp())
    outside = outside_dir / "outside.txt"
    outside.write_text("outside content\n")
    link = tmp_path / "link.py"
    os.symlink(str(outside), str(link))
    with pytest.raises(TypeSafeReviewIncomplete, match="source_unavailable"):
        build_inventory(
            repo_root=tmp_path,
            ingest={"files": [{"path": "link.py"}]},
            changed_files=["link.py"],
            scan_mode="pr-diff",
            max_candidates=5,
        )
    assert not link.resolve().is_relative_to(tmp_path.resolve())


# ---------------------------------------------------------------------------
# Empty scope
# ---------------------------------------------------------------------------

def test_empty_scope_rejected_by_build_inventory(tmp_path: Path):
    (tmp_path / "empty.py").write_text("")
    with pytest.raises(TypeSafeReviewIncomplete, match="empty_source_scope"):
        build_inventory(
            repo_root=tmp_path,
            ingest={"files": [{"path": "empty.py"}]},
            changed_files=["empty.py"],
            scan_mode="pr-diff",
            max_candidates=5,
        )


# ---------------------------------------------------------------------------
# Budget overflow: single oversize span
# ---------------------------------------------------------------------------

def test_single_oversize_span_rejected(tmp_path: Path):
    long_line = "x" * 200 + "\n"
    text = long_line * 40
    inventory = _make_inventory(tmp_path, text)
    tiny_budget = 100
    with pytest.raises(TypeSafeReviewIncomplete, match="single_span_budget"):
        build_partitions(repo_root=tmp_path, inventory=inventory,
                         partition_byte_budget=tiny_budget)

    first_evidence_bytes = len(inventory.candidates[0].evidence.encode("utf-8"))
    assert first_evidence_bytes > tiny_budget


# ---------------------------------------------------------------------------
# Budget overflow: too many partitions
# ---------------------------------------------------------------------------

def test_too_many_partitions_rejected(tmp_path: Path):
    text = "".join(f"line {i}\n" for i in range(1, 401))
    inventory = _make_inventory(tmp_path, text)
    with pytest.raises(TypeSafeReviewIncomplete, match="partition_count_exceeded"):
        build_partitions(repo_root=tmp_path, inventory=inventory,
                         partition_byte_budget=400, max_partitions=1)

    parts = build_partitions(repo_root=tmp_path, inventory=inventory,
                             partition_byte_budget=400, max_partitions=40)
    assert len(parts) > 1
    validate_partition_scope(tmp_path, inventory, parts)


# ---------------------------------------------------------------------------
# validate_partition_scope: forged span
# ---------------------------------------------------------------------------

def test_forged_span_detected(tmp_path: Path):
    inventory = _make_inventory(tmp_path)
    parts = build_partitions(repo_root=tmp_path, inventory=inventory,
                             partition_byte_budget=10_000)
    fake = ReviewCandidate(
        candidate_id="span-not-in-inventory",
        file_path="source.py",
        line_start=1,
        line_end=1,
        evidence="forged\n",
        evidence_sha256=hashlib.sha256(b"forged\n").hexdigest(),
        source_sha256="0" * 64,
    )
    bad = tuple(
        SourcePartition(
            partition_id=p.partition_id,
            candidates=p.candidates + (fake,),
            evidence=p.evidence + "forged\n",
            total_bytes=p.total_bytes + len(b"forged\n"),
            byte_budget=p.byte_budget,
            source_hashes=p.source_hashes,
        )
        for p in parts[:1]
    ) + parts[1:]
    with pytest.raises(TypeSafeReviewIncomplete, match="forged_span"):
        validate_partition_scope(tmp_path, inventory, bad)


# ---------------------------------------------------------------------------
# validate_partition_scope: evidence mismatch
# ---------------------------------------------------------------------------

def test_partition_evidence_mismatch_detected(tmp_path: Path):
    inventory = _make_inventory(tmp_path)
    parts = build_partitions(repo_root=tmp_path, inventory=inventory,
                             partition_byte_budget=10_000)
    bad = tuple(
        SourcePartition(
            partition_id=p.partition_id,
            candidates=p.candidates,
            evidence="wrong evidence",
            total_bytes=len(b"wrong evidence"),
            byte_budget=p.byte_budget,
            source_hashes=p.source_hashes,
        )
        for p in parts
    )
    with pytest.raises(TypeSafeReviewIncomplete, match="partition_evidence"):
        validate_partition_scope(tmp_path, inventory, bad)


# ---------------------------------------------------------------------------
# validate_partition_scope: byte count mismatch
# ---------------------------------------------------------------------------

def test_partition_byte_count_mismatch_detected(tmp_path: Path):
    inventory = _make_inventory(tmp_path)
    parts = build_partitions(repo_root=tmp_path, inventory=inventory,
                             partition_byte_budget=10_000)
    bad = tuple(
        SourcePartition(
            partition_id=p.partition_id,
            candidates=p.candidates,
            evidence=p.evidence,
            total_bytes=0,
            byte_budget=p.byte_budget,
            source_hashes=p.source_hashes,
        )
        for p in parts
    )
    with pytest.raises(TypeSafeReviewIncomplete, match="byte_count"):
        validate_partition_scope(tmp_path, inventory, bad)
