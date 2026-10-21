"""Deterministic source partitions from a ReviewInventory under a byte budget.

A partition groups one or more contiguous 40-line ReviewCandidates into an
ordered sequence that fits within *partition_byte_budget* bytes of raw source
evidence.  Every candidate in the inventory is assigned to exactly one partition;
partitions are non-overlapping and preserve original paths, line numbers and
hashes.  The output is deterministic: the same inventory + budget always produces
the same partition list and the same stable partition ids.

Public entry points
-------------------
- "'``build_partitions``          full-scope + partition coverage proof
- ``validate_partition_scope``  verify every expected span is covered exactly once
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .typesafe_review import (
    ReviewCandidate,
    ReviewInventory,
    TypeSafeReviewIncomplete,
    verify_sources,
)

# ---------------------------------------------------------------------------
# Budget constants (kept in sync with typesafe_review.py where they originate)
# ---------------------------------------------------------------------------

# Default partition byte budget: roughly 2x the max prompt payload we want
# to send to a single provider call, leaving headroom for the rest of the
# prompt.  The value is a tunable default; the integrator may set it lower.
DEFAULT_PARTITION_BYTE_BUDGET = 80_000

# Upper-bound sanity limits on the number of partitions so a misconfiguration
# or a pathological scope cannot spawn hundreds of provider calls silently.
MAX_PARTITIONS = 40


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourcePartition:
    """One ordered, non-overlapping slice of the full scope.

    The ``evidence`` field concatenates the evidence of every candidate in
    *candidates* in inventory order.  ``total_bytes`` is the byte length of
    that concatenation (always <= ``byte_budget``).  ``partition_id`` is stable
    for the same (inventory, budget) pair.
    """

    partition_id: str
    candidates: tuple[ReviewCandidate, ...]
    evidence: str
    total_bytes: int
    byte_budget: int
    source_hashes: tuple[tuple[str, str], ...]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _partition_id(candidates: Sequence[ReviewCandidate], budget: int) -> str:
    """Deterministic id for a non-empty list of candidates under a budget."""
    payload = "|".join(
        f"{c.candidate_id}:{c.file_path}:{c.line_start}:{c.line_end}"
        for c in candidates
    ) + f"|budget={budget}"
    return "part-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_partitions(
    *,
    repo_root: Path,
    inventory: ReviewInventory,
    partition_byte_budget: int = DEFAULT_PARTITION_BYTE_BUDGET,
    max_partitions: int = MAX_PARTITIONS,
) -> tuple[SourcePartition, ...]:
    """Split *inventory* into deterministic partitions under a byte budget.

    Every candidate is assigned to exactly one partition.  If a single
    candidate's evidence exceeds *partition_byte_budget*, or the number of
    required partitions exceeds *max_partitions*, the function raises
    "'``TypeSafeReviewIncomplete`` -- the caller MUST NOT make a provider call.

    The function also verifies source integrity via ``verify_sources`` before
    partitioning, so a source change mid-run is detected.
    """
    if not isinstance(partition_byte_budget, int) or partition_byte_budget < 1:
        raise TypeSafeReviewIncomplete("invalid_partition_budget")
    if not isinstance(max_partitions, int) or max_partitions < 1:
        raise TypeSafeReviewIncomplete("invalid_max_partitions")

    # Re-verify source integrity first (catches tampering / mid-run changes,
    # empty scope, mismatched hashes, etc.).
    verify_sources(repo_root, inventory)

    candidates = inventory.candidates
    partitions: list[SourcePartition] = []
    current_candidates: list[ReviewCandidate] = []
    current_bytes = 0

    for candidate in candidates:
        candidate_bytes = len(candidate.evidence.encode("utf-8"))

        # A single oversized span cannot fit in any budget.
        if candidate_bytes > partition_byte_budget:
            raise TypeSafeReviewIncomplete("single_span_budget_exceeded")

        # If adding this candidate would overflow, seal the current partition.
        if current_candidates and current_bytes + candidate_bytes > partition_byte_budget:
            evidence = "".join(c.evidence for c in current_candidates)
            partitions.append(
                SourcePartition(
                    partition_id=_partition_id(current_candidates, partition_byte_budget),
                    candidates=tuple(current_candidates),
                    evidence=evidence,
                    total_bytes=len(evidence.encode("utf-8")),
                    byte_budget=partition_byte_budget,
                    source_hashes=inventory.source_hashes,
                )
            )
            current_candidates = []
            current_bytes = 0

        current_candidates.append(candidate)
        current_bytes += candidate_bytes

    # Seal remainder.
    if current_candidates:
        evidence = "".join(c.evidence for c in current_candidates)
        partitions.append(
            SourcePartition(
                partition_id=_partition_id(current_candidates, partition_byte_budget),
                candidates=tuple(current_candidates),
                evidence=evidence,
                total_bytes=len(evidence.encode("utf-8")),
                byte_budget=partition_byte_budget,
                source_hashes=inventory.source_hashes,
            )
        )

    # Reject excessive fragmentation before any provider call.
    if len(partitions) > max_partitions:
        raise TypeSafeReviewIncomplete("partition_count_exceeded")

    return tuple(partitions)


def validate_partition_scope(
    repo_root: Path,
    inventory: ReviewInventory,
    partitions: tuple[SourcePartition, ...],
) -> None:
    """Prove every expected span is covered exactly once.

    Raises ``TypeSafeReviewIncomplete`` for:
    - omitted spans
    - duplicate spans (a candidate appears in more than one partition)
    - forged spans (a candidate not in the inventory)
    - evidence mismatch (a partition's evidence disagrees with the candidates
      it claims to hold)
    - any source change detected mid-run
    """
    verify_sources(repo_root, inventory)

    inventory_ids = {c.candidate_id for c in inventory.candidates}
    seen: set[str] = set()

    for partition in partitions:
        for candidate in partition.candidates:
            if candidate.candidate_id not in inventory_ids:
                raise TypeSafeReviewIncomplete("forged_span_in_partition")
            if candidate.candidate_id in seen:
                raise TypeSafeReviewIncomplete("duplicate_span_in_partition")
            seen.add(candidate.candidate_id)

    if seen != inventory_ids:
        raise TypeSafeReviewIncomplete("omitted_span_in_partition")

    for partition in partitions:
        expected = "".join(c.evidence for c in partition.candidates)
        if partition.evidence != expected:
            raise TypeSafeReviewIncomplete("partition_evidence_mismatch")
        if partition.total_bytes != len(expected.encode("utf-8")):
            raise TypeSafeReviewIncomplete("partition_byte_count_mismatch")
