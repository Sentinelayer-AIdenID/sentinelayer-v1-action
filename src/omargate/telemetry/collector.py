from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import hashlib
import time


@dataclass
class TelemetryCollector:
    """
    Collects telemetry throughout a run.

    Thread-safe stage timing. Accumulates metrics.
    Generates tier-appropriate payloads at end.
    """

    run_id: str
    repo_full_name: str

    # Computed on init
    repo_hash: str = field(init=False)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Stage timing
    _stages: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # LLM metrics
    llm_provider: Optional[str] = None
    model_used: Optional[str] = None
    model_fallback_used: bool = False
    fallback_provider: Optional[str] = None
    fallback_model: Optional[str] = None
    tokens_in: int = 0
    tokens_out: int = 0
    estimated_cost_usd: float = 0.0
    review_cost_ledger: Optional[Dict[str, Any]] = None
    llm_latency_ms: int = 0

    # Scan metrics
    scan_mode: str = "pr-diff"
    files_scanned: int = 0
    files_skipped: int = 0
    total_lines: int = 0

    # Finding counts
    counts: Dict[str, int] = field(
        default_factory=lambda: {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "total": 0}
    )
    deterministic_count: int = 0
    llm_count: int = 0

    # Gate result
    gate_status: Optional[str] = None
    gate_reason: Optional[str] = None

    # Preflight outcomes
    dedupe_skipped: bool = False
    rate_limit_skipped: bool = False
    fork_blocked: bool = False
    approval_state: Optional[str] = None

    # Run exit (populated even on early returns)
    exit_code: int = 0
    exit_reason: str = ""
    preflight_exits: list = field(default_factory=list)

    # Errors
    errors: list = field(default_factory=list)

    def __post_init__(self) -> None:
        """Compute repo hash for anonymous telemetry."""
        self.repo_hash = hashlib.sha256(self.repo_full_name.encode()).hexdigest()[:16]

    def stage_start(self, stage: str) -> None:
        """Mark stage start."""
        self._stages[stage] = {
            "start_ms": time.time() * 1000,
            "end_ms": None,
            "duration_ms": None,
            "success": None,
        }

    def stage_end(self, stage: str, success: bool = True) -> None:
        """Mark stage end."""
        if stage not in self._stages:
            return

        end_ms = time.time() * 1000
        self._stages[stage]["end_ms"] = end_ms
        self._stages[stage]["duration_ms"] = int(
            end_ms - self._stages[stage]["start_ms"]
        )
        self._stages[stage]["success"] = success

    def record_llm_usage(
        self,
        model: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
        latency_ms: int,
        fallback_used: bool = False,
        provider: Optional[str] = None,
        fallback_provider: Optional[str] = None,
        fallback_model: Optional[str] = None,
    ) -> None:
        """Record LLM usage metrics."""
        if provider:
            self.llm_provider = provider
        self.model_used = model
        self.tokens_in += tokens_in
        self.tokens_out += tokens_out
        self.estimated_cost_usd += cost_usd
        self.llm_latency_ms += latency_ms
        self.model_fallback_used = fallback_used
        if fallback_provider:
            self.fallback_provider = fallback_provider
        if fallback_model:
            self.fallback_model = fallback_model

    def record_findings(
        self,
        counts: Dict[str, int],
        deterministic_count: int,
        llm_count: int,
    ) -> None:
        """Record finding counts."""
        self.counts = counts
        self.deterministic_count = deterministic_count
        self.llm_count = llm_count

    def record_gate_result(self, status: str, reason: str) -> None:
        """Record gate outcome."""
        self.gate_status = status
        self.gate_reason = reason

    def record_error(self, stage: str, error: str) -> None:
        """Record an error."""
        self.errors.append({"stage": stage, "error": error})

    def record_preflight_exit(self, reason: str, exit_code: int) -> None:
        """Record an early return/short-circuit reason and exit code."""
        self.exit_reason = reason
        self.exit_code = int(exit_code)
        self.preflight_exits.append({"reason": reason, "exit_code": int(exit_code)})

    def total_duration_ms(self) -> int:
        """Total run duration."""
        elapsed = datetime.now(timezone.utc) - self.start_time
        return int(elapsed.total_seconds() * 1000)

    def stage_durations(self) -> Dict[str, int]:
        """Get all stage durations."""
        return {
            name: data.get("duration_ms", 0)
            for name, data in self._stages.items()
            if data.get("duration_ms") is not None
        }
