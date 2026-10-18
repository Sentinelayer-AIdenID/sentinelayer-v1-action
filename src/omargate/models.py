from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal, Optional

Severity = Literal["P0", "P1", "P2", "P3"]
SeverityGate = Literal["P0", "P1", "P2", "none"]
ScanMode = Literal["pr-diff", "deep", "nightly"]
LLMFailurePolicy = Literal["block", "deterministic_only", "allow_with_warning"]
ApprovalMode = Literal["pr_label", "workflow_dispatch", "none"]
ForkPolicy = Literal["block", "limited", "allow"]
RateLimitFailMode = Literal["open", "closed"]
LLMProviderType = Literal["openai", "anthropic", "google", "xai", "typesafe"]

@dataclass
class Counts:
    p0: int = 0
    p1: int = 0
    p2: int = 0
    p3: int = 0

    def total(self) -> int:
        return self.p0 + self.p1 + self.p2 + self.p3

@dataclass
class GateConfig:
    severity_gate: SeverityGate = "P1"
    require_llm_success: bool = False

class GateStatus(str, Enum):
    PASSED = "passed"
    BLOCKED = "blocked"
    BYPASSED = "bypassed"
    NEEDS_APPROVAL = "needs_approval"
    ERROR = "error"
    SKIPPED = "skipped"

@dataclass
class GateResult:
    status: GateStatus
    reason: str
    block_merge: bool
    counts: Counts
    dedupe_key: Optional[str] = None

@dataclass
class Finding:
    finding_id: str
    severity: Severity
    category: str
    file_path: str
    line_start: int
    line_end: int
    message: str
    recommendation: str
    fingerprint: str
    confidence: float = 0.5
