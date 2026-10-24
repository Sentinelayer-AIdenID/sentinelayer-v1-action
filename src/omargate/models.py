from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

Severity = Literal["P0", "P1", "P2", "P3", "P4"]
SeverityGate = Literal["P0", "P1", "P2", "none"]
ScanMode = Literal["pr-diff", "deep", "nightly"]
LLMFailurePolicy = Literal["block", "deterministic_only", "allow_with_warning"]
ApprovalMode = Literal["pr_label", "workflow_dispatch", "none"]
ForkPolicy = Literal["block", "limited", "allow"]
RateLimitFailMode = Literal["open", "closed"]
LLMProviderType = Literal["openai", "anthropic", "google", "xai", "typesafe"]
DEPENDENCY_AUDIT_SCHEMA_VERSION = "1.2"
DEPENDENCY_AUDIT_COVERAGE_SCOPE = {
    "npm": "package_lock_registry_graph",
    "pip": "declared_direct_pins",
    "cargo": "cargo_lock_packages",
}
DEPENDENCY_AUDIT_INDETERMINATE_REASONS = frozenset(
    {
        "command_not_found",
        "decode_error",
        "empty_output",
        "error_payload",
        "execution_error",
        "exit_result_mismatch",
        "exited_127",
        "invalid_json",
        "manifest_discovery_incomplete",
        "missing_lockfile",
        "output_limit_exceeded",
        "process_containment_error",
        "spawn_error",
        "suite_error",
        "suite_not_run",
        "suite_timed_out",
        "timed_out",
        "unexpected_exit",
        "unrecognized_schema",
        "unsupported_project_layout",
        "unsafe_lockfile",
        "unsafe_manifest",
        "unsafe_pip_input",
        "unsafe_working_directory",
        "unsupported_pip_input",
    }
)

@dataclass
class Counts:
    p0: int = 0
    p1: int = 0
    p2: int = 0
    p3: int = 0
    p4: int = 0

    def total(self) -> int:
        return self.p0 + self.p1 + self.p2 + self.p3 + self.p4

@dataclass
class GateConfig:
    severity_gate: SeverityGate = "P1"
    require_llm_success: bool = False
    require_dependency_audit_success: bool = False

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
    dedupe_key: str | None = None

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
