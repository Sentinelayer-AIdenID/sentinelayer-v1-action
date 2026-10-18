from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .models import (
    DEPENDENCY_AUDIT_COVERAGE_SCOPE,
    DEPENDENCY_AUDIT_INDETERMINATE_REASONS,
    DEPENDENCY_AUDIT_SCHEMA_VERSION,
    Counts,
    GateConfig,
    GateResult,
    GateStatus,
)
from .utils import sha256_file, sha256_hex


_DEPENDENCY_AUDIT_ECOSYSTEMS = frozenset(DEPENDENCY_AUDIT_COVERAGE_SCOPE)
_DEPENDENCY_AUDIT_EVIDENCE_KEYS = frozenset(
    {"schema_version", "enabled", "complete", "coverage_scope", "outcomes"}
)
_DEPENDENCY_AUDIT_OUTCOME_KEYS = frozenset(
    {
        "ecosystem",
        "applicable",
        "state",
        "vulnerability_count",
        "reason_code",
    }
)
_DEPENDENCY_AUDIT_FINDING_IDS = {
    "npm": "HARNESS-NPM-AUDIT",
    "pip": "HARNESS-PIP-AUDIT",
    "cargo": "HARNESS-CARGO-AUDIT",
}
_DEPENDENCY_AUDIT_INCOMPLETE_FINDING_IDS = frozenset(
    {
        "HARNESS-NPM-AUDIT-INCOMPLETE",
        "HARNESS-PIP-AUDIT-INCOMPLETE",
        "HARNESS-CARGO-AUDIT-INCOMPLETE",
    }
)


def _resolve_summary_path(run_dir_or_summary: Path) -> Path:
    if run_dir_or_summary.is_dir():
        return run_dir_or_summary / "PACK_SUMMARY.json"
    return run_dir_or_summary


def _validate_pack_summary(summary_path: Path) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """Validate PACK_SUMMARY.json integrity."""
    if not summary_path.exists():
        return False, "FAIL-CLOSED: PACK_SUMMARY.json missing. Run did not complete.", None

    try:
        summary: Dict[str, Any] = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, f"FAIL-CLOSED: PACK_SUMMARY.json corrupted ({exc}).", None

    if not summary.get("writer_complete", False):
        return (
            False,
            "FAIL-CLOSED: Run did not complete (writer_complete=false).",
            None,
        )

    required_fields = ["run_id", "counts", "findings_file", "findings_file_sha256"]
    missing = [field for field in required_fields if field not in summary]
    if missing:
        return False, f"FAIL-CLOSED: Missing fields: {missing}.", None

    counts = summary.get("counts")
    if not isinstance(counts, dict):
        return False, "FAIL-CLOSED: counts must be an object.", None
    missing_counts = [sev for sev in ("P0", "P1", "P2", "P3") if sev not in counts]
    if missing_counts:
        return False, f"FAIL-CLOSED: counts missing severities: {missing_counts}.", None

    findings_file = summary.get("findings_file")
    findings_path = summary_path.parent / findings_file
    if not findings_path.exists():
        return False, f"FAIL-CLOSED: Findings file missing: {findings_file}.", None

    expected_hash = summary.get("findings_file_sha256")
    if not expected_hash:
        return False, "FAIL-CLOSED: findings_file_sha256 missing.", None

    actual_hash = sha256_file(findings_path)
    if actual_hash != expected_hash:
        return (
            False,
            "FAIL-CLOSED: Findings file hash mismatch (tampering or corruption).",
            None,
        )

    return True, None, summary


def _validate_llm_evidence(summary: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    evidence = summary.get("llm_evidence")
    if not isinstance(evidence, dict):
        return False, "FAIL-CLOSED: live LLM evidence is missing."
    if evidence.get("schema_version") != "1.0":
        return False, "FAIL-CLOSED: live LLM evidence schema is unsupported."
    if evidence.get("attempted") is not True:
        return False, "FAIL-CLOSED: the required live LLM review was not attempted."
    if evidence.get("success") is not True:
        return False, "FAIL-CLOSED: the required live LLM review did not succeed."
    if evidence.get("output_valid") is not True:
        return False, "FAIL-CLOSED: the live LLM output contract was not satisfied."
    if evidence.get("usage_recorded") is not True:
        return False, "FAIL-CLOSED: live LLM usage evidence is missing."

    parse_error_count = evidence.get("parse_error_count")
    reported_count = evidence.get("reported_finding_count")
    if (
        not isinstance(parse_error_count, int)
        or isinstance(parse_error_count, bool)
        or parse_error_count != 0
    ):
        return False, "FAIL-CLOSED: live LLM output contains parse errors."
    if (
        not isinstance(reported_count, int)
        or isinstance(reported_count, bool)
        or reported_count < 0
    ):
        return False, "FAIL-CLOSED: live LLM finding evidence is invalid."

    no_findings = evidence.get("no_findings_reported")
    valid_result_shape = (
        reported_count > 0 and no_findings is False
    ) or (
        reported_count == 0 and no_findings is True
    )
    if not valid_result_shape:
        return False, "FAIL-CLOSED: live LLM result is neither findings nor an explicit clean result."

    for field in ("engine", "provider", "model"):
        value = evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            return False, f"FAIL-CLOSED: live LLM evidence field {field} is missing."
    latency_ms = evidence.get("latency_ms")
    if (
        not isinstance(latency_ms, (int, float))
        or isinstance(latency_ms, bool)
        or latency_ms <= 0
    ):
        return False, "FAIL-CLOSED: live LLM latency evidence is invalid."
    return True, None


def _validate_dependency_audit_evidence(
    summary: Dict[str, Any],
    findings_path: Path,
) -> Tuple[bool, Optional[str], int]:
    evidence = summary.get("dependency_audit_evidence")
    if not isinstance(evidence, dict):
        return False, "FAIL-CLOSED: dependency audit evidence is missing.", 0
    if set(evidence) != _DEPENDENCY_AUDIT_EVIDENCE_KEYS:
        return False, "FAIL-CLOSED: dependency audit evidence fields are invalid.", 0
    if evidence.get("schema_version") != DEPENDENCY_AUDIT_SCHEMA_VERSION:
        return False, "FAIL-CLOSED: dependency audit evidence schema is unsupported.", 0
    coverage_scope = evidence.get("coverage_scope")
    if (
        not isinstance(coverage_scope, dict)
        or set(coverage_scope) != _DEPENDENCY_AUDIT_ECOSYSTEMS
    ):
        return (
            False,
            "FAIL-CLOSED: dependency audit coverage scope fields are invalid.",
            0,
        )
    if coverage_scope != DEPENDENCY_AUDIT_COVERAGE_SCOPE:
        return (
            False,
            "FAIL-CLOSED: dependency audit coverage scope is unsupported.",
            0,
        )
    if evidence.get("enabled") is not True:
        return False, "FAIL-CLOSED: the required dependency audit was not enabled.", 0
    if not isinstance(evidence.get("complete"), bool):
        return False, "FAIL-CLOSED: dependency audit completion evidence is invalid.", 0

    outcomes = evidence.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != len(
        _DEPENDENCY_AUDIT_ECOSYSTEMS
    ):
        return False, "FAIL-CLOSED: dependency audit outcomes are incomplete.", 0

    seen: set[str] = set()
    states: dict[str, Optional[str]] = {}
    vulnerable_outcomes = 0
    for outcome in outcomes:
        if (
            not isinstance(outcome, dict)
            or set(outcome) != _DEPENDENCY_AUDIT_OUTCOME_KEYS
        ):
            return (
                False,
                "FAIL-CLOSED: dependency audit outcome fields are invalid.",
                0,
            )

        ecosystem = outcome.get("ecosystem")
        if (
            not isinstance(ecosystem, str)
            or ecosystem not in _DEPENDENCY_AUDIT_ECOSYSTEMS
            or ecosystem in seen
        ):
            return (
                False,
                "FAIL-CLOSED: dependency audit ecosystem evidence is invalid.",
                0,
            )
        seen.add(ecosystem)

        applicable = outcome.get("applicable")
        if not isinstance(applicable, bool):
            return False, "FAIL-CLOSED: dependency audit applicability is invalid.", 0
        state = outcome.get("state")
        vulnerability_count = outcome.get("vulnerability_count")
        reason_code = outcome.get("reason_code")

        if not applicable:
            if any(
                value is not None
                for value in (state, vulnerability_count, reason_code)
            ):
                return (
                    False,
                    "FAIL-CLOSED: non-applicable dependency audit evidence "
                    "is contradictory.",
                    0,
                )
            states[ecosystem] = None
            continue

        if not isinstance(state, str) or state not in {
            "clean",
            "vulnerable",
            "indeterminate",
        }:
            return False, "FAIL-CLOSED: dependency audit state is invalid.", 0
        if state == "indeterminate":
            if vulnerability_count is not None or not (
                isinstance(reason_code, str)
                and reason_code in DEPENDENCY_AUDIT_INDETERMINATE_REASONS
            ):
                return (
                    False,
                    "FAIL-CLOSED: indeterminate dependency audit evidence is invalid.",
                    0,
                )
            return (
                False,
                f"FAIL-CLOSED: {ecosystem} dependency audit is indeterminate "
                f"({reason_code}).",
                0,
            )

        if (
            not isinstance(vulnerability_count, int)
            or isinstance(vulnerability_count, bool)
            or vulnerability_count < 0
            or reason_code is not None
        ):
            return (
                False,
                "FAIL-CLOSED: dependency audit result evidence is invalid.",
                0,
            )
        if state == "clean" and vulnerability_count != 0:
            return (
                False,
                "FAIL-CLOSED: clean dependency audit evidence is contradictory.",
                0,
            )
        if state == "vulnerable":
            if vulnerability_count == 0:
                return (
                    False,
                    "FAIL-CLOSED: vulnerable dependency audit evidence is "
                    "contradictory.",
                    0,
                )
            vulnerable_outcomes += 1
        states[ecosystem] = state

    if seen != _DEPENDENCY_AUDIT_ECOSYSTEMS:
        return (
            False,
            "FAIL-CLOSED: dependency audit ecosystem evidence is incomplete.",
            0,
        )
    if evidence.get("complete") is not True:
        return False, "FAIL-CLOSED: dependency audit did not complete.", 0

    audit_finding_counts = dict.fromkeys(_DEPENDENCY_AUDIT_ECOSYSTEMS, 0)
    try:
        findings_bytes = findings_path.read_bytes()
        findings_text = findings_bytes.decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return False, "FAIL-CLOSED: dependency audit findings are unreadable.", 0
    if sha256_hex(findings_bytes) != summary.get("findings_file_sha256"):
        return (
            False,
            "FAIL-CLOSED: findings changed during dependency audit validation.",
            0,
        )

    for line_number, raw_line in enumerate(findings_text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            finding = json.loads(raw_line)
        except (json.JSONDecodeError, TypeError, ValueError):
            return (
                False,
                "FAIL-CLOSED: findings JSONL is malformed at line "
                f"{line_number}.",
                0,
            )
        if not isinstance(finding, dict):
            return (
                False,
                "FAIL-CLOSED: findings JSONL contains a non-object record.",
                0,
            )

        finding_id = finding.get("id")
        pattern_id = finding.get("pattern_id")
        if (
            isinstance(finding_id, str)
            and finding_id in _DEPENDENCY_AUDIT_INCOMPLETE_FINDING_IDS
        ) or (
            isinstance(pattern_id, str)
            and pattern_id in _DEPENDENCY_AUDIT_INCOMPLETE_FINDING_IDS
        ):
            return (
                False,
                "FAIL-CLOSED: complete dependency audit evidence contradicts an "
                "incomplete audit finding.",
                0,
            )

        matching_ecosystems = {
            ecosystem
            for ecosystem, expected_id in _DEPENDENCY_AUDIT_FINDING_IDS.items()
            if finding_id == expected_id or pattern_id == expected_id
        }
        if not matching_ecosystems:
            continue
        if len(matching_ecosystems) != 1:
            return (
                False,
                "FAIL-CLOSED: dependency audit finding ecosystem is ambiguous.",
                0,
            )
        ecosystem = matching_ecosystems.pop()
        expected_id = _DEPENDENCY_AUDIT_FINDING_IDS[ecosystem]
        if (
            finding_id != expected_id
            or pattern_id != expected_id
            or finding.get("severity") != "P1"
            or finding.get("source") != "harness"
            or finding.get("category") != "supply-chain"
        ):
            return (
                False,
                f"FAIL-CLOSED: {ecosystem} dependency audit finding is invalid.",
                0,
            )
        audit_finding_counts[ecosystem] += 1
        if audit_finding_counts[ecosystem] > 1:
            return (
                False,
                f"FAIL-CLOSED: duplicate {ecosystem} dependency audit findings.",
                0,
            )

    for ecosystem, state in states.items():
        finding_count = audit_finding_counts[ecosystem]
        if state != "vulnerable" and finding_count:
            return (
                False,
                f"FAIL-CLOSED: {ecosystem} audit finding contradicts "
                f"{state or 'not-applicable'} evidence.",
                0,
            )
    for ecosystem, state in states.items():
        if state == "vulnerable" and audit_finding_counts[ecosystem] != 1:
            return (
                False,
                f"FAIL-CLOSED: {ecosystem} vulnerability evidence is missing its "
                "audit finding.",
                0,
            )
    return True, None, vulnerable_outcomes


def evaluate_gate(run_dir: Path, config: GateConfig) -> GateResult:
    """Evaluate gate decision from local artifacts only (NO network calls)."""

    summary_path = _resolve_summary_path(run_dir)
    valid, error, summary = _validate_pack_summary(summary_path)
    if not valid:
        return GateResult(
            status=GateStatus.ERROR,
            reason=error or "FAIL-CLOSED: PACK_SUMMARY.json invalid.",
            block_merge=True,
            counts=Counts(),
        )

    counts = Counts(
        p0=int(summary.get("counts", {}).get("P0", 0)),
        p1=int(summary.get("counts", {}).get("P1", 0)),
        p2=int(summary.get("counts", {}).get("P2", 0)),
        p3=int(summary.get("counts", {}).get("P3", 0)),
    )
    dedupe_key = summary.get("dedupe_key")

    if config.require_dependency_audit_success:
        findings_path = summary_path.parent / summary["findings_file"]
        audit_valid, audit_error, vulnerable_outcomes = (
            _validate_dependency_audit_evidence(summary, findings_path)
        )
        if not audit_valid:
            return GateResult(
                status=GateStatus.ERROR,
                reason=(
                    audit_error
                    or "FAIL-CLOSED: dependency audit evidence is invalid."
                ),
                block_merge=True,
                counts=counts,
                dedupe_key=dedupe_key,
            )
        if counts.p1 < vulnerable_outcomes:
            return GateResult(
                status=GateStatus.ERROR,
                reason=(
                    "FAIL-CLOSED: dependency audit findings are missing from "
                    "packaged counts."
                ),
                block_merge=True,
                counts=counts,
                dedupe_key=dedupe_key,
            )

    if config.require_llm_success:
        llm_valid, llm_error = _validate_llm_evidence(summary)
        if not llm_valid:
            return GateResult(
                status=GateStatus.ERROR,
                reason=llm_error or "FAIL-CLOSED: live LLM evidence is invalid.",
                block_merge=True,
                counts=counts,
                dedupe_key=dedupe_key,
            )

    gate = str(config.severity_gate or "P1").strip().upper()
    if gate == "NONE":
        return GateResult(
            status=GateStatus.PASSED,
            reason="Gate disabled (severity_gate=none).",
            block_merge=False,
            counts=counts,
            dedupe_key=dedupe_key,
        )

    blocking: tuple[str, ...]
    if gate == "P0":
        blocking = ("P0",)
        block = counts.p0 > 0
    elif gate == "P1":
        blocking = ("P0", "P1")
        block = (counts.p0 + counts.p1) > 0
    elif gate == "P2":
        blocking = ("P0", "P1", "P2")
        block = (counts.p0 + counts.p1 + counts.p2) > 0
    else:
        blocking = ("P0", "P1")
        block = (counts.p0 + counts.p1) > 0

    if block:
        parts = []
        if "P0" in blocking:
            parts.append(f"P0={counts.p0}")
        if "P1" in blocking:
            parts.append(f"P1={counts.p1}")
        if "P2" in blocking:
            parts.append(f"P2={counts.p2}")
        return GateResult(
            status=GateStatus.BLOCKED,
            reason=f"Blocked (severity_gate={gate}): " + ", ".join(parts),
            block_merge=True,
            counts=counts,
            dedupe_key=dedupe_key,
        )

    return GateResult(
        status=GateStatus.PASSED,
        reason=(
            f"Passed (severity_gate={gate}): no {('/'.join(blocking))} findings. "
            f"Counts: P0={counts.p0}, P1={counts.p1}, P2={counts.p2}, P3={counts.p3}"
        ),
        block_merge=False,
        counts=counts,
        dedupe_key=dedupe_key,
    )
