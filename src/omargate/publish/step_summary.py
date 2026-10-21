from __future__ import annotations

import os
import html
import uuid
from typing import Any, Optional

from ..formatting import format_int, truncate
from ..models import GateResult, GateStatus
from ..ingest.codebase_snapshot import build_codebase_synopsis, render_codebase_snapshot_md
from ..redaction import sanitize_public_error, sanitize_untrusted_markdown_scalar


def _status_key(status: GateStatus | str) -> str:
    return status.value if isinstance(status, GateStatus) else str(status)


def _blocking_severities(severity_gate: str) -> set[str]:
    gate = (severity_gate or "P1").strip().upper()
    if gate == "P0":
        return {"P0"}
    if gate == "P1":
        return {"P0", "P1"}
    if gate == "P2":
        return {"P0", "P1", "P2"}
    return set()


def _sort_int(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError):
        return 0


def _sanitize_snapshot_scalars(value: Any) -> Any:
    """Encode repository-derived strings while preserving the trusted template."""

    if isinstance(value, dict):
        return {key: _sanitize_snapshot_scalars(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_snapshot_scalars(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_snapshot_scalars(item) for item in value)
    if isinstance(value, str):
        return sanitize_untrusted_markdown_scalar(value)
    return value


def _review_completeness(summary: dict) -> list[str]:
    lines = ["### Review completeness", ""]
    audit = summary.get("dependency_audit_evidence")
    if isinstance(audit, dict):
        state = ("DISABLED" if audit.get("enabled") is False else
                 "COMPLETE" if audit.get("complete") is True else "INCOMPLETE")
        lines.append(f"- Dependency audit: **{state}**")
        outcomes = audit.get("outcomes")
        if isinstance(outcomes, list):
            for outcome in outcomes[:3]:
                if not isinstance(outcome, dict) or outcome.get("applicable") is not True:
                    continue
                ecosystem = sanitize_untrusted_markdown_scalar(outcome.get("ecosystem", "unknown"))
                status = sanitize_untrusted_markdown_scalar(outcome.get("state", "unknown"))
                reason = sanitize_untrusted_markdown_scalar(outcome.get("reason_code") or "none")
                lines.append(f"  - {ecosystem}: {status} (reason: {reason})")
    evidence = summary.get("llm_evidence")
    if isinstance(evidence, dict):
        state = ("NOT ATTEMPTED" if evidence.get("attempted") is not True else
                 "COMPLETE" if evidence.get("success") is True and evidence.get("output_valid") is True else "INCOMPLETE")
        reason = sanitize_untrusted_markdown_scalar(evidence.get("failure_class") or "none")
        lines.append(f"- Live model review: **{state}** (reason: {reason})")
    lines.append("")
    return lines if len(lines) > 3 else []


def _write_console_report(markdown: str) -> None:
    # A report may contain repository/model text. Disable workflow commands
    # while rendering it, then flush before the final stderr annotation.
    token = uuid.uuid4().hex
    print("::group::Omar Gate report")
    print(f"::stop-commands::{token}")
    try:
        print(sanitize_public_error(html.unescape(markdown)), flush=True)
    finally:
        print(f"::{token}::")
        print("::endgroup::", flush=True)


def write_step_summary(
    gate_result: GateResult,
    summary: dict,
    findings: list[dict],
    run_id: str,
    version: str,
    *,
    codebase_snapshot: Optional[dict] = None,
    codebase_synopsis: Optional[str] = None,
) -> None:
    """
    Print the report before the gate annotation and write the Actions summary.

    This appears in the job summary, providing quick visibility
    without clicking into logs.
    """
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")

    counts = summary.get("counts", {}) if summary else {}
    if not counts:
        counts = {
            "P0": gate_result.counts.p0,
            "P1": gate_result.counts.p1,
            "P2": gate_result.counts.p2,
            "P3": gate_result.counts.p3,
            "P4": gate_result.counts.p4,
        }

    severity_gate = str(summary.get("severity_gate") or "P1").strip().upper() if summary else "P1"
    blocking = _blocking_severities(severity_gate)

    status = _status_key(gate_result.status)
    status_icon = {
        "passed": "✅",
        "blocked": "❌",
        "bypassed": "⚠️",
        "needs_approval": "⏸️",
        "error": "🔴",
    }.get(status, "❓")

    safe_status = sanitize_untrusted_markdown_scalar(status.upper())
    safe_severity_gate = sanitize_untrusted_markdown_scalar(severity_gate)
    safe_reason = sanitize_untrusted_markdown_scalar(gate_result.reason)

    md = [
        f"## 🛡️ Omar Gate: {status_icon} {safe_status}",
        "",
        f"**Gate:** `{safe_severity_gate}`",
        f"**Result:** {safe_reason}",
        "",
        "| Severity | Count | Blocks Merge? |",
        "|----------|------:|:------------:|",
        f"| P0 (Critical) | {format_int(counts.get('P0', 0))} | {'Yes' if 'P0' in blocking else 'No'} |",
        f"| P1 (High) | {format_int(counts.get('P1', 0))} | {'Yes' if 'P1' in blocking else 'No'} |",
        f"| P2 (Medium) | {format_int(counts.get('P2', 0))} | {'Yes' if 'P2' in blocking else 'No'} |",
        f"| P3 (Low) | {format_int(counts.get('P3', 0))} | No |",
        f"| P4 (Informational) | {format_int(counts.get('P4', 0))} | No |",
        "",
    ]

    md.extend(_review_completeness(summary))

    from ..analyze.review_costs import render_cost_ledger
    md.extend(render_cost_ledger((summary.get("llm_usage") or {}).get("cost_ledger")))

    resolved_synopsis = (codebase_synopsis or "").strip()
    if not resolved_synopsis and codebase_snapshot:
        resolved_synopsis = build_codebase_synopsis(codebase_snapshot=codebase_snapshot)
    if resolved_synopsis:
        safe_synopsis = sanitize_untrusted_markdown_scalar(resolved_synopsis)
        md.extend([f"**Codebase Synopsis:** {safe_synopsis}", ""])

    if findings:
        md.append("### Top Findings")
        md.append("")
        severity_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
        top = sorted(
            (f for f in findings if isinstance(f, dict)),
            key=lambda f: (
                severity_order.get(str(f.get("severity", "")).upper(), 99),
                str(f.get("file_path") or ""),
                _sort_int(f.get("line_start")),
            ),
        )[:3]
        for finding in top:
            severity = sanitize_untrusted_markdown_scalar(
                str(finding.get("severity", "?")).upper()
            )
            file_path = sanitize_untrusted_markdown_scalar(finding.get("file_path", "?"))
            line_start = sanitize_untrusted_markdown_scalar(finding.get("line_start", "?"))
            category = sanitize_untrusted_markdown_scalar(finding.get("category", "Issue"))
            message = sanitize_untrusted_markdown_scalar(
                truncate(str(finding.get("message") or "No description"), 200)
            )
            md.append(f"- **{severity}** `{file_path}:{line_start}` · **{category}**: {message}")
        md.append("")

    if codebase_snapshot:
        try:
            safe_snapshot = _sanitize_snapshot_scalars(codebase_snapshot)
            snapshot_md = render_codebase_snapshot_md(safe_snapshot).strip()
            if snapshot_md.startswith("# "):
                snapshot_md = "### " + snapshot_md[2:]
            md.extend(
                [
                    "<details>",
                    "<summary>Codebase Snapshot (Deterministic)</summary>",
                    "",
                    snapshot_md,
                    "",
                    "</details>",
                    "",
                ]
            )
        except Exception:
            pass

    safe_version = sanitize_untrusted_markdown_scalar(version)
    safe_run_id = sanitize_untrusted_markdown_scalar(run_id[:8])
    md.append(f"<sub>Omar Gate v{safe_version} • run_id={safe_run_id}</sub>")
    md.append("")

    report = "\n".join(md)
    _write_console_report(report)
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary_file:
            summary_file.write(report)
