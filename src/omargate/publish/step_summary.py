from __future__ import annotations

import os
from typing import Any, Optional

from ..formatting import format_int, truncate
from ..models import GateResult, GateStatus
from ..ingest.codebase_snapshot import build_codebase_synopsis, render_codebase_snapshot_md
from ..redaction import sanitize_untrusted_markdown_scalar


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
    Write GitHub Actions Step Summary.

    This appears in the job summary, providing quick visibility
    without clicking into logs.
    """
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    counts = summary.get("counts", {}) if summary else {}
    if not counts:
        counts = {
            "P0": gate_result.counts.p0,
            "P1": gate_result.counts.p1,
            "P2": gate_result.counts.p2,
            "P3": gate_result.counts.p3,
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
        "",
    ]

    resolved_synopsis = (codebase_synopsis or "").strip()
    if not resolved_synopsis and codebase_snapshot:
        resolved_synopsis = build_codebase_synopsis(codebase_snapshot=codebase_snapshot)
    if resolved_synopsis:
        safe_synopsis = sanitize_untrusted_markdown_scalar(resolved_synopsis)
        md.extend([f"**Codebase Synopsis:** {safe_synopsis}", ""])

    if findings:
        md.append("### Top Findings")
        md.append("")
        severity_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
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

    with open(summary_path, "a", encoding="utf-8") as summary_file:
        summary_file.write("\n".join(md))
