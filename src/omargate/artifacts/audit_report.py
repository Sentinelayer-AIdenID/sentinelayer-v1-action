from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from ..fix_plan import ensure_fix_plan
from ..formatting import humanize_duration_ms
from ..ingest.codebase_snapshot import build_codebase_snapshot
from ..redaction import sanitize_public_error, sanitize_untrusted_markdown_scalar

SEVERITY_ICONS = {"P0": "🔴", "P1": "🟠", "P2": "🟡", "P3": "⚪", "P4": "ℹ️"}
CATEGORY_ICONS = {
    "auth": "🔐",
    "payment": "💳",
    "secrets": "🔑",
    "injection": "💉",
    "webhook": "🔗",
    "database": "🗄️",
    "crypto": "🔑",
    "infrastructure": "🔧",
    "quality": "📋",
    "xss": "🌐",
}


def generate_audit_report(
    run_id: str,
    summary: dict,
    findings: List[dict],
    ingest: dict,
    config: dict,
    review_brief_path: Optional[Path] = None,
    version: str = "1.0.0",
) -> str:
    """
    Generate comprehensive human-readable audit report.

    This is AUDIT_REPORT.md - the full report for:
    - HITL reviewers
    - Artifact storage (Tier 3)
    - Export/download
    """
    _ = (review_brief_path,)

    severity_gate = str(
        (config or {}).get("severity_gate")
        or summary.get("severity_gate")
        or "P1"
    ).strip().upper()

    lines = []

    # Header
    policy_pack = summary.get("policy_pack", "omar")
    policy_pack_version = str(summary.get("policy_pack_version", "v1"))
    policy_display = (
        f"{policy_pack}@{policy_pack_version}"
        if "@" not in policy_pack_version
        else f"{policy_pack}{policy_pack_version}"
    )
    lines.extend(
        [
            "# 🛡️ Omar Gate Audit Report",
            "",
            f"**Run ID:** `{run_id}`",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Policy:** {policy_display}",
            f"**Gate:** `{severity_gate}`",
            f"**Duration:** {humanize_duration_ms(summary.get('duration_ms'))}",
            "",
            "---",
            "",
        ]
    )

    # Executive Summary
    counts = summary.get("counts", {})
    p0 = int(counts.get("P0", 0) or 0)
    p1 = int(counts.get("P1", 0) or 0)
    p2 = int(counts.get("P2", 0) or 0)

    if severity_gate == "NONE":
        gate_result = "DISABLED"
        gate_icon = "⚪"
    elif severity_gate == "P0":
        gate_result = "BLOCKED" if p0 > 0 else "PASSED"
        gate_icon = "❌" if gate_result == "BLOCKED" else "✅"
    elif severity_gate == "P2":
        gate_result = "BLOCKED" if (p0 + p1 + p2) > 0 else "PASSED"
        gate_icon = "❌" if gate_result == "BLOCKED" else "✅"
    else:
        # Default P1 semantics.
        gate_result = "BLOCKED" if (p0 + p1) > 0 else "PASSED"
        gate_icon = "❌" if gate_result == "BLOCKED" else "✅"

    lines.extend(
        [
            "## Executive Summary",
            "",
            f"**Gate Result:** {gate_icon} {gate_result}",
            "",
            "| Severity | Count | Description |",
            "|----------|-------|-------------|",
            f"| {SEVERITY_ICONS['P0']} P0 | {counts.get('P0', 0)} | Critical - Immediate action required |",
            f"| {SEVERITY_ICONS['P1']} P1 | {counts.get('P1', 0)} | High - Action required before merge |",
            f"| {SEVERITY_ICONS['P2']} P2 | {counts.get('P2', 0)} | Medium - Should fix soon |",
            f"| {SEVERITY_ICONS['P3']} P3 | {counts.get('P3', 0)} | Low - Consider fixing |",
            f"| {SEVERITY_ICONS['P4']} P4 | {counts.get('P4', 0)} | Informational - Advisory |",
            f"| **Total** | **{counts.get('total', 0)}** | |",
            "",
            "---",
            "",
        ]
    )

    # Repository Stats
    stats = ingest.get("stats", {})
    hotspots = ingest.get("hotspots", {})
    hotspot_count = sum(len(files) for files in hotspots.values())
    snapshot = {}
    try:
        snapshot = build_codebase_snapshot(ingest)
    except Exception:
        snapshot = {}
    snapshot_stats = snapshot.get("stats", {}) if isinstance(snapshot, dict) else {}
    source_loc_total = int(snapshot_stats.get("source_loc_total", 0) or 0)
    languages = snapshot.get("languages", []) if isinstance(snapshot, dict) else []
    god_files = snapshot.get("god_files", []) if isinstance(snapshot, dict) else []
    largest_source_files = (
        snapshot.get("largest_source_files", []) if isinstance(snapshot, dict) else []
    )

    lines.extend(
        [
            "## Repository Analysis",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Files Scanned | {stats.get('in_scope_files', 0)} |",
            f"| Total Lines | {stats.get('total_lines', 0):,} |",
            f"| LOC (source only) | {source_loc_total:,} |",
            f"| Hotspots Identified | {hotspot_count} |",
            f"| Package Manager | {ingest.get('dependencies', {}).get('package_manager', 'unknown')} |",
            "",
        ]
    )

    # Hotspot breakdown
    if any(files for files in hotspots.values()):
        lines.extend(["### Hotspot Categories", ""])
        for category, files in hotspots.items():
            if files:
                icon = CATEGORY_ICONS.get(category, "📁")
                lines.append(f"- {icon} **{category.title()}**: {len(files)} files")
        lines.append("")

    if languages:
        lines.extend(["### Language Breakdown (Source Only)", ""])
        lines.extend(["| Language | Files | LOC |", "|---|---:|---:|"])
        for item in languages[:20]:
            lang = str(item.get("language") or "unknown")
            files = int(item.get("files", 0) or 0)
            loc = int(item.get("loc", 0) or 0)
            lines.append(f"| {lang} | {files} | {loc:,} |")
        lines.append("")

    if god_files:
        threshold = int(snapshot.get("god_threshold_loc", 1000) or 1000)
        lines.extend([f"### God Components (>= {threshold} LOC)", ""])
        for item in god_files[:25]:
            path = str(item.get("path") or "?")
            loc = int(item.get("lines", 0) or 0)
            lines.append(f"- `{path}` ({loc:,} LOC)")
        lines.append("")

    if largest_source_files:
        lines.extend(["### Largest Source Files", ""])
        for item in largest_source_files[:25]:
            path = str(item.get("path") or "?")
            loc = int(item.get("lines", 0) or 0)
            lines.append(f"- `{path}` ({loc:,} LOC)")
        lines.append("")

    lines.extend(["---", ""])

    # Findings by Severity
    lines.extend(["## Findings Detail", ""])

    for severity in ["P0", "P1", "P2", "P3", "P4"]:
        sev_findings = [f for f in findings if f.get("severity") == severity]
        if not sev_findings:
            continue

        icon = SEVERITY_ICONS[severity]
        lines.extend([
            f"### {icon} {severity} Findings ({len(sev_findings)})",
            "",
        ])

        for idx, finding in enumerate(sev_findings, start=1):
            raw_category = str(finding.get("category", "Unknown"))
            cat_icon = CATEGORY_ICONS.get(raw_category.lower(), "📋")
            category = sanitize_untrusted_markdown_scalar(raw_category)
            confidence = finding.get("confidence")
            if isinstance(confidence, (int, float)):
                confidence_display = f"{confidence:.0%}"
            else:
                confidence_display = "n/a"

            line_start = finding.get("line_start", 0)
            line_end = finding.get("line_end", line_start)
            raw_message = sanitize_public_error(
                finding.get("message", "No description")
            )
            raw_recommendation = sanitize_public_error(
                str(finding.get("recommendation", "") or "").strip()
            )
            raw_fix_plan = ensure_fix_plan(
                fix_plan=sanitize_public_error(finding.get("fix_plan", "")),
                recommendation=raw_recommendation,
                message=raw_message,
            )
            message = sanitize_untrusted_markdown_scalar(raw_message)
            recommendation = sanitize_untrusted_markdown_scalar(raw_recommendation)
            fix_plan = sanitize_untrusted_markdown_scalar(raw_fix_plan)

            lines.extend(
                [
                    f"#### {idx}. {cat_icon} {category}",
                    "",
                    f"**File:** `{finding.get('file_path', 'unknown')}:{line_start}-{line_end}`",
                    f"**Source:** {finding.get('source', 'unknown')}",
                    f"**Confidence:** {confidence_display}",
                    f"**Fingerprint:** `{finding.get('fingerprint', 'n/a')[:12]}...`",
                    "",
                    f"**Issue:** {message}",
                    "",
                ]
            )

            # Snippet (if present and not a secret)
            snippet = finding.get("snippet", "")
            if snippet and str(finding.get("category", "")).lower() != "secrets":
                lines.extend(
                    [
                        "<details>",
                        "<summary>View Code Snippet</summary>",
                        "",
                        "```",
                        snippet[:500] + ("..." if len(snippet) > 500 else ""),
                        "```",
                        "",
                        "</details>",
                        "",
                    ]
                )

            # Recommendation
            lines.extend([f"**Fix Plan:** {fix_plan}", "**Apply Fix:** Coming soon.", ""])
            if recommendation and recommendation != fix_plan:
                lines.extend([f"**Recommendation:** {recommendation}", ""])

            lines.append("---")
            lines.append("")

    # If no findings
    if not findings:
        lines.extend(
            [
                "### ✅ No Findings",
                "",
                "No security or quality issues were detected in this scan.",
                "",
                "---",
                "",
            ]
        )

    # Scan Metadata
    lines.extend(
        [
            "## Scan Metadata",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Run ID | `{run_id}` |",
            f"| Dedupe Key | `{summary.get('dedupe_key', 'n/a')[:8]}...` |",
            f"| Policy Pack | {summary.get('policy_pack', 'omar')} |",
            f"| Policy Version | {summary.get('policy_pack_version', '1.0')} |",
            f"| Stages | {', '.join(summary.get('stages_completed', []))} |",
            f"| Duration | {summary.get('duration_ms', 0)}ms |",
            "",
        ]
    )

    # Tool versions
    tool_versions = summary.get("tool_versions", {})
    if tool_versions:
        lines.extend(["### Tool Versions", ""])
        for tool, version in tool_versions.items():
            lines.append(f"- **{tool}:** {version}")
        lines.append("")

    # Errors
    errors = summary.get("errors")
    if not errors and summary.get("error"):
        errors = [summary.get("error")]
    if errors:
        lines.extend(["### Errors & Warnings", ""])
        for error in errors:
            lines.append(f"- ⚠️ {sanitize_public_error(error)}")
        lines.append("")

    # Footer
    lines.extend(
        [
            "---",
            "",
            f"<sub>Generated by Omar Gate v{version} | [Request HITL Review](https://sentinelayer.com/hitl)</sub>",
        ]
    )

    return "\n".join(lines)


def write_audit_report(
    run_dir: Path,
    run_id: str,
    summary: dict,
    findings: List[dict],
    ingest: dict,
    config: dict,
    version: str = "1.0.0",
) -> Path:
    """Write AUDIT_REPORT.md to run directory."""
    content = generate_audit_report(
        run_id=run_id,
        summary=summary,
        findings=findings,
        ingest=ingest,
        config=config,
        version=version,
    )

    report_path = run_dir / "AUDIT_REPORT.md"
    report_path.write_text(content, encoding="utf-8")
    return report_path
