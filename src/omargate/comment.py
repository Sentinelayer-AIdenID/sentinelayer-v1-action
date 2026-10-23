from __future__ import annotations

import re
from typing import Iterable, List, Optional

from .formatting import (
    format_int,
    format_usd,
    github_blob_url,
    humanize_duration_ms,
    truncate,
)
from .fix_plan import ensure_fix_plan
from .ingest.codebase_snapshot import build_codebase_synopsis, render_codebase_snapshot_md
from .models import GateResult, GateStatus
from .redaction import sanitize_public_error, sanitize_untrusted_markdown_scalar

MARKER_PREFIX = "<!-- sentinelayer:omar-gate:v1:"

_SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


def _normalize_comment_tag(comment_tag: str = "") -> str:
    tag = str(comment_tag or "").strip().lower()
    if not tag:
        return ""
    tag = re.sub(r"[^a-z0-9_-]+", "-", tag)
    tag = re.sub(r"-{2,}", "-", tag).strip("-_")
    return tag


def marker(repo_full_name: str, pr_number: int, comment_tag: str = "") -> str:
    tag = _normalize_comment_tag(comment_tag)
    if tag:
        return f"{MARKER_PREFIX}{tag}:{repo_full_name}:{pr_number} -->"
    return f"{MARKER_PREFIX}{repo_full_name}:{pr_number} -->"


def marker_prefix(comment_tag: str = "") -> str:
    tag = _normalize_comment_tag(comment_tag)
    if tag:
        return f"{MARKER_PREFIX}{tag}:"
    return MARKER_PREFIX


def _status_key(status: GateStatus | str) -> str:
    return status.value if isinstance(status, GateStatus) else str(status)


def _status_badge(status: GateStatus | str) -> str:
    badges = {
        "passed": "✅ PASSED",
        "blocked": "❌ BLOCKED",
        "bypassed": "⚠️ BYPASSED",
        "needs_approval": "⏸️ NEEDS APPROVAL",
        "error": "🔴 ERROR",
    }
    return badges.get(_status_key(status), "❓ UNKNOWN")


def _blocking_severities(severity_gate: str) -> List[str]:
    gate = (severity_gate or "P1").strip().upper()
    if gate == "P0":
        return ["P0"]
    if gate == "P1":
        return ["P0", "P1"]
    if gate == "P2":
        return ["P0", "P1", "P2"]
    return []


def _gate_label(severity_gate: str) -> str:
    gate = (severity_gate or "P1").strip().upper()
    if gate == "NONE":
        return "none (disabled)"
    blocking = _blocking_severities(gate)
    if not blocking:
        return gate
    return f"{gate} (blocks {', '.join(blocking)})"


def _next_steps(status: GateStatus | str, severity_gate: str) -> str:
    gate = (severity_gate or "P1").strip().upper()
    blocking = _blocking_severities(gate)
    blocking_label = "/".join(blocking) if blocking else "configured severities"

    steps = {
        "passed": [
            "No action required from Omar Gate. Merge once other required checks pass.",
        ],
        "blocked": [
            f"Fix findings at or above the gate threshold ({blocking_label}), then re-run Omar Gate.",
            "If you believe a finding is a false positive, document the rationale and follow your exception workflow.",
        ],
        "bypassed": [
            "Gate was bypassed. Ensure manual review and document the exception.",
        ],
        "needs_approval": [
            "Approval required before scanning can proceed. Follow your repo's approval workflow (label or manual rerun).",
        ],
        "error": [
            "Gate failed closed. Inspect logs/artifacts, fix the underlying error, then re-run.",
        ],
    }
    lines = steps.get(_status_key(status), ["Review the run details and take appropriate action."])
    return "\n".join(f"- {line}" for line in lines)


def _warnings_section(warnings: Optional[List[str]]) -> str:
    if not warnings:
        return ""
    lines = ["<details>", "<summary>Warnings</summary>", ""]
    lines.extend(f"- {truncate(sanitize_public_error(w), 400)}" for w in warnings[:25])
    if len(warnings) > 25:
        lines.append(f"- ...and {len(warnings) - 25} more")
    lines.extend(["", "</details>"])
    return "\n".join(lines)


def _select_top_findings(findings: Iterable[dict], *, max_items: int = 5) -> List[dict]:
    out: List[dict] = []
    seen = set()
    for finding in sorted(
        (f for f in findings or [] if isinstance(f, dict)),
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity", "")).upper(), 99),
            float(f.get("confidence", 0.0) or 0.0) * -1.0,
            str(f.get("file_path") or ""),
            int(f.get("line_start") or 0),
        ),
    ):
        fid = str(finding.get("id") or "")
        fp = str(finding.get("fingerprint") or "")
        dedupe_key = fp or fid or (
            str(finding.get("severity") or ""),
            str(finding.get("category") or ""),
            str(finding.get("file_path") or ""),
            str(finding.get("line_start") or ""),
            str(finding.get("message") or ""),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        out.append(finding)
        if len(out) >= max_items:
            break
    return out


def _top_findings_section(
    findings: Optional[List[dict]],
    *,
    server_url: str,
    repo_full_name: str,
    head_sha: Optional[str],
    max_items: int = 5,
) -> str:
    if not findings:
        return ""

    selected = _select_top_findings(findings, max_items=max_items)
    if not selected:
        return ""

    lines = ["### Top Findings", ""]
    for idx, finding in enumerate(selected, start=1):
        severity = str(finding.get("severity") or "?").upper()
        file_path = str(finding.get("file_path") or "?").replace("\\", "/")
        line_start = finding.get("line_start")
        category = sanitize_untrusted_markdown_scalar(
            finding.get("category") or "Issue"
        )
        raw_message = sanitize_public_error(
            str(finding.get("message") or "No description").strip()
        )
        message = sanitize_untrusted_markdown_scalar(truncate(raw_message, 220))
        raw_fix_plan = truncate(
            ensure_fix_plan(
                fix_plan=sanitize_public_error(finding.get("fix_plan", "")),
                recommendation=sanitize_public_error(finding.get("recommendation", "")),
                message=raw_message,
            ),
            600,
        )
        fix_plan = sanitize_untrusted_markdown_scalar(raw_fix_plan)

        loc = f"{file_path}:{line_start}" if line_start else file_path
        link = None
        if head_sha and repo_full_name and file_path and file_path != "?":
            link = github_blob_url(
                server_url=server_url,
                repo_full_name=repo_full_name,
                head_sha=head_sha,
                path=file_path,
                line=int(line_start) if line_start else None,
            )
        if link:
            loc_md = f"[`{loc}`]({link})"
        else:
            loc_md = f"`{loc}`"

        lines.append(f"{idx}. **{severity}** {loc_md} · **{category}**: {message}")
        lines.append(f"   > **Fix:** {fix_plan}")
        lines.append("   > **Apply Fix:** Coming soon.")

    return "\n".join(lines)

def _review_chain_section(llm_evidence, review_routing, llm_engine, llm_model):
    """Render the review chain: triage, route, reviewer, and call outcome.

    Shows what the intent cascade decided and what actually happened, so a reader
    can see at a glance whether a review was refused, attempted, or completed —
    and never mistakes a refused review for a disabled one.
    """
    evidence = llm_evidence or {}
    routing = review_routing or {}

    lines = ["", "### Review chain", ""]

    # Triage row
    triage_status = routing.get("triage_status", "")
    failure_reason = routing.get("source_failure_reason", "")
    if triage_status:
        status_display = triage_status.replace("_", " ")
        lines.append("- **Triage:** `" + status_display + "`")
        if failure_reason:
            lines.append("  - Reason: `" + failure_reason + "`")
    elif evidence.get("failure_class"):
        lines.append("- **Triage:** not reached (`" + str(evidence["failure_class"]) + "`)")
    else:
        lines.append("- **Triage:** not available")

    # Route + reviewer row
    routes = routing.get("routes", [])
    if routes:
        lines.append("- **Route:**")
        for i, r in enumerate(routes):
            tier = r.get("tier", "?")
            req_model = r.get("model", "?")
            effort = r.get("effort", "?")
            success = r.get("success")
            reported = r.get("reported_model", "")
            has_reported = isinstance(reported, str) and reported != ""
            identity_matches = r.get("identity_matches")
            attempted = has_reported or identity_matches is True
            lines.append("  " + str(i + 1) + ". `" + tier + "` \u2192 `" + req_model + "` / `" + effort + "`")
            if attempted:
                status_mark = "passed" if success else "failed"
                returned_display = reported if has_reported else "unknown"
                lines.append("     - Attempted: yes, returned `" + returned_display + "` \u2014 **" + status_mark + "**")
            else:
                lines.append("     - Attempted: no")
    else:
        if llm_engine == "refused":
            lines.append("- **Route:** refused (`" + llm_model + "`)")
        elif llm_engine == "disabled":
            lines.append("- **Route:** LLM not configured")
        else:
            lines.append("- **Route:** `" + llm_engine + "` / `" + llm_model + "`")

    # Evidence row
    attempted = evidence.get("attempted")
    success = evidence.get("success")
    failure_class = evidence.get("failure_class")
    if attempted is not None:
        lines.append("- **Attempted:** " + str(attempted))
    if success is not None:
        lines.append("- **Success:** " + str(success))
    if failure_class:
        lines.append("- **Failure class:** `" + str(failure_class) + "`")

    return "\n".join(lines) + "\n"

def _codebase_snapshot_section(codebase_snapshot: Optional[dict]) -> str:
    if not codebase_snapshot:
        return ""
    try:
        snapshot_md = render_codebase_snapshot_md(codebase_snapshot).strip()
    except Exception:
        return ""

    # Avoid giant headings inside PR comment sections.
    if snapshot_md.startswith("# "):
        snapshot_md = "### " + snapshot_md[2:]

    # GitHub comment bodies have practical size limits; keep this bounded.
    if len(snapshot_md) > 12_000:
        snapshot_md = snapshot_md[:12_000].rstrip() + "\n\n...(truncated)...\n"

    lines = ["<details>", "<summary>Codebase Snapshot (Deterministic)</summary>", ""]
    lines.extend([snapshot_md, "", "</details>"])
    return "\n".join(lines)


def render_pr_comment(
    result: GateResult,
    run_id: str,
    repo_full_name: str,
    pr_number: int,
    dashboard_url: Optional[str],
    artifacts_url: Optional[str],
    estimated_cost_usd: Optional[float],
    version: str,
    findings: Optional[List[dict]] = None,
    warnings: Optional[List[str]] = None,
    review_brief_md: Optional[str] = None,
    scan_mode: str = "pr-diff",
    policy_pack: str = "omar",
    policy_pack_version: str = "v1",
    severity_gate: str = "P1",
    duration_ms: Optional[int] = None,
    files_scanned: Optional[int] = None,
    llm_engine: str = "disabled",
    llm_model: str = "n/a",
    actual_cost_usd: Optional[float] = None,
    review_cost_ledger: Optional[dict] = None,
    deterministic_count: int = 0,
    llm_count: int = 0,
    dedupe_key: Optional[str] = None,
    head_sha: Optional[str] = None,
    server_url: str = "https://github.com",
    codebase_snapshot: Optional[dict] = None,
    codebase_synopsis: Optional[str] = None,
    comment_tag: str = "",
    llm_evidence: Optional[dict] = None,
    review_routing: Optional[dict] = None,
) -> str:
    """
    Render the PR comment for Omar Gate.

    Design goals:
    - Short by default; actionable without expanding details
    - Accurate (no "0.00" when cost is unknown; no model=none when LLM ran)
    - Accessible (avoid meaning encoded only by emoji)
    """
    status_badge = _status_badge(result.status)
    gate_label = _gate_label(severity_gate)

    duration_value = humanize_duration_ms(duration_ms)
    estimated_cost_value = format_usd(estimated_cost_usd)
    actual_cost_value = format_usd(actual_cost_usd)
    from .analyze.review_costs import render_cost_ledger
    model_cost_section = "\n".join(render_cost_ledger(review_cost_ledger))

    blocking = set(_blocking_severities(severity_gate))

    warnings_section = _warnings_section(warnings)
    top_findings_section = _top_findings_section(
        findings,
        server_url=server_url,
        repo_full_name=repo_full_name,
        head_sha=head_sha,
        max_items=5,
    )
    next_steps = _next_steps(result.status, severity_gate)

    # Links / artifacts
    links: List[str] = []
    if artifacts_url:
        links.append(f"- Workflow run: {artifacts_url}")
    if dashboard_url:
        links.append(f"- Dashboard: {dashboard_url}")
    if not links:
        links.append("- Links not available (missing token or context).")

    artifacts_help = [
        "- Reports generated on the runner:",
        "  - `AUDIT_REPORT.md` (full report)",
        "  - `REVIEW_BRIEF.md` (reviewer summary)",
        "  - `FINDINGS.jsonl` (all findings)",
        "  - `PACK_SUMMARY.json` (counts + integrity)",
        "  - `CODEBASE_INGEST_SUMMARY.md` (deterministic codebase snapshot)",
        "  - `CODEBASE_INGEST_SUMMARY.json` (snapshot, machine-readable)",
        "  - `CODEBASE_INGEST.md` (source index)",
        "  - `CODEBASE_INGEST.json` (full ingest + file inventory)",
        f"- Run artifacts: `.sentinelayer/runs/{run_id}/`",
        "- Upload with `actions/upload-artifact` (replace the step id if yours is not `omar`):",
        "```yaml",
        "- uses: actions/upload-artifact@v4",
        "  if: always()",
        "  with:",
        "    name: sentinelayer-${{ steps.omar.outputs.run_id }}",
        "    path: .sentinelayer/runs/${{ steps.omar.outputs.run_id }}",
        "```",
        "- Optional: a small upload bundle is also staged under `.sentinelayer/artifacts/` when the workspace is writable.",
    ]

    # Keep the inline brief short; artifacts are the source of truth.
    inline_review_brief = ""
    if review_brief_md:
        trimmed = review_brief_md.strip()
        if len(trimmed) > 12_000:
            trimmed = trimmed[:12_000].rstrip() + "\n\n...(truncated)...\n"
        inline_review_brief = "\n".join(
            [
                "",
                "<details>",
                "<summary>Reviewer Brief (inline, truncated)</summary>",
                "",
                trimmed,
                "",
                "</details>",
            ]
        )

    # Counts table with explicit blocking semantics.
    review_chain_section = _review_chain_section(
        llm_evidence=llm_evidence, review_routing=review_routing,
        llm_engine=llm_engine, llm_model=llm_model,
    )

    lines = [
        f"## 🛡️ Omar Gate: {status_badge}",
        "",
        f"**Gate:** `{gate_label}`",
        f"**Policy:** `{policy_pack}@{policy_pack_version}` • **Scan:** `{scan_mode}`",
        f"**Duration:** `{duration_value}`"
        + (f" • **Files:** `{format_int(int(files_scanned))}`" if files_scanned is not None else "")
        + f" • **LLM:** `{llm_engine}` (`{llm_model}`)"
        + f" • **Cost (est.):** `{estimated_cost_value}`"
        + (f" • **Cost (usage estimate):** `{actual_cost_value}`" if actual_cost_usd is not None else ""),
        model_cost_section,
        review_chain_section,
        "",
        f"**Result:** {result.reason}",
        "",
        "| Severity | Count | Blocks Merge? |",
        "|----------|------:|:------------:|",
        f"| P0 (Critical) | {format_int(result.counts.p0)} | {'Yes' if 'P0' in blocking else 'No'} |",
        f"| P1 (High) | {format_int(result.counts.p1)} | {'Yes' if 'P1' in blocking else 'No'} |",
        f"| P2 (Medium) | {format_int(result.counts.p2)} | {'Yes' if 'P2' in blocking else 'No'} |",
        f"| P3 (Low) | {format_int(result.counts.p3)} | No |",
        f"| P4 (Informational) | {format_int(result.counts.p4)} | No |",
        "",
    ]

    resolved_synopsis = (codebase_synopsis or "").strip()
    if not resolved_synopsis and codebase_snapshot:
        resolved_synopsis = build_codebase_synopsis(codebase_snapshot=codebase_snapshot)

    if codebase_snapshot:
        stats = codebase_snapshot.get("stats", {}) if isinstance(codebase_snapshot, dict) else {}
        loc = stats.get("source_loc_total")
        in_scope = stats.get("in_scope_files")
        if loc is not None or in_scope is not None:
            loc_str = format_int(int(loc)) if loc is not None else "?"
            in_scope_str = format_int(int(in_scope)) if in_scope is not None else "?"
            # Insert just below the Duration line (before the first blank line).
            lines.insert(
                5,
                f"**Codebase:** `{in_scope_str}` in-scope files • `{loc_str}` LOC (source)",
            )
            if resolved_synopsis:
                lines.insert(6, f"**Codebase Synopsis:** {resolved_synopsis}")
        elif resolved_synopsis:
            lines.insert(5, f"**Codebase Synopsis:** {resolved_synopsis}")

    if top_findings_section:
        lines.append(top_findings_section)
        lines.append("")

    snapshot_section = _codebase_snapshot_section(codebase_snapshot)
    if snapshot_section:
        lines.append(snapshot_section)
        lines.append("")

    lines.extend(["### Next Steps", "", next_steps, ""])

    # False-positive defense explainer — always shown so users understand trust model.
    fp_defense = "\n".join(
        [
            "<details>",
            "<summary>False Positive Defense (3 layers)</summary>",
            "",
            "Omar Gate uses three independent layers to minimize false positives:",
            "",
            "**Layer 1 — AST & Syntax-Aware Deterministic Analysis**",
            "- Python dynamic execution primitives are detected via `ast.parse` + `ast.walk`, not regex — "
            "eliminates self-referential matches in comments, strings, and docs.",
            "- JS/TS comment and string literals are blanked before pattern matching.",
            "- Entropy-based secret detection requires context keywords nearby, "
            "minimum length (32), and high Shannon entropy (>4.7) to flag.",
            "",
            "**Layer 2 — Git-Aware Diff Scoping**",
            "- Only *added* lines can produce blocking (P0/P1) findings.",
            "- Removed lines are scanned separately at P3 for optional triage.",
            "- Entropy matches in doc files (`.md`, `.rst`, `.txt`) and historical "
            "commits are auto-downgraded to P3.",
            "",
            "**Layer 3 — LLM Guardrails (Corroboration Required)**",
            "- LLM-sourced P0/P1 findings are automatically downgraded to P2 "
            "unless a deterministic finding in the *same file*, *same category*, "
            "and within *5 lines* corroborates them.",
            "- Findings referencing files not in the scanned diff are dropped entirely.",
            "- Line numbers are clamped to valid ranges; hallucinated locations are discarded.",
            "",
            "This layered approach ensures that blocking findings are backed by "
            "deterministic evidence — LLM analysis enriches results but cannot "
            "unilaterally block a merge.",
            "",
            "</details>",
        ]
    )
    lines.append(fp_defense)
    lines.append("")

    if warnings_section:
        lines.append(warnings_section)
        lines.append("")

    lines.extend(
        [
            "<details>",
            "<summary>Artifacts & Full Report</summary>",
            "",
            "\n".join(links),
            "",
            "\n".join(artifacts_help),
            inline_review_brief,
            "",
            "</details>",
            "",
            "---",
            "",
            f"<sub>Omar Gate v{version} · run_id={run_id[:8]} · dedupe={(dedupe_key or 'n/a')[:8]} · raw_findings(det={deterministic_count}, llm={llm_count})</sub>",
            "",
            marker(repo_full_name, pr_number, comment_tag=comment_tag),
        ]
    )

    return "\n".join(lines)
