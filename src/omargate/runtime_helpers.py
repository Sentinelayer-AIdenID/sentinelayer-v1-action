from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from .config import OmarGateConfig
from .models import Counts, GateResult, GateStatus
from .packaging import write_pack_summary
from .telemetry.schemas import SpecComplianceTelemetry
from .utils import parse_iso8601


def _to_workspace_relative(path: Path) -> str:
    """Prefer workspace-relative artifact paths."""
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        try:
            rel = path.relative_to(Path(workspace))
            return str(rel).replace("\\", "/")
        except ValueError:
            pass
    return str(path).replace("\\", "/")


def _escape_workflow_command(value: str) -> str:
    """Escape a string for GitHub workflow commands (annotation messages)."""
    if value is None:
        return ""
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _emit_gate_annotation(
    *,
    gate_result: GateResult,
    severity_gate: str,
    run_id: str,
    run_dir: Path,
    workflow_run_url: str | None,
    dashboard_url: str | None,
) -> None:
    status = (
        gate_result.status.value
        if hasattr(gate_result.status, "value")
        else str(gate_result.status)
    )

    level = "notice"
    if status in {"blocked", "error", "needs_approval"}:
        level = "error"
    elif status in {"bypassed"}:
        level = "warning"

    title = f"Omar Gate {status.upper()}"
    counts = gate_result.counts
    counts_str = f"P0={counts.p0}, P1={counts.p1}, P2={counts.p2}, P3={counts.p3}, P4={counts.p4}"
    link = workflow_run_url or dashboard_url or ""
    link_str = f" Details: {link}" if link else ""

    run_dir_display = _to_workspace_relative(run_dir)
    message = (
        f"{gate_result.reason} | gate={severity_gate} | {counts_str} | "
        f"run_id={run_id}{link_str} | artifacts={run_dir_display}"
    )

    sys.stderr.write(
        f"::{level} title={_escape_workflow_command(title)}::{_escape_workflow_command(message)}\n"
    )
    sys.stderr.flush()


def _latest_completed_check_run(runs: list[dict]) -> dict | None:
    best: dict | None = None
    best_ts: datetime | None = None
    for run in runs:
        if run.get("status") != "completed":
            continue
        ts = parse_iso8601(run.get("completed_at"))
        if not ts:
            continue
        if best_ts is None or ts > best_ts:
            best = run
            best_ts = ts
    return best


def _counts_from_summary(summary: str) -> Counts:
    def _extract(sev: str) -> int:
        match = re.search(rf"\b{re.escape(sev)}=(\d+)\b", summary)
        return int(match.group(1)) if match else 0

    return Counts(
        p0=_extract("P0"),
        p1=_extract("P1"),
        p2=_extract("P2"),
        p3=_extract("P3"),
        p4=_extract("P4"),
    )


def _counts_from_check_run_output(summary: str, text: str) -> Counts:
    """Parse machine-readable marker in check text first, then summary fallback."""
    try:
        marker = re.search(
            r"<!--\s*sentinelayer:counts:(\{.*?\})\s*-->",
            text or "",
            flags=re.DOTALL,
        )
        if marker:
            payload = json.loads(marker.group(1))
            return Counts(
                p0=int(payload.get("P0", 0) or 0),
                p1=int(payload.get("P1", 0) or 0),
                p2=int(payload.get("P2", 0) or 0),
                p3=int(payload.get("P3", 0) or 0),
                p4=int(payload.get("P4", 0) or 0),
            )
    except Exception:
        pass
    return _counts_from_summary(summary or "")


def _gate_result_from_check_run(run: dict, fallback_reason: str, extra_note: str) -> GateResult:
    conclusion = str(run.get("conclusion") or "").lower()
    output = run.get("output") or {}
    summary = str(output.get("summary") or "")
    text = str(output.get("text") or "")

    counts = _counts_from_check_run_output(summary=summary, text=text)
    cleaned_text = re.sub(
        r"<!--\s*sentinelayer:counts:(\{.*?\})\s*-->",
        "",
        text,
        flags=re.DOTALL,
    ).strip()
    reason = (cleaned_text or summary.strip() or fallback_reason).strip()
    if extra_note:
        reason = f"{reason} | {extra_note}"

    if conclusion == "success":
        status = GateStatus.PASSED
    elif conclusion == "neutral":
        status = GateStatus.BYPASSED
    elif conclusion == "action_required":
        status = GateStatus.NEEDS_APPROVAL
    elif conclusion == "failure":
        status = GateStatus.BLOCKED
    else:
        status = GateStatus.ERROR
        if not reason:
            reason = f"Unable to resolve prior Omar Gate conclusion ({conclusion or 'unknown'})."

    block_merge = status in {GateStatus.BLOCKED, GateStatus.ERROR, GateStatus.NEEDS_APPROVAL}
    return GateResult(
        status=status,
        reason=reason,
        block_merge=block_merge,
        counts=counts,
        dedupe_key=str(run.get("external_id") or ""),
    )


def _exit_code_from_gate_result(result: GateResult) -> int:
    if result.status == GateStatus.NEEDS_APPROVAL:
        return 13
    return 1 if result.block_merge else 0


def _find_check_run_by_external_id(runs: list[dict], external_id: str) -> dict | None:
    for run in runs:
        if run.get("external_id") == external_id:
            return run
    return None


def _find_check_run_by_marker(runs: list[dict], marker: str) -> dict | None:
    for candidate in runs:
        output = candidate.get("output") or {}
        summary = output.get("summary") or ""
        text = output.get("text") or ""
        if marker in summary or marker in text:
            return candidate
    return None


def _select_check_run_for_dedupe(runs: list[dict], idem_key: str) -> dict | None:
    return _find_check_run_by_external_id(runs, idem_key) or _find_check_run_by_marker(
        runs,
        idem_key,
    )


def _select_check_run_for_mirror(runs: list[dict]) -> dict | None:
    return _latest_completed_check_run(runs) or (runs[0] if runs else None)


def _write_preflight_artifacts(
    *,
    run_dir: Path,
    run_id: str,
    gate_result: GateResult,
    config: OmarGateConfig,
    idem_key: str,
    skip_label: str,
    link_url: str | None,
    action_version: str,
) -> tuple[Path, Path]:
    run_dir.mkdir(parents=True, exist_ok=True)

    findings_path = run_dir / "FINDINGS.jsonl"
    if not findings_path.exists():
        findings_path.write_text("", encoding="utf-8")

    counts = {
        "P0": int(gate_result.counts.p0),
        "P1": int(gate_result.counts.p1),
        "P2": int(gate_result.counts.p2),
        "P3": int(gate_result.counts.p3),
        "P4": int(gate_result.counts.p4),
    }
    pack_summary_path = write_pack_summary(
        run_dir=run_dir,
        run_id=run_id,
        writer_complete=True,
        findings_path=findings_path,
        counts=counts,
        tool_versions={
            "action": action_version,
            "policy_pack": config.policy_pack_version,
        },
        stages_completed=["preflight"],
        review_brief_path=None,
        severity_gate=config.severity_gate,
        llm_usage=None,
        error=f"preflight_short_circuit:{skip_label}",
        fingerprint_count=None,
        dedupe_key=idem_key,
        policy_pack=config.policy_pack,
        policy_pack_version=config.policy_pack_version,
        scan_mode=config.scan_mode,
        llm_provider=config.llm_provider,
        model_used=config.model,
        model_fallback=config.model_fallback,
        model_fallback_used=False,
        duration_ms=0,
    )

    skip_md = run_dir / "SKIP.md"
    url_line = f"\n\nLink: {link_url}\n" if link_url else "\n"
    skip_md.write_text(
        f"# Omar Gate Short-Circuit\n\nReason: {skip_label}\n{url_line}",
        encoding="utf-8",
    )

    return findings_path, pack_summary_path


def _map_category_to_spec_sections(category: str) -> set[str]:
    value = str(category or "").strip().lower()
    if not value:
        return set()

    security_tokens = {
        "security",
        "auth",
        "secret",
        "permission",
        "crypto",
        "xss",
        "sqli",
        "sql",
        "csrf",
        "injection",
        "dependency",
        "supply",
        "vuln",
        "cve",
    }
    quality_tokens = {
        "quality",
        "lint",
        "style",
        "complexity",
        "performance",
        "type",
        "typing",
        "test",
    }
    domain_tokens = {"domain", "business", "logic"}

    sections: set[str] = set()
    if any(token in value for token in security_tokens):
        sections.add("5")
    if any(token in value for token in quality_tokens):
        sections.add("7")
    if any(token in value for token in domain_tokens):
        sections.add("6")
    return sections


def _build_spec_compliance_from_findings(
    *,
    spec_context: dict | None,
    findings: list[dict],
) -> SpecComplianceTelemetry | None:
    if not spec_context:
        return None

    spec_hash = str(spec_context.get("spec_hash") or "").strip().lower()
    if not spec_hash:
        return None

    sections_checked: set[str] = set()
    sections_violated: set[str] = set()

    if spec_context.get("security_rules"):
        sections_checked.add("5")
    if spec_context.get("quality_gates"):
        sections_checked.add("7")
    if spec_context.get("domain_rules"):
        sections_checked.add("6")

    for finding in findings or []:
        sections = _map_category_to_spec_sections(str(finding.get("category") or ""))
        if not sections:
            continue
        sections_checked.update(sections)
        sections_violated.update(sections)

    return SpecComplianceTelemetry(
        spec_hash=spec_hash,
        sections_checked=sorted(sections_checked),
        sections_violated=sorted(sections_violated),
    )
