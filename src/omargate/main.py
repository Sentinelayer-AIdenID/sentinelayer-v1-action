from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from .analyze import AnalysisOrchestrator
from .analyze.spec_context import fetch_spec_context
from .comment import marker, render_pr_comment
from .config import OmarGateConfig
from .context import GitHubContext
from .gate import evaluate_gate
from .github import GitHubClient, findings_to_annotations
from .idempotency import (
    compute_idempotency_key,
    dependency_audit_freshness_epoch,
    review_config_digest,
)
from .ingest.codebase_snapshot import (
    build_codebase_snapshot,
    build_codebase_synopsis,
    write_codebase_ingest_artifacts,
)
from .logging import OmarLogger
from .models import Counts, GateConfig, GateResult, GateStatus
from .artifacts import write_audit_report
from .packaging import get_run_dir, write_findings_jsonl, write_pack_summary
from .publish import prepare_artifacts_for_upload, write_step_summary
from .package import write_artifact_manifest
from .runtime_helpers import (
    _build_spec_compliance_from_findings,
    _counts_from_check_run_output,
    _emit_gate_annotation,
    _exit_code_from_gate_result,
    _gate_result_from_check_run,
    _latest_completed_check_run,
    _map_category_to_spec_sections,
    _write_preflight_artifacts,
)
from .telemetry_runtime import (
    _estimate_cost,
    _upload_telemetry_always,
    _write_github_outputs,
)
from .preflight import (
    check_branch_protection,
    check_cost_approval,
    check_fork_policy,
    check_rate_limits,
)
from .telemetry import (
    TelemetryCollector,
    fetch_oidc_token,
)
from .telemetry.schemas import (
    SpecComplianceTelemetry,
)
from .telemetry.uploader import upload_telemetry
from .utils import ensure_writable_dir, json_dumps

ACTION_VERSION = "1.3.11"
# Rotate this whenever a security-control contract changes so dedupe cannot
# mirror a successful check produced under weaker semantics on the same head.
ACTION_IDEMPOTENCY_VERSION = "4:dependency-audit-v1.2:complete-discovery:workspace-root:private-policy:review-config:verified-model:root-declared-peer-edges:isolated-npm-config:verified-scope-findings:failed-call-provenance:route-attempt-provenance"
DEPENDENCY_AUDIT_CONTRACT_VERSION = "dependency-audit-evidence-v1.2:workspace-root:complete-discovery:root-declared-peer-edges:isolated-npm-config"
CHECK_NAME_BASE = "Omar Gate"
__all__ = [
    "main",
    "async_main",
    "_latest_completed_check_run",
    "_counts_from_check_run_output",
    "_gate_result_from_check_run",
    "_exit_code_from_gate_result",
    "_map_category_to_spec_sections",
    "_build_spec_compliance_from_findings",
    "_github_publish_enabled",
    "DEPENDENCY_AUDIT_CONTRACT_VERSION",
]


def _check_name(comment_tag: str = "") -> str:
    tag = str(comment_tag or "").strip().lower()
    if not tag:
        return CHECK_NAME_BASE
    return f"{CHECK_NAME_BASE} ({tag})"


def _llm_fallback_used(llm_usage: dict, model_fallback: str) -> bool:
    model_used = str(llm_usage.get("model") or "").strip()
    route_used = str(llm_usage.get("route") or "").strip()
    return bool(
        (model_used and model_used == model_fallback)
        or route_used.startswith("managed_after_byo_capacity")
    )


def _llm_display_identity(analysis, **kwargs) -> tuple[str, str]:
    """Return the display identity (engine, model) for the LLM review.

    States: COMPLETE (returned model shown), ATTEMPTED-FAILED (unknown
    returned model / usage stays 'unknown'), NOT_ATTEMPTED (reason code from
    source_failure_reason / failure_class), DISABLED (only when the config
    truly disables the LLM).

    Accepts an optional `routing` kwarg (REVIEW_ROUTING data) to read the
    triage's source_failure_reason when the review was not attempted.
    """
    routing = kwargs.get("routing") if kwargs else None
    llm_enabled = kwargs.get("llm_enabled", True) if kwargs else True

    if not analysis.llm_attempted and not analysis.llm_success:
        if not llm_enabled:
            return "disabled", "n/a"
        reason = ""
        if isinstance(routing, dict):
            raw = routing.get("source_failure_reason", "")
            reason = str(raw).strip() if raw else ""
        if not reason:
            raw = getattr(analysis, "llm_failure_class", None)
            reason = str(raw).strip() if raw else ""
        if reason:
            return "NOT_ATTEMPTED", reason
        return "NOT_ATTEMPTED", "unknown"
    if analysis.llm_attempted and not analysis.llm_success:
        usage = analysis.llm_usage if isinstance(analysis.llm_usage, dict) else {}
        engine = str(usage.get("engine") or usage.get("provider") or "llm").strip() or "llm"
        return engine, "unknown"
    usage = analysis.llm_usage if isinstance(analysis.llm_usage, dict) else {}
    engine = str(usage.get("engine") or usage.get("provider") or "llm").strip() or "llm"
    model = str(usage.get("model") or "").strip() or "unknown"
    return engine, model

def _llm_enabled_for_display(orchestrator: AnalysisOrchestrator) -> bool:
    """Use the configured routes, including Codex and managed proxy, for display."""
    if not orchestrator.allow_llm:
        return False
    return bool(
        orchestrator.config.use_codex
        or orchestrator.config.llm_provider == "typesafe"
        or orchestrator._should_run_llm()
    )


def _llm_display_cost(analysis) -> tuple[Optional[float], bool]:
    """Return (cost_usd, complete) for the LLM review.

    When cost_ledger is present but incomplete (estimated_total_usd is None),
    the cost is the known subtotal and complete is False — the caller must
    label the displayed amount as a known subtotal, not a total.

    An unrefined refused review with a cost ledger also returns (known, False)
    rather than (None, False). When there is no cost information at all,
    returns (None, False).
    """
    usage = analysis.llm_usage if isinstance(analysis.llm_usage, dict) else {}
    if isinstance(usage.get("cost_ledger"), dict):
        ledger = usage["cost_ledger"]
        if ledger.get("complete"):
            total = ledger.get("estimated_total_usd")
            return (float(total) if total is not None else None, True)
        known = ledger.get("known_estimated_usd")
        return (float(known) if known is not None else None, False)
    if not analysis.llm_attempted and not analysis.llm_success:
        return (None, False)
    cost = usage.get("cost_usd")
    return (float(cost) if cost is not None else None, True)


def _build_llm_evidence(analysis, config: OmarGateConfig) -> dict:
    usage = analysis.llm_usage if isinstance(analysis.llm_usage, dict) else {}
    provider = str(usage.get("provider") or config.llm_provider).strip()
    engine = str(usage.get("engine") or provider).strip()
    model = str(usage.get("model") or "").strip()
    return {
        "schema_version": "1.0",
        "attempted": bool(analysis.llm_attempted),
        "success": bool(analysis.llm_success),
        "output_valid": bool(analysis.llm_output_valid),
        "no_findings_reported": bool(analysis.llm_no_findings_reported),
        "reported_finding_count": int(analysis.llm_reported_finding_count or 0),
        "accepted_finding_count": int(analysis.llm_count or 0),
        "parse_error_count": int(analysis.llm_parse_error_count or 0),
        "failure_class": analysis.llm_failure_class,
        "usage_recorded": bool(usage),
        "engine": engine,
        "provider": provider,
        "model": model,
        "route": str(usage.get("route") or "").strip() or None,
        "tokens_in": usage.get("tokens_in"),
        "tokens_out": usage.get("tokens_out"),
        "latency_ms": usage.get("latency_ms"),
        "fallback_used": _llm_fallback_used(usage, config.model_fallback),
    }


def _short_circuit_with_gate_result(
    *,
    run_dir: Path,
    run_id: str,
    gate_result: GateResult,
    config: OmarGateConfig,
    idem_key: str,
    skip_label: str,
    link_url: Optional[str],
    estimated_cost_usd: float = 0.0,
) -> int:
    findings_path, pack_summary_path = _write_preflight_artifacts(
        run_dir=run_dir,
        run_id=run_id,
        gate_result=gate_result,
        config=config,
        idem_key=idem_key,
        skip_label=skip_label,
        link_url=link_url,
        action_version=ACTION_VERSION,
    )

    write_step_summary(
        gate_result=gate_result,
        summary={
            "severity_gate": config.severity_gate,
            "counts": {
                "P0": gate_result.counts.p0,
                "P1": gate_result.counts.p1,
                "P2": gate_result.counts.p2,
                "P3": gate_result.counts.p3,
                "P4": gate_result.counts.p4,
            },
        },
        findings=[],
        run_id=run_id,
        version=ACTION_VERSION,
    )
    _write_github_outputs(
        run_id=run_id,
        gate_result=gate_result,
        idem_key=idem_key,
        findings_path=findings_path,
        pack_summary_path=pack_summary_path,
        estimated_cost_usd=estimated_cost_usd,
        scan_mode=config.scan_mode,
        severity_gate=config.severity_gate,
        llm_provider=config.llm_provider,
        model=config.model,
        model_fallback=config.model_fallback,
        model_fallback_used=False,
        policy_pack=config.policy_pack,
        policy_pack_version=config.policy_pack_version,
    )

    try:
        _emit_gate_annotation(
            gate_result=gate_result,
            severity_gate=config.severity_gate,
            run_id=run_id,
            run_dir=run_dir,
            workflow_run_url=link_url,
            dashboard_url=None,
        )
    except Exception:
        pass

    return _exit_code_from_gate_result(gate_result)


def main() -> int:
    """Main entry point."""
    return asyncio.run(async_main())

def _publish_strict() -> bool:
    """Return True when publish failures should fail the run."""
    if os.environ.get("ACT", "").lower() == "true":
        return False
    return True


def _github_publish_enabled(config: OmarGateConfig) -> bool:
    """Return True when this run should create GitHub comments/check-runs."""
    return bool(getattr(config, "publish_github", True))


def _write_configuration_failure_evidence(run_dir: Path, run_id: str) -> None:
    """Refuse before context/providers, retaining UNKNOWN rather than no report."""
    from .analyze.review_costs import cost_ledger
    required = ("TYPESAFE_API_KEY", "OPENAI_API_KEY", "INTENT_MODEL_PIN", "INTENT_POLICY")
    typed = (os.environ.get("INPUT_LLM_PROVIDER", "").strip().lower() == "typesafe"
             or os.environ.get("INPUT_REVIEW_ROUTING", "").strip().lower() == "intent-cascade-v1")
    missing = [name for name in required if not os.environ.get("INPUT_" + name, "").strip()] if typed else []
    reason = "private_config_missing" if missing else "configuration_invalid"
    findings = run_dir / "FINDINGS.jsonl"
    write_findings_jsonl(findings, [])
    summary = write_pack_summary(
        run_dir=run_dir, run_id=run_id, writer_complete=False, findings_path=findings,
        counts={severity: 0 for severity in ("P0", "P1", "P2", "P3", "P4")},
        tool_versions={"omargate": ACTION_VERSION}, stages_completed=[], error=reason,
        llm_usage={"cost_ledger": cost_ledger([])},
        llm_evidence={"schema_version": "1.0", "attempted": False, "success": False,
                      "output_valid": False, "failure_class": reason, "usage_recorded": False,
                      "provider": "unknown", "model": "unknown"},
    )
    payload = json.loads(summary.read_text(encoding="utf-8"))
    payload.update(review_verdict="UNKNOWN", block_merge=True, missing_private_inputs=missing)
    summary.write_text(json_dumps(payload), encoding="utf-8")
    gate = GateResult(status=GateStatus.ERROR, reason="UNKNOWN: " + reason,
                      block_merge=True, counts=Counts())
    _write_github_outputs(run_id=run_id, idem_key="", findings_path=findings,
                          pack_summary_path=summary, gate_result=gate, estimated_cost_usd=None,
                          llm_provider="unknown", model="unknown", llm_attempted=False,
                          llm_success=False, llm_output_valid=False, llm_failure_class=reason)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("review_verdict=UNKNOWN\nblock_merge=true\n")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write("## Omar Gate: UNKNOWN\nReview refused: " + reason + ". Merge is blocked.\n")
            if missing:
                handle.write("Missing private inputs: " + ", ".join(missing) + "\n")


async def async_main() -> int:
    """Async main entry point."""

    # Defaults ensure we can emit telemetry even on config/context failures.
    exit_code = 2
    run_id = str(uuid.uuid4())
    run_dir = get_run_dir(run_id)
    logger = OmarLogger(run_id)
    collector = TelemetryCollector(
        run_id=run_id,
        repo_full_name=os.environ.get("GITHUB_REPOSITORY", "unknown/unknown"),
    )
    collector.exit_code = exit_code

    # Best-effort config-derived fields (may be overwritten after config parses).
    collector.scan_mode = (
        os.environ.get("INPUT_SCAN_MODE", "pr-diff").strip().lower() or "pr-diff"
    )
    collector.llm_provider = (
        (os.environ.get("INPUT_LLM_PROVIDER") or "openai").strip().lower() or "openai"
    )
    collector.model_used = (os.environ.get("INPUT_MODEL") or "").strip()

    config: Optional[OmarGateConfig] = None
    ctx: Optional[GitHubContext] = None
    effective_scan_mode = "pr-diff"
    repo_root = Path(os.environ.get("GITHUB_WORKSPACE", "."))

    dashboard_url: Optional[str] = None
    idem_key = ""
    analysis = None
    codebase_snapshot: Optional[dict] = None
    codebase_synopsis = ""
    spec_context: Optional[dict] = None
    spec_compliance: Optional[SpecComplianceTelemetry] = None
    gate_result: Optional[GateResult] = None
    findings_path: Optional[Path] = None
    pack_summary_path: Optional[Path] = None
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    workflow_run_url: Optional[str] = None

    try:
        try:
            config = OmarGateConfig()
        except Exception:
            print("::error::Omar Gate UNKNOWN: review configuration unavailable or invalid; merge blocked")
            collector.record_error("config", "review_configuration_invalid")
            collector.record_preflight_exit(reason="config_error", exit_code=2)
            try:
                _write_configuration_failure_evidence(run_dir, run_id)
            except OSError:
                print("::error::Omar Gate UNKNOWN: configuration-failure evidence could not be written")
            exit_code = 2
            return exit_code

        collector.scan_mode = config.scan_mode
        collector.llm_provider = config.llm_provider
        collector.model_used = config.model
        check_name = _check_name(config.comment_tag)
        effective_scan_mode = config.scan_mode
        if config.scan_mode == "nightly":
            effective_scan_mode = "deep"
            collector.scan_mode = effective_scan_mode

        try:
            ctx = GitHubContext.from_environment()
        except Exception as exc:
            print(f"::error::Failed to load GitHub context: {exc}")
            collector.record_error("context", str(exc))
            collector.record_preflight_exit(reason="context_error", exit_code=2)
            exit_code = 2
            return exit_code

        logger.info(
            "Omar Gate starting",
            repo=ctx.repo_full_name,
            pr_number=ctx.pr_number,
            head_sha=ctx.head_sha,
            scan_mode=config.scan_mode,
        )
        if config.scan_mode == "nightly":
            logger.info("nightly mode: running full deep scan")

        for flag_name, enabled in (
            ("auto_commit_fixes", config.auto_commit_fixes),
            ("run_llm_fix", config.run_llm_fix),
            ("run_deterministic_fix", config.run_deterministic_fix),
        ):
            if enabled:
                logger.warning(
                    f"{flag_name} is not yet implemented - flag ignored",
                    flag=flag_name,
                )

        github_run_id = os.environ.get("GITHUB_RUN_ID")
        workflow_run_url = (
            f"{server_url}/{ctx.repo_full_name}/actions/runs/{github_run_id}"
            if github_run_id
            else None
        )

        if config.sentinelayer_token.get_secret_value():
            dashboard_url = f"https://sentinelayer.com/runs/{run_id}"

        idem_key = compute_idempotency_key(
            repo=ctx.repo_full_name,
            pr_number=ctx.pr_number or 0,
            head_sha=ctx.head_sha,
            scan_mode=config.scan_mode,
            policy_pack=config.policy_pack,
            policy_pack_version=config.policy_pack_version,
            action_major_version=ACTION_IDEMPOTENCY_VERSION,
            comment_tag=config.comment_tag,
            config_digest=review_config_digest(config),
            audit_contract_version=DEPENDENCY_AUDIT_CONTRACT_VERSION,
            run_harness=config.run_harness,
            pip_audit_ignore_ids=config.pip_audit_ignore_ids,
            audit_freshness_epoch=(
                dependency_audit_freshness_epoch()
                if config.run_harness
                else None
            ),
        )

        token = config.github_token.get_secret_value() or os.environ.get("GITHUB_TOKEN", "")
        gh = GitHubClient(token=token, repo=ctx.repo_full_name)

        oidc_token = await fetch_oidc_token(logger=logger)
        if config.sentinelayer_spec_id:
            spec_context = await fetch_spec_context(
                spec_hash=config.sentinelayer_spec_id,
                sentinelayer_token=config.sentinelayer_token.get_secret_value(),
                oidc_token=oidc_token or "",
            )
            if spec_context:
                logger.info(
                    "Loaded Sentinelayer spec context",
                    spec_hash=str(spec_context.get("spec_hash", ""))[:12],
                )

        estimated_cost = _estimate_cost(ctx=ctx, gh=gh, config=config)

        # === PREFLIGHT ===
        preflight_success = True
        scan_mode_override: Optional[str] = None
        collector.stage_start("preflight")
        try:
            with logger.stage("preflight"):
                # Remote check names, markers and external IDs are untrusted.
                # Every run must obtain fresh source-bound review evidence.
                proceed, scan_mode_override, fork_reason = check_fork_policy(ctx, config)
                if not proceed:
                    collector.fork_blocked = True
                    preflight_success = False
                    logger.info("Blocked by fork policy", reason=fork_reason)
                    if ctx.pr_number and _github_publish_enabled(config):
                        comment_body = (
                            "## 🛡️ Omar Gate: Blocked\n\n"
                            "Fork PRs cannot access secrets required for full analysis. "
                            "Please ask a maintainer to run the scan via workflow_dispatch.\n\n"
                            f"{marker(ctx.repo_full_name, ctx.pr_number, comment_tag=config.comment_tag)}"
                        )
                        comment_url = gh.create_or_update_pr_comment(
                            ctx.pr_number,
                            comment_body,
                            marker(
                                ctx.repo_full_name,
                                ctx.pr_number,
                                comment_tag=config.comment_tag,
                            ),
                        )
                        logger.info("PR comment upserted", url=comment_url)
                    exit_code = 12
                    collector.record_preflight_exit(reason="fork_blocked", exit_code=exit_code)
                    return exit_code

                proceed, rate_reason = await check_rate_limits(
                    gh, ctx.pr_number, config, logger, check_name=check_name
                )
                if not proceed:
                    collector.rate_limit_skipped = True
                    preflight_success = False
                    logger.info("Rate limited", reason=rate_reason)
                    if config.run_harness:
                        reason_msg = (
                            f"Rate limited ({rate_reason}); the required dependency audit "
                            "has not completed for this audit contract and UTC day. "
                            "A fresh review is required; check-run metadata cannot satisfy it."
                        )
                    elif rate_reason.endswith("require_approval"):
                        reason_msg = "Rate limit enforcement unavailable; approval required to proceed."
                    else:
                        reason_msg = (
                            f"Rate limited ({rate_reason}); a fresh review is required. "
                            "Unverified prior check runs cannot authorize a pass."
                        )
                    gate_result = GateResult(
                        status=GateStatus.NEEDS_APPROVAL,
                        reason=reason_msg,
                        block_merge=True,
                        counts=Counts(),
                        dedupe_key=idem_key,
                    )
                    collector.record_gate_result(gate_result.status.value, gate_result.reason)
                    exit_code = _short_circuit_with_gate_result(
                        run_dir=run_dir,
                        run_id=run_id,
                        gate_result=gate_result,
                        config=config,
                        idem_key=idem_key,
                        skip_label=f"rate_limit:{rate_reason}",
                        link_url=None,
                        estimated_cost_usd=estimated_cost,
                    )
                    collector.record_preflight_exit(reason="rate_limit", exit_code=exit_code)
                    return exit_code

                approved, cost_status = await check_cost_approval(
                    estimated_cost, config, ctx, gh
                )
                collector.approval_state = cost_status
                if not approved:
                    preflight_success = False
                    logger.info("Cost approval required", status=cost_status)
                    exit_code = 13
                    collector.record_preflight_exit(reason="cost_approval", exit_code=exit_code)
                    return exit_code

                bp_ok, bp_message = check_branch_protection(gh, ctx, check_name)
                if not bp_ok:
                    logger.warning("Branch protection issue", detail=bp_message)
        except Exception as exc:
            preflight_success = False
            collector.record_error("preflight", str(exc))
            raise
        finally:
            collector.stage_end("preflight", success=preflight_success)

        # === ANALYSIS ===
        limited_mode = scan_mode_override == "limited"

        orchestrator = AnalysisOrchestrator(
            config=config,
            logger=logger,
            repo_root=repo_root,
            allow_llm=not limited_mode,
        )

        diff_content: Optional[str] = None
        changed_files: Optional[list[str]] = None
        if effective_scan_mode == "pr-diff" and ctx.pr_number:
            collector.stage_start("fetch_diff")
            try:
                with logger.stage("fetch_diff"):
                    diff_content = await gh.get_pr_diff(ctx.pr_number)
                    changed_files = await gh.get_pr_changed_files(ctx.pr_number)
            except Exception as exc:
                collector.record_error("fetch_diff", str(exc))
                collector.stage_end("fetch_diff", success=False)
                raise
            else:
                collector.stage_end("fetch_diff", success=True)

        if (
            effective_scan_mode == "pr-diff"
            and ctx.pr_number
            and not (diff_content or "").strip()
            and not (changed_files or [])
        ):
            reason_msg = "No files changed - nothing to scan"
            logger.info("Skipping analysis: no changed files in PR")
            gate_result = GateResult(
                status=GateStatus.PASSED,
                reason=reason_msg,
                block_merge=False,
                counts=Counts(),
                dedupe_key=idem_key,
            )
            if gh.token and _github_publish_enabled(config):
                try:
                    gh.create_check_run(
                        name=check_name,
                        head_sha=ctx.head_sha,
                        conclusion="success",
                        summary=reason_msg,
                        title="Omar Gate: PASSED",
                        text=reason_msg,
                        details_url=workflow_run_url or dashboard_url,
                        external_id=idem_key,
                    )
                except Exception as exc:
                    logger.warning("Failed to create no-op check run", error=str(exc))

            status_value = (
                gate_result.status.value
                if hasattr(gate_result.status, "value")
                else str(gate_result.status)
            )
            collector.record_gate_result(status_value, gate_result.reason)
            exit_code = _short_circuit_with_gate_result(
                run_dir=run_dir,
                run_id=run_id,
                gate_result=gate_result,
                config=config,
                idem_key=idem_key,
                skip_label="no_files_changed",
                link_url=workflow_run_url or dashboard_url,
                estimated_cost_usd=0.0,
            )
            collector.record_preflight_exit(reason="no_files_changed", exit_code=exit_code)
            return exit_code

        if limited_mode:
            logger.info("Running in limited mode (deterministic only)")

        scan_start = time.perf_counter()
        collector.stage_start("analysis")
        try:
            analysis = await orchestrator.run(
                scan_mode=effective_scan_mode,
                diff_content=diff_content,
                changed_files=changed_files,
                spec_context=spec_context,
                run_dir=run_dir,
                run_id=run_id,
                version=ACTION_VERSION,
                dashboard_url=dashboard_url,
            )
        except Exception as exc:
            collector.record_error("analysis", str(exc))
            collector.stage_end("analysis", success=False)
            raise
        else:
            collector.stage_end("analysis", success=True)

        if analysis.llm_usage:
            model_used = str(analysis.llm_usage.get("model") or "").strip()
            provider_used = (
                str(analysis.llm_usage.get("engine") or analysis.llm_usage.get("provider") or "")
                .strip()
                or None
            )
            fallback_used = _llm_fallback_used(analysis.llm_usage, config.model_fallback)

            # Codex CLI runs may not provide token/cost accounting. Treat missing as 0 for telemetry.
            tokens_in = int(analysis.llm_usage.get("tokens_in") or 0)
            tokens_out = int(analysis.llm_usage.get("tokens_out") or 0)
            latency_ms = int(analysis.llm_usage.get("latency_ms") or 0)
            cost_raw = analysis.llm_usage.get("cost_usd")
            cost_usd = float(cost_raw) if cost_raw is not None else 0.0

            collector.record_llm_usage(
                model=model_used,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost_usd,
                latency_ms=latency_ms,
                fallback_used=fallback_used,
                provider=provider_used,
                fallback_provider=provider_used if fallback_used else None,
                fallback_model=model_used if fallback_used else None,
            )
            if isinstance(analysis.llm_usage.get("cost_ledger"), dict):
                collector.review_cost_ledger = analysis.llm_usage["cost_ledger"]
                # Legacy numeric telemetry is the known subtotal. The canonical
                # nullable total and partial status persist alongside it.
                collector.estimated_cost_usd = collector.review_cost_ledger["known_estimated_usd"]

        ingest_stats = analysis.ingest_stats or {}
        collector.files_scanned = int(
            ingest_stats.get("in_scope_files", analysis.total_files_scanned or 0) or 0
        )
        total_files = int(ingest_stats.get("total_files", 0) or 0)
        collector.files_skipped = max(total_files - collector.files_scanned, 0)
        collector.total_lines = int(ingest_stats.get("total_lines", 0) or 0)

        # === PACKAGING ===
        summary_payload: dict = {}
        scan_duration_ms = 0
        packaging_success = True
        collector.stage_start("packaging")
        try:
            with logger.stage("packaging"):
                ingest_path = run_dir / "INGEST.json"
                ingest_path.write_text(json_dumps(analysis.ingest), encoding="utf-8")

                try:
                    # Deterministic, bounded codebase snapshot artifacts (no LLM required).
                    codebase_snapshot = build_codebase_snapshot(analysis.ingest)
                    codebase_synopsis = build_codebase_synopsis(
                        codebase_snapshot=codebase_snapshot,
                        quick_learn=analysis.quick_learn,
                    )
                    write_codebase_ingest_artifacts(
                        run_dir, analysis.ingest, snapshot=codebase_snapshot
                    )
                except Exception as exc:
                    logger.warning("Codebase snapshot generation failed", error=str(exc))
                    analysis.warnings.append("Codebase snapshot generation failed")

                findings_path = run_dir / "FINDINGS.jsonl"
                write_findings_jsonl(findings_path, analysis.findings)

                pack_counts = {
                    key: analysis.counts.get(key, 0) for key in ("P0", "P1", "P2", "P3", "P4")
                }
                fingerprint_count = sum(
                    1 for finding in analysis.findings if finding.get("fingerprint")
                )
                scan_duration_ms = int((time.perf_counter() - scan_start) * 1000)
                pack_summary_path = write_pack_summary(
                    run_dir=run_dir,
                    run_id=run_id,
                    writer_complete=True,
                    findings_path=findings_path,
                    counts=pack_counts,
                    tool_versions={
                        "action": ACTION_VERSION,
                        "policy_pack": config.policy_pack_version,
                    },
                    stages_completed=(
                        ["preflight", "ingest", "deterministic"]
                        + (
                            ["llm"]
                            if analysis.llm_success and analysis.llm_output_valid
                            else (["llm_attempted"] if analysis.llm_attempted else [])
                        )
                        + ["packaging"]
                    ),
                    review_brief_path=analysis.review_brief_path,
                    severity_gate=config.severity_gate,
                    llm_usage=analysis.llm_usage,
                    llm_evidence=_build_llm_evidence(analysis, config),
                    dependency_audit_evidence=analysis.dependency_audit_evidence,
                    fingerprint_count=fingerprint_count,
                    dedupe_key=idem_key,
                    policy_pack=config.policy_pack,
                    policy_pack_version=config.policy_pack_version,
                    scan_mode=config.scan_mode,
                    llm_provider=(collector.llm_provider or config.llm_provider),
                    model_used=(collector.model_used or config.model),
                    model_fallback=config.model_fallback,
                    model_fallback_used=collector.model_fallback_used,
                    error=None,
                    duration_ms=scan_duration_ms,
                )
                try:
                    summary_payload = json.loads(
                        pack_summary_path.read_text(encoding="utf-8")
                    )
                    write_audit_report(
                        run_dir=run_dir,
                        run_id=run_id,
                        summary=summary_payload,
                        findings=analysis.findings,
                        ingest=analysis.ingest,
                        config={"severity_gate": config.severity_gate},
                        version=ACTION_VERSION,
                    )
                except Exception as exc:
                    logger.warning("Audit report generation failed", error=str(exc))
                    analysis.warnings.append("Audit report generation failed")

                try:
                    write_artifact_manifest(run_dir, run_id)
                except Exception as exc:
                    logger.warning("Manifest generation failed", error=str(exc))
                    analysis.warnings.append("Manifest generation failed")

                try:
                    artifacts_override = os.environ.get("SENTINELAYER_ARTIFACTS_DIR")
                    if artifacts_override:
                        artifacts_dir = Path(artifacts_override)
                    else:
                        workspace = os.environ.get("GITHUB_WORKSPACE")
                        artifacts_dir = (
                            Path(workspace) / ".sentinelayer" / "artifacts"
                            if workspace
                            else None
                        )

                    if artifacts_dir and ensure_writable_dir(artifacts_dir):
                        prepare_artifacts_for_upload(run_dir, artifacts_dir)
                    else:
                        logger.info(
                            "Artifact preparation skipped",
                            reason="workspace not writable",
                        )
                except Exception as exc:
                    logger.warning("Artifact preparation failed", error=str(exc))
                    analysis.warnings.append("Artifact preparation failed")
        except Exception as exc:
            packaging_success = False
            collector.record_error("packaging", str(exc))
            raise
        finally:
            collector.stage_end("packaging", success=packaging_success)

        # === GATE EVALUATION ===
        gate_success = True
        collector.stage_start("gate_eval")
        try:
            with logger.stage("gate_eval"):
                gate_result = evaluate_gate(
                    run_dir,
                    GateConfig(
                        severity_gate=config.severity_gate,
                        require_llm_success=config.llm_failure_policy == "block",
                        require_dependency_audit_success=config.run_harness,
                    ),
                )
        except Exception as exc:
            gate_success = False
            collector.record_error("gate_eval", str(exc))
            raise
        finally:
            collector.stage_end("gate_eval", success=gate_success)

        status_value = (
            gate_result.status.value
            if hasattr(gate_result.status, "value")
            else str(gate_result.status)
        )
        collector.record_gate_result(status_value, gate_result.reason)
        collector.record_findings(
            analysis.counts,
            analysis.deterministic_count,
            analysis.llm_count,
        )
        logger.info(
            "Gate evaluation complete",
            status=status_value,
            block_merge=gate_result.block_merge,
            counts=analysis.counts,
        )

        # Report the completed local review before external publication or the
        # final failure annotation. A publisher error must not hide the audit.
        try:
            write_step_summary(
                gate_result=gate_result,
                summary=summary_payload,
                findings=analysis.findings,
                codebase_snapshot=codebase_snapshot,
                codebase_synopsis=codebase_synopsis,
                run_id=run_id,
                version=ACTION_VERSION,
            )
        except OSError as exc:
            logger.warning("Step summary write failed", error=str(exc))

        if spec_context:
            spec_compliance = _build_spec_compliance_from_findings(
                spec_context=spec_context,
                findings=analysis.findings,
            )

        # === PUBLISHING ===
        publish_success = True
        collector.stage_start("publish")
        try:
            with logger.stage("publish"):
                publish_github = _github_publish_enabled(config)
                # An unsuccessful attempt can still incur an unreported cost.
                cost_usd, cost_complete = _llm_display_cost(analysis)

                if not publish_github:
                    logger.info("GitHub PR comment publish disabled by input")
                elif not gh.token:
                    message = "GitHub token missing; publish calls unavailable"
                    if _publish_strict():
                        raise RuntimeError(message)
                    logger.warning(message)
                    analysis.warnings.append(message)
                elif ctx.pr_number:
                    try:
                        llm_engine_used, llm_model_used = _llm_display_identity(
                            analysis,
                            llm_enabled=_llm_enabled_for_display(orchestrator),
                            routing=(analysis.llm_usage or {}).get("review_routing"),
                        )

                        review_brief_md = None
                        try:
                            if analysis.review_brief_path and analysis.review_brief_path.exists():
                                review_brief_md = analysis.review_brief_path.read_text(
                                    encoding="utf-8", errors="replace"
                                )
                        except Exception:
                            review_brief_md = None

                        comment_body = render_pr_comment(
                            result=gate_result,
                            run_id=run_id,
                            repo_full_name=ctx.repo_full_name,
                            pr_number=ctx.pr_number,
                            dashboard_url=dashboard_url,
                            artifacts_url=workflow_run_url,
                            estimated_cost_usd=estimated_cost,
                            version=ACTION_VERSION,
                            findings=analysis.findings,
                            codebase_snapshot=codebase_snapshot,
                            codebase_synopsis=codebase_synopsis,
                            warnings=analysis.warnings,
                            review_brief_md=review_brief_md,
                            scan_mode=config.scan_mode,
                            policy_pack=config.policy_pack,
                            policy_pack_version=config.policy_pack_version,
                            severity_gate=config.severity_gate,
                            duration_ms=summary_payload.get("duration_ms")
                            or scan_duration_ms,
                            files_scanned=collector.files_scanned,
                            llm_engine=llm_engine_used,
                            deterministic_count=analysis.deterministic_count,
                            llm_count=analysis.llm_count,
                            dedupe_key=gate_result.dedupe_key or idem_key,
                            llm_model=llm_model_used,
                            actual_cost_usd=cost_usd,
                            cost_ledger_complete=cost_complete,
                            review_cost_ledger=(analysis.llm_usage or {}).get("cost_ledger"),
                            head_sha=ctx.head_sha,
                            server_url=server_url,
                            comment_tag=config.comment_tag,
                            llm_evidence=_build_llm_evidence(analysis, config),
                            review_routing=(analysis.llm_usage or {}).get("review_routing"),
                            cascade_cost_envelope=config.review_routing == "intent-cascade-v1",
                        )
                        comment_url = gh.create_or_update_pr_comment(
                            ctx.pr_number,
                            comment_body,
                            marker(
                                ctx.repo_full_name,
                                ctx.pr_number,
                                comment_tag=config.comment_tag,
                            ),
                        )
                        logger.info("PR comment upserted", url=comment_url)
                    except Exception as exc:
                        if _publish_strict():
                            raise
                        logger.warning("PR comment failed", error=str(exc))
                        analysis.warnings.append("PR comment failed")

                counts = summary_payload.get("counts", {}) or analysis.counts
                summary_text = (
                    f"🔴 P0={counts.get('P0', 0)} • 🟠 P1={counts.get('P1', 0)} • "
                    f"🟡 P2={counts.get('P2', 0)} • ⚪ P3={counts.get('P3', 0)}"
                )
                check_text = gate_result.reason
                try:
                    counts_marker = json.dumps(
                        {
                            "P0": int(counts.get("P0", 0) or 0),
                            "P1": int(counts.get("P1", 0) or 0),
                            "P2": int(counts.get("P2", 0) or 0),
                            "P3": int(counts.get("P3", 0) or 0),
                            "P4": int(counts.get("P4", 0) or 0),
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    check_text = f"{check_text}\n\n<!-- sentinelayer:counts:{counts_marker} -->"
                except Exception:
                    pass
                status_key = (
                    gate_result.status.value
                    if hasattr(gate_result.status, "value")
                    else str(gate_result.status)
                )
                conclusion_map = {
                    "passed": "success",
                    "blocked": "failure",
                    "bypassed": "neutral",
                    "needs_approval": "action_required",
                    "error": "failure",
                }
                annotations = findings_to_annotations(analysis.findings)
                if not publish_github:
                    logger.info("GitHub check-run publish disabled by input")
                elif not gh.token:
                    message = "GitHub token missing; check run unavailable"
                    if _publish_strict():
                        raise RuntimeError(message)
                    logger.warning(message)
                    analysis.warnings.append(message)
                else:
                    try:
                        check_url = gh.create_check_run(
                            name=check_name,
                            head_sha=ctx.head_sha,
                            conclusion=conclusion_map.get(status_key, "failure"),
                            summary=summary_text,
                            title=f"Omar Gate: {status_key.upper()}",
                            text=check_text,
                            details_url=workflow_run_url or dashboard_url,
                            external_id=idem_key,
                            annotations=annotations,
                        )
                        logger.info("Check run created", url=check_url)
                    except Exception as exc:
                        if _publish_strict():
                            raise
                        logger.warning("Check run creation failed", error=str(exc))
                        analysis.warnings.append("Check run creation failed")

        except Exception as exc:
            publish_success = False
            collector.record_error("publish", str(exc))
            raise
        finally:
            collector.stage_end("publish", success=publish_success)

        # === OUTPUTS ===
        try:
            estimated_cost_usd, _ = _llm_display_cost(analysis)
            audit_report_path = run_dir / "AUDIT_REPORT.md"
            _write_github_outputs(
                run_id=run_id,
                idem_key=idem_key,
                findings_path=findings_path,
                pack_summary_path=pack_summary_path,
                gate_result=gate_result,
                estimated_cost_usd=estimated_cost_usd,
                review_brief_path=analysis.review_brief_path,
                audit_report_path=audit_report_path if audit_report_path.exists() else None,
                scan_mode=config.scan_mode,
                severity_gate=config.severity_gate,
                llm_provider=(collector.llm_provider or config.llm_provider),
                model=(collector.model_used or config.model),
                model_fallback=config.model_fallback,
                model_fallback_used=collector.model_fallback_used,
                llm_attempted=analysis.llm_attempted,
                llm_success=analysis.llm_success,
                llm_output_valid=analysis.llm_output_valid,
                llm_no_findings_reported=analysis.llm_no_findings_reported,
                llm_findings_count=analysis.llm_reported_finding_count,
                llm_parse_error_count=analysis.llm_parse_error_count,
                llm_failure_class=analysis.llm_failure_class,
                policy_pack=config.policy_pack,
                policy_pack_version=config.policy_pack_version,
            )
        except OSError as exc:
            logger.warning("GitHub outputs write failed", error=str(exc))

        try:
            _emit_gate_annotation(
                gate_result=gate_result,
                severity_gate=config.severity_gate,
                run_id=run_id,
                run_dir=run_dir,
                workflow_run_url=workflow_run_url,
                dashboard_url=dashboard_url,
            )
        except Exception:
            pass

        exit_code = 1 if gate_result.block_merge else 0
        collector.exit_reason = "completed"
        collector.exit_code = exit_code
        return exit_code
    except Exception as exc:
        collector.record_error("unhandled", str(exc))
        if not collector.exit_reason:
            collector.exit_reason = "unhandled"
        collector.exit_code = int(exit_code)
        raise
    finally:
        collector.exit_code = int(exit_code)
        if not collector.exit_reason:
            collector.exit_reason = "unhandled" if exit_code == 2 else "completed"
        try:
            await _upload_telemetry_always(
                config=config,
                run_id=run_id,
                idem_key=idem_key,
                analysis=analysis,
                gate_result=gate_result,
                spec_compliance=spec_compliance,
                ctx=ctx,
                run_dir=run_dir,
                collector=collector,
                logger=logger,
                action_version=ACTION_VERSION,
                upload_telemetry_fn=upload_telemetry,
            )
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
