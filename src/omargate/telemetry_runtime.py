from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .config import OmarGateConfig
from .context import GitHubContext
from .github import GitHubClient
from .logging import OmarLogger
from .models import GateResult
from .preflight import estimate_cost
from .runtime_helpers import _to_workspace_relative
from .telemetry import (
    ConsentConfig,
    TelemetryCollector,
    fetch_oidc_token,
    get_max_tier,
    should_upload_tier,
    validate_payload_tier,
)
from .telemetry.schemas import (
    SpecComplianceTelemetry,
    build_tier1_payload,
    build_tier2_payload,
    findings_to_summary,
)
from .telemetry.uploader import upload_artifacts, upload_telemetry


async def _upload_telemetry(
    *,
    config: OmarGateConfig,
    run_id: str,
    idem_key: str,
    analysis,
    gate_result: GateResult,
    spec_compliance: Optional[SpecComplianceTelemetry],
    ctx: GitHubContext,
    run_dir: Path,
    collector: TelemetryCollector,
    logger: OmarLogger,
    consent: ConsentConfig,
    action_version: str,
    upload_telemetry_fn=upload_telemetry,
) -> None:
    """Upload telemetry to Sentinelayer (best effort)."""
    _ = (run_id, gate_result)

    sentinelayer_token = config.sentinelayer_token.get_secret_value()
    oidc_token = await fetch_oidc_token(logger=logger)

    if should_upload_tier(1, consent):
        tier1_payload = build_tier1_payload(collector)
        if validate_payload_tier(tier1_payload, consent):
            await upload_telemetry_fn(
                tier1_payload,
                sentinelayer_token=sentinelayer_token,
                oidc_token=oidc_token,
                logger=logger,
            )

    if should_upload_tier(2, consent):
        if not sentinelayer_token and not oidc_token:
            logger.warning("Telemetry tier 2 requires authentication")
        else:
            tier2_payload = build_tier2_payload(
                collector=collector,
                repo_owner=ctx.repo_owner,
                repo_name=ctx.repo_name,
                branch=ctx.head_ref or ctx.base_ref or "main",
                pr_number=ctx.pr_number,
                head_sha=ctx.head_sha,
                is_fork_pr=ctx.is_fork,
                policy_pack=config.policy_pack,
                policy_pack_version=config.policy_pack_version,
                action_version=action_version,
                findings_summary=findings_to_summary(analysis.findings),
                idempotency_key=idem_key,
                severity_threshold=config.severity_gate,
                spec_compliance=spec_compliance,
            )
            if validate_payload_tier(tier2_payload, consent):
                await upload_telemetry_fn(
                    tier2_payload,
                    sentinelayer_token=sentinelayer_token,
                    oidc_token=oidc_token,
                    logger=logger,
                )

    if should_upload_tier(3, consent):
        if not sentinelayer_token:
            logger.warning("Telemetry tier 3 requires sentinelayer_token")
            return None
        manifest_path = run_dir / "ARTIFACT_MANIFEST.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to load artifact manifest", error=str(exc))
            return None
        await upload_artifacts(run_dir, manifest, sentinelayer_token, logger=logger)

    return None


def _resolve_consent(config: OmarGateConfig) -> ConsentConfig:
    """Resolve consent using explicit flags when set, otherwise telemetry_tier."""
    if config.share_metadata or config.share_artifacts or not config.telemetry:
        return ConsentConfig(
            telemetry=config.telemetry,
            share_metadata=config.share_metadata,
            share_artifacts=config.share_artifacts,
            training_consent=config.training_opt_in,
        )

    tier = config.telemetry_tier
    return ConsentConfig(
        telemetry=tier > 0,
        share_metadata=tier >= 2,
        share_artifacts=tier >= 3,
        training_consent=config.training_opt_in,
    )


def _parse_bool_env(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    return normalized in {"1", "true", "yes", "y", "on"}


def _parse_int_env(value: Optional[str], default: int) -> int:
    if value is None:
        return default
    try:
        return int(value.strip())
    except Exception:
        return default


def _resolve_consent_best_effort(config: Optional[OmarGateConfig]) -> ConsentConfig:
    if config is not None:
        return _resolve_consent(config)

    telemetry = _parse_bool_env(os.environ.get("INPUT_TELEMETRY"), True)
    share_metadata = _parse_bool_env(os.environ.get("INPUT_SHARE_METADATA"), False)
    share_artifacts = _parse_bool_env(os.environ.get("INPUT_SHARE_ARTIFACTS"), False)
    training_opt_in = _parse_bool_env(os.environ.get("INPUT_TRAINING_OPT_IN"), False)

    if share_metadata or share_artifacts or not telemetry:
        return ConsentConfig(
            telemetry=telemetry,
            share_metadata=share_metadata,
            share_artifacts=share_artifacts,
            training_consent=training_opt_in,
        )

    tier = _parse_int_env(os.environ.get("INPUT_TELEMETRY_TIER"), 1)
    tier = max(0, min(3, tier))
    return ConsentConfig(
        telemetry=telemetry and tier > 0,
        share_metadata=tier >= 2,
        share_artifacts=tier >= 3,
        training_consent=training_opt_in,
    )


async def _upload_telemetry_always(
    *,
    config: Optional[OmarGateConfig],
    run_id: str,
    idem_key: str,
    analysis,
    gate_result,
    spec_compliance: Optional[SpecComplianceTelemetry],
    ctx: Optional[GitHubContext],
    run_dir: Path,
    collector: TelemetryCollector,
    logger: OmarLogger,
    action_version: str,
    upload_telemetry_fn=upload_telemetry,
) -> None:
    """Upload telemetry even on preflight exits (best effort)."""
    consent = _resolve_consent_best_effort(config)
    if get_max_tier(consent) <= 0:
        return

    telemetry_success = True
    collector.stage_start("telemetry")
    try:
        with logger.stage("telemetry"):
            try:
                if (
                    config is not None
                    and ctx is not None
                    and analysis is not None
                    and gate_result is not None
                ):
                    await _upload_telemetry(
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
                        consent=consent,
                        action_version=action_version,
                        upload_telemetry_fn=upload_telemetry_fn,
                    )
                else:
                    sentinelayer_token = (
                        config.sentinelayer_token.get_secret_value()
                        if config is not None
                        else (
                            os.environ.get("INPUT_SENTINELAYER_TOKEN")
                            or os.environ.get("SENTINELAYER_TOKEN")
                            or ""
                        )
                    )
                    oidc_token = await fetch_oidc_token(logger=logger)

                    if should_upload_tier(1, consent):
                        tier1_payload = build_tier1_payload(collector)
                        if validate_payload_tier(tier1_payload, consent):
                            await upload_telemetry_fn(
                                tier1_payload,
                                sentinelayer_token=sentinelayer_token,
                                oidc_token=oidc_token,
                                logger=logger,
                            )

                    if config is not None and ctx is not None and should_upload_tier(2, consent):
                        if not sentinelayer_token and not oidc_token:
                            logger.warning("Telemetry tier 2 requires authentication")
                        else:
                            tier2_payload = build_tier2_payload(
                                collector=collector,
                                repo_owner=ctx.repo_owner,
                                repo_name=ctx.repo_name,
                                branch=ctx.head_ref or ctx.base_ref or "main",
                                pr_number=ctx.pr_number,
                                head_sha=ctx.head_sha,
                                is_fork_pr=ctx.is_fork,
                                policy_pack=config.policy_pack,
                                policy_pack_version=config.policy_pack_version,
                                action_version=action_version,
                                findings_summary=[],
                                idempotency_key=idem_key,
                                severity_threshold=config.severity_gate,
                                spec_compliance=None,
                            )
                            if validate_payload_tier(tier2_payload, consent):
                                await upload_telemetry_fn(
                                    tier2_payload,
                                    sentinelayer_token=sentinelayer_token,
                                    oidc_token=oidc_token,
                                    logger=logger,
                                )
            except Exception as exc:
                telemetry_success = False
                collector.record_error("telemetry", str(exc))
                logger.warning("Telemetry upload failed", error=str(exc))
    finally:
        collector.stage_end("telemetry", success=telemetry_success)


def _write_github_outputs(
    *,
    run_id: str,
    idem_key: str,
    findings_path: Path,
    pack_summary_path: Path,
    gate_result: GateResult,
    estimated_cost_usd: Optional[float] = 0.0,
    review_brief_path: Optional[Path] = None,
    audit_report_path: Optional[Path] = None,
    scan_mode: Optional[str] = None,
    severity_gate: Optional[str] = None,
    llm_provider: Optional[str] = None,
    model: Optional[str] = None,
    model_fallback: Optional[str] = None,
    model_fallback_used: Optional[bool] = None,
    llm_attempted: Optional[bool] = None,
    llm_success: Optional[bool] = None,
    llm_output_valid: Optional[bool] = None,
    llm_no_findings_reported: Optional[bool] = None,
    llm_findings_count: Optional[int] = None,
    llm_parse_error_count: Optional[int] = None,
    llm_failure_class: Optional[str] = None,
    policy_pack: Optional[str] = None,
    policy_pack_version: Optional[str] = None,
) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return

    with open(output_path, "a", encoding="utf-8") as output_file:
        status_value = (
            gate_result.status.value
            if hasattr(gate_result.status, "value")
            else str(gate_result.status)
        )
        output_file.write(f"gate_status={status_value}\n")
        output_file.write(f"run_id={run_id}\n")
        output_file.write(f"p0_count={gate_result.counts.p0}\n")
        output_file.write(f"p1_count={gate_result.counts.p1}\n")
        output_file.write(f"p2_count={gate_result.counts.p2}\n")
        output_file.write(f"p3_count={gate_result.counts.p3}\n")
        output_file.write(f"p4_count={gate_result.counts.p4}\n")
        output_file.write(f"findings_artifact={_to_workspace_relative(findings_path)}\n")
        output_file.write(f"pack_summary_artifact={_to_workspace_relative(pack_summary_path)}\n")

        ingest_path = pack_summary_path.parent / "INGEST.json"
        if ingest_path.exists():
            output_file.write(f"ingest_artifact={_to_workspace_relative(ingest_path)}\n")
        codebase_ingest_path = pack_summary_path.parent / "CODEBASE_INGEST.json"
        if codebase_ingest_path.exists():
            output_file.write(
                f"codebase_ingest_artifact={_to_workspace_relative(codebase_ingest_path)}\n"
            )
        codebase_summary_json = pack_summary_path.parent / "CODEBASE_INGEST_SUMMARY.json"
        if codebase_summary_json.exists():
            output_file.write(
                f"codebase_ingest_summary_artifact={_to_workspace_relative(codebase_summary_json)}\n"
            )
        codebase_summary_md = pack_summary_path.parent / "CODEBASE_INGEST_SUMMARY.md"
        if codebase_summary_md.exists():
            output_file.write(
                f"codebase_ingest_summary_md_artifact={_to_workspace_relative(codebase_summary_md)}\n"
            )
        if review_brief_path and review_brief_path.exists():
            output_file.write(
                f"review_brief_artifact={_to_workspace_relative(review_brief_path)}\n"
            )
        if audit_report_path and audit_report_path.exists():
            output_file.write(
                f"audit_report_artifact={_to_workspace_relative(audit_report_path)}\n"
            )
        output_file.write(f"idempotency_key={idem_key}\n")
        cost_value = f"{estimated_cost_usd:.8f}" if estimated_cost_usd is not None else "unknown"
        output_file.write(f"estimated_cost_usd={cost_value}\n")
        if scan_mode is not None:
            output_file.write(f"scan_mode={scan_mode}\n")
        if severity_gate is not None:
            output_file.write(f"severity_gate={severity_gate}\n")
        if llm_provider is not None:
            output_file.write(f"llm_provider={llm_provider}\n")
        if model is not None:
            output_file.write(f"model={model}\n")
        if model_fallback is not None:
            output_file.write(f"model_fallback={model_fallback}\n")
        if model_fallback_used is not None:
            output_file.write(f"model_fallback_used={'true' if model_fallback_used else 'false'}\n")
        if llm_attempted is not None:
            output_file.write(f"llm_attempted={'true' if llm_attempted else 'false'}\n")
        if llm_success is not None:
            output_file.write(f"llm_success={'true' if llm_success else 'false'}\n")
        if llm_output_valid is not None:
            output_file.write(f"llm_output_valid={'true' if llm_output_valid else 'false'}\n")
        if llm_no_findings_reported is not None:
            output_file.write(
                "llm_no_findings_reported="
                f"{'true' if llm_no_findings_reported else 'false'}\n"
            )
        if llm_findings_count is not None:
            output_file.write(f"llm_findings_count={int(llm_findings_count)}\n")
        if llm_parse_error_count is not None:
            output_file.write(f"llm_parse_error_count={int(llm_parse_error_count)}\n")
        if llm_failure_class is not None:
            output_file.write(f"llm_failure_class={llm_failure_class}\n")
        if policy_pack is not None:
            output_file.write(f"policy_pack={policy_pack}\n")
        if policy_pack_version is not None:
            output_file.write(f"policy_pack_version={policy_pack_version}\n")


def _load_event() -> dict:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return {}
    try:
        return json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _estimate_cost(
    *,
    ctx: GitHubContext,
    gh: GitHubClient,
    config: OmarGateConfig,
) -> float:
    if not ctx.pr_number:
        return 0.0

    pull_request_event = _load_event()
    pr = pull_request_event.get("pull_request") or {}

    if not pr:
        try:
            pr = gh.get_pull_request(ctx.pr_number)
        except Exception:
            pr = {}

    additions = int(pr.get("additions") or 0)
    deletions = int(pr.get("deletions") or 0)
    changed_files = int(pr.get("changed_files") or 0)

    return estimate_cost(
        file_count=changed_files,
        total_lines=additions + deletions,
        model=config.model,
    )
