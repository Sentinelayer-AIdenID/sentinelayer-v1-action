from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .collector import TelemetryCollector


@dataclass
class SpecComplianceTelemetry:
    spec_hash: str
    sections_checked: list[str]
    sections_violated: list[str]


def build_tier1_payload(collector: TelemetryCollector) -> dict:
    """
    Build Tier 1 (anonymous) telemetry payload.

    CRITICAL: This payload contains NO identifying information.
    - repo_hash is one-way hash, not reversible
    - No repo name, owner, PR number, SHA
    - No finding details (just counts)
    """
    return {
        "schema_version": "1.0",
        "tier": 1,
        "run": {
            "run_id": collector.run_id,
            "timestamp_utc": collector.start_time.isoformat(),
            "duration_ms": collector.total_duration_ms(),
            "state": collector.gate_status,
            "exit_code": collector.exit_code,
            "exit_reason": collector.exit_reason,
        },
        "repo": {
            "repo_hash": collector.repo_hash,
        },
        "scan": {
            "mode": collector.scan_mode,
            "llm_provider": collector.llm_provider,
            # Canonical fields (v1 schema).
            "model_used": collector.model_used,
            "model_fallback_used": collector.model_fallback_used,
            "fallback_provider": collector.fallback_provider,
            "fallback_model": collector.fallback_model,
            "tokens_in": collector.tokens_in,
            "tokens_out": collector.tokens_out,
            "cost_estimate_usd": round(collector.estimated_cost_usd, 4),
            "llm_latency_ms": collector.llm_latency_ms,
            # Aliases to match build spec field naming (keep both for compatibility).
            "llm_model": collector.model_used,
            "llm_tokens_in": collector.tokens_in,
            "llm_tokens_out": collector.tokens_out,
            "llm_cost_usd": round(collector.estimated_cost_usd, 4),
            "llm_fallback_used": collector.model_fallback_used,
            "llm_fallback_provider": collector.fallback_provider,
            "llm_fallback_model": collector.fallback_model,
            "files_scanned": collector.files_scanned,
        },
        "findings": {**collector.counts, **({"model_cost_estimates": collector.review_cost_ledger}
                                         if collector.review_cost_ledger is not None else {})},
        "gate": {
            "result": collector.gate_status,
            "exit_code": collector.exit_code,
            "exit_reason": collector.exit_reason,
            "preflight_exits": collector.preflight_exits,
            "dedupe_skipped": collector.dedupe_skipped,
            "rate_limit_skipped": collector.rate_limit_skipped,
            "fork_blocked": collector.fork_blocked,
        },
        "stages": collector.stage_durations(),
        "errors_count": len(collector.errors),
        # Keep Tier 1 errors anonymous: stages only (no raw messages).
        "errors": [e.get("stage") for e in collector.errors],
    }


def build_tier2_payload(
    collector: TelemetryCollector,
    repo_owner: str,
    repo_name: str,
    branch: str,
    pr_number: int | None,
    head_sha: str,
    is_fork_pr: bool,
    policy_pack: str,
    policy_pack_version: str,
    action_version: str,
    findings_summary: list[dict],
    idempotency_key: str,
    severity_threshold: str = "P1",
    spec_compliance: SpecComplianceTelemetry | None = None,
) -> dict:
    """
    Build Tier 2 (identified) telemetry payload.

    Requires explicit opt-in (share_metadata=true).
    Includes repo identity and finding metadata (no code snippets).
    """
    return {
        "schema_version": "1.0",
        "tier": 2,
        "run": {
            "run_id": collector.run_id,
            "timestamp_utc": collector.start_time.isoformat(),
            "duration_ms": collector.total_duration_ms(),
            "state": collector.gate_status,
            "exit_code": collector.exit_code,
            "exit_reason": collector.exit_reason,
        },
        "repo": {
            "owner": repo_owner,
            "name": repo_name,
            "branch": branch,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "is_fork_pr": is_fork_pr,
        },
        "scan": {
            "mode": collector.scan_mode,
            "policy_pack": policy_pack,
            "policy_pack_version": policy_pack_version,
            "llm_provider": collector.llm_provider,
            # Canonical fields (v1 schema).
            "model_used": collector.model_used,
            "model_fallback_used": collector.model_fallback_used,
            "tokens_in": collector.tokens_in,
            "tokens_out": collector.tokens_out,
            "cost_estimate_usd": round(collector.estimated_cost_usd, 4),
            "llm_latency_ms": collector.llm_latency_ms,
            "fallback_provider": collector.fallback_provider,
            "fallback_model": collector.fallback_model,
            # Aliases to match build spec field naming (keep both for compatibility).
            "llm_model": collector.model_used,
            "llm_tokens_in": collector.tokens_in,
            "llm_tokens_out": collector.tokens_out,
            "llm_cost_usd": round(collector.estimated_cost_usd, 4),
            "llm_fallback_used": collector.model_fallback_used,
            "llm_fallback_provider": collector.fallback_provider,
            "llm_fallback_model": collector.fallback_model,
        },
        "findings": {
            "summary": [
                {
                    "finding_id": f.get("id"),
                    "severity": f.get("severity"),
                    "category": f.get("category"),
                    "file_path": f.get("file_path"),
                    "line_start": f.get("line_start"),
                    "line_end": f.get("line_end"),
                    "fingerprint": f.get("fingerprint"),
                    "confidence": f.get("confidence"),
                    "source": f.get("source"),
                }
                for f in findings_summary
            ],
            "counts": collector.counts,
            **({"model_cost_estimates": collector.review_cost_ledger}
               if collector.review_cost_ledger is not None else {}),
        },
        "gate": {
            "severity_threshold": severity_threshold,
            "result": collector.gate_status,
            "bypass_reason": None,
            "exit_code": collector.exit_code,
            "exit_reason": collector.exit_reason,
            "preflight_exits": collector.preflight_exits,
        },
        "meta": {
            "action_version": action_version,
            "telemetry_tier": 2,
            "idempotency_key": idempotency_key,
        },
        "spec_compliance": asdict(spec_compliance) if spec_compliance else None,
        "errors": collector.errors,
    }


def build_tier3_manifest(
    collector: TelemetryCollector,
    tenant_id: str,
    repo_id: str,
    artifacts: list[dict],
    s3_prefix: str,
) -> dict:
    """
    Build Tier 3 artifact manifest for upload.

    Requires explicit opt-in (share_artifacts=true).
    References full artifacts stored in S3.
    """
    return {
        "schema_version": "1.0",
        "tier": 3,
        "tenant_id": tenant_id,
        "repo_id": repo_id,
        "run_id": collector.run_id,
        "artifact_root": f"{s3_prefix}/{tenant_id}/{repo_id}/{collector.run_id}/",
        "uploaded_at_utc": datetime.now(UTC).isoformat(),
        "objects": artifacts,
        "retention_days": 90,
        "encryption": {
            "mode": "SSE-S3",
        },
    }


def findings_to_summary(findings: list[dict]) -> list[dict]:
    """
    Strip findings to Tier 2-safe summary.

    Removes: snippet, message, recommendation, fix_plan (could contain code)
    Keeps: id, severity, category, file_path, line_start/end, fingerprint, confidence, source
    """
    return [
        {
            "finding_id": f.get("id"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            "file_path": f.get("file_path"),
            "line_start": f.get("line_start"),
            "line_end": f.get("line_end"),
            "fingerprint": f.get("fingerprint"),
            "confidence": f.get("confidence"),
            "source": f.get("source"),
        }
        for f in findings
    ]
