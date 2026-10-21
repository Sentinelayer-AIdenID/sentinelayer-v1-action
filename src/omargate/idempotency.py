from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone

GENERATOR_SOURCE_BOUNDARY_VERSION = "generator-source-privacy-v5:complete-tracked-text:non-utf8-png-jpeg-ico:private-coordinates:scanner-credential-backstop"


def review_config_digest(config) -> str:
    """Bind effective settings without publishing credentials or private policy."""
    from pydantic import SecretStr
    values = config.model_dump(mode="json")
    # A same-head receipt predating the outbound privacy boundary is not reusable.
    if config.review_routing == "intent-cascade-v1":
        values["_source_boundary_contract"] = GENERATOR_SOURCE_BOUNDARY_VERSION
    for name in type(config).model_fields:
        value = getattr(config, name)
        if isinstance(value, SecretStr):
            secret = value.get_secret_value()
            values[name] = hashlib.sha256(secret.encode()).hexdigest() if name in {"intent_model_pin", "intent_policy"} else bool(secret)
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def dependency_audit_freshness_epoch(now: datetime | None = None) -> str:
    """Return the UTC calendar day used to bound dependency-audit dedupe."""
    instant = datetime.now(timezone.utc) if now is None else now
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("dependency audit freshness time must be timezone-aware")
    return instant.astimezone(timezone.utc).date().isoformat()


def _normalize_dependency_audit_freshness_epoch(value: str) -> str:
    raw = str(value).strip()
    try:
        parsed = date.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(
            "dependency audit freshness epoch must be an ISO UTC date"
        ) from exc
    canonical = parsed.isoformat()
    if raw != canonical:
        raise ValueError(
            "dependency audit freshness epoch must be an ISO UTC date"
        )
    return canonical


def _canonicalize_pip_audit_ignore_ids(raw: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                token.strip()
                for token in re.split(r"[,\s;]+", str(raw or ""))
                if token.strip()
            }
        )
    )


def compute_idempotency_key(
    repo: str,
    pr_number: int,
    head_sha: str,
    scan_mode: str,
    policy_pack: str,
    policy_pack_version: str,
    action_major_version: str,
    comment_tag: str = "",
    audit_contract_version: str = "",
    run_harness: bool | None = None,
    pip_audit_ignore_ids: str = "",
    audit_freshness_epoch: str | None = None,
    config_digest: str = "",
) -> str:
    # P0: do NOT truncate; show shortened form only for display
    payload = (
        f"{repo}:{pr_number}:{head_sha}:{scan_mode}:{policy_pack}:"
        f"{policy_pack_version}:{action_major_version}"
    )
    tag = str(comment_tag or "").strip().lower()
    tag = re.sub(r"[^a-z0-9_-]+", "-", tag)
    tag = re.sub(r"-{2,}", "-", tag).strip("-_")
    if tag:
        payload = f"{payload}:{tag}"
    audit_contract = str(audit_contract_version or "").strip()
    canonical_ignore_ids = _canonicalize_pip_audit_ignore_ids(
        pip_audit_ignore_ids
    )
    freshness_epoch = None
    if run_harness is True:
        freshness_epoch = (
            dependency_audit_freshness_epoch()
            if audit_freshness_epoch is None
            else _normalize_dependency_audit_freshness_epoch(
                audit_freshness_epoch
            )
        )
    if audit_contract or run_harness is not None or canonical_ignore_ids:
        audit_binding_fields = {
            "contract": audit_contract,
            "pip_audit_ignore_ids": canonical_ignore_ids,
            "run_harness": run_harness,
        }
        if freshness_epoch is not None:
            audit_binding_fields["freshness_epoch"] = freshness_epoch
        audit_binding = json.dumps(
            audit_binding_fields,
            sort_keys=True,
            separators=(",", ":"),
        )
        payload = f"{payload}:dependency-audit:{audit_binding}"
    if config_digest:
        if re.fullmatch(r"[a-f0-9]{64}", config_digest) is None:
            raise ValueError("review config digest must be a SHA-256")
        payload += ":review-config:" + config_digest
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
