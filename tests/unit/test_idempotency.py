from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from omargate.idempotency import (
    compute_idempotency_key,
    dependency_audit_freshness_epoch,
)
from omargate.main import (
    ACTION_IDEMPOTENCY_VERSION,
    DEPENDENCY_AUDIT_CONTRACT_VERSION,
)


def _legacy_hash() -> str:
    payload = "octo/repo:7:deadbeef:pr-diff:omar:v1:1"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def test_idempotency_key_empty_comment_tag_matches_legacy() -> None:
    key = compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
        comment_tag="",
    )
    assert key == _legacy_hash()


def test_idempotency_key_changes_when_comment_tag_is_set() -> None:
    base = compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
    )
    tagged = compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
        comment_tag="gemini",
    )
    assert tagged != base
    assert tagged == compute_idempotency_key(
        repo="octo/repo",
        pr_number=7,
        head_sha="deadbeef",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        action_major_version="1",
        comment_tag="gemini",
    )


def test_live_llm_evidence_contract_invalidates_legacy_dedupe_keys() -> None:
    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "policy_pack": "omar",
        "policy_pack_version": "v1",
    }

    legacy = compute_idempotency_key(action_major_version="1", **common)
    evidence_contract = compute_idempotency_key(
        action_major_version=ACTION_IDEMPOTENCY_VERSION,
        **common,
    )

    assert evidence_contract != legacy


def test_dependency_audit_contract_and_harness_mode_are_bound() -> None:
    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "policy_pack": "omar",
        "policy_pack_version": "v1",
        "action_major_version": ACTION_IDEMPOTENCY_VERSION,
        "audit_contract_version": DEPENDENCY_AUDIT_CONTRACT_VERSION,
    }

    enabled = compute_idempotency_key(
        run_harness=True,
        audit_freshness_epoch="2026-10-18",
        **common,
    )
    disabled = compute_idempotency_key(run_harness=False, **common)
    prior_contract = compute_idempotency_key(
        run_harness=True,
        audit_freshness_epoch="2026-10-18",
        **{**common, "audit_contract_version": "dependency-audit-evidence-v1"},
    )

    assert enabled != disabled
    assert enabled != prior_contract


def test_nested_pip_boundary_rotates_both_contract_tokens() -> None:
    assert DEPENDENCY_AUDIT_CONTRACT_VERSION == "dependency-audit-evidence-v1.3:workspace-root:complete-discovery:root-declared-peer-edges:isolated-npm-config:nested-pip-direct-pins"
    assert (
        ACTION_IDEMPOTENCY_VERSION
        == "4:dependency-audit-v1.3:complete-discovery:workspace-root:private-policy:review-config:verified-model:root-declared-peer-edges:isolated-npm-config:verified-scope-findings:failed-call-provenance:route-attempt-provenance:nested-pip-direct-pins:entropy-candidate-boundaries"
    )

    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "policy_pack": "omar",
        "policy_pack_version": "v1",
        "run_harness": True,
        "audit_freshness_epoch": "2026-10-18",
    }
    current = compute_idempotency_key(
        action_major_version=ACTION_IDEMPOTENCY_VERSION,
        audit_contract_version=DEPENDENCY_AUDIT_CONTRACT_VERSION,
        **common,
    )
    prior_schema = compute_idempotency_key(
        action_major_version="1:llm-evidence-v1:dependency-audit-v1",
        audit_contract_version="dependency-audit-evidence-v1",
        **common,
    )

    assert current != prior_schema
    assert current != compute_idempotency_key(
        action_major_version="2:dependency-audit-v1.1:private-policy:review-config:verified-model",
        audit_contract_version="dependency-audit-evidence-v1.1", **common,
    )
    old_action = "3:dependency-audit-v1.2:project-coverage:private-policy:review-config:verified-model"
    old_audit = "dependency-audit-evidence-v1.2"
    for action, audit in [(old_action, old_audit), (old_action, DEPENDENCY_AUDIT_CONTRACT_VERSION),
                          (ACTION_IDEMPOTENCY_VERSION, old_audit)]:
        assert current != compute_idempotency_key(action_major_version=action, audit_contract_version=audit, **common)
    previous_action = "4:dependency-audit-v1.2:complete-discovery:workspace-root:private-policy:review-config:verified-model:root-declared-peer-edges:isolated-npm-config:verified-scope-findings:failed-call-provenance:route-attempt-provenance"
    previous_audit = "dependency-audit-evidence-v1.2:workspace-root:complete-discovery:root-declared-peer-edges:isolated-npm-config"
    for action, audit in [
        (previous_action, previous_audit),
        (previous_action, DEPENDENCY_AUDIT_CONTRACT_VERSION),
        (ACTION_IDEMPOTENCY_VERSION, previous_audit),
    ]:
        assert current != compute_idempotency_key(
            action_major_version=action, audit_contract_version=audit, **common,
        )


def test_pip_audit_ignore_ids_are_canonicalized_for_idempotency() -> None:
    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "policy_pack": "omar",
        "policy_pack_version": "v1",
        "action_major_version": ACTION_IDEMPOTENCY_VERSION,
        "audit_contract_version": DEPENDENCY_AUDIT_CONTRACT_VERSION,
        "run_harness": True,
        "audit_freshness_epoch": "2026-10-18",
    }

    mixed = compute_idempotency_key(
        pip_audit_ignore_ids=" GHSA-TEST, CVE-2026-1; CVE-2026-1 ",
        **common,
    )
    canonical = compute_idempotency_key(
        pip_audit_ignore_ids="CVE-2026-1 GHSA-TEST",
        **common,
    )
    changed = compute_idempotency_key(
        pip_audit_ignore_ids="CVE-2026-2 GHSA-TEST",
        **common,
    )
    case_changed = compute_idempotency_key(
        pip_audit_ignore_ids="CVE-2026-1 ghsa-test",
        **common,
    )

    assert mixed == canonical
    assert mixed != changed
    assert mixed != case_changed


def test_current_main_contract_does_not_reuse_legacy_audit_key() -> None:
    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "policy_pack": "omar",
        "policy_pack_version": "v1",
        "action_major_version": ACTION_IDEMPOTENCY_VERSION,
    }

    version_only = compute_idempotency_key(**common)
    current = compute_idempotency_key(
        audit_contract_version=DEPENDENCY_AUDIT_CONTRACT_VERSION,
        run_harness=True,
        pip_audit_ignore_ids="",
        audit_freshness_epoch="2026-10-18",
        **common,
    )

    assert current != version_only


def test_dependency_audit_freshness_epoch_uses_utc_day_boundary() -> None:
    before_midnight = datetime(2026, 10, 18, 23, 59, 59, tzinfo=timezone.utc)
    after_midnight = before_midnight + timedelta(seconds=1)
    ahead_of_utc = datetime(
        2026,
        10,
        19,
        1,
        30,
        tzinfo=timezone(timedelta(hours=2)),
    )

    assert dependency_audit_freshness_epoch(before_midnight) == "2026-10-18"
    assert dependency_audit_freshness_epoch(after_midnight) == "2026-10-19"
    assert dependency_audit_freshness_epoch(ahead_of_utc) == "2026-10-18"


def test_dependency_audit_freshness_epoch_rejects_naive_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        dependency_audit_freshness_epoch(datetime(2026, 10, 18, 12, 0))


def test_enabled_harness_dedupes_only_within_same_utc_epoch() -> None:
    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "policy_pack": "omar",
        "policy_pack_version": "v1",
        "action_major_version": ACTION_IDEMPOTENCY_VERSION,
        "audit_contract_version": DEPENDENCY_AUDIT_CONTRACT_VERSION,
        "run_harness": True,
    }

    same_epoch = compute_idempotency_key(
        audit_freshness_epoch="2026-10-18",
        **common,
    )
    repeated = compute_idempotency_key(
        audit_freshness_epoch="2026-10-18",
        **common,
    )
    next_epoch = compute_idempotency_key(
        audit_freshness_epoch="2026-10-19",
        **common,
    )
    stale_epoch = compute_idempotency_key(
        audit_freshness_epoch="2026-10-17",
        **common,
    )

    assert same_epoch == repeated
    assert same_epoch != next_epoch
    assert same_epoch != stale_epoch


def test_disabled_harness_key_is_time_stable() -> None:
    common = {
        "repo": "octo/repo",
        "pr_number": 7,
        "head_sha": "deadbeef",
        "scan_mode": "deep",
        "policy_pack": "omar",
        "policy_pack_version": "v1",
        "action_major_version": ACTION_IDEMPOTENCY_VERSION,
        "audit_contract_version": DEPENDENCY_AUDIT_CONTRACT_VERSION,
        "run_harness": False,
    }

    first = compute_idempotency_key(
        audit_freshness_epoch="2026-10-18",
        **common,
    )
    later = compute_idempotency_key(
        audit_freshness_epoch="2026-10-19",
        **common,
    )
    omitted = compute_idempotency_key(**common)

    assert first == later == omitted
