"""Golden render tests for the Review chain section in PR comments.

Covers the four states the ticket requires:
- NOT_ATTEMPTED (sanitized #660 shape)
- COMPLETE (successful review with returned model)
- ATTEMPTED-FAILED (call attempted, provider failure)
- DISABLED (no LLM configured)
"""

from __future__ import annotations

import json
from pathlib import Path

from omargate.comment import render_pr_comment
from omargate.models import Counts, GateResult, GateStatus


def _base_result() -> GateResult:
    return GateResult(
        status=GateStatus.PASSED,
        reason="No blocking findings",
        block_merge=False,
        counts=Counts(p0=0, p1=0, p2=0, p3=0),
        dedupe_key="dedupe-test",
    )


def _base_kwargs():
    return dict(
        result=_base_result(),
        run_id="run-test",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url="https://example.com/artifacts",
        estimated_cost_usd=0.0032,
        version="1.2.0",
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        severity_gate="P1",
        duration_ms=1234,
        files_scanned=15,
        deterministic_count=12,
        llm_count=3,
        dedupe_key="dedupe-test",
    )


# ── NOT_ATTEMPTED (sanitized #660 shape) ──────────────────────────────

def test_review_chain_not_attempted_sanitized_660() -> None:
    """Sanitized #660: NOT_ATTEMPTED with candidate_budget_exceeded reason."""
    kwargs = _base_kwargs()
    kwargs.update(
        llm_engine="NOT_ATTEMPTED",
        llm_model="candidate_budget_exceeded",
        actual_cost_usd=None,
        cost_ledger_complete=False,
        llm_evidence={
            "attempted": False,
            "success": False,
            "failure_class": "cascade_source_scope_incomplete",
        },
        review_routing={
            "triage_status": "source_scope_incomplete",
            "source_failure_reason": "candidate_budget_exceeded",
            "routes": [
                {
                    "tier": "deep",
                    "model": "gpt-6-sol",
                    "effort": "max",
                    "attempted": False,
                    "success": False,
                    "reported_model": "",
                    "identity_matches": None,
                }
            ],
        },
    )
    body = render_pr_comment(**kwargs)

    assert "`NOT_ATTEMPTED` (`candidate_budget_exceeded`)" in body
    assert "**Cost (usage):** unknown (subtotal)" in body
    assert "### Review chain" in body
    assert "- **Triage:** `source scope incomplete`" in body
    assert "  - Reason: `candidate_budget_exceeded`" in body
    assert "`deep`" in body
    assert "`gpt-6-sol`" in body
    assert "`max`" in body
    assert "     - Attempted: no" in body
    assert "- **Attempted:** False" in body
    assert "- **Failure class:** `cascade_source_scope_incomplete`" in body


# ── COMPLETE (successful review) ──────────────────────────────────────

def test_review_chain_complete() -> None:
    """Successful LLM review with returned model and identity verified."""
    kwargs = _base_kwargs()
    kwargs.update(
        llm_engine="openai",
        llm_model="gpt-5.3-codex",
        actual_cost_usd=0.125,
        cost_ledger_complete=True,
        llm_evidence={
            "attempted": True,
            "success": True,
            "failure_class": None,
            "model": "gpt-5.3-codex",
        },
        review_routing={
            "triage_status": "ok",
            "source_failure_reason": "",
            "routes": [
                {
                    "tier": "primary",
                    "model": "gpt-5.3-codex",
                    "effort": "medium",
                    "success": True,
                    "reported_model": "gpt-5.3-codex",
                    "identity_matches": True,
                }
            ],
        },
    )
    body = render_pr_comment(**kwargs)

    assert "`openai` (`gpt-5.3-codex`)" in body
    assert "**Cost (usage):** `$0.12`" in body
    assert "### Review chain" in body
    assert "- **Triage:** `ok`" in body
    assert "`primary`" in body
    assert "`gpt-5.3-codex`" in body
    assert "     - Attempted: yes, returned `gpt-5.3-codex`" in body
    assert "**passed**" in body
    assert "     - Identity: verified" in body
    assert "- **Attempted:** True" in body
    assert "- **Success:** True" in body


# ── ATTEMPTED-FAILED ─────────────────────────────────────────────────

def test_review_chain_attempted_failed() -> None:
    """A failed call without a returned model has no identity to compare."""
    kwargs = _base_kwargs()
    kwargs.update(
        llm_engine="openai",
        llm_model="unknown",
        actual_cost_usd=None,
        cost_ledger_complete=False,
        llm_evidence={
            "attempted": True,
            "success": False,
            "failure_class": "provider_failure",
        },
        review_routing={
            "triage_status": "ok",
            "source_failure_reason": "",
            "routes": [
                {
                    "tier": "primary",
                    "model": "gpt-5.3-codex",
                    "effort": "medium",
                    "attempted": True,
                    "success": False,
                    "reported_model": "",
                    "identity_matches": None,
                }
            ],
        },
    )
    body = render_pr_comment(**kwargs)

    assert "`openai` (`unknown`)" in body
    assert "**Cost (usage):** unknown (subtotal)" in body
    assert "### Review chain" in body
    assert "     - Attempted: yes, no model returned" in body
    assert "**failed**" in body
    assert "     - Identity: unavailable (no model returned)" in body
    assert "- **Failure class:** `provider_failure`" in body
    assert "- **Attempted:** True" in body
    assert "- **Success:** False" in body


# ── DISABLED (no LLM configured) ─────────────────────────────────────

def test_review_chain_disabled() -> None:
    """LLM genuinely disabled — no evidence, no routing."""
    kwargs = _base_kwargs()
    kwargs.update(
        llm_engine="disabled",
        llm_model="n/a",
        actual_cost_usd=None,
        cost_ledger_complete=True,
        llm_evidence={
            "attempted": False,
            "success": False,
            "failure_class": None,
        },
        review_routing={},
    )
    body = render_pr_comment(**kwargs)

    assert "`disabled` (`n/a`)" in body
    assert "**Cost (usage):** unknown" in body
    assert "### Review chain" in body
    assert "LLM not configured" in body


# ── Identity unknown (no identity_matches key) ───────────────────────

def test_review_chain_identity_unknown_when_missing() -> None:
    """When identity_matches is absent, render 'Identity: unknown'."""
    kwargs = _base_kwargs()
    kwargs.update(
        llm_engine="openai",
        llm_model="gpt-5.3-codex",
        actual_cost_usd=0.05,
        cost_ledger_complete=True,
        llm_evidence={
            "attempted": True,
            "success": True,
            "failure_class": None,
            "model": "gpt-5.3-codex",
        },
        review_routing={
            "triage_status": "ok",
            "routes": [
                {
                    "tier": "primary",
                    "model": "gpt-5.3-codex",
                    "effort": "medium",
                    "success": True,
                    "reported_model": "gpt-5.3-codex",
                }
            ],
        },
    )
    body = render_pr_comment(**kwargs)

    assert "     - Identity: unknown" in body


# ── COMPLETE golden (sanitized production-shaped fixture) ─────────────

def test_review_chain_complete_golden() -> None:
    """Sanitized production-shaped COMPLETE fixture: full golden render."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / "review_chain_complete.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    kwargs = _base_kwargs()
    kwargs.update(
        llm_engine="openai",
        llm_model="gpt-5.3-codex",
        actual_cost_usd=0.125,
        cost_ledger_complete=True,
        estimated_cost_usd=0.0032,
        llm_evidence=fixture["llm_evidence"],
        review_routing=fixture["review_routing"],
        deterministic_count=12,
        llm_count=2,
    )
    body = render_pr_comment(**kwargs)

    # Header identity
    assert "`openai` (`gpt-5.3-codex`)" in body

    # Cost: estimate and usage separated
    assert "**Cost (est.):** `$0.0032`" in body
    assert "**Cost (usage):** `$0.12`" in body
    assert "(subtotal)" not in body  # complete ledger, no subtotal marker

    # Review chain section
    assert "### Review chain" in body
    assert "- **Triage:** `ok`" in body
    assert "`primary`" in body
    assert "`gpt-5.3-codex`" in body
    assert "`medium`" in body
    assert "     - Attempted: yes, returned `gpt-5.3-codex`" in body
    assert "**passed**" in body
    assert "     - Identity: verified" in body
    assert "- **Attempted:** True" in body
    assert "- **Success:** True" in body

    # Failure class absent when success is true
    assert "Failure class" not in body

    # No disabled language or LLM-not-configured fallback
    assert "`disabled`" not in body
    assert "LLM not configured" not in body

    # Full golden snapshot for exact output verification
    golden_section = (
        "### Review chain\n"
        "\n"
        "- **Triage:** `ok`\n"
        "- **Route:**\n"
        "  1. `primary` \u2192 `gpt-5.3-codex` / `medium`\n"
        "     - Attempted: yes, returned `gpt-5.3-codex` \u2014 **passed**\n"
        "     - Identity: verified\n"
        "- **Attempted:** True\n"
        "- **Success:** True\n"
    )
    assert golden_section in body, f"golden section mismatch. Body:\n{body}"


# ── Multi-route: per-route attempted evidence ────────────────────────

def test_review_chain_multi_route_per_route_attempted() -> None:
    """When routes list has alternatives, per-route 'attempted' field
    determines display, not cascade-wide evidence.attempted."""
    kwargs = _base_kwargs()
    kwargs.update(
        llm_engine="NOT_ATTEMPTED",
        llm_model="candidate_budget_exceeded",
        actual_cost_usd=None,
        cost_ledger_complete=False,
        llm_evidence={
            "attempted": False,  # cascade-wide: not attempted
            "success": False,
            "failure_class": "cascade_source_scope_incomplete",
        },
        review_routing={
            "triage_status": "source_scope_incomplete",
            "source_failure_reason": "candidate_budget_exceeded",
            "routes": [
                {
                    "tier": "shallow",
                    "model": "gpt-6-luna",
                    "effort": "low",
                    "attempted": True,   # per-route: this one was attempted
                    "success": False,
                    "reported_model": "",
                    "identity_matches": False,
                },
                {
                    "tier": "deep",
                    "model": "gpt-6-sol",
                    "effort": "max",
                    "attempted": False,  # per-route: this one was NOT attempted
                    "success": False,
                    "reported_model": "",
                    "identity_matches": False,
                },
            ],
        },
    )
    body = render_pr_comment(**kwargs)

    assert "### Review chain" in body

    # Route 1 (shallow): per-route attempted=true → shown as attempted
    assert "`shallow`" in body
    assert "`gpt-6-luna`" in body
    assert "`low`" in body
    # Route 1 should say attempted: yes
    assert "     - Attempted: yes" in body

    # Route 2 (deep): per-route attempted=false → shown as not attempted
    assert "`deep`" in body
    assert "`gpt-6-sol`" in body
    assert "`max`" in body
    # Route 2 should say attempted: no
    # Count occurrences of "Attempted: no" — should be exactly 1 (for route 2)
    assert body.count("     - Attempted: no") == 1


def test_legacy_route_without_attempt_bit_does_not_borrow_aggregate_attempt() -> None:
    kwargs = _base_kwargs()
    kwargs.update(
        llm_engine="openai",
        llm_model="gpt-6-sol",
        llm_evidence={"attempted": True, "success": True},
        review_routing={"routes": [
            {"tier": "low", "model": "gpt-6-luna", "effort": "max",
             "success": False, "reported_model": "", "identity_matches": False},
            {"tier": "deep", "model": "gpt-6-sol", "effort": "max",
             "attempted": True, "success": True, "reported_model": "gpt-6-sol",
             "identity_matches": True},
        ]},
    )
    body = render_pr_comment(**kwargs)
    first_route = body.split("  1. ")[1].split("  2. ")[0]
    assert "Attempted: unknown (missing per-route evidence)" in first_route
    assert "Attempted: yes" not in first_route
