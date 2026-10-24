"""Preflight approval must account for the paid cascade, not just PR line count."""

import asyncio
from types import SimpleNamespace

import pytest

from omargate.comment import render_pr_comment
from omargate.models import Counts, GateResult, GateStatus
from omargate.preflight.cost import check_cost_approval
from omargate import telemetry_runtime


def _config(*, routing="intent-cascade-v1", profile="typesafe-input-20261020", threshold=0.01):
    policy = SimpleNamespace(
        routing={"domains": {"security": [100, "Review security implications"]}},
        generator_instructions="Review verified source before deciding.",
    )
    return SimpleNamespace(
        review_routing=routing,
        scan_mode="pr-diff",
        model="gpt-6-sol",
        max_input_tokens=100_000,
        intent_price_profile=profile,
        review_policy=policy,
        require_cost_confirmation=threshold,
        approval_mode="pr_label",
        approval_label="sentinelayer:approved",
    )


def _context():
    return SimpleNamespace(pr_number=176, event_name="pull_request")


def _estimate(monkeypatch, config):
    monkeypatch.setattr(telemetry_runtime, "_load_event", lambda: {
        "pull_request": {"additions": 2, "deletions": 1, "changed_files": 2}
    })
    return telemetry_runtime._estimate_cost(ctx=_context(), gh=object(), config=config)


def test_three_line_cascade_requires_manual_approval_below_stage_forecast(monkeypatch):
    config = _config()
    forecast = _estimate(monkeypatch, config)
    # The legacy diff-only heuristic is $0.000072 and would bypass $0.01.
    assert forecast is not None and 0.022655912 < forecast <= 5.00

    class GitHub:
        def has_label(self, *_args):
            return False

    approved, status = asyncio.run(check_cost_approval(forecast, config, _context(), GitHub()))
    assert (approved, status) == (False, "label_missing")


def test_cascade_default_threshold_and_legacy_route_keep_their_behavior(monkeypatch):
    forecast = _estimate(monkeypatch, _config(threshold=5.00))
    assert forecast is not None and forecast <= 5.00
    legacy = _estimate(monkeypatch, _config(routing="legacy"))
    assert legacy == pytest.approx(0.000072)


def test_unconfigured_cascade_price_requires_approval_instead_of_zero_cost(monkeypatch):
    config = _config(profile="")
    forecast = _estimate(monkeypatch, config)
    assert forecast is None

    class GitHub:
        def has_label(self, *_args):
            return False

    approved, status = asyncio.run(check_cost_approval(forecast, config, _context(), GitHub()))
    assert (approved, status) == (False, "label_missing")


def test_cascade_comment_distinguishes_approval_forecast_from_usage_estimate():
    result = GateResult(status=GateStatus.PASSED, reason="No blocking findings",
                        block_merge=False, counts=Counts(p0=0, p1=0, p2=0, p3=0))
    body = render_pr_comment(
        result=result, run_id="run", repo_full_name="owner/repo", pr_number=176,
        dashboard_url=None, artifacts_url=None, estimated_cost_usd=3.5,
        version="1.3.11", actual_cost_usd=0.022655912,
        cascade_cost_envelope=True,
        review_routing={"routes": [{"tier": "deep", "model": "gpt-6-sol", "effort": "max",
                                    "attempted": True, "success": True,
                                    "reported_model": "gpt-6-sol", "identity_matches": True}]},
    )
    assert "Cost (preflight forecast):** `$3.50`" in body
    assert "Cost (usage estimate):** `$0.02`" in body
    assert "Cost (est.):**" not in body
