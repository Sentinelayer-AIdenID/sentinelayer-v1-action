"""Bounded paid synthetic integration trial; never publishes a merge verdict."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace

from omargate.analyze.llm.llm_client import LLMClient
from omargate.analyze.orchestrator import AnalysisOrchestrator
from omargate.analyze.review_cascade import LOW, MID, DEEP, response_model_matches
from omargate.analyze.review_costs import cost_ledger, estimate_usage
from omargate.config import OmarGateConfig
from omargate.logging import OmarLogger
from omargate.mask_inputs import main as mask_inputs
from omargate.main import _build_llm_evidence
from omargate.gate import evaluate_gate
from omargate.models import GateConfig
from omargate.packaging import write_findings_jsonl, write_pack_summary


def evaluate_case(name, result, config, root):
    """Use the actual pack/gate boundary, keeping review state separate from test expectations."""
    projection = SimpleNamespace(llm_usage=result.usage, llm_attempted=result.attempted,
        llm_success=result.success, llm_output_valid=result.output_valid,
        llm_no_findings_reported=result.no_findings_reported,
        llm_reported_finding_count=result.reported_finding_count, llm_count=len(result.findings),
        llm_parse_error_count=result.parse_error_count, llm_failure_class=result.failure_class)
    path = root / "FINDINGS.jsonl"
    write_findings_jsonl(path, result.findings)
    counts = {severity: sum(row.get("severity") == severity for row in result.findings)
              for severity in ("P0", "P1", "P2", "P3", "P4")}
    summary = write_pack_summary(root, "synthetic-" + name, True, path, counts, {}, ["packaging"],
        llm_usage=result.usage, llm_evidence=_build_llm_evidence(projection, config))
    gate = evaluate_gate(summary, GateConfig(require_llm_success=True))
    routes = (result.usage or {}).get("review_routing", {}).get("routes", [])
    if name == "ordinary":
        expectation_met = result.success and gate.status.value == "passed" and not gate.block_merge
    else:
        # A serious synthetic defect must block. Policy uncertainty is retained
        # explicitly; a provider failure or missing defect does not count as proof.
        expectation_met = (bool(routes) and routes[0].get("tier") == "deep"
            and routes[-1].get("identity_matches") is True and routes[-1].get("success") is True
            and bool(counts["P0"] + counts["P1"]) and gate.block_merge
            and (result.success or result.failure_class == "cascade_policy_incomplete"))
    return {"expectation_met": expectation_met, "review_complete": result.success,
            "gate_status": gate.status.value, "block_merge": gate.block_merge, "gate_reason": gate.reason}


async def run(output: Path) -> bool:
    config = OmarGateConfig(
        llm_provider="typesafe", review_routing="intent-cascade-v1",
        typesafe_api_key=os.environ.get("INPUT_TYPESAFE_API_KEY", ""),
        openai_api_key=os.environ.get("INPUT_OPENAI_API_KEY", ""),
        intent_model_pin=os.environ.get("INPUT_INTENT_MODEL_PIN", ""),
        intent_policy=os.environ.get("INPUT_INTENT_POLICY", ""),
        intent_price_profile=os.environ.get("INPUT_INTENT_PRICE_PROFILE", ""),
        max_input_tokens=30_000, run_harness=False, use_codex=False,
        publish_github=False, telemetry=False, llm_failure_policy="block",
    )
    report = {
        "schema": "omargate.synthetic-canary.v1", "revision": os.environ.get("GITHUB_SHA", "unknown"),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "scope": "synthetic routing/policy/generator stages only; no deployment, merge verdict or recall claim",
        "model_reference": config.intent_model_reference, "policy_reference": config.review_policy.reference,
        "capability_probes": [], "cases": [],
    }
    calls = []
    success = True
    try:
        # Three explicit capability probes plus two bounded cascades: at most nine
        # generator calls, each with no SDK/outer retry and <=16,384 output tokens.
        for route in (LOW, MID, DEEP):
            client = LLMClient(api_key=config.openai_api_key.get_secret_value(), primary_model=route.model,
                               fallback_model=route.model, reasoning_effort=route.effort, max_retries=1,
                               allow_fallback=False, timeout_seconds=300)
            response = await client.analyze("Return the word ready.", "Synthetic capability probe.", max_tokens=16384)
            usage = response.usage
            matched = response_model_matches(usage.model, route.model)
            complete = response.success and matched
            calls.append({**estimate_usage("openai", usage.model, usage.raw_usage), "stage": "capability-probe"})
            report["capability_probes"].append({"tier": route.tier, "effort": route.effort,
                "reported_model": usage.model if matched else "unknown", "success": complete})
            success = success and complete
        sources = (
            ("ordinary", "src/format.py", "def display_label(value):\n    return str(value).strip()\n", []),
            ("serious", "src/auth.py", "def may_read(actor, document):\n    return True\n", [
                {"id": "synthetic-policy-control", "source": "deterministic", "rule_id": "CANARY-CONTROL",
                 "severity": "P1", "category": "auth", "file_path": "src/auth.py", "line_start": 2,
                 "message": "Synthetic access-control defect supplied to verify routing."}]),
        )
        for name, path, source, findings in sources:
            with tempfile.TemporaryDirectory(prefix="intent-canary-") as directory:
                root = Path(directory)
                target = root / path
                target.parent.mkdir(parents=True)
                target.write_text(source, encoding="utf-8")
                diff = f"diff --git a/{path} b/{path}\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{len(source.splitlines())} @@\n"
                diff += "".join("+" + line for line in source.splitlines(keepends=True))
                engine = AnalysisOrchestrator(config, OmarLogger("synthetic-" + name), root)
                result = await engine._run_cascade_analysis(
                    ingest={"files": [{"path": path, "lines": len(source.splitlines()), "language": "Python"}],
                            "stats": {"in_scope_files": 1}}, changed_files=[path], scan_mode="pr-diff",
                    deterministic_findings=findings, quick_learn=None, spec_context=None,
                    diff_content=diff, run_dir=None,
                )
                usage = result.usage or {}
                routes = usage.get("review_routing", {}).get("routes", [])
                calls.extend(usage.get("cost_ledger", {}).get("calls", []))
                outcome = evaluate_case(name, result, config, root)
                report["cases"].append({"name": name, **outcome, "failure_class": result.failure_class,
                    "routes": routes, "triage_status": usage.get("review_routing", {}).get("triage_status"),
                    "triage_answers": usage.get("review_routing", {}).get("answers"),
                    "policy_assessment": usage.get("policy_assessment"),
                    "finding_severities": [row.get("severity") for row in result.findings]})
                success = success and outcome["expectation_met"]
    except Exception:
        # Never publish private config/provider exception bodies. No-call or
        # interrupted usage remains unknown, even if an earlier subtotal exists.
        calls.append({"provider": "unknown", "model": "unknown", "stage": "interrupted-trial",
                      "kind": "estimated_not_billed", "estimated_usd": None, "status": "usage_unknown"})
        report["failure_class"] = "synthetic_trial_incomplete"
        success = False
    report.update(expectations_met=success, costs=cost_ledger(calls), completed_at=datetime.now(timezone.utc).isoformat())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return success


if __name__ == "__main__":
    mask_inputs()
    raise SystemExit(0 if asyncio.run(run(Path("canary-evidence/intent-canary.json"))) else 1)
