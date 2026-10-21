"""A refused gate must explain the review before emitting its failure annotation."""
import io
import re
import sys

from omargate.models import Counts, GateResult, GateStatus
from omargate.publish import write_step_summary
from omargate.runtime_helpers import _emit_gate_annotation


def test_incomplete_audit_and_real_finding_are_visible_before_error(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(sys, "stderr", output)
    result = GateResult(status=GateStatus.ERROR, reason="npm dependency audit is indeterminate (unsafe_lockfile)",
                        block_merge=True, counts=Counts(p0=1, p1=1, p2=8, p3=48, p4=1), dedupe_key="fixture")
    summary = {
        "severity_gate": "P1",
        "dependency_audit_evidence": {"enabled": True, "complete": False, "outcomes": [
            {"ecosystem": "npm", "applicable": True, "state": "indeterminate", "reason_code": "unsafe_lockfile"}]},
        "llm_evidence": {"attempted": True, "success": False, "output_valid": False,
                         "usage_recorded": True, "failure_class": "cascade_policy_incomplete"},
    }
    findings = [{"severity": "P1", "file_path": ".github/workflows/pilot.yml", "line_start": 10,
                 "message": "Fork PRs skip the required gate."}]
    write_step_summary(result, summary, findings, "fixture-run", "test")
    _emit_gate_annotation(gate_result=result, severity_gate="P1", run_id="fixture-run", run_dir=tmp_path,
                          workflow_run_url=None, dashboard_url=None)
    text = output.getvalue()
    annotation = text.index("::error title=")
    report = text[:annotation]
    assert "Omar Gate" in report and "unsafe_lockfile" in report
    assert "cascade_policy_incomplete" in report and "INCOMPLETE" in report
    assert "Fork PRs skip the required gate" in report
    assert "| P1 (High) | 1 | Yes |" in report
    assert "| P2 (Medium) | 8 | No |" in report and "| P3 (Low) | 48 | No |" in report
    assert "| P4 (Informational) | 1 | No |" in report


def test_console_report_disables_commands_and_restores_them_before_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr(sys, "stderr", output)
    result = GateResult(status=GateStatus.BLOCKED, reason="blocking finding", block_merge=True,
                        counts=Counts(p1=1), dedupe_key="fixture")
    # Exercise the outer output boundary even if an inner renderer emits a
    # command-shaped line. It must be inert inside the report.
    monkeypatch.setattr("omargate.publish.step_summary.render_codebase_snapshot_md",
                        lambda snapshot: "::error::forged annotation\n::endgroup::")
    write_step_summary(result, {"severity_gate": "P1"}, [], "fixture-run", "test",
                       codebase_snapshot={"stats": {}}, codebase_synopsis="fixture")
    _emit_gate_annotation(gate_result=result, severity_gate="P1", run_id="fixture-run", run_dir=tmp_path,
                          workflow_run_url=None, dashboard_url=None)
    text = output.getvalue()
    token = re.search(r"::stop-commands::([a-f0-9]{32})", text)
    assert token, "untrusted report must not be parsed as GitHub workflow commands"
    disabled = text.index(token.group(0))
    restored = text.index("::" + token.group(1) + "::")
    assert disabled < text.index("::error::forged annotation") < restored < text.index("::error title=")
