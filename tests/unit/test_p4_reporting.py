import json
import html

import pytest

from omargate.analyze.finding_contract import parse_finding_payload
from omargate.gate import evaluate_gate
from omargate.models import Counts, GateConfig, GateStatus
from omargate.packaging import write_findings_jsonl, write_pack_summary
from omargate.publish.artifacts import prepare_artifacts_for_upload
from omargate.publish.step_summary import write_step_summary
from omargate.analyze.review_costs import cost_ledger, estimate_usage


def test_p4_survives_parse_pack_gate_summary_and_download(tmp_path, monkeypatch):
    finding = {"severity": "P4", "category": "quality", "file_path": "x.py", "line_start": 1,
               "message": "Advisory: simplify this expression", "confidence": .92}
    parsed = parse_finding_payload(json.dumps(finding))
    assert not parsed.parse_errors and parsed.findings[0]["severity"] == "P4"
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 1}
    path = tmp_path / "FINDINGS.jsonl"
    write_findings_jsonl(path, [finding])
    ledger = cost_ledger([estimate_usage("typesafe", "jev-1.13.0", {"input_tokens": 1000, "output_tokens": 8}),
                          estimate_usage("openai", "gpt-6-luna", None)])
    summary_path = write_pack_summary(tmp_path, "p4-test", True, path, counts, {}, ["packaging"],
                                      llm_usage={"cost_ledger": ledger})
    result = evaluate_gate(summary_path, GateConfig(severity_gate="P1"))
    assert result.status == GateStatus.PASSED and not result.block_merge
    assert result.counts.p4 == result.counts.total() == 1
    output = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(output))
    write_step_summary(result, json.loads(summary_path.read_text()), [finding], "p4-test", "test")
    text = html.unescape(output.read_text(encoding="utf-8"))
    assert "P4 (Informational) | 1 | No" in text
    assert "typesafe / jev-1.13.0" in text and "openai / gpt-6-luna" in text
    assert "unknown (partial usage)" in text and "not billed charges" in text
    (tmp_path / "REVIEW_ROUTING.json").write_text('{"test":true}')
    prepare_artifacts_for_upload(tmp_path, tmp_path / "download")
    assert (tmp_path / "download/REVIEW_ROUTING.json").is_file()


@pytest.mark.parametrize("bad", [-1, True, 1.5, "0"])
def test_invalid_counts_cannot_fabricate_pass(tmp_path, bad):
    path = tmp_path / "FINDINGS.jsonl"
    write_findings_jsonl(path, [])
    summary_path = write_pack_summary(tmp_path, "invalid", True, path,
        {"P0": 0, "P1": 0, "P2": 0, "P3": 0}, {}, ["packaging"])
    payload = json.loads(summary_path.read_text())
    payload["counts"]["P1"] = bad
    summary_path.write_text(json.dumps(payload))
    result = evaluate_gate(summary_path, GateConfig())
    assert result.status == GateStatus.ERROR and result.block_merge


def test_historical_count_objects_default_p4_to_zero():
    assert Counts(p1=1).p4 == 0 and Counts(p1=1).total() == 1


def test_separate_price_estimates_survive_tier1_payload_without_source_identity():
    from omargate.telemetry.collector import TelemetryCollector
    from omargate.telemetry.schemas import build_tier1_payload
    collector = TelemetryCollector(run_id="cost-test", repo_full_name="private-owner/private-repo")
    collector.review_cost_ledger = cost_ledger([
        estimate_usage("typesafe", "jev-1.13.0", {"input_tokens": 1000, "output_tokens": 8}),
        estimate_usage("openai", "gpt-6-sol", None),
    ])
    payload = build_tier1_payload(collector)
    restored = json.loads(json.dumps(payload))["findings"]["model_cost_estimates"]
    assert [row["provider"] for row in restored["calls"]] == ["typesafe", "openai"]
    assert restored["estimated_total_usd"] is None
    assert "private-owner" not in json.dumps(payload)
    assert "private-repo" not in json.dumps(payload)


def test_unexpected_model_text_is_not_copied_to_cost_artifacts():
    record = estimate_usage("openai", "credential-shaped-untrusted-text", {"input_tokens": 1, "output_tokens": 1})
    assert record["model"] == "unrecognized" and record["estimated_usd"] is None
