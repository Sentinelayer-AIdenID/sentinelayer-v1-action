from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from omargate.analyze.codex.codex_runner import parse_codex_findings
from omargate.analyze.llm.llm_client import LLMClient, LLMResponse, LLMUsage
from omargate.analyze.llm.response_parser import ResponseParser
from omargate.analyze.orchestrator import AnalysisOrchestrator
from omargate.config import OmarGateConfig
from omargate.gate import evaluate_gate
from omargate.logging import OmarLogger
from omargate.main import _build_llm_evidence
from omargate.models import GateConfig, GateStatus
from omargate.packaging import write_findings_jsonl, write_pack_summary

ParserAdapter = Callable[[str], tuple[list[object], list[str], bool]]

_FINDING = {
    "severity": "P0",
    "category": "auth",
    "file_path": "src/auth.py",
    "line_start": 7,
    "message": "Authorization can be bypassed.",
}
_FINDING_JSON = json.dumps(_FINDING, separators=(",", ":"))


def _parse_api(payload: str) -> tuple[list[object], list[str], bool]:
    result = ResponseParser().parse(payload)
    return list(result.findings), list(result.parse_errors), result.no_findings_reported


def _parse_codex(payload: str) -> tuple[list[object], list[str], bool]:
    findings, errors, no_findings = parse_codex_findings(payload)
    return list(findings), list(errors), no_findings


_PARSERS: tuple[ParserAdapter, ...] = (_parse_api, _parse_codex)

_ADVERSARIAL_PAYLOADS = [
    pytest.param(
        json.dumps({"no_findings": True, "findings": [_FINDING]}),
        id="contradictory-clean-object-with-hidden-finding",
    ),
    pytest.param(
        json.dumps({**_FINDING, "category": None}),
        id="null-category",
    ),
    pytest.param(
        json.dumps({**_FINDING, "file_path": None}),
        id="null-file-path",
    ),
    pytest.param(
        json.dumps({**_FINDING, "message": None}),
        id="null-message",
    ),
    pytest.param(
        json.dumps({**_FINDING, "line_start": True}),
        id="boolean-line-start",
    ),
    pytest.param(
        json.dumps({**_FINDING, "line_end": True}),
        id="boolean-line-end",
    ),
    pytest.param(
        json.dumps({**_FINDING, "line_end": 6}),
        id="line-end-before-line-start",
    ),
    pytest.param(
        f'{_FINDING_JSON[:-1]},"confidence":NaN}}',
        id="non-finite-confidence",
    ),
    pytest.param(
        f'{_FINDING_JSON[:-1]},"confidence":Infinity}}',
        id="infinite-confidence",
    ),
    pytest.param(
        f'{_FINDING_JSON[:-1]},"confidence":{"9" * 310}}}',
        id="oversized-integer-confidence",
    ),
    pytest.param(
        json.dumps({**_FINDING, "confidence": True}),
        id="boolean-confidence",
    ),
    pytest.param(
        json.dumps({**_FINDING, "confidence": 1.01}),
        id="out-of-range-confidence",
    ),
    pytest.param(
        json.dumps({**_FINDING, "recommendation": None}),
        id="null-optional-string",
    ),
    pytest.param(
        json.dumps({**_FINDING, "message": "   "}),
        id="blank-required-string",
    ),
    pytest.param(
        json.dumps({**_FINDING, "source": "uncontracted"}),
        id="unknown-source-field",
    ),
    pytest.param(
        json.dumps({**_FINDING, "id": "caller-controlled"}),
        id="unknown-id-field",
    ),
    pytest.param(
        json.dumps({**_FINDING, "snippet": "caller-controlled"}),
        id="unknown-snippet-field",
    ),
    pytest.param(
        "[]",
        id="empty-array-without-explicit-clean-sentinel",
    ),
    pytest.param(
        '"clean"',
        id="top-level-scalar",
    ),
    pytest.param(
        ("[" * 1100) + "0" + ("]" * 1100),
        id="excessive-json-nesting",
    ),
    pytest.param(
        (
            '{"severity":"P0","severity":"P3","category":"auth",'
            '"file_path":"src/auth.py","line_start":7,'
            '"message":"Authorization can be bypassed."}'
        ),
        id="duplicate-object-key",
    ),
    pytest.param(
        f"Model analysis follows:\n```json\n{_FINDING_JSON}\n```\nEnd analysis.",
        id="surrounding-prose-and-fence",
    ),
    pytest.param(
        (f'```json\n{{"no_findings":true}}\n```\n```json\n{_FINDING_JSON}\n```'),
        id="multiple-fenced-blocks",
    ),
    pytest.param(
        f'[{{"no_findings":true}},{_FINDING_JSON}]',
        id="sentinel-mixed-with-finding-in-array",
    ),
    pytest.param(
        f'{{"no_findings":true}}\n{_FINDING_JSON}',
        id="sentinel-mixed-with-finding-in-jsonl",
    ),
]


@pytest.mark.parametrize("parse_payload", _PARSERS, ids=("api", "codex"))
@pytest.mark.parametrize("payload", _ADVERSARIAL_PAYLOADS)
def test_adversarial_payloads_cannot_satisfy_the_finding_contract(
    parse_payload: ParserAdapter,
    payload: str,
) -> None:
    findings, errors, no_findings = parse_payload(payload)

    valid_result_shape = not errors and (
        (len(findings) > 0 and no_findings is False)
        or (len(findings) == 0 and no_findings is True)
    )

    assert errors
    assert no_findings is False
    assert valid_result_shape is False


@pytest.mark.parametrize("parse_payload", _PARSERS, ids=("api", "codex"))
def test_nonempty_finding_array_remains_compatible(
    parse_payload: ParserAdapter,
) -> None:
    findings, errors, no_findings = parse_payload(json.dumps([_FINDING, _FINDING]))

    assert len(findings) == 2
    assert errors == []
    assert no_findings is False


@pytest.mark.parametrize("parse_payload", _PARSERS, ids=("api", "codex"))
def test_prompt_contract_optional_fields_remain_compatible(
    parse_payload: ParserAdapter,
) -> None:
    payload = json.dumps(
        {
            **_FINDING,
            "line_end": 9,
            "evidence_snippet": "if not actor: allow()",
            "impact": "Unauthorized access",
            "verification": "Add a denied-user regression test",
            "recommendation": "Enforce authorization before dispatch",
            "fix_plan": "Guard the dispatch path and add the regression test.",
            "confidence": 0.95,
            "source_agent": "OmarPack",
            "provenance_tag": "security_auth_v1",
        }
    )

    findings, errors, no_findings = parse_payload(payload)

    assert len(findings) == 1
    assert errors == []
    assert no_findings is False


@pytest.mark.anyio
async def test_hidden_finding_fails_closed_through_orchestrator_evidence_and_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = OmarGateConfig(
        openai_api_key="sk_test_dummy",
        use_codex=False,
        run_harness=False,
        llm_failure_policy="block",
        severity_gate="none",
    )
    orchestrator = AnalysisOrchestrator(
        config=config,
        logger=OmarLogger("strict-contract-regression"),
        repo_root=tmp_path,
        allow_llm=True,
    )
    contradictory_payload = json.dumps({"no_findings": True, "findings": [_FINDING]})

    async def _fake_analyze(
        _self: LLMClient,
        *_args: object,
        **_kwargs: object,
    ) -> LLMResponse:
        return LLMResponse(
            content=contradictory_payload,
            usage=LLMUsage(
                model=config.model,
                provider="openai",
                tokens_in=20,
                tokens_out=10,
                cost_usd=0.001,
                latency_ms=25,
            ),
            success=True,
        )

    monkeypatch.setattr(LLMClient, "analyze", _fake_analyze)
    monkeypatch.setattr(
        AnalysisOrchestrator,
        "_run_deterministic_scans",
        lambda _self, _ingest: [],
    )
    monkeypatch.setattr(
        "omargate.analyze.orchestrator.is_boilerplate_description",
        lambda _description: False,
    )

    analysis = await orchestrator.run(scan_mode="deep")

    assert analysis.llm_attempted is True
    assert analysis.llm_success is False
    assert analysis.llm_output_valid is False
    assert analysis.llm_no_findings_reported is False
    assert analysis.llm_parse_error_count > 0
    assert analysis.llm_failure_class == "invalid_output"
    assert analysis.counts["P0"] == 1
    assert any(
        finding.get("category") == "LLM Failure" and finding.get("source") == "system"
        for finding in analysis.findings
    )

    evidence = _build_llm_evidence(analysis, config)
    assert evidence["attempted"] is True
    assert evidence["success"] is False
    assert evidence["output_valid"] is False
    assert evidence["parse_error_count"] > 0
    assert evidence["failure_class"] == "invalid_output"

    findings_path = tmp_path / "FINDINGS.jsonl"
    write_findings_jsonl(findings_path, analysis.findings)
    write_pack_summary(
        run_dir=tmp_path,
        run_id="strict-contract-regression",
        writer_complete=True,
        findings_path=findings_path,
        counts=analysis.counts,
        tool_versions={"omargate": "test"},
        stages_completed=["analysis"],
        severity_gate="none",
        llm_usage=analysis.llm_usage,
        llm_evidence=evidence,
    )

    gate_result = evaluate_gate(
        tmp_path,
        GateConfig(severity_gate="none", require_llm_success=True),
    )

    assert gate_result.status == GateStatus.ERROR
    assert gate_result.block_merge is True
    assert "live LLM review did not succeed" in gate_result.reason
