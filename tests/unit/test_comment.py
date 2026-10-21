from __future__ import annotations

from copy import deepcopy

from omargate.comment import MARKER_PREFIX, marker, marker_prefix, render_pr_comment
from omargate.models import Counts, GateResult, GateStatus


def _gate_result() -> GateResult:
    return GateResult(
        status=GateStatus.PASSED,
        reason="No blocking findings",
        block_merge=False,
        counts=Counts(p0=0, p1=1, p2=2, p3=3),
        dedupe_key="dedupe-123456",
    )


def test_marker_without_comment_tag_is_unchanged() -> None:
    assert marker("acme/demo", 42) == "<!-- sentinelayer:omar-gate:v1:acme/demo:42 -->"
    assert marker_prefix() == MARKER_PREFIX


def test_marker_with_comment_tag_is_provider_aware() -> None:
    assert marker("acme/demo", 42, comment_tag="gemini") == (
        "<!-- sentinelayer:omar-gate:v1:gemini:acme/demo:42 -->"
    )
    assert marker_prefix("gemini") == "<!-- sentinelayer:omar-gate:v1:gemini:"


def test_comment_contains_marker() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url="https://example.com/artifacts",
        estimated_cost_usd=0.0032,
        version="1.2.0",
        findings=[
            {
                "severity": "P1",
                "file_path": "app.py",
                "line_start": 10,
                "category": "XSS",
                "message": "Unsafe output",
                "fix_plan": "Pseudo-code: escape untrusted output before rendering and add an XSS regression test.",
            }
        ],
        warnings=["Sample warning"],
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        severity_gate="P1",
        duration_ms=1234,
        deterministic_count=1,
        llm_count=2,
        dedupe_key="dedupe-123456",
        llm_engine="openai",
        llm_model="gpt-4o",
        actual_cost_usd=0.05,
        head_sha="deadbeef",
        server_url="https://github.com",
    )

    assert MARKER_PREFIX in body
    assert "<!-- sentinelayer:omar-gate:v1:acme/demo:42 -->" in body
    assert "Cost (est.):** `$0.0032`" in body
    assert "**Fix:**" in body
    assert "Apply Fix:** Coming soon." in body


def test_comment_contains_provider_specific_marker_when_tagged() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url=None,
        estimated_cost_usd=0.0032,
        version="1.2.0",
        comment_tag="gemini",
    )
    assert "<!-- sentinelayer:omar-gate:v1:gemini:acme/demo:42 -->" in body


def test_comment_contains_all_sections() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url="https://example.com/artifacts",
        estimated_cost_usd=1.23,
        version="1.2.0",
        findings=[
            {
                "severity": "P1",
                "file_path": "app.py",
                "line_start": 10,
                "category": "XSS",
                "message": "Unsafe output",
                "fix_plan": "Pseudo-code: escape untrusted output before rendering.",
            }
        ],
        warnings=None,
        scan_mode="pr-diff",
        policy_pack="omar",
        policy_pack_version="v1",
        severity_gate="P1",
        duration_ms=1234,
        deterministic_count=1,
        llm_count=2,
        dedupe_key="dedupe-123456",
    )

    assert "| Severity | Count | Blocks Merge? |" in body
    assert "### Next Steps" in body
    assert "Top Findings" in body
    assert "**Fix:**" in body
    assert "run_id=run-abcd" in body
    assert "Artifacts & Full Report" in body


def test_comment_footer_shows_llm_model() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url=None,
        estimated_cost_usd=0.05,
        version="1.2.0",
        deterministic_count=10,
        llm_count=3,
        dedupe_key="dedupe-123456",
        llm_engine="openai",
        llm_model="gpt-4o",
    )

    assert "**LLM:** `openai` (`gpt-4o`)" in body
    assert "raw_findings(det=10, llm=3)" in body


def test_comment_footer_default_model_none() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url=None,
        estimated_cost_usd=None,
        version="1.2.0",
    )

    assert "**LLM:** `disabled` (`n/a`)" in body


def test_comment_renders_codebase_synopsis() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url=None,
        estimated_cost_usd=0.01,
        version="1.2.0",
        codebase_snapshot={
            "stats": {"in_scope_files": 10, "source_loc_total": 1000},
            "languages": [{"language": "python", "files": 8, "loc": 900}],
            "hotspots": [],
        },
        codebase_synopsis="README: Deterministic gate for CI pipelines.",
    )

    assert "Codebase Synopsis" in body
    assert "README: Deterministic gate for CI pipelines." in body


def test_comment_redacts_provider_error_details() -> None:
    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-abcdef123456",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url=None,
        estimated_cost_usd=0.01,
        version="1.2.0",
        findings=[
            {
                "severity": "P0",
                "file_path": "<system>",
                "line_start": 0,
                "category": "LLM Failure",
                "message": (
                    "".join((
                        'LLM analysis failed: 403 PERMISSION_DENIED consumer projects/123456789012 with key AI',
                        'zaSyDUMMYDUMMYDUMMYDUMMYDUMMY.',
                    ))
                ),
                "fix_plan": "Retry once provider capacity is healthy.",
            }
        ],
        warnings=[
            "".join(('Fallback failed for project_id=my-prod-project token=sk', '-testtesttesttest'))
        ],
        head_sha="deadbeef",
    )

    assert "PERMISSION&#95;DENIED" in body
    assert "123456789012" not in body
    assert "my-prod-project" not in body
    assert "".join(('AI', 'za')) not in body
    assert "".join(('sk', '-testtesttesttest')) not in body
    assert "&#91;redacted&#45;provider&#45;id&#93;" in body


def test_comment_neutralizes_untrusted_finding_markdown_without_mutation() -> None:
    findings = [
        {
            "severity": "P1",
            "file_path": "app.py",
            "line_start": 10,
            "category": "auth\n## forged category",
            "message": "</details>\r\n# forged [click](https://evil.test)\x00\u202e",
            "recommendation": (
                "Use [patch](javascript:alert(1))\n"
                "<details><summary>forged recommendation</summary>"
            ),
            "fix_plan": "",
        }
    ]
    original = deepcopy(findings)

    body = render_pr_comment(
        result=_gate_result(),
        run_id="run-boundary",
        repo_full_name="acme/demo",
        pr_number=42,
        dashboard_url=None,
        artifacts_url=None,
        estimated_cost_usd=None,
        version="1.2.0",
        findings=findings,
        head_sha="deadbeef",
    )

    assert findings == original
    assert body.count("<details>") == 2
    assert body.count("</details>") == 2
    assert "\n## forged category" not in body
    assert "\n# forged" not in body
    assert "[click](" not in body
    assert "[patch](" not in body
    assert "<summary>forged recommendation" not in body
    assert "\x00" not in body
    assert "\u202e" not in body
    assert "auth &#35;&#35; forged category" in body
    assert "&#60;&#47;details&#62;" in body
    assert "&#91;click&#93;&#40;https&#58;&#47;&#47;evil&#46;test&#41;" in body
