from copy import deepcopy
from pathlib import Path

import pytest

from omargate.artifacts.audit_report import generate_audit_report, write_audit_report


@pytest.fixture
def sample_data():
    return {
        "run_id": "test-run-123",
        "summary": {
            "counts": {"P0": 1, "P1": 2, "P2": 3, "P3": 4, "total": 10},
            "policy_pack": "omar",
            "policy_pack_version": "1.0",
            "dedupe_key": "abc123def456",
            "duration_ms": 5000,
            "stages_completed": ["preflight", "ingest", "scan", "gate"],
            "tool_versions": {"action": "1.2.0"},
            "errors": [],
        },
        "findings": [
            {
                "severity": "P0",
                "category": "Auth Bypass",
                "file_path": "src/auth.ts",
                "line_start": 42,
                "line_end": 50,
                "message": "Missing authentication check",
                "recommendation": "Add auth middleware",
                "fix_plan": "Pseudo-code: enforce auth middleware in the route chain and add unauthorized-access tests.",
                "snippet": "if (user) { ... }",
                "confidence": 0.9,
                "source": "llm",
                "fingerprint": "abc123",
            }
        ],
        "ingest": {
            "stats": {"in_scope_files": 100, "total_lines": 10000},
            "hotspots": {"auth": ["src/auth.ts"], "payment": []},
            "dependencies": {"package_manager": "pnpm"},
        },
        "config": {"severity_gate": "P1"},
    }


def test_report_contains_summary(sample_data):
    """Report includes executive summary."""
    report = generate_audit_report(**sample_data)
    assert "Executive Summary" in report
    assert "P0" in report
    assert "BLOCKED" in report


def test_report_contains_findings(sample_data):
    """Report includes finding details."""
    report = generate_audit_report(**sample_data)
    assert "Auth Bypass" in report
    assert "src/auth.ts" in report
    assert "Missing authentication check" in report
    assert "Fix Plan" in report
    assert "Apply Fix" in report


def test_report_contains_metadata(sample_data):
    """Report includes scan metadata."""
    report = generate_audit_report(**sample_data)
    assert "test-run-123" in report
    assert "omar" in report


def test_report_hides_secret_snippets(sample_data):
    """Snippets for secrets findings are hidden."""
    secret_value = "dummy" + "_value"
    sample_data["findings"][0]["category"] = "secrets"
    sample_data["findings"][0]["snippet"] = "api_key = '" + secret_value + "'"
    report = generate_audit_report(**sample_data)
    assert secret_value not in report


def test_write_audit_report(sample_data, tmp_path: Path):
    """Audit report written to disk."""
    report_path = write_audit_report(tmp_path, **sample_data)
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "Omar Gate Audit Report" in content


def test_report_redacts_provider_error_details(sample_data):
    sample_data["summary"]["errors"] = [
        "Google 403 PERMISSION_DENIED consumer projects/123456789012 key=AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMY"
    ]
    sample_data["findings"][0]["message"] = (
        "LLM failed for project_id=my-prod-project with token sk-testtesttesttest"
    )

    report = generate_audit_report(**sample_data)

    assert "PERMISSION_DENIED" in report
    assert "123456789012" not in report
    assert "my-prod-project" not in report
    assert "AIza" not in report
    assert "sk-testtesttesttest" not in report


def test_report_neutralizes_untrusted_finding_markdown_without_mutation(sample_data):
    finding = sample_data["findings"][0]
    finding["category"] = "auth\n# forged category"
    finding["message"] = "</details>\r\n## forged [click](https://evil.test)\x00\u202e"
    finding["recommendation"] = "Use [patch](javascript:alert(1))\n<details>"
    finding["fix_plan"] = "</details>\n# forged fix <script>alert(1)</script>"
    finding["snippet"] = ""
    original = deepcopy(sample_data["findings"])

    report = generate_audit_report(**sample_data)

    assert sample_data["findings"] == original
    assert "\n# forged category" not in report
    assert "\n## forged" not in report
    assert "\n# forged fix" not in report
    assert "[click](" not in report
    assert "[patch](" not in report
    assert "<details>" not in report
    assert "</details>" not in report
    assert "<script>" not in report
    assert "\x00" not in report
    assert "\u202e" not in report
    assert "auth &#35; forged category" in report
    assert "&#60;&#47;details&#62;" in report
    assert "&#60;script&#62;alert&#40;1&#41;&#60;&#47;script&#62;" in report
