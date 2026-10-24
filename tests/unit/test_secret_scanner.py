from __future__ import annotations

from omargate.analyze.deterministic.secret_scanner import (
    calculate_entropy,
    scan_for_secrets,
)


def test_entropy_detection() -> None:
    high_entropy = "aB3$kL9mNpQrStUvWxYz"
    low_entropy = "aaaaaaaaaa"  # 10 identical chars = 0 entropy
    assert calculate_entropy(high_entropy) > 3.5
    assert calculate_entropy(low_entropy) < 1.0


def test_aws_key_detection() -> None:
    prefix = "AK" + "IA" + "XXXX"
    suffix = "A" * 12
    content = 'AWS_KEY = "' + prefix + suffix + '"'
    findings = scan_for_secrets(content, "config.py")
    assert any(finding.pattern_id == "SEC-004" for finding in findings)


def test_github_token_detection() -> None:
    prefix = "gh" + "p_"
    content = 'token = "' + prefix + ("x" * 36) + '"'
    findings = scan_for_secrets(content, "deploy.sh")
    assert any(finding.pattern_id == "SEC-005" for finding in findings)


def test_entropy_scanner_emits_finding() -> None:
    part_a = "Z9xQ1pLm"
    part_b = "N8vR2tYkS3wX"
    content = 'const token = "' + part_a + part_b + '"'
    findings = scan_for_secrets(content, "config.ts")
    entropy_findings = [finding for finding in findings if finding.pattern_id == "SEC-ENTROPY"]
    assert entropy_findings
    assert entropy_findings[0].severity == "P1"
    assert "****" in entropy_findings[0].snippet


def test_entropy_scanner_strong_token_without_context_is_advisory() -> None:
    candidate = "A9mQ2nV5xR7tY9pL3cD6fG1hJ4kN0sW2"
    content = 'const blob = "' + candidate + '"'
    findings = scan_for_secrets(content, "config.ts")
    entropy_findings = [finding for finding in findings if finding.pattern_id == "SEC-ENTROPY"]
    assert entropy_findings
    assert entropy_findings[0].severity == "P2"


def test_entropy_skips_path_template_constants() -> None:
    content = (
        'TEMPLATES = ["docs/templates/ADR_TEMPLATE.md", '
        '"docs/templates/RUNBOOK_TEMPLATE.md"]\n'
    )
    findings = scan_for_secrets(content, "scripts/doc_inventory.py")
    assert not any(f.pattern_id == "SEC-ENTROPY" for f in findings)


def test_entropy_skips_markdown_table_lines() -> None:
    content = "| Incident ID | |\n| --- | --- |\n"
    findings = scan_for_secrets(content, "docs/table.md")
    assert not any(f.pattern_id == "SEC-ENTROPY" for f in findings)


def test_entropy_skips_private_constant_identifiers() -> None:
    content = 'MAX = _VERY_LONG_INTERNAL_CONFIGURATION_CONSTANT_NAME\n'
    findings = scan_for_secrets(content, "src/module.py")
    assert not any(f.pattern_id == "SEC-ENTROPY" for f in findings)


def test_entropy_skips_identifier_assignment_pairs() -> None:
    content = "excerpt = _truncate_to_tokens(excerpt, max_tokens=_MAX_TOKENS)\n"
    findings = scan_for_secrets(content, "src/omargate/ingest/quick_learn.py")
    assert not any(f.pattern_id == "SEC-ENTROPY" for f in findings)
