from omargate.package.fingerprint import (
    add_fingerprints_to_findings,
    compute_fingerprint,
    normalize_snippet,
)


def test_normalize_removes_line_numbers():
    """Line numbers are stripped from snippets."""
    snippet = "42 | const x = 1;\n43 | const y = 2;"
    normalized = normalize_snippet(snippet)
    assert "42" not in normalized
    assert "43" not in normalized


def test_normalize_collapses_whitespace():
    """Multiple spaces/newlines become single space."""
    snippet = "const   x   =\n\n   1;"
    normalized = normalize_snippet(snippet)
    assert "   " not in normalized
    assert "\n" not in normalized


def test_normalize_removes_comments():
    """Comments are stripped."""
    snippet = "const x = 1; // this is a comment"
    normalized = normalize_snippet(snippet)
    assert "comment" not in normalized


def test_normalize_lowercases():
    """Normalization lowercases text."""
    snippet = "CONST X = 1;"
    normalized = normalize_snippet(snippet)
    assert normalized == "const x = 1;"


def test_fingerprint_stability():
    """Same input produces same fingerprint."""
    fp1 = compute_fingerprint("secrets", "P1", "auth.ts", 42, "api_key = 'xxx'", "1.0")
    fp2 = compute_fingerprint("secrets", "P1", "auth.ts", 42, "api_key = 'xxx'", "1.0")
    assert fp1 == fp2


def test_fingerprint_differs_on_file_change():
    """Different file produces different fingerprint."""
    fp1 = compute_fingerprint("secrets", "P1", "auth.ts", 42, "api_key = 'xxx'", "1.0")
    fp2 = compute_fingerprint("secrets", "P1", "other.ts", 42, "api_key = 'xxx'", "1.0")
    assert fp1 != fp2


def test_fingerprint_differs_on_severity_change():
    """Different severity produces different fingerprint."""
    fp1 = compute_fingerprint("secrets", "P0", "auth.ts", 42, "api_key = 'xxx'", "1.0")
    fp2 = compute_fingerprint("secrets", "P1", "auth.ts", 42, "api_key = 'xxx'", "1.0")
    assert fp1 != fp2


def test_fingerprint_ignores_whitespace_variance():
    """Whitespace differences don't change fingerprint."""
    fp1 = compute_fingerprint("xss", "P1", "app.tsx", 10, "const x = 1;", "1.0")
    fp2 = compute_fingerprint("xss", "P1", "app.tsx", 10, "const   x   =   1;", "1.0")
    assert fp1 == fp2


def test_fingerprint_policy_version_matters():
    """Different policy version produces different fingerprint."""
    fp1 = compute_fingerprint("secrets", "P1", "auth.ts", 42, "api_key = 'xxx'", "1.0")
    fp2 = compute_fingerprint("secrets", "P1", "auth.ts", 42, "api_key = 'xxx'", "2.0")
    assert fp1 != fp2


def test_fingerprint_tenant_salt():
    """Tenant salt isolates fingerprints."""
    fp1 = compute_fingerprint("secrets", "P1", "auth.ts", 42, "api_key = 'xxx'", "1.0", "tenant_a")
    fp2 = compute_fingerprint("secrets", "P1", "auth.ts", 42, "api_key = 'xxx'", "1.0", "tenant_b")
    assert fp1 != fp2


def test_add_fingerprints_to_findings():
    """Fingerprints added to finding dicts."""
    findings = [
        {
            "category": "secrets",
            "severity": "P1",
            "file_path": "auth.ts",
            "line_start": 42,
            "snippet": "key=xxx",
        },
        {
            "category": "xss",
            "severity": "P2",
            "file_path": "app.tsx",
            "line_start": 10,
            "snippet": "innerHTML",
        },
    ]
    result = add_fingerprints_to_findings(findings, "1.0")
    assert all("fingerprint" in f for f in result)
    assert len(result[0]["fingerprint"]) == 32
