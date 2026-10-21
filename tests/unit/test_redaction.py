from __future__ import annotations

import pytest

from omargate.redaction import (
    redact_secret_source,
    sanitize_public_error,
    sanitize_untrusted_markdown_scalar,
)


def test_sanitize_public_error_redacts_provider_ids_and_keys() -> None:
    raw = (
        "".join((
            "Fallback failed: 403 PERMISSION_DENIED. {'error': {'message': 'API key AI",
            'zaSyDUMMYDUMMYDUMMYDUMMYDUMMY is invalid for consumer projects/123456789012 and proje',
            "ct_id=my-prod-project'}} standalone projects/999999999999 https://example.test/v1?key",
            '=AI',
            'zaSyQUERYDUMMYDUMMYDUMMYDUMMY',
        ))
    )

    sanitized = sanitize_public_error(raw)

    assert "PERMISSION_DENIED" in sanitized
    assert "403" in sanitized
    assert "".join(('AI', 'za')) not in sanitized
    assert "123456789012" not in sanitized
    assert "999999999999" not in sanitized
    assert "my-prod-project" not in sanitized
    assert "projects/[redacted]" in sanitized
    assert "[redacted-provider-id]" in sanitized


def test_sanitize_public_error_keeps_capacity_context() -> None:
    raw = (
        "Primary failed: Error code: 429 - insufficient_quota; "
        "Fallback failed: 403 RESOURCE_EXHAUSTED consumer 987654321 suspended; "
        "retry after provider capacity is restored"
    )

    sanitized = sanitize_public_error(raw)

    assert "Primary failed" in sanitized
    assert "429" in sanitized
    assert "insufficient_quota" in sanitized
    assert "RESOURCE_EXHAUSTED" in sanitized
    assert "provider capacity" in sanitized
    assert "987654321" not in sanitized


def test_sanitize_public_error_redacts_cli_masked_openai_key() -> None:
    raw = "".join(('Incorrect API key provided: sk', '-test-***************lder'))

    sanitized = sanitize_public_error(raw)

    assert "".join(('sk', '-test')) not in sanitized
    assert "[redacted-secret]" in sanitized


@pytest.mark.parametrize(
    "source",
    [
        "# rotated key AKIA" + "1234567890ABCDEF\n",
        "token = low-entropy-but-still-private\n",
        "authorization: Bearer opaque-credential\n",
        'DB_PASSWORD="database-private"\n',
        "AWS_SECRET_ACCESS_KEY=aws-private\n",
        "DATABASE_URL=postgres://dbuser:db-private@db.example.test/app\n",
        'headers = {"Authorization": "Bearer bearer-private"}\n',
        "url = 'https://example.test/?signature=private-value'\n",
        "".join(('-----', 'BEGIN PRIVATE KEY-----\nprivate-body\n-----', 'END PRIVATE KEY-----\n')),
    ],
    ids=[
        "aws-comment",
        "assignment",
        "authorization",
        "db-password",
        "aws-secret-access-key",
        "credentialed-postgres-url",
        "quoted-authorization",
        "query",
        "private-key",
    ],
)
def test_redact_secret_source_excludes_complete_secret_lines(source: str) -> None:
    safe, changed = redact_secret_source(source, file_path="src/config.py")

    assert changed is True
    assert "private" not in safe.lower()
    assert "akia" not in safe.lower()
    assert "opaque-credential" not in safe
    assert safe.count("[secret-bearing source excluded]") >= 1


def test_redact_secret_source_excludes_complete_sensitive_file() -> None:
    source = "ORDINARY_NAME=ordinary-value\nPUBLIC_FLAG=true\n"

    safe, changed = redact_secret_source(source, file_path="deploy/.env.production")

    assert changed is True
    assert "ORDINARY_NAME" not in safe
    assert safe.splitlines() == [
        "[secret-bearing source excluded]",
        "[secret-bearing source excluded]",
    ]


def test_redact_secret_source_leaves_ordinary_source_byte_exact() -> None:
    source = "def add(left, right):\n    return left + right\n"

    safe, changed = redact_secret_source(source, file_path="src/math.py")

    assert changed is False
    assert safe == source


def test_sanitize_public_error_preserves_canonical_redaction_placeholders() -> None:
    raw = (
        'token=[redacted-secret] {"api_key":"[redacted]"} '
        "https://example.test?access_token=[redacted-provider-id]"
    )

    assert sanitize_public_error(raw) == raw


def test_untrusted_markdown_scalar_is_inert_single_line_and_idempotent() -> None:
    raw = (
        "".join(('\r\n# forged [click](javascript:alert(1)) </details><!-- x -->\x00\u202e token=sk', '-testtesttesttest'))
    )

    sanitized = sanitize_untrusted_markdown_scalar(raw)

    assert sanitized == sanitize_untrusted_markdown_scalar(sanitized)
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "\x00" not in sanitized
    assert "\u202e" not in sanitized
    assert "# forged" not in sanitized
    assert "[click](" not in sanitized
    assert "</details>" not in sanitized
    assert "<!--" not in sanitized
    assert "".join(('sk', '-testtesttesttest')) not in sanitized
    assert "&#35;" in sanitized
    assert "&#91;click&#93;&#40;" in sanitized
    assert "&#60;&#47;details&#62;" in sanitized
