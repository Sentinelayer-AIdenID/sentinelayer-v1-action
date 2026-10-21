from __future__ import annotations

import html
import re
from pathlib import PurePosixPath
import string
import unicodedata


_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:key|api_key|access_token|token|signature)=)"
    r"(?!\[redacted(?:-secret|-provider-id)?\](?:[&#\s]|$))([^&#\s]+)"
)
_JSON_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<prefix>["']?
      (?:api[_-]?key|access[_-]?token|token|authorization|x[-_]?api[-_]?key)
      ["']?\s*[:=]\s*["']?
    )
    (?!\[redacted(?:-secret|-provider-id)?\](?:["',\s}\]]|$))
    (?!\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}(?:["',\s}\]]|$))
    (?P<value>[^"',\s}\]]{8,})
    """
)
_KEYLIKE_RE = re.compile(
    r"(?i)\b(?:sk-[A-Za-z0-9_*.-]{8,}|sk-ant-[A-Za-z0-9_*.-]{8,}|"
    r"AIza[0-9A-Za-z_-]{20,}|xai-[A-Za-z0-9_-]{16,}|slrt_v1\.[A-Za-z0-9_.-]+|"
    r"sl_[A-Za-z0-9_-]{16,})\b"
)
_GOOGLE_PROJECT_RESOURCE_RE = re.compile(r"(?i)\bprojects/\d{6,}\b")
_PROVIDER_ID_RE = re.compile(
    r"""(?ix)
    \b(?:
      consumer(?:[\s_-]+project)?|
      project(?:[\s_-]+(?:number|id))?|
      provider[\s_-]+(?:consumer|project|account|tenant)
    )
    (?P<sep>\s*[:=/]\s*|\s+)
    (?P<quote>["']?)
    (?P<value>(?:projects/)?[A-Za-z0-9][A-Za-z0-9_.:-]{5,})
    (?P=quote)
    """
)

_SENSITIVE_SOURCE_NAMES = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "service-account.json",
        "service_account.json",
    }
)
_SENSITIVE_SOURCE_SUFFIXES = (
    ".jks",
    ".key",
    ".kdbx",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
)
_PRIVATE_KEY_BEGIN_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----", re.IGNORECASE
)
_PRIVATE_KEY_END_RE = re.compile(
    r"-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----", re.IGNORECASE
)
_SOURCE_SECRET_LINE_RE = re.compile(
    r"""(?ix)
    (?:
      \bAKIA[0-9A-Z]{16}\b |
      \bgh[pousr]_[A-Za-z0-9_]{20,}\b |
      \bglpat-[A-Za-z0-9_-]{16,}\b |
      \bsk_(?:live|test)_[A-Za-z0-9]{16,}\b |
      \bsk-ant-[A-Za-z0-9_-]{16,}\b |
      \bsk-[A-Za-z0-9_-]{16,}\b |
      \bAIza[0-9A-Za-z_-]{20,}\b |
      \bxox[baprs]-[A-Za-z0-9-]{10,}\b |
      \bslrt_v1\.[A-Za-z0-9_.-]+\b |
      \bsl_[A-Za-z0-9_-]{16,}\b |
      \beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b |
      ["']?authorization["']?\s*[:=]\s*["']?(?:bearer|basic)\s+\S+ |
      \b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|https?)
        ://[^\s/:@]+:[^\s/@]+@ |
      [?&](?:api[_-]?key|access[_-]?token|token|signature|secret)=[^&#\s]+ |
      (?<![A-Za-z0-9])(?:[A-Za-z0-9]+[_-])*
        (?:secret[_-]?access[_-]?key|api[_-]?key|access[_-]?token|
          auth[_-]?token|client[_-]?secret|private[_-]?key|secret|token|
          password|passwd|pwd|credential|webhook[_-]?secret)
        \b\s*[:=]\s*(?!["']?(?:none|null|false|true|
          example|sample|dummy|placeholder|redacted|changeme|replace[_-]?me)\b)\S+
    )
    """
)
_SECRET_SOURCE_MARKER = "[secret-bearing source excluded]"
_SYMBOLIC_SECRET_ASSIGNMENT_RE = re.compile(
    r"""^(?P<prefix>\s*[+-]?\s*(?:export\s+)?[\w.-]+\s*[:=]\s*)
    (?P<quote>["']?)\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}(?P=quote)
    (?P<suffix>[ \t]*(?:\#.*)?)$""",
    re.VERBOSE,
)


def is_sensitive_source_path(file_path: object) -> bool:
    """Return whether a source path conventionally contains credential material."""

    normalized = str(file_path or "").replace("\\", "/").lower().strip("/")
    if not normalized:
        return False
    logical = PurePosixPath(normalized)
    name = logical.name
    parts = logical.parts
    return (
        name in _SENSITIVE_SOURCE_NAMES
        or name.startswith(".env.")
        or name.endswith(_SENSITIVE_SOURCE_SUFFIXES)
        or (".aws" in parts and name == "credentials")
        or ".ssh" in parts
        or name.startswith(("secrets.", "secret."))
    )


def redact_secret_source(value: object, *, file_path: object = "") -> tuple[str, bool]:
    """Exclude secret-bearing source lines before they cross a provider boundary.

    Public-error redaction targets diagnostic strings. This stricter source boundary
    deliberately drops complete lines (and complete sensitive files) so surrounding
    syntax cannot reconstruct a credential that spans multiple tokens.
    """

    text = str(value or "")
    if not text:
        return "", False

    exclude_all = is_sensitive_source_path(file_path)
    private_key_block = False
    redacted = False
    safe_lines: list[str] = []
    for line in text.splitlines(keepends=True):
        begins_private_key = bool(_PRIVATE_KEY_BEGIN_RE.search(line))
        ends_private_key = bool(_PRIVATE_KEY_END_RE.search(line))
        symbolic = _SYMBOLIC_SECRET_ASSIGNMENT_RE.fullmatch(line.rstrip("\r\n"))
        # A whole static GitHub secret reference contains no credential bytes.
        # Replace it only for detection, retaining the original source and its
        # hash. Keep comments visible to the detector; mixed/dynamic values,
        # sensitive files and PEM blocks receive no exemption.
        detection_line = (symbolic["prefix"] + "placeholder" + symbolic["suffix"]) if symbolic else line
        exclude_line = (
            exclude_all
            or private_key_block
            or begins_private_key
            or bool(_SOURCE_SECRET_LINE_RE.search(detection_line))
        )
        if exclude_line:
            newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            safe_lines.append(_SECRET_SOURCE_MARKER + newline)
            redacted = True
        else:
            safe_lines.append(line)
        if begins_private_key:
            private_key_block = True
        if private_key_block and ends_private_key:
            private_key_block = False

    # splitlines(keepends=True) returns no rows only for the empty string handled above.
    return "".join(safe_lines), redacted


def sanitize_public_error(value: object) -> str:
    """Redact provider identifiers and key-like material from public outputs."""

    text = str(value or "")
    if not text:
        return ""

    text = _QUERY_SECRET_RE.sub(r"\1[redacted]", text)
    text = _JSON_SECRET_RE.sub(r"\g<prefix>[redacted]", text)
    text = _KEYLIKE_RE.sub("[redacted-secret]", text)

    def _provider_repl(match: re.Match[str]) -> str:
        prefix = match.group(0)[: match.start("value") - match.start()]
        quote = match.group("quote") or ""
        return f"{prefix}[redacted-provider-id]{quote}"

    text = _PROVIDER_ID_RE.sub(_provider_repl, text)
    return _GOOGLE_PROJECT_RESOURCE_RE.sub("projects/[redacted]", text)


def sanitize_untrusted_markdown_scalar(value: object) -> str:
    """Return inert, single-line text for a Markdown/HTML scalar position.

    Finding prose is stored in its source-bound form and encoded only when it is
    rendered.  Numeric character references preserve the visible punctuation,
    but CommonMark never sees raw heading, link, blockquote, code, table, or HTML
    delimiters.  Decoding once before canonical encoding makes this boundary
    idempotent and closes entity-encoded variants of the same payload.
    """

    text = sanitize_public_error(html.unescape(str(value or "")))
    normalized = "".join(
        " "
        if char.isspace() or unicodedata.category(char) in {"Cc", "Cf", "Cs"}
        else char
        for char in text
    )
    normalized = " ".join(normalized.split())
    return "".join(
        f"&#{ord(char)};" if char in string.punctuation else char
        for char in normalized
    )
