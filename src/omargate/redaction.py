from __future__ import annotations

import ast
import html
import io
import re
import string
import tokenize
import unicodedata
from pathlib import PurePosixPath

_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:key|api_key|access_token|token|signature)=)"
    r"(?!\[redacted(?:-secret|-provider-id)?\](?:[&#\s]|$))([^&#\s]+)"
)
_JSON_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<prefix>["']?
      (?:api[_-]?key|access[_-]?token|token|authorization|x[-_]?api[-_]?key|
         secret[_-]?key|signing[_-]?key|private[_-]?key|db[_-]?pass|
         password|passwd|pwd|client[_-]?secret|secret[_-]?access[_-]?key)
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
      [?&](?:key|api[_-]?key|access[_-]?token|token|signature|secret)=[^&#\s]+
    )
    """
)
_SOURCE_FIELD_RE = re.compile(
    r'''(?<![\w-])(?P<quote>["']?)(?P<name>[A-Za-z_][A-Za-z0-9_-]*)(?P=quote)[ \t]*(?P<op>[:=])(?!=)'''
)
_SOURCE_ANNOTATION_RE = re.compile(
    r"(?:Optional\[(?:str|string|String)\]|(?:str|string|String)(?:[ \t]*\|[ \t]*(?:None|null|undefined))?)"
    r"(?:[ \t]*=[ \t]*(?:None|null|false|False|true|True))?[ \t]*(?:[,);]|$)"
)
_SOURCE_PLACEHOLDERS = frozenset({
    "none", "null", "false", "true", "example", "sample", "dummy", "placeholder",
    "redacted", "changeme", "replace_me", "replace-me", "[redacted]", "[redacted-secret]",
    "[redacted-provider-id]", "your github token", "your token", "...", "…",
})
_CODE_SOURCE_SUFFIXES = frozenset({".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".swift", ".go", ".rs", ".java", ".cs"})
_TYPE_VALUE_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.\[\], |<>?]{0,200}[ \t]*=(?!=)[ \t]*")


def _credential_field(name: str) -> bool:
    # Split camelCase and acronym boundaries before losing case information.
    # Fixed-width lookarounds avoid retrying a greedy uppercase prefix at every
    # position of an attacker-controlled identifier.
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", name).lower().replace("-", "_")
    compact = name.replace("_", "")
    return (compact.endswith(("secretaccesskey", "apikey", "accesstoken", "authtoken",
                              "clientsecret", "privatekey", "secretkey", "signingkey", "webhooksecret",
                              "encryptionkey", "stripekey", "token", "password", "passwd", "pwd",
                              "credential", "secret", "authorization"))
            or name.split("_")[-1] in {"secret", "token", "password", "passwd", "pwd", "credential", "pass", "authorization"})


def _code_reference(value: str) -> bool:
    """Recognize bounded reference expressions without evaluating repository code.

    Literal credentials wrapped in calls/fallbacks remain unsafe. Only the first
    selector of a get/getenv lookup may be a credential-field/env-variable name;
    later/default arguments are inspected normally. Data files never use this.
    """
    if len(value) > 16_384:
        return False
    depth = 0
    end = len(value)
    try:
        for token in tokenize.generate_tokens(io.StringIO(value).readline):
            if token.type == tokenize.COMMENT:
                end = token.start[1]
                break
            if token.type != tokenize.OP:
                continue
            if token.string in {",", ";"} and depth == 0:
                end = token.start[1]
                break
            if token.string in {"(", "[", "{"}:
                depth += 1
            elif token.string in {")", "]", "}"}:
                if depth == 0:
                    end = token.start[1]
                    break
                depth -= 1
        expression = ast.parse(value[:end].strip(), mode="eval").body
    except (SyntaxError, ValueError, RecursionError, tokenize.TokenError, IndentationError):
        return False
    if not isinstance(expression, (ast.Name, ast.Attribute, ast.Subscript, ast.Call, ast.Await)):
        return False
    selectors = set()
    for node in ast.walk(expression):
        if isinstance(node, ast.Call) and node.args:
            function = node.func
            name = function.attr if isinstance(function, ast.Attribute) else function.id if isinstance(function, ast.Name) else ""
            if name in {"get", "getenv", "get_env"}:
                argument = node.args[0]
                if (isinstance(argument, ast.Constant) and isinstance(argument.value, str)
                        and (_credential_field(argument.value) or argument.value.lower() in {"authorization", "session"})):
                    selectors.add(id(argument))
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, str) and _credential_field(node.slice.value):
                selectors.add(id(node.slice))
    for node in ast.walk(expression):
        if isinstance(node, ast.Constant) and id(node) not in selectors:
            value = node.value
            if value is None or value is Ellipsis or isinstance(value, bool) or value == "":
                continue
            # Exact conventional example placeholders carry no credential value.
            if isinstance(value, str) and value.lower() in _SOURCE_PLACEHOLDERS - {"none", "null", "false", "true"}:
                continue
            return False
    return True


def _has_secret_assignment(line: str, *, code_context: bool) -> bool:
    # Match complete identifiers once; retrying a repeated prefix at every
    # underscore caused quadratic work on long ordinary identifiers.
    credential_fields = 0
    for match in _SOURCE_FIELD_RE.finditer(line):
        if not _credential_field(match["name"]):
            continue
        credential_fields += 1
        if credential_fields > 64:
            # Refuse an unusually dense line instead of repeatedly parsing
            # attacker-controlled suffixes. This is incomplete verification,
            # not proof that any particular field contains a credential.
            return True
        tail = line[match.end():].strip()
        if not tail:
            continue
        # A reference-looking value in a comment is still prose/data. Do not
        # turn '# password=literal' into a trusted source reference.
        prefix = line[:match.start()]
        reference_context = code_context and not any(marker in prefix for marker in ("#", "//", "/*"))
        if reference_context and match["op"] == ":" and _SOURCE_ANNOTATION_RE.match(tail):
            continue
        # Only exact conventional placeholders are safe. A literal suffix,
        # fallback expression, dynamic reference or comment credential is not.
        scalar = tail.split("#", 1)[0].strip().strip("`*").strip()
        quoted = len(scalar) >= 2 and scalar[0] in "\"'" and scalar[-1] == scalar[0]
        if quoted:
            scalar = scalar[1:-1]
        placeholders = _SOURCE_PLACEHOLDERS - {"none", "null", "false", "true"} if quoted else _SOURCE_PLACEHOLDERS
        if scalar == "" or scalar.lower() in placeholders:
            continue
        if reference_context:
            assignment = _TYPE_VALUE_ASSIGNMENT_RE.match(tail) if match["op"] == ":" else None
            if _code_reference(tail[assignment.end():] if assignment else tail):
                continue
        return True
    return False
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


def redact_secret_source(value: object, *, file_path: object = "", code_context: bool | None = None) -> tuple[str, bool]:
    """Exclude secret-bearing source lines before they cross a provider boundary.

    Public-error redaction targets diagnostic strings. This stricter source boundary
    deliberately drops complete lines (and complete sensitive files) so surrounding
    syntax cannot reconstruct a credential that spans multiple tokens.
    """

    text = str(value or "")
    if not text:
        return "", False

    exclude_all = is_sensitive_source_path(file_path)
    if code_context is None:
        code_context = PurePosixPath(str(file_path)).suffix.lower() in _CODE_SOURCE_SUFFIXES
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
            or bool(_KEYLIKE_RE.search(detection_line))
            or _has_secret_assignment(detection_line, code_context=code_context)
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


def contains_credential_material(value: object, *, code_context: bool = False) -> bool:
    """Check outbound source without treating public project metadata as a secret.

    Keep the source rules and credential-specific diagnostic backstops together:
    quoted JSON keys and shorter key-like values also need protection. Provider
    project/account identifiers belong to public error sanitization, not this
    source-content decision. A match refuses the request; it never sends a
    redacted subset and calls that a complete review.
    """
    text = str(value or "")
    return redact_secret_source(text, code_context=code_context)[1]


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
