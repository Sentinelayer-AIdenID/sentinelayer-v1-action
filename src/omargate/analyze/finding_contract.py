from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

_REQUIRED_STRING_FIELDS = {"severity", "category", "file_path", "message"}
_REQUIRED_FIELDS = _REQUIRED_STRING_FIELDS | {"line_start"}
_OPTIONAL_STRING_FIELDS = {
    "evidence_snippet",
    "fix_plan",
    "impact",
    "provenance_tag",
    "recommendation",
    "source_agent",
    "verification",
}
_OPTIONAL_FIELDS = _OPTIONAL_STRING_FIELDS | {"confidence", "line_end"}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | _OPTIONAL_FIELDS
_VALID_SEVERITIES = {"P0", "P1", "P2", "P3", "P4"}
_FULL_CODE_FENCE = re.compile(
    r"\A```(?:json|jsonl)?[ \t]*\r?\n(?P<body>.*?)\r?\n?```[ \t]*\Z",
    re.DOTALL,
)


@dataclass(frozen=True)
class FindingPayload:
    findings: list[dict[str, Any]]
    parse_errors: list[str]
    no_findings_reported: bool


class _StrictJSONError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise _StrictJSONError(f"Duplicate key: {key}")
        parsed[key] = value
    return parsed


def _reject_non_finite_constant(value: str) -> None:
    raise _StrictJSONError(f"Non-finite number: {value}")


def _strict_json_loads(value: str) -> Any:
    try:
        return json.loads(
            value,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except (ValueError, RecursionError) as exc:
        raise _StrictJSONError(str(exc)) from exc


def _extract_exact_code_fence(text: str) -> str:
    stripped = text.strip()
    match = _FULL_CODE_FENCE.fullmatch(stripped)
    if match is None:
        return stripped
    return match.group("body").strip()


def _is_clean_sentinel(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"no_findings"}
        and value["no_findings"] is True
    )


def _validate_finding(value: Any) -> str | None:
    if not isinstance(value, dict):
        return "Not an object"

    missing = sorted(_REQUIRED_FIELDS - set(value))
    if missing:
        return f"Missing required fields: {', '.join(missing)}"

    unknown = sorted(set(value) - _ALLOWED_FIELDS)
    if unknown:
        return f"Unknown fields: {', '.join(unknown)}"

    for field in sorted(_REQUIRED_STRING_FIELDS):
        field_value = value[field]
        if not isinstance(field_value, str) or not field_value.strip():
            return f"{field} must be a non-empty string"

    if value["severity"] not in _VALID_SEVERITIES:
        return "severity must be one of P0, P1, P2, P3, or P4"

    line_start = value["line_start"]
    if type(line_start) is not int or line_start <= 0:
        return "line_start must be a positive integer"

    if "line_end" in value:
        line_end = value["line_end"]
        if type(line_end) is not int or line_end < line_start:
            return "line_end must be an integer greater than or equal to line_start"

    if "confidence" in value:
        confidence = value["confidence"]
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or (isinstance(confidence, float) and not math.isfinite(confidence))
            or not 0 <= confidence <= 1
        ):
            return "confidence must be a finite number between 0 and 1"

    for field in sorted(_OPTIONAL_STRING_FIELDS):
        if field in value and not isinstance(value[field], str):
            return f"{field} must be a string"

    return None


def _parse_loaded_value(value: Any) -> FindingPayload:
    if _is_clean_sentinel(value):
        return FindingPayload([], [], True)

    if isinstance(value, dict):
        error = _validate_finding(value)
        if error is not None:
            return FindingPayload([], [f"Object: {error}"], False)
        return FindingPayload([value], [], False)

    if isinstance(value, list):
        if not value:
            return FindingPayload(
                [],
                ['Array: Empty; use exactly {"no_findings": true} for a clean result'],
                False,
            )

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        for index, item in enumerate(value, start=1):
            if _is_clean_sentinel(item):
                errors.append(
                    f"Item {index}: Clean sentinel is only valid as the exact top-level object "
                    '{"no_findings": true}'
                )
                continue
            error = _validate_finding(item)
            if error is not None:
                errors.append(f"Item {index}: {error}")
                continue
            findings.append(item)
        return FindingPayload(findings, errors, False)

    return FindingPayload(
        [],
        ["Top level must be a finding object, an array of findings, or JSONL findings"],
        False,
    )


def _parse_jsonl(content: str) -> FindingPayload:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = _strict_json_loads(stripped)
        except _StrictJSONError as exc:
            errors.append(f"Line {line_number}: Invalid JSON - {exc}")
            continue

        if _is_clean_sentinel(item):
            errors.append(
                f"Line {line_number}: Clean sentinel is only valid as the exact top-level "
                'object {"no_findings": true}'
            )
            continue

        error = _validate_finding(item)
        if error is not None:
            errors.append(f"Line {line_number}: {error}")
            continue
        findings.append(item)

    if not findings and not errors:
        errors.append("Empty response")

    return FindingPayload(findings, errors, False)


def parse_finding_payload(text: str) -> FindingPayload:
    """
    Parse one governed LLM response.

    Accepted shapes are a finding object, an array of findings, JSONL findings,
    or the exact clean sentinel ``{"no_findings": true}``. A markdown code fence
    is unwrapped only when it encloses the entire response.
    """
    content = _extract_exact_code_fence(text or "")
    if not content:
        return FindingPayload([], ["Empty response"], False)

    try:
        loaded = _strict_json_loads(content)
    except _StrictJSONError:
        return _parse_jsonl(content)

    return _parse_loaded_value(loaded)
