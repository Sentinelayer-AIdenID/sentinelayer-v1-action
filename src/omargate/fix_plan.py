from __future__ import annotations

from typing import Any

_DEFAULT_FIX_PLAN = (
    "Pseudo-code: locate the affected code path, replace the unsafe pattern with a safe "
    "implementation, add a regression test that fails before and passes after the change, "
    "and verify in CI."
)


def _normalize_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return " ".join(text.split())


def _truncate(text: str, max_chars: int = 600) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def ensure_fix_plan(
    *,
    fix_plan: Any = "",
    recommendation: Any = "",
    message: Any = "",
) -> str:
    """
    Ensure every finding has an actionable fix plan.

    Priority:
    1. Explicit fix_plan from scanner/LLM
    2. recommendation fallback
    3. message-derived generic pseudo-code fallback
    """
    explicit = _normalize_text(fix_plan)
    if explicit:
        return _truncate(explicit)

    rec = _normalize_text(recommendation)
    if rec:
        if rec.lower().startswith("pseudo-code:"):
            return _truncate(rec)
        return _truncate(f"Pseudo-code: {rec}")

    msg = _normalize_text(message)
    if msg:
        return _truncate(
            "Pseudo-code: reproduce the issue at this location, implement the minimal safe "
            f"fix for '{msg}', and add a regression test to lock in the behavior."
        )

    return _DEFAULT_FIX_PLAN
