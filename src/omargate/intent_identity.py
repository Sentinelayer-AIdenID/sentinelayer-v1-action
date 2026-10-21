"""Public trace labels for a privately configured provider pin."""
from __future__ import annotations

import hashlib


def intent_model_reference(pin: str) -> str:
    if not pin:
        return "intent-model:unknown"
    return "intent-model:" + hashlib.sha256(pin.encode("utf-8")).hexdigest()[:16]


def redact_intent_pin(value, pin: str):
    """Redact echoed pin text, including source/policy/usage metadata."""
    if not pin:
        return value
    if isinstance(value, str):
        return value.replace(pin, intent_model_reference(pin))
    if isinstance(value, dict):
        return {redact_intent_pin(key, pin): redact_intent_pin(item, pin) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_intent_pin(item, pin) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_intent_pin(item, pin) for item in value)
    return value
