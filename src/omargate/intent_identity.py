"""Public trace labels for a privately configured provider pin."""
from __future__ import annotations

import hashlib


def intent_model_reference(pin: str) -> str:
    if not pin:
        return "intent-model:unknown"
    return "intent-model:" + hashlib.sha256(pin.encode("utf-8")).hexdigest()[:16]
