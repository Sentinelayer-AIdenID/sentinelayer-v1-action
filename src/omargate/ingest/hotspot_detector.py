from __future__ import annotations

import re
from collections.abc import Iterable

HOTSPOT_PATTERNS: dict[str, list[str]] = {
    "auth": [
        r"auth",
        r"session",
        r"login",
        r"logout",
        r"password",
        r"credential",
        r"token",
        r"jwt",
    ],
    "payment": [
        r"payment",
        r"billing",
        r"stripe",
        r"invoice",
        r"subscription",
        r"charge",
    ],
    "crypto": [
        r"crypto",
        r"encrypt",
        r"decrypt",
        r"hash",
        r"sign",
        r"verify",
        r"secret",
    ],
    "webhook": [
        r"webhook",
        r"callback",
        r"hook",
    ],
    "database": [
        r"migration",
        r"schema",
        r"model",
        r"query",
    ],
    "infrastructure": [
        r"terraform",
        r"\.tf$",
        r"cloudformation",
        r"kubernetes",
        r"k8s",
        r"docker",
    ],
}


_COMPILED_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    category: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for category, patterns in HOTSPOT_PATTERNS.items()
}


def hotspot_categories_for_path(path: str) -> list[str]:
    normalized = path.replace("\\", "/")
    matched: list[str] = []
    for category, patterns in _COMPILED_PATTERNS.items():
        if any(pattern.search(normalized) for pattern in patterns):
            matched.append(category)
    return matched


def build_hotspot_map(paths: Iterable[str]) -> dict[str, list[str]]:
    hotspots: dict[str, list[str]] = {category: [] for category in HOTSPOT_PATTERNS}
    for path in paths:
        for category in hotspot_categories_for_path(path):
            hotspots[category].append(path)
    return hotspots
