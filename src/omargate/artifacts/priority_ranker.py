from __future__ import annotations

import fnmatch

CATEGORIES: dict[str, dict[str, object]] = {
    "auth": {
        "icon": "🔐",
        "name": "Auth & Session",
        "keywords": [
            "auth",
            "login",
            "password",
            "session",
            "jwt",
            "oauth",
            "credential",
            "token",
        ],
        "globs": ["**/auth/**", "**/session/**", "**/login/**"],
        "commands": ['rg -n "password|credential|token|session" .'],
    },
    "payment": {
        "icon": "💳",
        "name": "Payment & Billing",
        "keywords": ["stripe", "payment", "billing", "invoice", "subscription", "charge"],
        "globs": ["**/billing/**", "**/payment/**", "**/stripe/**"],
        "commands": ['rg -n "stripe|payment|billing|charge" .'],
    },
    "webhook": {
        "icon": "🔗",
        "name": "Webhooks & Callbacks",
        "keywords": ["webhook", "callback", "hook", "handler"],
        "globs": ["**/webhook*/**", "**/callback*/**"],
        "commands": ['rg -n "webhook|signature|verify" .'],
    },
    "database": {
        "icon": "🗄️",
        "name": "Database & Queries",
        "keywords": ["query", "sql", "database", "migration", "schema", "prisma"],
        "globs": ["**/db/**", "**/database/**", "**/migrations/**"],
        "commands": ['rg -n "query|sql|execute|rawQuery" .'],
    },
    "crypto": {
        "icon": "🔑",
        "name": "Crypto & Secrets",
        "keywords": ["encrypt", "decrypt", "hash", "sign", "secret", "key", "crypto"],
        "globs": ["**/crypto/**", "**/secrets/**"],
        "commands": ['rg -n "encrypt|decrypt|hash|sign" .'],
    },
    "infrastructure": {
        "icon": "🔧",
        "name": "Infrastructure & CI/CD",
        "keywords": ["docker", "kubernetes", "terraform", "aws", "deploy", "ci", "pipeline"],
        "globs": ["**/.github/**", "**/terraform/**", "**/k8s/**", "Dockerfile*"],
        "commands": ['rg -n "docker|kubernetes|terraform" .'],
    },
}

SEVERITY_SCORE = {"P0": 20, "P1": 10, "P2": 3, "P3": 1, "P4": 0}
CATEGORY_SCORE = {
    "auth": 5,
    "payment": 5,
    "crypto": 4,
    "webhook": 4,
    "database": 3,
    "infrastructure": 3,
}


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lower()


def detect_categories(path: str, hotspots: dict | None = None) -> list[str]:
    """Detect category keys for a path using globs, keywords, and hotspot lists."""
    if not path:
        return []

    normalized = _normalize_path(path)
    hotspots = hotspots or {}
    detected: list[str] = []

    for key, config in CATEGORIES.items():
        if _matches_category(normalized, key, config, hotspots):
            detected.append(key)

    return detected


def _matches_category(
    normalized_path: str,
    key: str,
    config: dict[str, object],
    hotspots: dict,
) -> bool:
    hotspot_paths = hotspots.get(key) or []
    for hotspot_path in hotspot_paths:
        if _normalize_path(str(hotspot_path)) == normalized_path:
            return True

    for pattern in config.get("globs", []):
        if fnmatch.fnmatch(normalized_path, _normalize_path(str(pattern))):
            return True

    for keyword in config.get("keywords", []):
        if str(keyword).lower() in normalized_path:
            return True

    return False


def calculate_priority(
    file_path: str,
    findings: list[dict],
    categories: list[str],
    loc: int,
    file_findings: list[dict] | None = None,
) -> float:
    """
    Priority = severity_sum + category_weight + complexity_factor

    - severity_sum: Sum of SEVERITY_SCORE for findings in this file
    - category_weight: Max category score for detected categories
    - complexity_factor: min(LOC / 100, 5) — caps at 5 points
    """
    if file_findings is None:
        normalized = _normalize_path(file_path)
        file_findings = [
            f
            for f in findings
            if _normalize_path(str(f.get("file_path", ""))) == normalized
        ]

    severity_sum = sum(
        SEVERITY_SCORE.get(str(f.get("severity", "")), 0) for f in file_findings
    )

    category_weight = max((CATEGORY_SCORE.get(c, 1) for c in categories), default=1)

    complexity = min((loc or 0) / 100.0, 5)

    return float(severity_sum + category_weight + complexity)


def rank_files(findings: list[dict], ingest: dict, top_n: int = 10) -> list[dict]:
    """Return top N priority files with ranking details."""
    file_scores: dict[str, dict] = {}
    hotspots = ingest.get("hotspots", {}) if isinstance(ingest, dict) else {}

    findings_by_path: dict[str, list[dict]] = {}
    for finding in findings:
        path = finding.get("file_path")
        if not path:
            continue
        normalized = _normalize_path(str(path))
        findings_by_path.setdefault(normalized, []).append(finding)

    for file_info in ingest.get("files", []) if isinstance(ingest, dict) else []:
        path = file_info.get("path")
        if not path:
            continue
        normalized = _normalize_path(str(path))
        loc = int(file_info.get("lines", 0) or 0)
        categories = detect_categories(str(path), hotspots)
        file_findings = findings_by_path.get(normalized, [])

        if not file_findings and not categories:
            continue

        score = calculate_priority(
            str(path),
            findings,
            categories,
            loc,
            file_findings=file_findings,
        )

        if score > 0:
            file_scores[str(path)] = {
                "path": str(path),
                "score": score,
                "categories": categories,
                "findings": file_findings,
                "loc": loc,
            }

    ranked = sorted(file_scores.values(), key=lambda x: x["score"], reverse=True)
    return ranked[: max(int(top_n), 0)]
