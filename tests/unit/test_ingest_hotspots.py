from __future__ import annotations

from omargate.ingest.hotspot_detector import (
    HOTSPOT_PATTERNS,
    build_hotspot_map,
    hotspot_categories_for_path,
)


def test_hotspot_categories_for_path() -> None:
    assert "auth" in hotspot_categories_for_path("src/auth/session.py")
    assert "payment" in hotspot_categories_for_path("src/billing/stripe.ts")
    assert "infrastructure" in hotspot_categories_for_path("infra/terraform/main.tf")
    assert "database" in hotspot_categories_for_path("db/migrations/001_init.sql")


def test_build_hotspot_map_includes_all_categories() -> None:
    paths = [
        "src/auth/session.py",
        "src/billing/stripe.ts",
        "docs/readme.md",
    ]
    hotspots = build_hotspot_map(paths)
    assert set(hotspots.keys()) == set(HOTSPOT_PATTERNS.keys())
    assert "src/auth/session.py" in hotspots["auth"]
    assert "src/billing/stripe.ts" in hotspots["payment"]
