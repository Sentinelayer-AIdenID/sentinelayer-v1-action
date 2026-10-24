"""Telemetry package for Sentinelayer."""

from .collector import TelemetryCollector
from .consent import (
    ConsentConfig,
    TelemetryTier,
    get_max_tier,
    should_upload_tier,
    validate_payload_tier,
)
from .schemas import (
    build_tier1_payload,
    build_tier2_payload,
    build_tier3_manifest,
    findings_to_summary,
)
from .uploader import fetch_oidc_token, upload_artifacts, upload_telemetry

__all__ = [
    "ConsentConfig",
    "TelemetryCollector",
    "TelemetryTier",
    "build_tier1_payload",
    "build_tier2_payload",
    "build_tier3_manifest",
    "fetch_oidc_token",
    "findings_to_summary",
    "get_max_tier",
    "should_upload_tier",
    "upload_artifacts",
    "upload_telemetry",
    "validate_payload_tier",
]
