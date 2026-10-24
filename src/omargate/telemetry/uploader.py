from __future__ import annotations

import asyncio
import os
from pathlib import Path

import httpx

from ..logging import OmarLogger

SENTINELAYER_API_URL = "https://api.sentinelayer.com"
UPLOAD_TIMEOUT_SECONDS = 10
MAX_RETRIES = 2
BACKOFF_SECONDS = 1


async def upload_telemetry(
    payload: dict,
    sentinelayer_token: str | None = None,
    oidc_token: str | None = None,
    logger: OmarLogger | None = None,
) -> bool:
    """
    Upload telemetry to Sentinelayer API.

    Best-effort: failures are logged but don't affect gate.

    Auth priority:
    1. OIDC token (from GitHub Actions OIDC)
    2. Sentinelayer API token
    3. Anonymous (Tier 1 only)
    """
    headers = {"Content-Type": "application/json"}

    tier = payload.get("tier", 1)

    # Prefer ephemeral OIDC for all tiers when available so server-side
    # telemetry can attribute runs to the authenticated actor without
    # requiring Tier 2 metadata.  Fall back to sentinelayer_token for
    # any tier so the API can still attribute the run when OIDC is
    # unavailable.
    if oidc_token:
        headers["Authorization"] = f"Bearer {oidc_token}"
    elif sentinelayer_token:
        headers["Authorization"] = f"Bearer {sentinelayer_token}"
    endpoint = f"{SENTINELAYER_API_URL}/api/v1/telemetry"

    for attempt in range(MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=UPLOAD_TIMEOUT_SECONDS) as client:
                response = await client.post(endpoint, json=payload, headers=headers)

            if response.status_code == 200:
                if logger:
                    logger.info(
                        "Telemetry uploaded",
                        tier=tier,
                        status=response.status_code,
                    )
                return True

            if response.status_code == 429:
                if logger:
                    logger.warning("Telemetry rate limited", tier=tier)
                return False

            if logger:
                logger.warning(
                    "Telemetry upload failed",
                    tier=tier,
                    status=response.status_code,
                    attempt=attempt + 1,
                )
        except httpx.TimeoutException:
            if logger:
                logger.warning(
                    "Telemetry upload timeout",
                    tier=tier,
                    attempt=attempt + 1,
                )
        except Exception as exc:
            if logger:
                logger.warning("Telemetry upload error", tier=tier, error=str(exc))

        if attempt < MAX_RETRIES - 1:
            await asyncio.sleep(BACKOFF_SECONDS * (attempt + 1))

    return False


async def upload_artifacts(
    run_dir: Path,
    manifest: dict,
    sentinelayer_token: str,
    logger: OmarLogger | None = None,
) -> bool:
    """
    Upload Tier 3 artifacts to Sentinelayer S3.

    Uses presigned URLs from API.
    """
    if not sentinelayer_token:
        if logger:
            logger.warning("Artifact upload requires sentinelayer_token")
        return False

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{SENTINELAYER_API_URL}/api/v1/artifacts/upload-urls",
                json={
                    "run_id": manifest.get("run_id"),
                    "objects": [obj.get("name") for obj in manifest.get("objects", [])],
                },
                headers={"Authorization": f"Bearer {sentinelayer_token}"},
            )

            if response.status_code != 200:
                if logger:
                    logger.warning(
                        "Failed to get upload URLs",
                        status=response.status_code,
                    )
                return False

            urls = response.json().get("urls", {})

        uploaded_count = 0
        for obj in manifest.get("objects", []):
            name = obj.get("name")
            if not name:
                continue

            file_path = run_dir / name
            if not file_path.exists():
                continue

            upload_url = urls.get(name)
            if not upload_url:
                continue

            async with httpx.AsyncClient(timeout=60) as client:
                with open(file_path, "rb") as f:
                    put_response = await client.put(
                        upload_url,
                        content=f.read(),
                        headers={
                            "Content-Type": obj.get(
                                "content_type", "application/octet-stream"
                            )
                        },
                    )

            if put_response.status_code not in (200, 201, 204):
                if logger:
                    logger.warning(
                        "Artifact upload failed",
                        file=name,
                        status=put_response.status_code,
                    )
                return False

            uploaded_count += 1

        if logger:
            logger.info("Artifacts uploaded", count=uploaded_count)
        return True
    except Exception as exc:
        if logger:
            logger.warning("Artifact upload error", error=str(exc))
        return False


async def fetch_oidc_token(logger: OmarLogger | None = None) -> str | None:
    """Fetch GitHub Actions OIDC token if available."""
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not request_url or not request_token:
        return None

    audience = (os.environ.get("SENTINELAYER_OIDC_AUDIENCE") or "sentinelayer").strip()
    if audience:
        separator = "&" if "?" in request_url else "?"
        request_url = f"{request_url}{separator}audience={audience}"

    try:
        async with httpx.AsyncClient(timeout=UPLOAD_TIMEOUT_SECONDS) as client:
            response = await client.get(
                request_url,
                headers={
                    "Authorization": f"Bearer {request_token}",
                    "Accept": "application/json",
                },
            )
        if response.status_code != 200:
            if logger:
                logger.warning("OIDC token request failed", status=response.status_code)
            return None
        payload = response.json()
        token = payload.get("value") or payload.get("id_token")
        if not token and logger:
            logger.warning("OIDC token response missing value")
        return token
    except Exception as exc:
        if logger:
            logger.warning("OIDC token request error", error=str(exc))
        return None
