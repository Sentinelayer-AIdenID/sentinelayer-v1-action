from __future__ import annotations

import logging
import re

import httpx

logger = logging.getLogger(__name__)

SENTINELAYER_API = "https://api.sentinelayer.com"


async def fetch_spec_context(
    spec_hash: str,
    sentinelayer_token: str = "",
    oidc_token: str = "",
) -> dict | None:
    """
    Fetch compact spec context from Sentinelayer API.

    Returns None when the context is unavailable.
    This call must remain non-blocking for CI runs.
    """
    normalized_hash = str(spec_hash or "").strip().lower()
    if not normalized_hash or not re.fullmatch(r"[0-9a-f]{64}", normalized_hash):
        return None

    headers: dict[str, str] = {}
    if sentinelayer_token:
        headers["Authorization"] = f"Bearer {sentinelayer_token}"
    elif oidc_token:
        headers["Authorization"] = f"Bearer {oidc_token}"
    else:
        logger.info("No auth token for spec context fetch; skipping")
        return None

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"{SENTINELAYER_API}/api/v1/specs/context/{normalized_hash}",
                headers=headers,
            )

        if response.status_code == 200:
            return response.json()
        if response.status_code == 404:
            logger.info("Spec context not found for hash %s", normalized_hash[:12])
            return None
        logger.warning("Spec context fetch failed: %d", response.status_code)
        return None
    except Exception:
        logger.warning("Spec context fetch error (non-blocking)", exc_info=True)
        return None
