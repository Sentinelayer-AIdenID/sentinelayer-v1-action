from __future__ import annotations

from urllib.parse import quote


def humanize_duration_ms(duration_ms: int | None) -> str:
    if duration_ms is None:
        return "n/a"
    try:
        ms = int(duration_ms)
    except (TypeError, ValueError):
        return "n/a"
    if ms < 0:
        return "n/a"
    if ms < 1000:
        return f"{ms}ms"

    seconds = ms / 1000.0
    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(seconds // 60)
    rem_s = int(round(seconds - minutes * 60))
    if rem_s == 60:
        minutes += 1
        rem_s = 0
    if minutes < 60:
        return f"{minutes}m {rem_s}s"

    hours = minutes // 60
    rem_m = minutes % 60
    return f"{hours}h {rem_m}m"


def format_int(value: int) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def format_usd(cost_usd: float | None) -> str:
    if cost_usd is None:
        return "unknown"
    try:
        value = float(cost_usd)
        if value == 0:
            return "$0.00"
        # Avoid rounding small, non-zero costs to "$0.00".
        if abs(value) < 0.01:
            return f"${value:.4f}"
        return f"${value:.2f}"
    except (TypeError, ValueError):
        return "unknown"


def truncate(text: str, max_len: int) -> str:
    if not text:
        return ""
    if max_len <= 0:
        return ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


def github_blob_url(
    *,
    server_url: str,
    repo_full_name: str,
    head_sha: str,
    path: str,
    line: int | None = None,
) -> str:
    """
    Build a stable GitHub blob URL for a file at a specific commit SHA.

    Note: `path` is URL-encoded to handle spaces and special chars.
    """
    base = (server_url or "https://github.com").rstrip("/")
    safe_path = quote((path or "").lstrip("/"), safe="/")
    url = f"{base}/{repo_full_name}/blob/{head_sha}/{safe_path}"
    if line:
        try:
            url += f"#L{int(line)}"
        except (TypeError, ValueError):
            pass
    return url
