"""Published-rate estimates, never provider billing records. Unknown stays null."""
from __future__ import annotations

from decimal import Decimal
import re

PRICE_DATE = "2026-10-20"
OPENAI_SOURCE = "https://developers.openai.com/api/docs/pricing"
JEV_SOURCE = "https://docs.typesafe.ai/models"
RATES = {
    "gpt-6-luna": ("0.10", "0.01", "0.50"),
    "gpt-6.1-sol": ("2", "0.10", "10"),
    "gpt-6-sol": ("2", "0.20", "10"),
}


def _count(value) -> bool:
    return type(value) is int and value >= 0


def estimate_usage(provider: str, model: str, usage: dict | None) -> dict:
    usage = usage or {}
    record = {
        "provider": provider, "model": model if re.fullmatch(r"(?:gpt-|jev-)[a-zA-Z0-9.-]{1,100}", model) else "unrecognized", "kind": "estimated_not_billed",
        "price_date": PRICE_DATE,
        "price_source": JEV_SOURCE if provider == "typesafe" else OPENAI_SOURCE,
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "estimated_usd": None,
        "assumptions": "standard tier; token rates only; excludes cache-write and other fees; reasoning included in output tokens",
    }
    n_in, n_out = record["input_tokens"], record["output_tokens"]
    if not _count(n_in) or not _count(n_out):
        record["status"] = "usage_unknown"
        return record
    if provider == "typesafe" and model in {"jev-1.13.0", "jev-1.14.0"}:
        rates = (Decimal(".042"), Decimal(0), Decimal(0))
        cached = 0
    else:
        base = next((key for key in RATES if model == key or re.fullmatch(re.escape(key) + r"-\d{4}-\d{2}-\d{2}", model)), None)
        if provider != "openai" or base is None:
            record["status"] = "price_unknown"
            return record
        details = usage.get("input_tokens_details") or {}
        cached = details.get("cached_tokens", 0) if isinstance(details, dict) else None
        if not _count(cached) or cached > n_in:
            record["status"] = "usage_invalid"
            return record
        rates = tuple(Decimal(value) for value in RATES[base])
        if n_in > 272000:
            rates = (rates[0] * 2, rates[1] * 2, rates[2] * Decimal("1.5"))
    record.update({
        "cached_input_tokens": cached,
        "rates_per_million": [str(rate) for rate in rates],
        "estimated_usd": float(((n_in - cached) * rates[0] + cached * rates[1] + n_out * rates[2]) / 1_000_000),
        "status": "estimated",
    })
    return record


def cost_ledger(records: list[dict]) -> dict:
    known = sum(Decimal(str(row["estimated_usd"])) for row in records if row.get("estimated_usd") is not None)
    complete = bool(records) and all(row.get("estimated_usd") is not None for row in records)
    return {"schema": "omargate.cost-ledger.v1", "kind": "estimated_not_billed",
            "calls": records, "known_estimated_usd": float(known),
            "estimated_total_usd": float(known) if complete else None,
            "complete": complete}


def render_cost_ledger(ledger: dict | None) -> list[str]:
    if not ledger:
        return []
    from ..redaction import sanitize_untrusted_markdown_scalar
    lines = ["", "### Model cost estimates", "",
             "Published token-rate estimates, not billed charges. Unknown usage stays unknown.", "",
             "| Provider / model | Estimated USD |", "|---|---:|"]
    for row in ledger.get("calls", []):
        name = sanitize_untrusted_markdown_scalar(f"{row['provider']} / {row['model']}")
        amount = row.get("estimated_usd")
        lines.append(f"| {name} | {'unknown' if amount is None else f'${amount:.8f}'} |")
    total = ledger.get("estimated_total_usd")
    lines.extend(["", f"Total estimate: {'unknown (partial usage)' if total is None else f'${total:.8f}'}. Excludes cache-write and non-token fees.", ""])
    return lines
