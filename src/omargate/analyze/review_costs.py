"""Published-rate estimates, never provider billing records. Unknown stays null."""
from __future__ import annotations

from decimal import Decimal
import re

from ..intent_identity import intent_model_reference
from .review_cascade import response_model_matches

PRICE_DATE = "2026-10-20"
OPENAI_SOURCE = "https://developers.openai.com/api/docs/pricing"
INTENT_PRICE_SOURCE = "https://docs.typesafe.ai/models"
RATES = {
    "gpt-6-luna": ("0.10", "0.01", "0.50"),
    "gpt-6.1-sol": ("2", "0.10", "10"),
    "gpt-6-sol": ("2", "0.20", "10"),
}
CASCADE_MAX_OUTPUT_TOKENS = 16384
# ContextBuilder budgets approximately four characters per token. The cascade
# also enforces this as a UTF-8 byte ceiling before a paid generator request.
CASCADE_CONTEXT_BYTES_PER_BUDGET_TOKEN = 4


def partition_cost_reservation(context: str, system_prompt: str, *, intent_price_profile: str) -> float | None:
    """Forecast the full escalation envelope, separate from actual paid-call usage.

    UTF-8 bytes conservatively bound source/prompt BPE tokens. Add protocol
    overhead, assume no cache discount, and reserve every possible generator
    tier with its entire output limit. The two intent requests already have
    enforced 24k/48k byte envelope limits. This is a token-rate estimate, never
    a guarantee about the provider's bill or non-token fees.
    """
    return cascade_cost_reservation_bytes(
        len(context.encode("utf-8")), len(system_prompt.encode("utf-8")),
        intent_price_profile=intent_price_profile,
    )


def cascade_cost_reservation_bytes(
    context_bytes: int, system_prompt_bytes: int, *, intent_price_profile: str,
) -> float | None:
    """Reserve every route from bounded byte lengths without allocating a dummy prompt."""
    from .review_cascade import LOW, MID, DEEP
    tokens = context_bytes + system_prompt_bytes + 1024
    predicted = [estimate_usage("openai", route.model,
                 {"input_tokens": tokens, "output_tokens": CASCADE_MAX_OUTPUT_TOKENS})
                 for route in (LOW, MID, DEEP)]
    predicted.append(estimate_usage("typesafe", "reservation-only",
        {"input_tokens": 24_000 + 48_000 + 2048, "output_tokens": 0},
        intent_price_profile=intent_price_profile))
    if any(row["estimated_usd"] is None for row in predicted):
        return None
    return float(sum(Decimal(str(row["estimated_usd"])) for row in predicted))


def _count(value) -> bool:
    return type(value) is int and value >= 0


def estimate_usage(provider: str, model: str, usage: dict | None, *, intent_price_profile: str = "") -> dict:
    usage = usage or {}
    record = {
        "provider": provider,
        "model": intent_model_reference(model) if provider == "typesafe" else (model if re.fullmatch(r"gpt-[a-zA-Z0-9.-]{1,100}", model) else "unrecognized"),
        "kind": "estimated_not_billed",
        "price_date": PRICE_DATE,
        "price_source": INTENT_PRICE_SOURCE if provider == "typesafe" else OPENAI_SOURCE,
        "price_profile": intent_price_profile if provider == "typesafe" else "published-model-rates",
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "estimated_usd": None,
        "assumptions": "standard tier; token rates only; excludes cache-write and other fees; reasoning included in output tokens",
    }
    n_in, n_out = record["input_tokens"], record["output_tokens"]
    if not _count(n_in) or not _count(n_out):
        record["status"] = "usage_unknown"
        return record
    if provider == "typesafe" and intent_price_profile == "typesafe-input-20261020":
        rates = (Decimal(".042"), Decimal(0), Decimal(0))
        cached = 0
    else:
        base = next((key for key in RATES if response_model_matches(model, key)), None)
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
             "| Provider / model | Stage | Estimated USD |", "|---|---|---:|"]
    for row in ledger.get("calls", []):
        label = row["model"]
        if row["provider"] == "typesafe" and not re.fullmatch(r"intent-model:[a-f0-9]{16}", label):
            label = "intent-model:unknown"
        name = sanitize_untrusted_markdown_scalar(f"{row['provider']} / {label}")
        stage = sanitize_untrusted_markdown_scalar(str(row.get("stage") or "unspecified"))
        amount = row.get("estimated_usd")
        lines.append(f"| {name} | {stage} | {'unknown' if amount is None else f'${amount:.8f}'} |")
    total = ledger.get("estimated_total_usd")
    lines.extend(["", f"Total estimate: {'unknown (partial usage)' if total is None else f'${total:.8f}'}. Excludes cache-write and non-token fees.", ""])
    return lines
