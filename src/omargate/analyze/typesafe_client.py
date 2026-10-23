"""Bounded HTTP transport for TypeSafe Noul and Choice evaluations.

This module validates the wire contract only. It does not choose thresholds,
interpret findings, estimate cost, or decide whether a gate passes.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
import json
import math
import re
import time
from types import MappingProxyType
from typing import Any

import httpx


_ENDPOINT = "https://api.typesafe.ai/v1/systemone"


class TypeSafeError(RuntimeError):
    """A transport/contract error whose message contains no provider content."""

    @property
    def reason_code(self) -> str:
        codes = {
            "TypeSafe request timed out": "typesafe_timeout",
            "TypeSafe request was invalid": "typesafe_request_invalid",
            "TypeSafe request failed": "typesafe_transport_failed",
            "TypeSafe response was invalid": "typesafe_response_invalid",
            "TypeSafe response model did not match the requested model": "typesafe_model_mismatch",
            "TypeSafe response answers were invalid": "typesafe_answers_invalid",
            "TypeSafe response usage was invalid": "typesafe_usage_invalid",
        }
        status = re.fullmatch(r"TypeSafe request failed \(HTTP ([1-5][0-9]{2})\)", str(self))
        return "typesafe_http_" + status[1] if status else codes.get(str(self), "typesafe_error")


@dataclass(frozen=True)
class ChoiceAnswer:
    """Provider-reported Choice distribution; interpretation belongs to policy."""

    choice: str
    probabilities: Mapping[str, float]
    confidence: float

    def __post_init__(self) -> None:
        # Copy before wrapping so a caller cannot mutate the original dictionary.
        object.__setattr__(self, "probabilities", MappingProxyType(dict(self.probabilities)))

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": "choice",
            "choice": self.choice,
            "probabilities": dict(self.probabilities),
            "confidence": self.confidence,
        }


TypeSafeAnswer = float | ChoiceAnswer


@dataclass(frozen=True)
class TypeSafeResult:
    model: str = field(repr=False)
    answers: dict[str, TypeSafeAnswer]
    usage: dict
    latency_ms: int


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite JSON number")
    return number


def _reject_constant(_: str) -> None:
    raise ValueError("nonfinite JSON constant")


def _validate_questions(questions: dict[str, dict]) -> None:
    if not isinstance(questions, dict) or not questions:
        raise TypeSafeError("TypeSafe request was invalid")
    for question_id, question in questions.items():
        if (
            not isinstance(question_id, str)
            or not question_id
            or not isinstance(question, dict)
            or not isinstance(question.get("type"), str)
            or question.get("type") not in {"noul", "choice"}
            or not isinstance(question.get("instructions"), (str, dict, list))
        ):
            raise TypeSafeError("TypeSafe request was invalid")
        if question["type"] == "choice":
            criteria = question.get("criteria")
            if (
                not isinstance(criteria, dict)
                or not 1 <= len(criteria) <= 255
                or any(not isinstance(option, str) or not option for option in criteria)
                or any(value is not None and not isinstance(value, (str, dict, list)) for value in criteria.values())
            ):
                raise TypeSafeError("TypeSafe request was invalid")


def _probability(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and 0 <= value <= 1
        and math.isfinite(value)
    )


# TypeSafe reports each Choice probability rounded to hundredths (jev-1.14.0, measured
# 2026-10-23: a six-option answer summed to 0.99), so an honest distribution can miss
# 1.0 by half a hundredth per option. Values off that grid were not rounded and keep
# float tolerance; the bound never exceeds what rounding the reported options explains.
_REPORTED_STEP = 0.01


def is_unit_distribution(probabilities: Mapping[str, float]) -> bool:
    values = [float(value) for value in probabilities.values()]
    on_grid = all(
        math.isclose(value, round(value / _REPORTED_STEP) * _REPORTED_STEP, rel_tol=0.0, abs_tol=1e-9)
        for value in values
    )
    tolerance = _REPORTED_STEP / 2 * len(values) + 1e-9 if on_grid else 1e-6
    return math.isclose(math.fsum(values), 1.0, rel_tol=0.0, abs_tol=tolerance)


def validate_answers(
    answers: dict[str, TypeSafeAnswer], questions: dict[str, dict]
) -> dict[str, TypeSafeAnswer]:
    """Validate normalized real/fake client answers against the request contract.

    Noul remains a float. Choice preserves the API's probabilities and reported
    confidence; this boundary neither derives confidence nor applies thresholds.
    """
    _validate_questions(questions)
    if not isinstance(answers, dict) or answers.keys() != questions.keys():
        raise TypeSafeError("TypeSafe response answers were invalid")
    normalized: dict[str, TypeSafeAnswer] = {}
    for question_id, question in questions.items():
        answer = answers[question_id]
        if question["type"] == "noul":
            if not _probability(answer):
                raise TypeSafeError("TypeSafe response answers were invalid")
            normalized[question_id] = float(answer)
            continue
        if (
            not isinstance(answer, ChoiceAnswer)
            or not isinstance(answer.choice, str)
            or answer.choice not in question["criteria"]
            or not isinstance(answer.probabilities, Mapping)
            or answer.probabilities.keys() != question["criteria"].keys()
            or not all(_probability(value) for value in answer.probabilities.values())
            or not _probability(answer.confidence)
        ):
            raise TypeSafeError("TypeSafe response answers were invalid")
        probabilities = {option: float(value) for option, value in answer.probabilities.items()}
        # The primary docs specify an approximately-unit distribution but no numeric
        # tolerance; the reported rounding is the tolerance, not calibration.
        if (
            not is_unit_distribution(probabilities)
            or probabilities[answer.choice] != max(probabilities.values())
        ):
            raise TypeSafeError("TypeSafe response answers were invalid")
        normalized[question_id] = ChoiceAnswer(answer.choice, probabilities, float(answer.confidence))
    return normalized


def _decode_answers(raw: Any, questions: dict[str, dict]) -> dict[str, TypeSafeAnswer]:
    if not isinstance(raw, dict) or raw.keys() != questions.keys():
        raise TypeSafeError("TypeSafe response answers were invalid")
    decoded: dict[str, TypeSafeAnswer] = {}
    for question_id, question in questions.items():
        answer = raw[question_id]
        if not isinstance(answer, dict) or answer.get("type") != question["type"]:
            raise TypeSafeError("TypeSafe response answers were invalid")
        if question["type"] == "noul":
            decoded[question_id] = answer.get("noul")
        else:
            probabilities = answer.get("probabilities")
            if not isinstance(probabilities, dict):
                raise TypeSafeError("TypeSafe response answers were invalid")
            decoded[question_id] = ChoiceAnswer(answer.get("choice"), probabilities, answer.get("confidence"))
    return validate_answers(decoded, questions)


class TypeSafeClient:
    def __init__(
        self,
        api_key: str,
        timeout_seconds: float = 30,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise TypeSafeError("TypeSafe API key is missing or invalid")
        key = api_key.strip()
        if not key.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in key):
            raise TypeSafeError("TypeSafe API key is missing or invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise TypeSafeError("TypeSafe timeout is invalid")
        self._api_key = key
        self._timeout = float(timeout_seconds)
        self._client = client
        self._attempted = False
        self._observed_usage: dict | None = None

    @property
    def attempted(self) -> bool:
        """Whether this client has attempted an HTTP post, not a billed evaluation."""
        return self._attempted

    @property
    def observed_usage(self) -> dict | None:
        """Validated counts from an exact-model response, even if its answers fail."""
        return dict(self._observed_usage) if self._observed_usage is not None else None

    async def rate(
        self,
        *,
        state: dict,
        questions: dict[str, dict],
        model: str,
    ) -> TypeSafeResult:
        """Evaluate named Noul/Choice questions; never retry or follow redirects.

        A supplied HTTP client remains owned by its caller. The elapsed timeout
        includes transport, body reading and response validation. A response must
        name exactly the requested model; aliases are not silently resolved here.
        """
        started = time.monotonic()
        try:
            return await asyncio.wait_for(
                self._rate(state, questions, model, started), timeout=self._timeout
            )
        except (TimeoutError, httpx.TimeoutException):
            raise TypeSafeError("TypeSafe request timed out") from None
        except TypeSafeError:
            raise
        except Exception:
            raise TypeSafeError("TypeSafe request failed") from None

    async def _rate(
        self, state: dict, questions: dict[str, dict], model: str, started: float
    ) -> TypeSafeResult:
        self._observed_usage = None
        if (
            not isinstance(state, dict)
            or not isinstance(questions, dict)
            or not questions
            or not isinstance(model, str)
            or not model
            or model.strip() != model
        ):
            raise TypeSafeError("TypeSafe request was invalid")
        _validate_questions(questions)
        try:
            body = json.dumps(
                {"model": model, "state": state, "questions": questions},
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise TypeSafeError("TypeSafe request was invalid") from None

        if self._client is None:
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
                response = await self._post(client, body)
        else:
            response = await self._post(self._client, body)
        if not 200 <= response.status_code < 300:
            raise TypeSafeError(f"TypeSafe request failed (HTTP {response.status_code})")
        try:
            raw = json.loads(
                response.content.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_float=_finite_float,
                parse_constant=_reject_constant,
            )
        except (ValueError, UnicodeError, RecursionError):
            raise TypeSafeError("TypeSafe response was invalid") from None
        if not isinstance(raw, dict) or raw.get("model") != model:
            raise TypeSafeError("TypeSafe response model did not match the requested model")
        usage = raw.get("usage")
        if not isinstance(usage, dict):
            raise TypeSafeError("TypeSafe response usage was invalid")
        for name in ("input_tokens", "output_tokens"):
            count = usage.get(name)
            if count is not None and (
                isinstance(count, bool) or not isinstance(count, int) or count < 0
            ):
                raise TypeSafeError("TypeSafe response usage was invalid")
        self._observed_usage = {name: usage.get(name) for name in ("input_tokens", "output_tokens")}
        parsed = _decode_answers(raw.get("answers"), questions)
        if time.monotonic() - started >= self._timeout:
            raise TypeSafeError("TypeSafe request timed out")
        return TypeSafeResult(
            model=model,
            answers=parsed,
            usage=usage,
            latency_ms=max(0, int((time.monotonic() - started) * 1000)),
        )

    async def _post(self, client: httpx.AsyncClient, body: bytes) -> httpx.Response:
        self._attempted = True
        return await client.post(
            _ENDPOINT,
            content=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=self._timeout,
            follow_redirects=False,
            auth=None,
        )
