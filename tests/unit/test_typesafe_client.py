from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
import json
import traceback

import httpx
import pytest

from omargate.analyze.typesafe_client import (
    ChoiceAnswer,
    TypeSafeClient,
    TypeSafeError,
    TypeSafeResult,
    validate_answers,
)


KEY = "synthetic-typesafe-key"
MODEL = "jev-1.13.0"
QUESTIONS = {
    "candidate-1": {"type": "noul", "instructions": "Does the supplied candidate apply?"},
    "candidate-2": {"type": "noul", "instructions": {"question": "Is the claim supported?"}},
}


def projection(**changes):
    return {
        "model": MODEL,
        "answers": {
            "candidate-1": {"type": "noul", "noul": 0},
            "candidate-2": {"type": "noul", "noul": 1},
        },
        "usage": {"input_tokens": 12, "output_tokens": 3},
        **changes,
    }


async def evaluate(payload=None, *, content=None, status=200):
    calls = []

    def handler(request):
        calls.append(request)
        if content is not None:
            return httpx.Response(status, content=content)
        return httpx.Response(status, json=projection() if payload is None else payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        evaluator = TypeSafeClient(KEY, client=client)
        result = await evaluator.rate(state={"diff": "exact fixture"}, questions=QUESTIONS)
        return result, calls


@pytest.mark.anyio
async def test_exact_wire_contract_zero_one_frozen_result_and_raw_usage():
    usage = {"input_tokens": 12, "output_tokens": 0, "future": {"reported": True}}
    result, calls = await evaluate(projection(usage=usage))
    assert isinstance(result, TypeSafeResult)
    assert result.answers == {"candidate-1": 0.0, "candidate-2": 1.0}
    assert result.model == MODEL
    assert result.usage == usage
    assert "cost" not in result.usage
    assert type(result.latency_ms) is int and result.latency_ms >= 0
    with pytest.raises(FrozenInstanceError):
        result.model = "changed"
    assert len(calls) == 1
    request = calls[0]
    assert request.method == "POST"
    assert str(request.url) == "https://api.typesafe.ai/v1/systemone"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == {
        "model": MODEL, "state": {"diff": "exact fixture"}, "questions": QUESTIONS,
    }


@pytest.mark.anyio
async def test_supplied_client_reused_not_closed_and_cannot_override_bearer():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["authorization"] == f"Bearer {KEY}"
        return httpx.Response(200, json=projection())

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), auth=("unrelated", "client-auth")
    ) as client:
        evaluator = TypeSafeClient(KEY, client=client)
        for _ in range(2):
            await evaluator.rate(state={}, questions=QUESTIONS)
        assert not client.is_closed
    assert len(calls) == 2


@pytest.mark.anyio
async def test_owned_client_is_closed_and_disables_ambient_proxy_and_redirects(monkeypatch):
    original = httpx.AsyncClient
    created = []

    def factory(**kwargs):
        assert kwargs == {"trust_env": False, "follow_redirects": False}
        client = original(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=projection())), **kwargs)
        created.append(client)
        return client

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    assert (await TypeSafeClient(KEY).rate(state={}, questions=QUESTIONS)).model == MODEL
    assert len(created) == 1 and created[0].is_closed


@pytest.mark.anyio
async def test_redirect_is_refused_even_when_injected_client_follows_redirects():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(307, headers={"Location": "https://untrusted.example/collect"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(TypeSafeError, match=r"HTTP 307"):
            await TypeSafeClient(KEY, client=client).rate(state={}, questions=QUESTIONS)
    assert len(calls) == 1
    assert calls[0].url.host == "api.typesafe.ai"


@pytest.mark.anyio
@pytest.mark.parametrize("status", [400, 401, 403, 408, 413, 415, 422, 429, 500, 529])
async def test_status_errors_are_safe_and_never_retried(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, text=f"PRIVATE BODY {KEY}", headers={"Retry-After": "0"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TypeSafeError) as failure:
            await TypeSafeClient(KEY, client=client).rate(state={}, questions=QUESTIONS)
    assert str(failure.value) == f"TypeSafe request failed (HTTP {status})"
    assert KEY not in str(failure.value) and "PRIVATE BODY" not in str(failure.value)
    assert len(calls) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("content", [
    b'{"model":"jev-1.13.0","model":"jev-1.13.0"}',
    b'{"model":"jev-1.13.0","answers":{"candidate-1":{"type":"noul","noul":0,"noul":1}}}',
    b'{"model":"jev-1.13.0","unused":{"x":1,"x":2}}',
    b'{"number":NaN}', b'{"number":Infinity}', b'{"number":-Infinity}',
    b'{"number":1e400}', b'\xef\xbb\xbf{}', b'\xff', b'{', b'[]',
])
async def test_strict_json_rejects_duplicate_nonfinite_invalid_encoding_and_nonobject(content):
    with pytest.raises(TypeSafeError) as failure:
        await evaluate(content=content)
    assert KEY not in str(failure.value)


@pytest.mark.anyio
@pytest.mark.parametrize("answers", [
    {}, {"candidate-1": {"type": "noul", "noul": 0.2}},
    {"candidate-1": {"type": "noul", "noul": 0.2}, "candidate-2": {"type": "noul", "noul": 0.2}, "unexpected": {"type": "noul", "noul": 0.2}},
    {"candidate-1": {"type": "choice", "choice": "yes"}, "candidate-2": {"type": "noul", "noul": 0.2}},
    {"candidate-1": None, "candidate-2": {"type": "noul", "noul": 0.2}},
    [], None,
])
async def test_all_ids_exactly_once_and_noul_type_required(answers):
    with pytest.raises(TypeSafeError, match="answers were invalid"):
        await evaluate(projection(answers=answers))


@pytest.mark.anyio
@pytest.mark.parametrize("value", [True, False, "0.5", None, -0.01, 1.01, [], {}])
async def test_noul_must_be_numeric_nonbool_and_in_range(value):
    row = projection()
    row["answers"]["candidate-1"]["noul"] = value
    with pytest.raises(TypeSafeError, match="answers were invalid"):
        await evaluate(row)


@pytest.mark.anyio
@pytest.mark.parametrize("model", [None, "", "jev-latest", "jev-1.14.0", 13])
async def test_response_model_must_match_requested_pin(model):
    with pytest.raises(TypeSafeError, match="model did not match"):
        await evaluate(projection(model=model))


@pytest.mark.anyio
async def test_explicit_new_pin_is_sent_and_actual_model_returned():
    def handler(request):
        assert json.loads(request.content)["model"] == "jev-1.14.0"
        return httpx.Response(200, json=projection(model="jev-1.14.0"))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await TypeSafeClient(KEY, client=client).rate(state={}, questions=QUESTIONS, model="jev-1.14.0")
    assert result.model == "jev-1.14.0"


@pytest.mark.anyio
@pytest.mark.parametrize("usage", [{}, {"input_tokens": None, "output_tokens": None}])
async def test_unreported_usage_remains_unreported_without_fabricated_zeros(usage):
    result, _ = await evaluate(projection(usage=usage))
    assert result.usage == usage


@pytest.mark.anyio
@pytest.mark.parametrize("usage", [None, [], {"input_tokens": True}, {"input_tokens": -1}, {"output_tokens": 1.5}])
async def test_invalid_usage_is_rejected(usage):
    with pytest.raises(TypeSafeError, match="usage was invalid"):
        await evaluate(projection(usage=usage))


@pytest.mark.parametrize("key", [None, "", " ", "bad\nkey", "bad key", "nonascii-ñ"])
def test_invalid_keys_are_safe(key):
    with pytest.raises(TypeSafeError, match="API key is missing or invalid"):
        TypeSafeClient(key)


@pytest.mark.parametrize("seconds", [True, 0, -1, float("nan"), float("inf")])
def test_invalid_timeout_is_safe(seconds):
    with pytest.raises(TypeSafeError, match="timeout is invalid"):
        TypeSafeClient(KEY, timeout_seconds=seconds)


@pytest.mark.anyio
@pytest.mark.parametrize("state,questions,model", [
    ([], QUESTIONS, MODEL), ({}, {}, MODEL), ({}, {1: QUESTIONS["candidate-1"]}, MODEL),
    ({}, {"": QUESTIONS["candidate-1"]}, MODEL), ({}, {"q": {"type": "choice", "instructions": "pick"}}, MODEL),
    ({}, {"q": {"type": "noul"}}, MODEL), ({"number": float("nan")}, QUESTIONS, MODEL),
    ({"not_json": object()}, QUESTIONS, MODEL), ({}, QUESTIONS, ""), ({}, QUESTIONS, " bad-model "),
])
async def test_invalid_request_is_refused_before_transport(state, questions, model):
    calls = []

    def handler(request):
        calls.append(request)
        raise AssertionError("invalid request reached transport")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TypeSafeError, match="request was invalid"):
            await TypeSafeClient(KEY, client=client).rate(state=state, questions=questions, model=model)
    assert calls == []


@pytest.mark.anyio
async def test_overall_timeout_cancels_delayed_transport_and_leaves_supplied_client_open():
    cancelled = asyncio.Event()

    async def handler(request):
        try:
            await asyncio.sleep(1)
        finally:
            cancelled.set()
        return httpx.Response(200, json=projection())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        evaluator = TypeSafeClient(KEY, timeout_seconds=0.01, client=client)
        with pytest.raises(TypeSafeError, match="request timed out"):
            await evaluator.rate(state={}, questions=QUESTIONS)
        assert cancelled.is_set() and not client.is_closed
        assert evaluator.attempted is True


@pytest.mark.anyio
@pytest.mark.parametrize("exception", [httpx.ReadTimeout, httpx.ConnectError])
async def test_transport_errors_hide_provider_key_body_and_exception_chain(exception):
    def handler(request):
        raise exception(f"PRIVATE BODY {KEY}", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TypeSafeError) as failure:
            await TypeSafeClient(KEY, client=client).rate(state={}, questions=QUESTIONS)
    rendered = "".join(traceback.format_exception(failure.value))
    assert KEY not in rendered and "PRIVATE BODY" not in rendered


@pytest.mark.anyio
async def test_caller_cancellation_is_not_relabelled_as_provider_failure():
    entered = asyncio.Event()

    async def handler(request):
        entered.set()
        await asyncio.sleep(1)
        return httpx.Response(200, json=projection())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        task = asyncio.create_task(TypeSafeClient(KEY, client=client).rate(state={}, questions=QUESTIONS))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not client.is_closed


MIXED_QUESTIONS = {
    "risk": {"type": "noul", "instructions": "Does the fixture claim apply?"},
    "severity": {
        "type": "choice",
        "instructions": "Choose the fixture severity label.",
        "criteria": {"P0": None, "P1": None, "P2": None, "P3": None, "none": None},
    },
    "category": {
        "type": "choice",
        "instructions": "Choose the fixture category label.",
        "criteria": {"security": None, "quality": {"fixture": "quality"}, "none": ["No fixture match"]},
    },
}


def mixed_projection():
    return {
        "model": MODEL,
        "answers": {
            "risk": {"type": "noul", "noul": 0.73},
            "severity": {
                "type": "choice", "choice": "P1", "confidence": 0.66,
                "probabilities": {"P0": 0.04, "P1": 0.8, "P2": 0.1, "P3": 0.04, "none": 0.02},
            },
            "category": {
                "type": "choice", "choice": "quality", "confidence": 0.81,
                "probabilities": {"security": 0.12, "quality": 0.88, "none": 0.0},
            },
        },
        "usage": {"input_tokens": 80, "output_tokens": 12},
    }


async def evaluate_mixed(payload=None, *, questions=None, content=None):
    calls = []

    def handler(request):
        calls.append(request)
        if content is not None:
            return httpx.Response(200, content=content)
        return httpx.Response(200, json=mixed_projection() if payload is None else payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await TypeSafeClient(KEY, client=client).rate(
            state={"fixture": "bound source"},
            questions=MIXED_QUESTIONS if questions is None else questions,
            model=MODEL,
        )
    return result, calls


@pytest.mark.anyio
async def test_mixed_noul_choice_wire_contract_and_reported_confidence():
    payload = mixed_projection()
    result, calls = await evaluate_mixed(payload)
    assert len(calls) == 1
    sent = json.loads(calls[0].content)
    assert sent == {"model": MODEL, "state": {"fixture": "bound source"}, "questions": MIXED_QUESTIONS}
    assert type(result.answers["risk"]) is float
    assert result.answers["risk"] == 0.73
    severity = result.answers["severity"]
    category = result.answers["category"]
    assert isinstance(severity, ChoiceAnswer) and isinstance(category, ChoiceAnswer)
    assert severity.as_dict() == payload["answers"]["severity"]
    assert category.choice == "quality"
    assert category.confidence == 0.81
    assert category.confidence != category.probabilities[category.choice]
    assert json.loads(json.dumps(category.as_dict())) == payload["answers"]["category"]
    assert result.model == MODEL and result.usage == payload["usage"]
    assert validate_answers(result.answers, MIXED_QUESTIONS) == result.answers


def test_choice_is_immutable_and_does_not_alias_source_or_serialized_dictionary():
    probabilities = {"a": 0.75, "b": 0.25}
    answer = ChoiceAnswer("a", probabilities, 0.5)
    probabilities["a"] = 0.01
    assert answer.probabilities["a"] == 0.75
    with pytest.raises(FrozenInstanceError):
        answer.choice = "b"
    with pytest.raises(TypeError):
        answer.probabilities["a"] = 0.1
    output = answer.as_dict()
    output["probabilities"]["a"] = 0.2
    assert answer.probabilities["a"] == 0.75


@pytest.mark.anyio
@pytest.mark.parametrize(
    "kind",
    ["missing-answer", "extra-answer", "noul-tag-for-choice", "choice-tag-for-noul", "bare-number-for-noul"],
)
async def test_mixed_answers_keep_exact_question_census_and_wire_tags(kind):
    payload = mixed_projection()
    answers = payload["answers"]
    if kind == "missing-answer":
        del answers["category"]
    elif kind == "extra-answer":
        answers["unexpected"] = {"type": "noul", "noul": 0.1}
    elif kind == "noul-tag-for-choice":
        answers["severity"] = {"type": "noul", "noul": 0.9}
    elif kind == "choice-tag-for-noul":
        answers["risk"] = answers["severity"]
    else:
        answers["risk"] = 0.73
    with pytest.raises(TypeSafeError, match="answers were invalid"):
        await evaluate_mixed(payload)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "kind",
    ["missing-option", "extra-option", "negative", "over-one", "boolean", "string", "non-unit", "not-highest", "unknown-choice", "missing-confidence", "boolean-confidence", "out-of-range-confidence", "scores-alias"],
)
async def test_malformed_choice_distribution_or_confidence_is_rejected(kind):
    payload = mixed_projection()
    answer = payload["answers"]["severity"]
    probabilities = answer["probabilities"]
    if kind == "missing-option":
        del probabilities["none"]
    elif kind == "extra-option":
        probabilities["invented"] = 0
    elif kind in {"negative", "over-one", "boolean", "string"}:
        probabilities["P0"] = {"negative": -0.01, "over-one": 1.01, "boolean": True, "string": "0.04"}[kind]
    elif kind == "non-unit":
        probabilities["P1"] = 0.5
    elif kind == "not-highest":
        answer["choice"] = "P0"
    elif kind == "unknown-choice":
        answer["choice"] = "invented"
    elif kind == "missing-confidence":
        del answer["confidence"]
    elif kind == "boolean-confidence":
        answer["confidence"] = True
    elif kind == "out-of-range-confidence":
        answer["confidence"] = 1.01
    else:
        answer["scores"] = answer.pop("probabilities")
    with pytest.raises(TypeSafeError, match="answers were invalid"):
        await evaluate_mixed(payload)


@pytest.mark.anyio
@pytest.mark.parametrize("field", ["probability", "confidence"])
async def test_nonfinite_choice_values_and_duplicate_option_keys_are_not_accepted(field):
    payload = mixed_projection()
    answer = payload["answers"]["severity"]
    if field == "probability":
        answer["probabilities"]["P0"] = float("nan")
    else:
        answer["confidence"] = float("inf")
    with pytest.raises(TypeSafeError, match="response was invalid"):
        await evaluate_mixed(content=json.dumps(payload).encode())
    content = json.dumps(mixed_projection()).replace('"P0": 0.04,', '"P0": 0.04, "P0": 0.04,')
    with pytest.raises(TypeSafeError, match="response was invalid"):
        await evaluate_mixed(content=content.encode())


@pytest.mark.anyio
@pytest.mark.parametrize("criteria", [{}, {"a": True}, {"a": 1}, {"": None}, {str(i): None for i in range(256)}])
async def test_invalid_choice_criteria_refuse_before_transport(criteria):
    calls = []
    questions = {"q": {"type": "choice", "instructions": "Choose a fixture option", "criteria": criteria}}

    def handler(request):
        calls.append(request)
        raise AssertionError("invalid criteria reached transport")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TypeSafeError, match="request was invalid"):
            await TypeSafeClient(KEY, client=client).rate(state={}, questions=questions)
    assert calls == []


@pytest.mark.anyio
@pytest.mark.parametrize("count", [1, 255])
async def test_choice_option_count_boundaries(count):
    criteria = {str(i): None for i in range(count)}
    questions = {"q": {"type": "choice", "instructions": "Choose a fixture option", "criteria": criteria}}
    payload = {
        "model": MODEL,
        "answers": {"q": {"type": "choice", "choice": "0", "confidence": 1,
                           "probabilities": {str(i): 1 if i == 0 else 0 for i in range(count)}}},
        "usage": {},
    }
    result, calls = await evaluate_mixed(payload, questions=questions)
    assert len(calls) == 1 and result.answers["q"].choice == "0"


def test_normalized_validator_defends_fake_clients_and_keeps_noul_compatibility():
    questions = {
        "n": {"type": "noul", "instructions": "Fixture yes or no"},
        "c": {"type": "choice", "instructions": "Fixture label", "criteria": {"a": None, "b": None}},
    }
    answer = ChoiceAnswer("b", {"a": 0.5, "b": 0.5}, 0.0)
    assert validate_answers({"n": 1, "c": answer}, questions) == {"n": 1.0, "c": answer}
    invalid = [
        {"n": True, "c": answer},
        {"n": 0.2, "c": 0.9},
        {"n": 0.2, "c": answer.as_dict()},
        {"n": 0.2, "c": ChoiceAnswer("a", {"a": 0.3, "b": 0.7}, 0.5)},
        {"n": 0.2, "c": ChoiceAnswer("a", {"a": 0.7, "b": float("nan")}, 0.5)},
        {"n": 0.2, "c": ChoiceAnswer("a", {"a": 0.7, "b": 0.3}, True)},
    ]
    for value in invalid:
        with pytest.raises(TypeSafeError, match="answers were invalid"):
            validate_answers(value, questions)


def test_probability_mass_tolerance_is_bounded_without_recomputing_confidence():
    questions = {"c": {"type": "choice", "instructions": "Fixture label", "criteria": {"a": None, "b": None}}}
    answer = ChoiceAnswer("a", {"a": 0.5, "b": 0.4999995}, 0.123)
    assert validate_answers({"c": answer}, questions)["c"].confidence == 0.123
    with pytest.raises(TypeSafeError, match="answers were invalid"):
        validate_answers({"c": ChoiceAnswer("a", {"a": 0.5, "b": 0.49999}, 0.123)}, questions)


@pytest.mark.anyio
async def test_http_attempted_changes_only_at_post_not_invalid_rate_entry():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=mixed_projection())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        evaluator = TypeSafeClient(KEY, client=client)
        assert evaluator.attempted is False
        with pytest.raises(TypeSafeError, match="request was invalid"):
            await evaluator.rate(state={}, questions={})
        assert evaluator.attempted is False and calls == []
        await evaluator.rate(state={}, questions=MIXED_QUESTIONS)
        assert evaluator.attempted is True and len(calls) == 1
