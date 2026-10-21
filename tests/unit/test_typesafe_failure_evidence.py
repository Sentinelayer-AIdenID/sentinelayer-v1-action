import httpx
import pytest

from omargate.analyze.typesafe_client import TypeSafeClient, TypeSafeError

pytestmark = pytest.mark.anyio
MODEL = "model-under-test-1.13.0"
QUESTION = {"q": {"type": "noul", "instructions": "Fixture claim"}}


@pytest.mark.parametrize("change,known", [
    ({"answers": {"q": {"type": "noul", "noul": "invalid"}}}, True),
    ({"model": "another-model"}, False),
    ({"usage": {"input_tokens": -1, "output_tokens": 3}}, False),
])
async def test_validated_usage_survives_bad_answers_but_not_bad_identity_or_counts(change, known):
    payload = {"model": MODEL, "answers": {"q": {"type": "noul", "noul": .2}},
               "usage": {"input_tokens": 12, "output_tokens": 3}, **change}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))) as http:
        client = TypeSafeClient("test-only", client=http)
        with pytest.raises(TypeSafeError):
            await client.rate(state={}, questions=QUESTION, model=MODEL)
        assert client.attempted
        assert client.observed_usage == ({"input_tokens": 12, "output_tokens": 3} if known else None)


async def test_reused_client_does_not_reuse_old_usage_on_later_failure():
    bodies = iter([httpx.Response(200, json={"model": MODEL, "answers": {"q": {"type": "noul", "noul": .2}},
                                         "usage": {"input_tokens": 12, "output_tokens": 3}}),
                   httpx.Response(429, text="private provider detail")])
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: next(bodies))) as http:
        client = TypeSafeClient("test-only", client=http)
        await client.rate(state={}, questions=QUESTION, model=MODEL)
        copy = client.observed_usage
        copy["input_tokens"] = 999
        assert client.observed_usage["input_tokens"] == 12
        with pytest.raises(TypeSafeError) as failure:
            await client.rate(state={}, questions=QUESTION, model=MODEL)
        assert failure.value.reason_code == "typesafe_http_429"
        assert client.observed_usage is None
        assert "private" not in str(failure.value)


def test_reason_codes_never_retain_arbitrary_error_content():
    assert TypeSafeError("sensitive_private_text").reason_code == "typesafe_error"
    assert TypeSafeError("TypeSafe response answers were invalid").reason_code == "typesafe_answers_invalid"
