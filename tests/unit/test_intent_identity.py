from policy_fixture import FAKE_POLICY_JSON

import json

import pytest
from pydantic import ValidationError

from omargate.config import OmarGateConfig
from omargate.intent_identity import intent_model_reference, redact_intent_pin


def test_pin_is_private_in_config_and_stably_referenced_without_naming_it():
    pin = "model-under-test-1.13.0"
    config = OmarGateConfig(llm_provider="typesafe", typesafe_api_key="test-only",
        openai_api_key="test-only", intent_model_pin=pin, intent_policy=FAKE_POLICY_JSON)
    assert pin not in repr(config)
    assert pin not in config.model_dump_json()
    assert config.intent_model_reference == intent_model_reference(pin)
    assert config.intent_model_reference != intent_model_reference("other-test-1.13.0")
    assert pin not in json.dumps({"model": config.intent_model_reference})
    echoed = {"source": f"source mentions {pin}", "usage": {pin: [pin, 3]}}
    public = redact_intent_pin(echoed, pin)
    assert pin not in json.dumps(public)
    assert echoed["usage"][pin][0] == pin  # do not mutate bound source/evidence


@pytest.mark.parametrize("pin", ["", "not-a-pin", "model-under-test-1.13.0\n", "model-under-test-1.13.0 " + "x" * 500])
def test_missing_or_malformed_private_pin_refuses_without_echoing_input(pin):
    with pytest.raises(ValidationError) as caught:
        OmarGateConfig(llm_provider="typesafe", typesafe_api_key="test-only",
            openai_api_key="test-only", intent_model_pin=pin, intent_policy=FAKE_POLICY_JSON)
    if pin:
        assert pin not in str(caught.value)
    assert intent_model_reference("") == "intent-model:unknown"
