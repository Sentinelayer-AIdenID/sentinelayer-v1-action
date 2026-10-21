import copy
import json

import pytest

from omargate.private_policy import PrivatePolicyError, load_private_policy
from policy_fixture import FAKE_DOCUMENT, FAKE_POLICY, FAKE_POLICY_JSON


def test_private_profile_has_stable_public_reference_and_fresh_data_views():
    alternate = json.dumps(FAKE_DOCUMENT, indent=2)
    assert load_private_policy(alternate).reference == FAKE_POLICY.reference
    first = FAKE_POLICY.routing
    first["domains"].clear()
    assert FAKE_POLICY.routing["domains"]
    assert "Test-only" not in repr(FAKE_POLICY)


@pytest.mark.parametrize("raw", ["", "{}", "[]", "null", "{", "x" * 65537,
    '{"schema":"a","schema":"b"}', '{"schema":NaN}'],
    ids=["empty", "object", "array", "null", "invalid", "oversized", "duplicate", "nonfinite"])
def test_missing_ambiguous_or_invalid_private_profile_refuses_without_echo(raw):
    with pytest.raises(PrivatePolicyError, match="review is unknown") as caught:
        load_private_policy(raw)
    assert "Test-only" not in str(caught.value)


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(extra="unexpected"),
    lambda value: value["routing"]["thresholds"].update(hazard_max=True),
    lambda value: value["routing"]["thresholds"].update(hazard_max=float("nan")),
    lambda value: value["routing"]["domains"].update(fixture=[99, "Test-only"]),
    lambda value: value["routing"].update(critical_path_tokens=[]),
    lambda value: value["routing"]["questions"].pop("sensitive"),
    lambda value: value["routing"]["questions"]["risk"].update(criteria={"low": "x"}),
    lambda value: value["typed"]["thresholds"].update(RISK_ABSENT_MAX=1),
    lambda value: value["typed"]["finding_templates"].clear(),
    lambda value: value["typed"]["severity_support_floors"].update(P0=-1),
])
def test_private_profile_contract_is_required_before_model_work(mutation):
    value = copy.deepcopy(FAKE_DOCUMENT)
    mutation(value)
    with pytest.raises(PrivatePolicyError):
        load_private_policy(json.dumps(value))
    assert load_private_policy(FAKE_POLICY_JSON).reference == FAKE_POLICY.reference
