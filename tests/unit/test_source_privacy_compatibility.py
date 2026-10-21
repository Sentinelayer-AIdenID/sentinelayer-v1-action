import json
import subprocess
import sys
from unittest.mock import AsyncMock

import pytest

from test_review_cascade import configured as configured, generator_transport as generator_transport, triage
from omargate.ingest.quick_learn import QuickLearnSummary
from omargate.redaction import contains_credential_material, redact_secret_source, sanitize_public_error

pytestmark = pytest.mark.anyio


@pytest.fixture
def subject(request):
    return request.getfixturevalue("configured")


@pytest.fixture
def transport(request):
    return request.getfixturevalue("generator_transport")


async def review_source(instance, source, *, quick=None, file_path="x.py"):
    (instance.repo_root / file_path).write_bytes(source.encode())
    lines = source.splitlines()
    diff = (f"diff --git a/{file_path} b/{file_path}\n--- /dev/null\n+++ b/{file_path}\n@@ -0,0 +1,"
            + str(len(lines)) + " @@\n" + "\n".join("+" + line for line in lines) + "\n")
    return await instance._run_cascade_analysis(
        ingest={"files": [{"path": file_path}]}, changed_files=[file_path], scan_mode="pr-diff",
        deterministic_findings=[], quick_learn=quick, spec_context=None, diff_content=diff, run_dir=None)


@pytest.mark.parametrize("source", [
    "# This project provides source review\nvalue = 1\n",
    "# Project: PublicProject\nvalue = 1\n",
    "password: str\n",
    "token: Optional[str]\n",
    "def handle(token: Optional[str], password: str):\n    return 1\n",
    "token: Optional[str] = None\n",
    "token = self.token\n",
    "api_key = self.config.api_key.get_secret_value()\n",
    "password = os.getenv('DB_PASSWORD')\n",
    "token = request.headers.get('authorization')\n",
    "password: str = os.getenv('DB_PASSWORD')\n",
    "token = config['access_token']\n",
    "token = parse_token(payload)\n",
    "secret = Field(default=None)\n",
    "authorization: str\n",
])
async def test_ordinary_source_reaches_both_provider_call_boundaries(subject, transport, monkeypatch, source):
    rate = AsyncMock(return_value=triage(sensitive=1))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    result = await review_source(subject, source)
    rate.assert_awaited_once()
    transport.assert_awaited_once()
    assert result.success, result.failure_class
    assert source.rstrip() in transport.call_args.kwargs["input"]
    sent = json.dumps(rate.call_args.kwargs["state"])
    assert "[redacted-provider-id]" not in sent
    assert rate.call_args.kwargs["state"]["candidates"][0]["evidence"] == source


@pytest.mark.parametrize("excerpt", ["- token: your GitHub token\n", "**Token:** …\n", "**Token:** your GitHub token\n"])
async def test_readme_placeholder_prose_does_not_disable_generator(subject, transport, monkeypatch, excerpt):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage(sensitive=1)))
    quick = QuickLearnSummary("PublicProject", "A public project", [], "", [], "README.md", excerpt)
    result = await review_source(subject, "value = 1\n", quick=quick)
    transport.assert_awaited_once()
    assert result.success


@pytest.mark.parametrize("shape", [
    "SECRET_KEY={value}", "JWT_SECRET_KEY={value}", "SIGNING_KEY={value}", "DB_PASS={value}",
    '{{"password": "{value}"}}', "{{'client_secret': '{value}'}}",
    '{{"aws_secret_access_key": "{value}"}}', 'password = None or "{value}"',
    'password: str = "{value}"', 'token: Optional[str] = None or "{value}"',
    'password = SecretStr("{value}")', 'api_key = os.getenv("API_KEY", "{value}")',
    'token = settings.get("TOKEN", "{value}")', 'password = "None"',
    '# password={value}', '// token={value}', '/* SECRET_KEY={value} */',
    '{{"Authorization": "{value}"}}', 'url = "https://example.invalid/?key={value}"',
])
async def test_recognized_credential_shapes_never_reach_either_provider(
    subject, transport, monkeypatch, shape,
):
    value = "private-" + "bounded-fixture-value"
    source = shape.format(value=value) + "\n"
    rate = AsyncMock(side_effect=AssertionError("credential source must stay local"))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    result = await review_source(subject, source)
    rate.assert_not_awaited()
    transport.assert_not_awaited()
    assert not result.success and not result.attempted
    assert result.failure_class == "cascade_source_privacy_incomplete"
    assert result.usage["review_routing"]["source_failure_reason"] == "redacted_source"
    assert result.usage["policy_assessment"]["reason_code"] == "redacted_source"
    assert value not in redact_secret_source(source)[0]


_RETURNED_FIELDS = ("githubToken", "refreshToken", "sessionToken", "botToken", "dbPassword", "jwtSecret", "ENCRYPTION_KEY", "STRIPE_KEY",
                    "githubtoken", "refreshtoken", "sessiontoken", "bottoken",
                    "GITHUBTOKEN", "REFRESHTOKEN", "SESSIONTOKEN", "BOTTOKEN", "smtpPass")


@pytest.mark.parametrize("field", _RETURNED_FIELDS)
@pytest.mark.parametrize("suffix", ["py", "ts"])
async def test_returned_credential_families_stay_local(subject, transport, monkeypatch, field, suffix):
    value = "private-" + "bounded-fixture-value"
    rate = AsyncMock(side_effect=AssertionError("literal credential must stay local"))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    result = await review_source(subject, json.dumps({field: value}) + "\n", file_path="x." + suffix)
    rate.assert_not_awaited()
    transport.assert_not_awaited()
    assert result.failure_class == "cascade_source_privacy_incomplete"
    assert not result.success and not result.attempted
    assert result.usage["cost_ledger"]["calls"] == []


@pytest.mark.parametrize("field", _RETURNED_FIELDS)
async def test_returned_field_references_remain_reviewable(subject, transport, monkeypatch, field):
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", AsyncMock(return_value=triage(sensitive=1)))
    result = await review_source(subject, f"{field} = config.{field}\n")
    transport.assert_awaited_once()
    assert result.success


@pytest.mark.parametrize("field", _RETURNED_FIELDS[:4])
async def test_removed_camelcase_credential_stays_local(subject, transport, monkeypatch, field):
    rate = AsyncMock(side_effect=AssertionError("removed credential must stay local"))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    result = await subject._run_cascade_analysis(
        ingest={"files": [{"path": "x.py"}]}, changed_files=["x.py"], scan_mode="pr-diff",
        deterministic_findings=[], quick_learn=None, spec_context=None, run_dir=None,
        diff_content="diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-"
        + json.dumps({field: "private-" + "bounded-fixture-value"}) + "\n+value = 1\n")
    rate.assert_not_awaited()
    transport.assert_not_awaited()
    assert result.failure_class == "cascade_source_privacy_incomplete"


@pytest.mark.parametrize("field", _RETURNED_FIELDS[:4])
async def test_auxiliary_camelcase_credential_stays_local(subject, transport, field):
    from omargate.analyze.review_cascade import DEEP
    quick = QuickLearnSummary("PublicProject", "Public description", [], "", [], "README.md",
                              json.dumps({field: "private-" + "bounded-fixture-value"}))
    result = await subject._run_llm_analysis(
        ingest={"files": [{"path": "x.py"}]}, deterministic_findings=[], quick_learn=quick,
        spec_context=None, scan_mode="pr-diff", diff_content="+value = 1\n", changed_files=["x.py"], review_route=DEEP)
    transport.assert_not_awaited()
    assert result.failure_class == "cascade_source_privacy_incomplete"


@pytest.mark.parametrize("position", ["prefix", "suffix"])
async def test_unbound_diff_prose_is_refused_before_providers(subject, transport, monkeypatch, position):
    rate = AsyncMock(return_value=triage(sensitive=1))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    diff = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+value = 1\n"
    note = "NOTE password=private_fixture_value\n"
    result = await subject._run_cascade_analysis(
        ingest={"files": [{"path": "x.py"}]}, changed_files=["x.py"], scan_mode="pr-diff",
        deterministic_findings=[], quick_learn=None, spec_context=None, run_dir=None,
        diff_content=note + diff if position == "prefix" else diff + note)
    rate.assert_not_awaited()
    transport.assert_not_awaited()
    assert not result.success and not result.attempted
    assert result.usage["review_routing"]["source_failure_reason"] == "unbound_typed_diff_record"


def test_public_error_identifier_scrubbing_remains_separate_from_source_privacy():
    text = "Project: PublicProject"
    assert "PublicProject" not in sanitize_public_error(text)
    assert not contains_credential_material(text)


@pytest.mark.parametrize("name", ["secret_key", "signing_key", "db_pass", "password", "client_secret", "secret_access_key"])
def test_public_diagnostics_still_hide_new_credential_families(name):
    value = "private-" + "bounded-fixture-value"
    assert value not in sanitize_public_error(json.dumps({name: value}))


@pytest.mark.parametrize("path", ["settings.yml", "settings.json", "README.md"])
def test_data_files_and_auxiliary_prose_do_not_inherit_code_reference_exemptions(path):
    for source in ["password: str\n", "SECRET_KEY=PrivateReference\n", 'password: "str"\n']:
        assert redact_secret_source(source, file_path=path)[1]
        assert contains_credential_material(source)


def test_long_noncredential_identifier_has_bounded_work_and_cannot_hide_later_secret():
    code = ("from omargate.redaction import contains_credential_material as check;"
            "text='a_'*32768;assert not check(text);"
            "assert check(text+'\\nSECRET_KEY=private-fixture-value')")
    subprocess.run([sys.executable, "-c", code], check=True, timeout=5, capture_output=True)


def test_long_uppercase_camelcase_boundary_has_bounded_work():
    code = ("from omargate.redaction import contains_credential_material as check;"
            "name='A'*300000;assert not check(name+' = 1',code_context=True);"
            "assert check(name+'Token = '+repr('private-fixture-value'),code_context=True)")
    subprocess.run([sys.executable, "-c", code], check=True, timeout=5, capture_output=True)


def test_dense_annotation_line_refuses_bounded_verification():
    assert contains_credential_material("token: str, " * 10000, code_context=True)


def test_reference_inspection_never_executes_repository_expressions(tmp_path):
    marker = tmp_path / "never-executed"
    source = "password = __import__('pathlib').Path(" + repr(str(marker)) + ").write_text('executed')"
    assert contains_credential_material(source, code_context=True)
    assert not marker.exists()


@pytest.mark.parametrize("removed", [
    "SECRET_KEY=private-fixture-value", '{"password": "private-fixture-value"}',
    'password = None or "private-fixture-value"', '# password=private_fixture_value',
])
async def test_removed_credential_stays_local_even_when_current_source_is_safe(subject, transport, monkeypatch, removed):
    rate = AsyncMock(side_effect=AssertionError("removed credential must stay local"))
    monkeypatch.setattr("omargate.analyze.orchestrator.TypeSafeClient.rate", rate)
    result = await subject._run_cascade_analysis(
        ingest={"files": [{"path": "x.py"}]}, changed_files=["x.py"], scan_mode="pr-diff",
        deterministic_findings=[], quick_learn=None, spec_context=None, run_dir=None,
        diff_content="diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-" + removed + "\n+value = 1\n")
    rate.assert_not_awaited()
    transport.assert_not_awaited()
    assert result.failure_class == "cascade_source_privacy_incomplete"
    assert result.usage["policy_assessment"]["reason_code"] == "redacted_source"
