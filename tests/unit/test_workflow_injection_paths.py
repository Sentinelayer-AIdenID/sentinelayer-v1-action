import pytest

from omargate.analyze.deterministic.workflow_scanner import scan_workflow


def scan(expression, *, input_name=None):
    if input_name:
        step = "      - uses: docker://alpine@sha256:" + "a" * 64 + "\n        with:\n          " + input_name + ": |\n            ${{ " + expression + " }}\n"
    else:
        step = "      - run: |\n          echo ${{ " + expression + " }}\n"
    source = "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" + step
    return scan_workflow(".github/workflows/ci.yml", source)


@pytest.mark.parametrize("expression", [
    "github.event.issue.labels[0].name", "github.event.issue.labels[*].name",
    "github['event']['issue']['labels'][0]['name']", "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message", "github.event.commits[0].message", "github.event.commits.*.message",
    "github.event.deployment.description", "github.event.issue.author_association",
])
def test_indexed_and_less_common_context_strings_remain_executable_probes(expression):
    results = scan(expression)
    assert any(row.pattern_id == "CICD-001" and row.severity == "P0" for row in results)


@pytest.mark.parametrize("name", ["args", "entrypoint", "command", "script"])
def test_execution_related_action_inputs_are_reviewed_without_assuming_receiver_execution(name):
    results = scan("github.event.issue.title", input_name=name)
    assert any(row.pattern_id == "CICD-ACTION-INPUT" and row.severity == "P2" for row in results)


def test_all_action_input_values_are_seen_but_metadata_is_only_advisory():
    results = scan("github.event.issue.title", input_name="description")
    assert [(row.pattern_id, row.severity) for row in results] == [("CICD-INPUT-FLOW", "P4")]


@pytest.mark.parametrize("expression", ["github.event.issue.number", "github.event.comment.id",
    "github.sha", "github.event.repository.private", "'github.event.issue.title'", "format('github.event.issue.title')"])
def test_identifiers_boolean_metadata_and_quoted_path_literals_do_not_claim_injection(expression):
    assert scan(expression) == []


@pytest.mark.parametrize("rule", ["CICD-ACTION-INPUT", "CICD-INPUT-FLOW"])
def test_input_observations_cannot_corroborate_a_blocking_generator_finding(rule, tmp_path):
    from omargate.analyze.orchestrator import AnalysisOrchestrator
    from omargate.config import OmarGateConfig
    from omargate.logging import OmarLogger
    engine = AnalysisOrchestrator(OmarGateConfig(), OmarLogger("input-flow-test"), tmp_path, allow_llm=False)
    observed = {"rule_id": rule, "category": "ci-cd", "file_path": "ci.yml", "line_start": 2, "line_end": 2}
    assert not engine._is_corroborated("ci.yml", 2, 2, "ci-cd", [observed], typed_candidate=False)
