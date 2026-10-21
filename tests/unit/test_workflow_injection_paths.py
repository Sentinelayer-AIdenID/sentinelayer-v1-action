from dataclasses import asdict
import json

import pytest

from omargate.analyze.deterministic.workflow_scanner import scan_workflow


def scan(expression, *, input_name=None, reference=None):
    if input_name:
        reference = reference or "owner/action@" + "a" * 40
        step = "      - uses: " + reference + "\n        with:\n          " + input_name + ": |\n            ${{ " + expression + " }}\n"
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


@pytest.mark.parametrize("reference", ["docker://alpine:latest", "docker://alpine@sha256:" + "a" * 64])
@pytest.mark.parametrize("name", ["args", "entrypoint"])
def test_container_execution_inputs_with_untrusted_context_block_the_default_gate(tmp_path, reference, name):
    from omargate.gate import evaluate_gate
    from omargate.models import GateConfig, GateStatus
    from omargate.utils import sha256_hex

    # A container is the receiver: unlike owner/action@sha, its execution input
    # has no intervening action implementation that can validate the value.
    text = ("jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: " + reference + "\n        with:\n          " + name
            + ": sh -c \"echo ${{ github.event.issue.title }}\"\n")
    findings = scan_workflow(".github/workflows/ci.yml", text)
    counts = {severity: sum(row.severity == severity for row in findings) for severity in ("P0", "P1", "P2", "P3", "P4")}
    packed = tmp_path / "FINDINGS.jsonl"
    packed.write_text("\n".join(json.dumps(asdict(row)) for row in findings), encoding="utf-8")
    (tmp_path / "PACK_SUMMARY.json").write_text(json.dumps({
        "run_id": "container-injection", "writer_complete": True, "counts": counts,
        "findings_file": packed.name, "findings_file_sha256": sha256_hex(packed.read_bytes()),
    }), encoding="utf-8")
    result = evaluate_gate(tmp_path, GateConfig())
    assert result.status == GateStatus.BLOCKED
    assert result.block_merge is True
    assert counts["P0"] == 1
    assert any(row.pattern_id == "CICD-001" and row.severity == "P0" for row in findings)


@pytest.mark.parametrize("name", ["args", "entrypoint"])
def test_container_execution_input_boundaries_do_not_trust_pinning_or_shell_quoting(name):
    reference = "docker://alpine@sha256:" + "a" * 64
    rows = scan("github['event']['issue']['title']", input_name=name, reference=reference)
    assert [(row.pattern_id, row.severity) for row in rows] == [("CICD-001", "P0")]


def test_container_literal_commands_and_quoted_environment_data_remain_clean():
    text = ("jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: docker://alpine@sha256:" + "a" * 64 + "\n"
            "        env:\n          TITLE: ${{ github.event.issue.title }}\n"
            "        with:\n          entrypoint: sh\n          args: -c 'printf %s \"$TITLE\"'\n")
    assert scan_workflow(".github/workflows/ci.yml", text) == []
    assert scan("github.event.issue.number", input_name="args", reference="docker://alpine@sha256:" + "a" * 64) == []


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
