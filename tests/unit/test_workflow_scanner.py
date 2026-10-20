import json

import pytest

from omargate.analyze.deterministic.workflow_scanner import scan_workflow, scan_workflow_files
from omargate.analyze.deterministic.eng_quality_scanner import EngQualityScanner
from omargate.analyze.deterministic.pattern_scanner import PatternScanner

PATH = ".github/workflows/ci.yml"
SHA = "a" * 40


def workflow(steps):
    return "name: test\non: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n" + steps


def ids(text, lock=None):
    return [finding.pattern_id for finding in scan_workflow(PATH, text, lock_text=lock)]


@pytest.mark.parametrize("expression", [
    "github.event.pull_request.title", "github['event']['comment']['body']", "github.head_ref", "inputs.script",
])
def test_untrusted_executable_interpolation_including_previously_missed_pr_title(expression):
    text = workflow("      - run: |\n          echo \"${{ " + expression + " }}\"\n")
    assert "CICD-001" in ids(text)


def test_safe_env_and_action_arguments_are_data_not_script_injection():
    text = workflow(f"      - uses: actions/checkout@{SHA}\n"
                    "      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n"
                    "        run: printf '%s' \"$TITLE\"\n"
                    f"      - uses: owner/action@{SHA}\n"
                    "        with:\n          title: ${{ github.event.issue.title }}\n")
    assert ids(text) == []
    assert ids(workflow("      - run: echo '${{ github.event.issue.number }}'\n")) == []


def test_github_script_inline_expression_is_code_but_context_api_is_not():
    direct = workflow(f"      - uses: actions/github-script@{SHA}\n        with:\n          script: console.log('${{{{ github.event.issue.title }}}}')\n")
    assert "CICD-001" in ids(direct)
    api = workflow(f"      - uses: actions/github-script@{SHA}\n        with:\n          script: console.log(context.payload.issue.title)\n")
    assert ids(api) == []


def lock(commit="sha1-" + SHA, repo_id="123", workflow_path=PATH):
    return ("version: v0.0.2\nworkflows:\n  '" + workflow_path + "':\n    - owner/action@v3\n"
            "dependencies:\n  owner/action@v3:\n    ref: v3\n    commit: " + commit + "\n    owner_id: 99\n    repo_id: " + repo_id + "\n")


def test_version_tags_need_pin_or_exact_onboarded_lock():
    text = workflow("      - uses: owner/action@v3\n")
    assert ids(text) == ["CICD-002"]
    assert ids(text, lock()) == []
    assert ids(text, lock(workflow_path=".github/workflows/other.yml")) == ["CICD-002"]
    assert ids(workflow(f"      - uses: owner/action@{SHA}\n")) == []
    assert ids(workflow("      - uses: ./local-action\n")) == []


@pytest.mark.parametrize("kwargs", [{"commit": "main"}, {"repo_id": "0"}, {"repo_id": "false"}])
def test_malformed_lock_cannot_suppress_dependency_warning(kwargs):
    assert "CICD-COVERAGE-INCOMPLETE" in ids(workflow("      - uses: owner/action@v3\n"), lock(**kwargs))


@pytest.mark.parametrize("text", ["jobs: [", "jobs: {}\njobs: {}\n", "!!python/object/apply:os.system ['exit 1']"])
def test_invalid_or_ambiguous_yaml_reports_incomplete(text):
    assert "CICD-COVERAGE-INCOMPLETE" in ids(text)


def test_lock_version_is_validated_even_when_direct_dependencies_are_pinned():
    text = workflow(f"      - uses: owner/action@{SHA}\n")
    assert "CICD-COVERAGE-INCOMPLETE" in ids(text, lock().replace("v0.0.2", "v999"))


def test_oversize_and_missing_source_are_incomplete_not_clean(tmp_path):
    assert "CICD-COVERAGE-INCOMPLETE" in ids("a" * 1_000_001)
    results = scan_workflow_files([{"path": PATH}], tmp_path)
    assert results[0].pattern_id == "CICD-COVERAGE-INCOMPLETE"


def test_reusable_workflow_and_docker_dependencies():
    reusable = "jobs:\n  build:\n    uses: owner/repo/.github/workflows/ci.yml@v2\n"
    assert ids(reusable) == ["CICD-002"]
    assert ids(workflow("      - uses: docker://alpine:latest\n")) == ["CICD-002"]
    assert ids(workflow("      - uses: docker://alpine@sha256:" + "b" * 64 + "\n")) == []


def test_comments_do_not_create_executable_workflow_dependencies():
    text = workflow("      # uses: owner/action@main\n      - run: echo done\n")
    assert ids(text) == []


def test_modern_react_updates_are_not_automatically_a_defect():
    scanner = EngQualityScanner(["React"])
    direct = scanner.scan({"App.tsx": "items.forEach(item => { setCount(item.count); });\n"})
    advisory = [finding for finding in direct if finding.pattern_id == "EQ-001"]
    assert advisory and advisory[0].severity == "P4" and advisory[0].confidence < .8
    for code in ["items.forEach(item => { setCount(n => n + item.count); });",
                 "items.forEach(item => { setCount((n) => n + item.count); });",
                 "// items.forEach(item => { setCount(item.count); });"]:
        assert not any(f.pattern_id == "EQ-001" for f in scanner.scan({"App.tsx": code}))


def test_regex_rules_have_explicit_retirement_and_new_scanner_runs_in_orchestrator(tmp_path):
    from pathlib import Path
    from omargate.analyze.orchestrator import AnalysisOrchestrator
    from omargate.config import OmarGateConfig
    from omargate.logging import OmarLogger
    patterns = Path(__file__).parents[2] / "src/omargate/analyze/deterministic/patterns"
    metadata = json.loads((patterns / "ci_cd.json").read_text())
    assert {row["id"] for row in metadata["retired_patterns"]} == {"CICD-001", "CICD-002"}
    assert not any(p["id"] in {"CICD-001", "CICD-002"} for p in PatternScanner(patterns).patterns)
    target = tmp_path / PATH
    target.parent.mkdir(parents=True)
    target.write_text(workflow("      - run: echo '${{ github.event.pull_request.title }}'\n"))
    orchestrator = AnalysisOrchestrator(OmarGateConfig(), OmarLogger("workflow-test"), tmp_path, allow_llm=False)
    results = orchestrator._run_deterministic_scans({"files": [{"path": PATH, "category": "config"}]})
    assert any(f["id"].startswith("CICD-001-") for f in results)
