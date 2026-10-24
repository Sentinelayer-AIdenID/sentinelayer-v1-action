"""Exercise the real process boundary with offline npm stand-ins, never network."""
import json
import os
import shutil
from dataclasses import asdict
from pathlib import Path

import pytest
import test_dep_audit_suite as fixture
from test_nested_npm_audits import evaluate

from omargate.harness.suites.dep_audit import DepAuditSuite

pytestmark = pytest.mark.anyio


def npm_standin(directory: Path, marker: Path, *, clean: bool) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("real Node executable required for process-boundary proof")
    directory.mkdir(parents=True)
    payload = fixture._clean_stdout("npm") if clean else fixture._vulnerable_stdout("npm")
    source = ("require('node:fs').writeFileSync(" + json.dumps(str(marker)) + ", 'executed');\n"
              + "process.stdout.write(" + json.dumps(payload) + ");\n"
              + f"process.exit({0 if clean else 1});\n")
    if os.name == "nt":
        (directory / "npm.cmd").write_text("@echo off\n")
        cli = directory / "node_modules/npm/bin/npm-cli.js"
        cli.parent.mkdir(parents=True)
        cli.write_text(source)
    else:
        command = directory / "npm"
        command.write_text("#!" + node + "\n" + source)
        command.chmod(0o700)


@pytest.mark.parametrize("nested", [False, True], ids=["root-control", "nested-project"])
async def test_workspace_root_npm_shim_cannot_forge_a_clean_gate(tmp_path, monkeypatch, nested):
    workspace = tmp_path / "checkout"
    project = workspace / "apps/web" if nested else workspace
    project.mkdir(parents=True)
    fixture._prepare_project(project, "npm")
    malicious, trusted = workspace / "tools/bin", tmp_path / "runner-tools"
    malicious_marker, trusted_marker = tmp_path / "malicious-ran", tmp_path / "trusted-ran"
    npm_standin(malicious, malicious_marker, clean=True)
    npm_standin(trusted, trusted_marker, clean=False)
    monkeypatch.setenv("PATH", os.pathsep.join((str(malicious), str(trusted), os.environ["PATH"])))
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(workspace))
    gate = evaluate(workspace, result.evidence.to_dict(), findings=[asdict(f) for f in result.findings])
    assert gate.block_merge, "checkout-owned npm forged a passing end-to-end gate"
    assert not malicious_marker.exists(), "checkout-owned npm executed through the real runner"
    assert trusted_marker.exists(), "trusted offline npm control must actually execute"
    assert result.evidence.complete
    assert next(row for row in result.evidence.outcomes if row.ecosystem == "npm").state == "vulnerable"


@pytest.mark.parametrize("variable", ["NODE_EXTRA_CA_CERTS", "NPM_CONFIG_CAFILE"])
async def test_workspace_root_ca_file_is_rejected_for_a_nested_project(tmp_path, monkeypatch, variable):
    workspace = tmp_path / "checkout"
    project = workspace / "apps/web"
    project.mkdir(parents=True)
    fixture._prepare_project(project, "npm")
    ca = workspace / "tools/root-ca.crt"
    ca.parent.mkdir()
    ca.write_text("test-only trust configuration; no real certificate")
    trusted, marker = tmp_path / "runner-tools", tmp_path / "trusted-ran"
    npm_standin(trusted, marker, clean=True)
    monkeypatch.setenv("PATH", os.pathsep.join((str(trusted), os.environ["PATH"])))
    monkeypatch.setenv(variable, str(ca))
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(workspace))
    assert not marker.exists(), "workspace CA material reached a real child process"
    assert not result.evidence.complete
    assert evaluate(workspace, result.evidence.to_dict()).block_merge


@pytest.mark.parametrize("directory", ["vendor", "services/build", "apps/dist", "infra/target/lambda", "venv", ".venv", ".tox", "__pycache__"])
async def test_directory_names_cannot_hide_a_required_npm_manifest(tmp_path, directory):
    (tmp_path / "package.json").write_text('{"name":"empty-parent"}')
    child = tmp_path / directory
    child.mkdir(parents=True)
    fixture._prepare_project(child, "npm", include_lock=False)
    result = await DepAuditSuite(tech_stack=[]).run_with_evidence(str(tmp_path))
    assert not result.evidence.complete
    assert (directory + "/package.json") in result.evidence.to_dict()["npm_projects"]["discovered_manifests"]
    assert evaluate(tmp_path, result.evidence.to_dict()).block_merge
