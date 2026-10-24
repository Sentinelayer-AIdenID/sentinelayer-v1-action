from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from omargate.models import Counts, GateResult, GateStatus
from omargate.publish import write_step_summary


def test_step_summary_writes_file(tmp_path, monkeypatch) -> None:
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    gate_result = GateResult(
        status=GateStatus.PASSED,
        reason="All good",
        block_merge=False,
        counts=Counts(p0=0, p1=0, p2=1, p3=2),
        dedupe_key="dedupe-123",
    )
    summary = {"counts": {"P0": 0, "P1": 0, "P2": 1, "P3": 2}}
    findings = [
        {
            "severity": "P2",
            "file_path": "app.py",
            "line_start": 5,
            "message": "Example issue",
        }
    ]

    write_step_summary(
        gate_result,
        summary,
        findings,
        "test-run",
        "1.0.0",
        codebase_snapshot={
            "stats": {"in_scope_files": 10, "source_loc_total": 1000},
            "languages": [{"language": "python", "files": 8, "loc": 900}],
            "hotspots": [],
        },
        codebase_synopsis="README: Deterministic gate for CI pipelines.",
    )

    assert summary_file.exists()
    content = summary_file.read_text(encoding="utf-8")
    assert "Omar Gate" in content
    assert "P0" in content
    assert "Codebase Synopsis" in content
    assert "README&#58; Deterministic gate for CI pipelines&#46;" in content


def test_step_summary_neutralizes_untrusted_markdown(tmp_path, monkeypatch) -> None:
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    gate_result = GateResult(
        status=GateStatus.PASSED,
        reason="All good\n## PASSED [click](https://evil.test) <img src=x> @admins",
        block_merge=False,
        counts=Counts(p0=0, p1=0, p2=1, p3=0),
        dedupe_key="dedupe-unsafe",
    )
    finding = {
        "severity": "P2\n## PASSED",
        "file_path": "`breakout` [click](https://evil.test)",
        "line_start": "5\n## PASSED",
        "category": "auth </details><img src=x>",
        "message": "message @admins :shipit: ```spoof```",
    }

    write_step_summary(
        gate_result,
        {"counts": {"P0": 0, "P1": 0, "P2": 1, "P3": 0}},
        [finding],
        "@admins!",
        "1.0</sub><img src=x>",
        codebase_snapshot={
            "stats": {"in_scope_files": 1, "source_loc_total": 10},
            "languages": [
                {"language": "Python | forged", "files": 1, "loc": 10}
            ],
            "hotspots": [
                {
                    "category": "## PASSED",
                    "count": 1,
                    "examples": ["</details><img src=x>"],
                }
            ],
        },
        codebase_synopsis="README\n## PASSED [click](javascript:alert(1))",
    )

    content = summary_file.read_text(encoding="utf-8")
    assert "\n## PASSED" not in content
    assert "[click](" not in content
    assert "<img" not in content
    assert "@admins" not in content
    assert "```spoof```" not in content
    assert "&#35;&#35; PASSED" in content
    assert "&#60;img src&#61;x&#62;" in content
    assert "&#64;admins" in content


@pytest.mark.parametrize("encoding", ["cp1252", "ascii", "utf-8"])
def test_real_console_encoding_preserves_report_and_final_error_order(tmp_path, encoding):
    summary_file = tmp_path / "summary.md"
    env = {**os.environ, "PYTHONIOENCODING": f"{encoding}:strict",
           "GITHUB_STEP_SUMMARY": str(summary_file)}
    source = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [source, env.get("PYTHONPATH")]))
    program = r'''
import sys
from pathlib import Path
from omargate.models import Counts, GateResult, GateStatus
from omargate.publish import write_step_summary
from omargate.runtime_helpers import _emit_gate_annotation
gate = GateResult(status=GateStatus.BLOCKED, reason="Review incomplete: \u6f22\u5b57",
                  block_merge=True, counts=Counts(p0=1, p1=1, p2=8, p3=48), dedupe_key="fixture")
write_step_summary(gate, {"severity_gate": "P1"}, [
    {"severity": "P1", "file_path": "source.py", "line_start": 1,
     "message": "::error::untrusted fixture"}], "fixture-run", "1.0.0")
_emit_gate_annotation(gate_result=gate, severity_gate="P1", run_id="fixture-run",
                      run_dir=Path("."), workflow_run_url=None, dashboard_url=None)
raise SystemExit(1)
'''
    result = subprocess.run([sys.executable, "-c", program], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    assert result.returncode == 1
    console = result.stdout.decode(encoding, errors="strict")
    assert "UnicodeEncodeError" not in console
    assert "P3 (Low) | 48" in console
    token = re.search(r"::stop-commands::([a-f0-9]{32})", console)
    assert token is not None
    assert (console.index(token.group(0)) < console.index("::error::untrusted fixture")
            < console.index(f"::{token.group(1)}::")
            < console.index("::endgroup::") < console.index("::error title="))
    saved = summary_file.read_text(encoding="utf-8")
    assert "\U0001f6e1\ufe0f" in saved  # The file keeps the full Unicode template.
    assert "Review incomplete&#58; \u6f22\u5b57" in saved


def test_console_io_failure_cannot_prevent_persisted_summary(tmp_path, monkeypatch):
    import omargate.publish.step_summary as module
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    def broken_console(_):
        raise OSError("owned fixture broken pipe")
    monkeypatch.setattr(module, "_write_console_report", broken_console)
    gate = GateResult(status=GateStatus.BLOCKED, reason="Incomplete review", block_merge=True,
                      counts=Counts(p0=1), dedupe_key="fixture")
    with pytest.raises(OSError, match="owned fixture broken pipe"):
        write_step_summary(gate, {}, [], "fixture", "1.0.0")
    assert "Incomplete review" in summary_file.read_text(encoding="utf-8")


def test_summary_file_io_failure_cannot_prevent_console_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path))  # A directory is not a summary file.
    gate = GateResult(status=GateStatus.BLOCKED, reason="Incomplete review", block_merge=True,
                      counts=Counts(p0=1), dedupe_key="fixture")
    with pytest.raises(OSError):
        write_step_summary(gate, {}, [], "fixture", "1.0.0")
    assert "Incomplete review" in capsys.readouterr().out
