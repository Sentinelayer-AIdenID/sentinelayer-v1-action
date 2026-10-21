from __future__ import annotations

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
