from __future__ import annotations

import json
from pathlib import Path

import pytest

from omargate.ingest import ingest_runner
from omargate.ingest.ingest_runner import run_ingest


class StubCompleted:
    def __init__(self, stdout: str) -> None:
        self.returncode = 0
        self.stdout = stdout
        self.stderr = ""


def test_run_ingest_returns_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo_root = tmp_path / "repo"
    (repo_root / "src").mkdir(parents=True)
    file_path = repo_root / "src" / "app.py"
    content = "print('hello')\n"
    file_path.write_text(content, encoding="utf-8")
    size_bytes = file_path.stat().st_size

    node_payload = {
        "files": [
            {
                "path": "src/app.py",
                "size_bytes": size_bytes,
            }
        ],
        "stats": {
            "binary_files": 1,
            "too_large": 0,
            "truncated": False,
        },
    }

    def fake_run(args, **kwargs):
        return StubCompleted(json.dumps(node_payload))

    monkeypatch.setattr(ingest_runner.subprocess, "run", fake_run)

    result = run_ingest(repo_root)

    assert result["schema_version"] == "1.0"
    assert "timestamp_utc" in result
    assert result["stats"]["text_files"] == 1
    assert result["stats"]["binary_files"] == 1
    assert result["stats"]["total_files"] == 2
    assert result["stats"]["in_scope_files"] == 1
    assert result["stats"]["total_lines"] == 1
    assert len(result["files"]) == 1
    assert result["files"][0]["path"] == "src/app.py"
    assert result["files"][0]["language"] == "python"
    assert result["dependencies"]["package_manager"] == "unknown"


def test_run_ingest_passes_max_files_to_node(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        payload = {"files": [], "stats": {}}
        return StubCompleted(json.dumps(payload))

    monkeypatch.setattr(ingest_runner.subprocess, "run", fake_run)

    run_ingest(repo_root, max_files=5)

    assert captured["args"][3] == "5"


def test_run_ingest_respects_ignore_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo_root = tmp_path / "repo"
    (repo_root / "tests").mkdir(parents=True)
    (repo_root / "src").mkdir(parents=True)
    (repo_root / ".sentinelayerignore").write_text("tests/\n", encoding="utf-8")

    ignored_file = repo_root / "tests" / "secret.py"
    ignored_file.write_text("password = 'fake'\n", encoding="utf-8")
    kept_file = repo_root / "src" / "app.py"
    kept_file.write_text("print('ok')\n", encoding="utf-8")

    node_payload = {
        "files": [
            {"path": "tests/secret.py", "size_bytes": ignored_file.stat().st_size},
            {"path": "src/app.py", "size_bytes": kept_file.stat().st_size},
        ],
        "stats": {"binary_files": 0, "too_large": 0, "truncated": False},
    }

    def fake_run(args, **kwargs):
        return StubCompleted(json.dumps(node_payload))

    monkeypatch.setattr(ingest_runner.subprocess, "run", fake_run)

    result = run_ingest(repo_root)

    paths = [entry["path"] for entry in result["files"]]
    assert "tests/secret.py" not in paths
    assert "src/app.py" in paths


def test_run_ingest_default_ignores_tests_and_env_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root = tmp_path / "repo"
    (repo_root / "tests").mkdir(parents=True)
    (repo_root / "src").mkdir(parents=True)

    env_file = repo_root / ".env.local"
    env_file.write_text("OPENAI_API_KEY=dummy\n", encoding="utf-8")
    ignored_file = repo_root / "tests" / "secret.py"
    ignored_file.write_text("password = 'fake'\n", encoding="utf-8")
    kept_file = repo_root / "src" / "app.py"
    kept_file.write_text("print('ok')\n", encoding="utf-8")

    node_payload = {
        "files": [
            {"path": ".env.local", "size_bytes": env_file.stat().st_size},
            {"path": "tests/secret.py", "size_bytes": ignored_file.stat().st_size},
            {"path": "src/app.py", "size_bytes": kept_file.stat().st_size},
        ],
        "stats": {"binary_files": 0, "too_large": 0, "truncated": False},
    }

    def fake_run(args, **kwargs):
        return StubCompleted(json.dumps(node_payload))

    monkeypatch.setattr(ingest_runner.subprocess, "run", fake_run)

    result = run_ingest(repo_root)

    paths = [entry["path"] for entry in result["files"]]
    assert ".env.local" not in paths
    assert "tests/secret.py" not in paths
    assert "src/app.py" in paths


def test_run_ingest_default_ignores_local_cache_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root = tmp_path / "repo"
    (repo_root / ".mypy_cache").mkdir(parents=True)
    (repo_root / "src").mkdir(parents=True)

    ignored_file = repo_root / ".mypy_cache" / "meta.json"
    ignored_file.write_text("{}", encoding="utf-8")
    kept_file = repo_root / "src" / "app.py"
    kept_file.write_text("print('ok')\n", encoding="utf-8")

    node_payload = {
        "files": [
            {"path": ".mypy_cache/meta.json", "size_bytes": ignored_file.stat().st_size},
            {"path": "src/app.py", "size_bytes": kept_file.stat().st_size},
        ],
        "stats": {"binary_files": 0, "too_large": 0, "truncated": False},
    }

    def fake_run(args, **kwargs):
        return StubCompleted(json.dumps(node_payload))

    monkeypatch.setattr(ingest_runner.subprocess, "run", fake_run)

    result = run_ingest(repo_root)

    paths = [entry["path"] for entry in result["files"]]
    assert ".mypy_cache/meta.json" not in paths
    assert "src/app.py" in paths
