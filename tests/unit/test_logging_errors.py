from __future__ import annotations

import json

from omargate.constants import ExitCode
from omargate.errors import DedupeSkip, GateBlockedError
from omargate.logging import OmarLogger


def test_logger_emits_json(capsys) -> None:
    logger = OmarLogger("run-1")
    logger.info("hello", detail="world")
    captured = capsys.readouterr()

    payload = json.loads(captured.err.strip().splitlines()[0])
    assert payload["run_id"] == "run-1"
    assert payload["message"] == "hello"
    assert payload["detail"] == "world"


def test_logger_emits_error_annotation(capsys) -> None:
    logger = OmarLogger("run-2")
    logger.error("fail")
    captured = capsys.readouterr()
    assert "::error::fail" in captured.err


def test_logger_redacts_sensitive_keys(capsys) -> None:
    logger = OmarLogger("run-3")
    logger.info("secret", api_key="sk_test_dummy")
    captured = capsys.readouterr()
    payload = json.loads(captured.err.strip().splitlines()[0])
    assert payload["api_key"] == "***"


def test_error_exit_codes() -> None:
    assert GateBlockedError().exit_code == ExitCode.BLOCKED
    assert DedupeSkip().exit_code == ExitCode.SKIPPED
