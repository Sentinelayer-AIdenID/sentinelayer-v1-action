from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from omargate.analyze.codex import codex_runner
from omargate.analyze.codex.codex_runner import (
    CodexRunner,
    _codex_child_env,
    extract_codex_cli_failure,
    parse_codex_findings,
)


def test_jsonl_parsing_valid() -> None:
    text = (
        '{"severity":"P1","category":"auth","file_path":"src/a.py","line_start":3,"message":"x",'
        '"fix_plan":"Pseudo-code: enforce auth guard in this handler and add authorization tests."}'
    )
    findings, errors, no_findings = parse_codex_findings(text)
    assert len(findings) == 1
    assert errors == []
    assert no_findings is False
    assert findings[0]["source"] == "codex"
    assert "auth guard" in findings[0]["fix_plan"]


def test_jsonl_parsing_malformed_lines() -> None:
    text = "\n".join(
        [
            "{not json}",
            '{"severity":"P9","category":"x","file_path":"a","line_start":1,"message":"x"}',
            '{"severity":"P2","category":"x","file_path":"a","line_start":1,"message":"ok"}',
        ]
    )
    findings, errors, no_findings = parse_codex_findings(text)
    assert len(findings) == 1
    assert no_findings is False
    assert len(errors) >= 2
    assert findings[0]["fix_plan"].startswith("Pseudo-code:")


def test_jsonl_parsing_empty() -> None:
    findings, errors, no_findings = parse_codex_findings("")
    assert findings == []
    assert no_findings is False
    assert errors


def test_code_fenced_jsonl_is_stripped_cleanly() -> None:
    text = "\n".join(
        [
            "```jsonl",
            '{"severity":"P1","category":"auth","file_path":"src/a.py","line_start":3,"message":"x"}',
            "```",
        ]
    )
    findings, errors, no_findings = parse_codex_findings(text)
    assert len(findings) == 1
    assert errors == []
    assert no_findings is False


def test_exact_clean_sentinel_is_accepted() -> None:
    findings, errors, no_findings = parse_codex_findings('{"no_findings": true}')

    assert findings == []
    assert errors == []
    assert no_findings is True


def test_extract_codex_cli_failure_prefers_terminal_event() -> None:
    stdout = "\n".join(
        [
            '{"type":"error","message":"Reconnecting... 1/5"}',
            '{"type":"turn.failed","error":{"message":"unexpected status 401 Unauthorized"}}',
        ]
    )

    assert extract_codex_cli_failure(stdout) == "unexpected status 401 Unauthorized"


def test_codex_child_env_is_an_exact_process_allowlist() -> None:
    inherited = {
        "PATH": "/tools/bin",
        "HOME": "/home/runner",
        "TMPDIR": "/tmp",
        "LANG": "en_US.UTF-8",
        "SYSTEMROOT": r"C:\Windows",
        "COMSPEC": r"C:\Windows\System32\cmd.exe",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "CODEX_HOME": "/home/runner/.codex",
        "PYTHONPATH": "/attacker/imports",
        "NODE_OPTIONS": "--require=/attacker/preload.js",
        "INPUT_OPENAI_API_KEY": "input-openai-secret",
        "OPENAI_API_KEY": "ambient-openai-secret",
        "CODEX_API_KEY": "ambient-codex-secret",
        "CODEX_MODEL": "ambient-model",
        "TYPESAFE_API_KEY": "typesafe-secret",
        "INPUT_TYPESAFE_API_KEY": "input-typesafe-secret",
        "ANTHROPIC_API_KEY": "anthropic-secret",
        "GEMINI_API_KEY": "gemini-secret",
        "XAI_API_KEY": "xai-secret",
        "GITHUB_TOKEN": "github-secret",
        "INPUT_SENTINELAYER_TOKEN": "sentinelayer-secret",
        "SENTINELAYER_TOKEN": "sentinelayer-secret-2",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-secret",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "DATABASE_PASSWORD": "database-secret",
        "GENERIC_TOKEN": "generic-secret",
    }

    child = _codex_child_env(
        api_key="intended-codex-key",
        model="gpt-5.3-codex",
        inherited=inherited,
    )

    assert child == {
        "PATH": "/tools/bin",
        "HOME": "/home/runner",
        "TMPDIR": "/tmp",
        "LANG": "en_US.UTF-8",
        "SYSTEMROOT": r"C:\Windows",
        "COMSPEC": r"C:\Windows\System32\cmd.exe",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "CODEX_HOME": "/home/runner/.codex",
        "OPENAI_API_KEY": "intended-codex-key",
        "CODEX_API_KEY": "intended-codex-key",
        "CODEX_MODEL": "gpt-5.3-codex",
    }


@pytest.mark.anyio
async def test_codex_subprocess_receives_only_the_bounded_child_env(
    tmp_path: Path, monkeypatch
) -> None:
    inherited = {
        "PATH": "/tools/bin",
        "HOME": "/home/runner",
        "TEMP": str(tmp_path),
        "CODEX_HOME": "/home/runner/.codex",
        "TYPESAFE_API_KEY": "typesafe-secret",
        "ANTHROPIC_API_KEY": "anthropic-secret",
        "GITHUB_TOKEN": "github-secret",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-secret",
        "CUSTOM_PASSWORD": "password-secret",
    }
    captured: dict[str, str] = {}

    class FakeProc:
        returncode = 0

        async def communicate(self, input: bytes | None = None):  # noqa: A002
            assert input == b"audit prompt"
            return b"", b""

    async def fake_create(*args, **kwargs):  # noqa: ANN001
        captured.update(kwargs["env"])
        output_path = Path(args[args.index("--output-last-message") + 1])
        output_path.write_text('{"no_findings": true}', encoding="utf-8")
        return FakeProc()

    monkeypatch.setattr(codex_runner.os, "environ", inherited)
    monkeypatch.setattr("shutil.which", lambda _: "codex")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)

    result = await CodexRunner(
        api_key="intended-codex-key", model="gpt-5.3-codex"
    ).run_audit(prompt="audit prompt", working_dir=str(tmp_path))

    assert result.success is True
    assert captured == {
        "PATH": "/tools/bin",
        "HOME": "/home/runner",
        "TEMP": str(tmp_path),
        "CODEX_HOME": "/home/runner/.codex",
        "OPENAI_API_KEY": "intended-codex-key",
        "CODEX_API_KEY": "intended-codex-key",
        "CODEX_MODEL": "gpt-5.3-codex",
    }


@pytest.mark.anyio
async def test_nonzero_exit_uses_json_error_without_prompt_content(
    tmp_path: Path, monkeypatch
) -> None:
    class FakeProc:
        returncode = 1

        async def communicate(self, input: bytes | None = None):  # noqa: A002
            assert input == b"private prompt content"
            return (
                b'{"type":"turn.failed","error":{"message":"unexpected status 403 Forbidden"}}',
                b"user\nprivate prompt content",
            )

    async def fake_create(*args, **kwargs):  # noqa: ANN001
        assert "--json" in args
        return FakeProc()

    monkeypatch.setattr("shutil.which", lambda _: "codex")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)

    result = await CodexRunner(api_key="sk_test_dummy").run_audit(
        prompt="private prompt content",
        working_dir=str(tmp_path),
    )

    assert result.success is False
    assert result.error == "Codex exited with code 1: unexpected status 403 Forbidden"
    assert "private prompt content" not in result.error


@pytest.mark.anyio
async def test_timeout_handling(tmp_path: Path, monkeypatch) -> None:
    class FakeProc:
        def __init__(self) -> None:
            self.returncode = None

        async def communicate(self, input: bytes | None = None):  # noqa: A002
            await asyncio.sleep(10)
            return b"", b""

        def kill(self) -> None:
            self.returncode = -9

    async def fake_create(*args, **kwargs):  # noqa: ANN001
        return FakeProc()

    monkeypatch.setattr("shutil.which", lambda _: "codex")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)

    runner = CodexRunner(api_key="sk_test_dummy", model="gpt-5.2-codex")
    res = await runner.run_audit(prompt="x", working_dir=str(tmp_path), timeout=0.01)
    assert res.success is False
    assert res.error and "timed out" in res.error.lower()


@pytest.mark.anyio
async def test_missing_codex_cli_is_graceful(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    runner = CodexRunner(api_key="sk_test_dummy", model="gpt-5.2-codex")
    res = await runner.run_audit(prompt="x", working_dir=str(tmp_path))
    assert res.success is False
    assert res.error and "not found" in res.error.lower()
