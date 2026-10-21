from __future__ import annotations

import asyncio
import json
import os
import signal
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import omargate.harness.runner as harness_runner
from omargate.harness.runner import (
    HarnessRunner,
    SecuritySuite,
    _harness_child_env,
    run_command,
)


ROOT = Path(__file__).resolve().parents[2]


def _touch(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _external_tool(tmp_path: Path, name: str = "audit-tool") -> tuple[Path, Path]:
    tool_directory = tmp_path.parent / f"{tmp_path.name}-tools"
    tool_directory.mkdir(exist_ok=True)
    filename = f"{name}.EXE" if os.name == "nt" else name
    tool = tool_directory / filename
    tool.write_text("external tool placeholder", encoding="utf-8")
    tool.chmod(0o755)
    return tool_directory, tool


def _stream(data: bytes, *, eof: bool = True) -> asyncio.StreamReader:
    stream = asyncio.StreamReader()
    if data:
        stream.feed_data(data)
    if eof:
        stream.feed_eof()
    return stream


def _process_is_running(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, pid)
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(handle, 0) == 0x00000102
        finally:
            kernel32.CloseHandle(handle)
    try:
        process_stat = Path(f"/proc/{pid}/stat")
        if process_stat.is_file() and process_stat.read_text().split()[2] == "Z":
            return False
        os.kill(pid, 0)
    except (OSError, IndexError):
        return False
    return True


class _CompletedProcess:
    def __init__(
        self,
        *,
        returncode: int = 0,
        stdout: bytes = b"{}",
        stderr: bytes = b"",
    ) -> None:
        self.returncode: int | None = returncode
        self.stdout = _stream(stdout)
        self.stderr = _stream(stderr)
        self.killed = False

    async def wait(self) -> int:
        assert self.returncode is not None
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class _BlockingProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.stdout = _stream(b"", eof=False)
        self.stderr = _stream(b"", eof=False)
        self.killed = False
        self.reaped = False
        self._done = asyncio.Event()

    async def wait(self) -> int:
        await self._done.wait()
        self.reaped = True
        assert self.returncode is not None
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._done.set()


class _ExitedWithHeldPipesProcess:
    def __init__(self) -> None:
        self.returncode: int | None = 0
        self.stdout = _stream(b"{}", eof=False)
        self.stderr = _stream(b"", eof=False)
        self.wait_calls = 0
        self.killed = False

    async def wait(self) -> int:
        self.wait_calls += 1
        return 0

    def kill(self) -> None:
        self.killed = True


class _DirectTestContainment:
    uses_windows_launcher = False

    def attach(self, _proc: object) -> None:
        return None

    async def terminate(self, _proc: object) -> bool:
        return False

    async def verify_empty(self) -> bool:
        return True

    def close(self) -> bool:
        return True


class _RecordingWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _BlockedLauncherProcess(_BlockingProcess):
    def __init__(self) -> None:
        super().__init__()
        self.pid = 424242
        self.stdin = _RecordingWriter()


@pytest.fixture
def direct_test_containment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        harness_runner._ProcessContainment,
        "create",
        staticmethod(lambda: _DirectTestContainment()),
    )


def test_process_containment_rejects_process_without_valid_pid() -> None:
    containment = harness_runner._ProcessContainment()
    with pytest.raises(harness_runner._HarnessSetupError) as raised:
        containment.attach(object())  # type: ignore[arg-type]
    assert raised.value.reason_code == "process_containment_error"


@pytest.mark.anyio
async def test_invalid_pid_attach_failure_retains_scratch_and_is_unproven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool_directory, _tool = _external_tool(tmp_path)
    process = _BlockingProcess()
    captured_env: dict[str, str] = {}

    async def _invalid_pid_process(*_args: str, **kwargs: object) -> _BlockingProcess:
        env = kwargs.get("env")
        assert isinstance(env, dict)
        captured_env.update(env)
        return process

    monkeypatch.setattr(
        harness_runner._ProcessContainment,
        "create",
        staticmethod(lambda: harness_runner._ProcessContainment()),
    )
    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", _invalid_pid_process
    )

    result = await run_command(
        ["audit-tool"],
        cwd=tmp_path,
        timeout_s=5,
        inherited_env={"PATH": str(tool_directory)},
    )

    retained_root = Path(captured_env["HOME"]).parent
    try:
        assert result.status == "spawn_error"
        assert result.reason_code == "process_containment_error"
        assert result.cleanup_proven is False
        assert process.killed is True
        assert process.reaped is True
        assert retained_root.is_dir()
    finally:
        shutil.rmtree(retained_root, ignore_errors=True)


def test_node_project_selects_expected_suites(tmp_path: Path) -> None:
    _touch(tmp_path / "package.json", '{"name":"x","dependencies":{}}')
    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=["Node.js"])
    names = {suite.name for suite in runner._select_suites()}
    assert "secrets_in_git" in names
    assert "dependency_audit" in names
    assert "config_hardening" in names
    assert "build_integrity" in names


def test_python_project_selects_expected_suites(tmp_path: Path) -> None:
    _touch(tmp_path / "pyproject.toml", "[project]\nname='x'\n")
    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=["Python"])
    names = {suite.name for suite in runner._select_suites()}
    assert "secrets_in_git" in names
    assert "dependency_audit" in names
    assert "config_hardening" in names
    assert "build_integrity" not in names


def test_empty_project_still_selects_dependency_audit_for_nonapplicable_evidence(
    tmp_path: Path,
) -> None:
    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=[])
    names = [suite.name for suite in runner._select_suites()]
    assert names == ["secrets_in_git", "dependency_audit"]


def test_harness_public_import_isolated_from_analyze_initialization(
    tmp_path: Path,
) -> None:
    child_env = os.environ.copy()
    child_env["PYTHONPATH"] = str(ROOT / "src")
    child_env["PYTHONSAFEPATH"] = "1"

    probe = subprocess.run(
        [
            sys.executable,
            "-P",
            "-c",
            "from omargate.harness import HarnessRunner; print(HarnessRunner.__name__)",
        ],
        cwd=tmp_path,
        env=child_env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "HarnessRunner"


def test_harness_child_env_isolates_homes_and_copies_sanitized_connectivity(
    tmp_path: Path,
) -> None:
    project = tmp_path / "workspace"
    scratch = tmp_path / "scratch"
    external = tmp_path / "external"
    tool_directory = external / "bin"
    ca_directory = external / "ca-directory"
    project.mkdir()
    scratch.mkdir()
    tool_directory.mkdir(parents=True)
    ca_directory.mkdir(parents=True)
    ca_bundle = external / "corp-ca.pem"
    ca_bundle.write_text("certificate", encoding="utf-8")
    (ca_directory / "cert.0").write_text("certificate", encoding="utf-8")
    inherited = {
        "PATH": str(tool_directory),
        "HTTPS_PROXY": "HTTPS://Proxy.Example.Test:8443/",
        "https_proxy": "https://proxy.example.test:8443",
        "NO_PROXY": "localhost,.Example.Test,10.0.0.1/8,[::1]:8080",
        "SSL_CERT_FILE": str(ca_bundle),
        "SSL_CERT_DIR": str(ca_directory),
        "INPUT_TYPESAFE_API_KEY": "typesafe-private",
        "GITHUB_TOKEN": "github-private",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-private",
        "AWS_SECRET_ACCESS_KEY": "aws-private",
        "NODE_OPTIONS": "--require=./workspace-controlled.js",
        "PYTHONPATH": "./workspace-controlled",
        "NPM_CONFIG_USERCONFIG": "./workspace-controlled.npmrc",
        "HOME": "PRIVATE_CALLER_HOME",
        "USERPROFILE": "PRIVATE_CALLER_PROFILE",
    }

    child = _harness_child_env(
        inherited,
        scratch_dir=scratch,
        project_root=project,
    )

    assert child["PATH"] == str(tool_directory)
    assert child["HTTPS_PROXY"] == "https://proxy.example.test:8443"
    assert child["https_proxy"] == "https://proxy.example.test:8443"
    assert child["NO_PROXY"] == "localhost,.example.test,10.0.0.0/8,[::1]:8080"
    assert Path(child["SSL_CERT_FILE"]).read_text(encoding="utf-8") == "certificate"
    assert (Path(child["SSL_CERT_DIR"]) / "cert.0").read_text(encoding="utf-8") == (
        "certificate"
    )
    for key in (
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "CARGO_HOME",
    ):
        assert Path(child[key]).is_relative_to(scratch)
    assert Path(child["PIP_CONFIG_FILE"]).is_relative_to(scratch)
    assert Path(child["NPM_CONFIG_USERCONFIG"]).is_relative_to(scratch)
    assert Path(child["NPM_CONFIG_GLOBALCONFIG"]).is_relative_to(scratch)
    assert child["NPM_CONFIG_USERCONFIG"] != child["NPM_CONFIG_GLOBALCONFIG"]
    assert Path(child["NPM_CONFIG_USERCONFIG"]).read_text() == ""
    assert Path(child["NPM_CONFIG_GLOBALCONFIG"]).read_text() == ""
    assert Path(child["GIT_CONFIG_GLOBAL"]).is_relative_to(scratch)
    serialized = repr(child)
    for secret in (
        "typesafe-private",
        "github-private",
        "oidc-private",
        "aws-private",
        "workspace-controlled",
        "PRIVATE_CALLER_HOME",
        "PRIVATE_CALLER_PROFILE",
    ):
        assert secret not in serialized


@pytest.mark.anyio
async def test_run_command_rejects_credentialed_or_conflicting_proxy_without_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool_directory, _tool = _external_tool(tmp_path)
    spawned = False

    async def _should_not_spawn(*_args: object, **_kwargs: object) -> _CompletedProcess:
        nonlocal spawned
        spawned = True
        raise AssertionError("invalid proxy must stop before spawn")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _should_not_spawn)
    base = {"PATH": str(tool_directory)}
    cases = (
        {**base, "HTTPS_PROXY": "https://user:PRIVATE_PROXY@proxy.example.test"},
        {
            **base,
            "HTTPS_PROXY": "https://proxy-one.example.test",
            "https_proxy": "https://proxy-two.example.test",
        },
        {**base, "NO_PROXY": "safe.example,invalid entry"},
    )

    for inherited in cases:
        result = await run_command(
            ["audit-tool"],
            cwd=tmp_path,
            timeout_s=5,
            inherited_env=inherited,
        )
        assert result.status == "spawn_error"
        assert result.reason_code in {
            "invalid_proxy",
            "conflicting_proxy",
            "invalid_no_proxy",
        }
        assert "PRIVATE_" not in repr(result)
    assert spawned is False


@pytest.mark.anyio
async def test_run_command_uses_external_executable_and_secret_free_ephemeral_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_test_containment: None,
) -> None:
    external_directory, external_tool = _external_tool(tmp_path)
    workspace_tool = tmp_path / "audit-tool"
    workspace_tool.write_text("workspace decoy", encoding="utf-8")
    captured: dict[str, object] = {}

    async def _fake_create_subprocess_exec(
        *args: str, **kwargs: object
    ) -> _CompletedProcess:
        captured["args"] = args
        captured["env"] = kwargs.get("env")
        return _CompletedProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    inherited = {
        "PATH": os.pathsep.join((str(tmp_path), str(external_directory))),
        "INPUT_TYPESAFE_API_KEY": "PRIVATE_TYPESAFE",
        "GITHUB_TOKEN": "PRIVATE_GITHUB",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "PRIVATE_OIDC",
        "AWS_SECRET_ACCESS_KEY": "PRIVATE_AWS",
        "HOME": "PRIVATE_HOME",
        "USERPROFILE": "PRIVATE_PROFILE",
    }

    result = await run_command(
        ["audit-tool", "--json"],
        cwd=tmp_path,
        timeout_s=5,
        inherited_env=inherited,
    )

    assert result.status == "exited"
    assert result.returncode == 0
    actual_args = captured["args"]
    assert isinstance(actual_args, tuple)
    assert Path(actual_args[0]).resolve() == external_tool.resolve()
    child_env = captured["env"]
    assert isinstance(child_env, dict)
    assert str(tmp_path) not in child_env["PATH"].split(os.pathsep)
    assert child_env["PATH"] == str(external_directory)
    serialized = repr(child_env)
    assert "PRIVATE_" not in serialized
    for key in ("HOME", "USERPROFILE", "TMP", "CARGO_HOME"):
        assert Path(child_env[key]).exists() is False


@pytest.mark.anyio
async def test_run_command_executes_canonical_target_from_symlinked_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_test_containment: None,
) -> None:
    real_directory, external_tool = _external_tool(tmp_path)
    alias_directory = tmp_path.parent / f"{tmp_path.name}-tool-alias"
    try:
        alias_directory.symlink_to(real_directory, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are not available")
    captured: dict[str, object] = {}

    async def _fake_create_subprocess_exec(
        *args: str, **kwargs: object
    ) -> _CompletedProcess:
        captured["args"] = args
        captured["env"] = kwargs.get("env")
        return _CompletedProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    result = await run_command(
        ["audit-tool", "--json"],
        cwd=tmp_path,
        timeout_s=5,
        inherited_env={"PATH": str(alias_directory)},
    )

    assert result.status == "exited"
    args = captured["args"]
    env = captured["env"]
    assert isinstance(args, tuple)
    assert isinstance(env, dict)
    assert args[0] == str(external_tool.resolve())
    assert env["PATH"] == str(real_directory.resolve())
    assert str(alias_directory) not in env["PATH"]


@pytest.mark.anyio
async def test_run_command_rejects_lexically_workspace_local_path_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    external_directory = tmp_path / "external-tools"
    workspace.mkdir()
    external_directory.mkdir()
    workspace_alias = workspace / "tools"
    try:
        workspace_alias.symlink_to(external_directory, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are not available")
    spawned = False

    async def _should_not_spawn(*_args: object, **_kwargs: object) -> _CompletedProcess:
        nonlocal spawned
        spawned = True
        raise AssertionError("workspace-local PATH entry must be rejected lexically")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _should_not_spawn)
    result = await run_command(
        ["audit-tool"],
        cwd=workspace,
        timeout_s=5,
        inherited_env={"PATH": str(workspace_alias)},
    )

    assert spawned is False
    assert result.status == "spawn_error"
    assert result.reason_code == "invalid_path"


@pytest.mark.anyio
@pytest.mark.parametrize("case", ("workspace-source", "directory-entry"))
async def test_run_command_rejects_symlinked_ca_trust_material(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tool_directory, _tool = _external_tool(tmp_path)
    external = tmp_path.parent / f"{tmp_path.name}-ca-material"
    external.mkdir()
    real_bundle = external / "real.pem"
    real_bundle.write_text("certificate", encoding="utf-8")
    if case == "workspace-source":
        configured_path = workspace / "repo-controlled.pem"
        variable = "SSL_CERT_FILE"
    else:
        configured_path = external / "directory"
        configured_path.mkdir()
        variable = "SSL_CERT_DIR"
    try:
        if case == "workspace-source":
            configured_path.symlink_to(real_bundle)
        else:
            (configured_path / "linked.pem").symlink_to(real_bundle)
    except (NotImplementedError, OSError):
        pytest.skip("file symlinks are not available")
    spawned = False

    async def _should_not_spawn(*_args: object, **_kwargs: object) -> _CompletedProcess:
        nonlocal spawned
        spawned = True
        raise AssertionError("symlinked CA material must be rejected before spawn")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _should_not_spawn)
    result = await run_command(
        ["audit-tool"],
        cwd=workspace,
        timeout_s=5,
        inherited_env={"PATH": str(tool_directory), variable: str(configured_path)},
    )

    assert spawned is False
    assert result.status == "spawn_error"
    assert result.reason_code == "invalid_ca_path"


@pytest.mark.anyio
async def test_run_command_bypasses_npm_cmd_wrapper_with_direct_node(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_test_containment: None,
) -> None:
    distribution = tmp_path.parent / f"{tmp_path.name}-node-distribution"
    npm_cli = distribution / "node_modules" / "npm" / "bin" / "npm-cli.js"
    npm_cli.parent.mkdir(parents=True)
    npm_cli.write_text("// trusted npm cli placeholder", encoding="utf-8")
    npm_wrapper = distribution / "npm.cmd"
    npm_wrapper.write_text("PRIVATE_WRAPPER_CONTENT", encoding="utf-8")
    node = distribution / ("node.exe" if os.name == "nt" else "node")
    node.write_text("trusted node placeholder", encoding="utf-8")
    node.chmod(0o755)
    captured: dict[str, object] = {}

    async def _fake_create_subprocess_exec(
        *args: str, **kwargs: object
    ) -> _CompletedProcess:
        captured["args"] = args
        return _CompletedProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    result = await run_command(
        [str(npm_wrapper), "audit", "--json"],
        cwd=tmp_path,
        timeout_s=5,
        inherited_env={"PATH": str(distribution)},
    )

    assert result.status == "exited"
    spawn_args = captured["args"]
    assert isinstance(spawn_args, tuple)
    assert spawn_args == (
        str(node.resolve()),
        str(npm_cli.resolve()),
        "audit",
        "--json",
    )
    assert str(npm_wrapper.resolve()) not in spawn_args


@pytest.mark.anyio
async def test_run_command_distinguishes_not_found_from_real_exit_127(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_test_containment: None,
) -> None:
    tool_directory, _tool = _external_tool(tmp_path, "different-tool")
    inherited = {"PATH": str(tool_directory)}

    missing = await run_command(
        ["missing-tool"],
        cwd=tmp_path,
        timeout_s=5,
        inherited_env=inherited,
    )
    assert missing.status == "not_found"
    assert missing.returncode is None

    async def _exit_127(*_args: str, **_kwargs: object) -> _CompletedProcess:
        return _CompletedProcess(returncode=127)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _exit_127)
    exited = await run_command(
        ["different-tool"],
        cwd=tmp_path,
        timeout_s=5,
        inherited_env=inherited,
    )
    assert exited.status == "exited"
    assert exited.returncode == 127


@pytest.mark.anyio
async def test_run_command_reports_spawn_decode_and_streaming_output_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_test_containment: None,
) -> None:
    tool_directory, _tool = _external_tool(tmp_path)
    inherited = {"PATH": str(tool_directory)}

    async def _spawn_error(*_args: str, **_kwargs: object) -> _CompletedProcess:
        raise OSError("PRIVATE_SPAWN_ERROR")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn_error)
    spawn_error = await run_command(
        ["audit-tool"], cwd=tmp_path, timeout_s=5, inherited_env=inherited
    )
    assert spawn_error.status == "spawn_error"
    assert "PRIVATE_" not in repr(spawn_error)

    async def _invalid_utf8(*_args: str, **_kwargs: object) -> _CompletedProcess:
        return _CompletedProcess(stdout=b"\xff")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _invalid_utf8)
    decode_error = await run_command(
        ["audit-tool"], cwd=tmp_path, timeout_s=5, inherited_env=inherited
    )
    assert decode_error.status == "decode_error"
    assert decode_error.stdout == ""

    async def _oversized(*_args: str, **_kwargs: object) -> _CompletedProcess:
        return _CompletedProcess(stdout=b"0123456789")

    monkeypatch.setattr(harness_runner, "_MAX_CAPTURE_BYTES", 8)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _oversized)
    oversized = await run_command(
        ["audit-tool"], cwd=tmp_path, timeout_s=5, inherited_env=inherited
    )
    assert oversized.status == "output_limit_exceeded"
    assert oversized.stdout == ""

    class _FailingStream:
        async def read(self, _limit: int) -> bytes:
            raise RuntimeError("PRIVATE_READER_ERROR")

    async def _reader_error(*_args: str, **_kwargs: object) -> _CompletedProcess:
        process = _CompletedProcess()
        process.stdout = _FailingStream()  # type: ignore[assignment]
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _reader_error)
    capture_error = await run_command(
        ["audit-tool"], cwd=tmp_path, timeout_s=5, inherited_env=inherited
    )
    assert capture_error.status == "spawn_error"
    assert capture_error.reason_code == "capture_error"
    assert "PRIVATE_" not in repr(capture_error)


@pytest.mark.anyio
async def test_run_command_timeout_kills_reaps_and_deletes_private_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_test_containment: None,
) -> None:
    tool_directory, _tool = _external_tool(tmp_path)
    process = _BlockingProcess()
    captured_env: dict[str, str] = {}

    async def _blocking(*_args: str, **kwargs: object) -> _BlockingProcess:
        env = kwargs.get("env")
        assert isinstance(env, dict)
        captured_env.update(env)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _blocking)
    result = await run_command(
        ["audit-tool"],
        cwd=tmp_path,
        timeout_s=0,
        inherited_env={"PATH": str(tool_directory)},
    )

    assert result.status == "timed_out"
    assert process.killed is True
    assert process.reaped is True
    assert Path(captured_env["HOME"]).exists() is False


@pytest.mark.anyio
async def test_run_command_timeout_also_bounds_pipe_drain_after_child_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_test_containment: None,
) -> None:
    tool_directory, _tool = _external_tool(tmp_path)
    process = _ExitedWithHeldPipesProcess()
    captured_env: dict[str, str] = {}

    async def _held_pipes(*_args: str, **kwargs: object) -> _ExitedWithHeldPipesProcess:
        env = kwargs.get("env")
        assert isinstance(env, dict)
        captured_env.update(env)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _held_pipes)
    result = await run_command(
        ["audit-tool"],
        cwd=tmp_path,
        timeout_s=0.01,
        inherited_env={"PATH": str(tool_directory)},
    )

    assert result.status == "timed_out"
    assert process.wait_calls >= 2
    assert process.killed is False
    assert Path(captured_env["HOME"]).exists() is False


@pytest.mark.anyio
async def test_run_command_cancellation_kills_reaps_and_reraises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_test_containment: None,
) -> None:
    tool_directory, _tool = _external_tool(tmp_path)
    process = _BlockingProcess()
    spawned = asyncio.Event()
    captured_env: dict[str, str] = {}

    async def _blocking(*_args: str, **kwargs: object) -> _BlockingProcess:
        env = kwargs.get("env")
        assert isinstance(env, dict)
        captured_env.update(env)
        spawned.set()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _blocking)
    task = asyncio.create_task(
        run_command(
            ["audit-tool"],
            cwd=tmp_path,
            timeout_s=30,
            inherited_env={"PATH": str(tool_directory)},
        )
    )
    await spawned.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.killed is True
    assert process.reaped is True
    assert Path(captured_env["HOME"]).exists() is False


@pytest.mark.anyio
async def test_windows_launcher_is_not_released_when_job_attach_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool_directory, external_tool = _external_tool(tmp_path)
    process = _BlockedLauncherProcess()
    captured_args: tuple[str, ...] = ()
    captured_env: dict[str, str] = {}

    class _AttachFailureContainment(_DirectTestContainment):
        uses_windows_launcher = True

        def attach(self, _proc: object) -> None:
            raise harness_runner._HarnessSetupError("process_containment_error")

    async def _blocked_launcher(*args: str, **kwargs: object):
        nonlocal captured_args
        captured_args = args
        env = kwargs.get("env")
        assert isinstance(env, dict)
        captured_env.update(env)
        return process

    monkeypatch.setattr(
        harness_runner._ProcessContainment,
        "create",
        staticmethod(lambda: _AttachFailureContainment()),
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _blocked_launcher)

    result = await run_command(
        ["audit-tool", "--json"],
        cwd=tmp_path,
        timeout_s=5,
        inherited_env={"PATH": str(tool_directory)},
    )

    retained_root = Path(captured_env["HOME"]).parent
    try:
        assert result.status == "spawn_error"
        assert result.reason_code == "process_containment_error"
        assert result.cleanup_proven is False
        assert captured_args[:4] == (
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-c",
        )
        assert str(external_tool.resolve()) in captured_args
        assert process.stdin.data == b""
        assert process.stdin.closed is True
        assert process.killed is True
        assert process.reaped is True
        assert retained_root.is_dir()
    finally:
        shutil.rmtree(retained_root, ignore_errors=True)


@pytest.mark.anyio
@pytest.mark.skipif(os.name != "nt", reason="Windows nested-job regression")
async def test_windows_launcher_operates_inside_an_outer_job(
    tmp_path: Path,
) -> None:
    probe_code = (
        "import asyncio,json,pathlib,sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "from omargate.harness.runner import run_command;"
        "result=asyncio.run(run_command("
        "[sys.executable,'-c',\"print('nested')\"],"
        "cwd=pathlib.Path(sys.argv[2]),timeout_s=5));"
        "print(json.dumps({'status':result.status,'stdout':result.stdout}))"
    )
    outer = harness_runner._ProcessContainment.create()
    owned_args, spawn_options = harness_runner._spawn_spec(
        [sys.executable, "-c", probe_code, str(ROOT / "src"), str(tmp_path)],
        outer,
        tmp_path.resolve(),
    )
    child_env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR"}
    }
    child_env["PYTHONIOENCODING"] = "utf-8"
    process = await asyncio.create_subprocess_exec(
        *owned_args,
        cwd=str(tmp_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=child_env,
        **spawn_options,
    )
    try:
        outer.attach(process)
        await harness_runner._release_windows_launcher(process)
        stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=15)
        payload = json.loads(stdout.decode("utf-8", errors="strict"))
        assert payload["status"] == "exited"
        assert payload["stdout"].strip() == "nested"
    finally:
        await outer.terminate(process)
        if process.returncode is None:
            process.kill()
        await process.wait()
        assert await outer.verify_empty()
        assert outer.close()


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ("verify", "close"))
async def test_run_command_fails_closed_when_process_tree_cleanup_is_unproven(
    failure: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool_directory, _tool = _external_tool(tmp_path)

    class _UnprovenContainment(_DirectTestContainment):
        async def terminate(self, _proc: object) -> bool:
            return True

        async def verify_empty(self) -> bool:
            return failure != "verify"

        def close(self) -> bool:
            return failure != "close"

    async def _completed(*_args: str, **_kwargs: object) -> _CompletedProcess:
        return _CompletedProcess()

    monkeypatch.setattr(
        harness_runner._ProcessContainment,
        "create",
        staticmethod(lambda: _UnprovenContainment()),
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _completed)

    result = await run_command(
        ["audit-tool"],
        cwd=tmp_path,
        timeout_s=5,
        inherited_env={"PATH": str(tool_directory)},
    )

    assert result.status == "spawn_error"
    assert result.reason_code == "process_containment_error"


@pytest.mark.anyio
async def test_unreapable_process_cleanup_is_bounded_and_retains_private_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool_directory, _tool = _external_tool(tmp_path)
    process = _BlockingProcess()
    captured_env: dict[str, str] = {}

    class _StalledContainment(_DirectTestContainment):
        async def terminate(self, _proc: object) -> bool:
            return True

    async def _stalled(*_args: str, **kwargs: object) -> _BlockingProcess:
        env = kwargs.get("env")
        assert isinstance(env, dict)
        captured_env.update(env)
        return process

    monkeypatch.setattr(harness_runner, "_PROCESS_CLEANUP_TIMEOUT_S", 0.02)
    monkeypatch.setattr(
        harness_runner._ProcessContainment,
        "create",
        staticmethod(lambda: _StalledContainment()),
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _stalled)
    started = asyncio.get_running_loop().time()
    result = await run_command(
        ["audit-tool"],
        cwd=tmp_path,
        timeout_s=0,
        inherited_env={"PATH": str(tool_directory)},
    )
    elapsed = asyncio.get_running_loop().time() - started

    retained_root = Path(captured_env["HOME"]).parent
    try:
        assert result.status == "spawn_error"
        assert result.reason_code == "process_containment_error"
        assert elapsed < 1
        assert retained_root.is_dir()
    finally:
        shutil.rmtree(retained_root, ignore_errors=True)


@pytest.mark.anyio
async def test_run_command_timeout_terminates_real_grandchild_process(
    tmp_path: Path,
) -> None:
    grandchild_pid_file = tmp_path / "grandchild.pid"
    grandchild_code = "import time; time.sleep(60)"
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-c',sys.argv[2]]);"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='utf-8');"
        "time.sleep(60)"
    )

    result = await run_command(
        [
            sys.executable,
            "-c",
            parent_code,
            str(grandchild_pid_file),
            grandchild_code,
        ],
        cwd=tmp_path,
        timeout_s=2,
    )

    assert result.status == "timed_out"
    assert grandchild_pid_file.is_file()
    grandchild_pid = int(grandchild_pid_file.read_text(encoding="utf-8"))
    try:
        for _ in range(100):
            if not _process_is_running(grandchild_pid):
                break
            await asyncio.sleep(0.05)
        assert _process_is_running(grandchild_pid) is False
    finally:
        if _process_is_running(grandchild_pid):
            try:
                os.kill(grandchild_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


@pytest.mark.anyio
async def test_parent_exit_with_inherited_pipes_is_bounded_and_kills_grandchild(
    tmp_path: Path,
) -> None:
    grandchild_pid_file = tmp_path / "held-pipe-grandchild.pid"
    parent_code = (
        "import pathlib,subprocess,sys;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='utf-8')"
    )

    result = await run_command(
        [sys.executable, "-c", parent_code, str(grandchild_pid_file)],
        cwd=tmp_path,
        timeout_s=1,
    )

    assert result.status == "timed_out"
    grandchild_pid = int(grandchild_pid_file.read_text(encoding="utf-8"))
    try:
        assert _process_is_running(grandchild_pid) is False
    finally:
        if _process_is_running(grandchild_pid):
            try:
                os.kill(grandchild_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


@pytest.mark.anyio
async def test_run_command_normal_exit_terminates_background_grandchild(
    tmp_path: Path,
) -> None:
    grandchild_pid_file = tmp_path / "normal-exit-grandchild.pid"
    grandchild_code = "import time; time.sleep(60)"
    parent_code = (
        "import os,pathlib,subprocess,sys;"
        "sink=open(os.devnull,'wb');"
        "child=subprocess.Popen([sys.executable,'-c',sys.argv[2]],"
        "stdin=subprocess.DEVNULL,stdout=sink,stderr=sink);"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='utf-8')"
    )

    result = await run_command(
        [
            sys.executable,
            "-c",
            parent_code,
            str(grandchild_pid_file),
            grandchild_code,
        ],
        cwd=tmp_path,
        timeout_s=5,
    )

    assert result.status == "exited"
    assert result.returncode == 0
    grandchild_pid = int(grandchild_pid_file.read_text(encoding="utf-8"))
    try:
        assert _process_is_running(grandchild_pid) is False
    finally:
        if _process_is_running(grandchild_pid):
            try:
                os.kill(grandchild_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


@pytest.mark.anyio
async def test_run_command_cancellation_terminates_real_grandchild(
    tmp_path: Path,
) -> None:
    grandchild_pid_file = tmp_path / "cancelled-grandchild.pid"
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='utf-8');"
        "time.sleep(60)"
    )
    task = asyncio.create_task(
        run_command(
            [sys.executable, "-c", parent_code, str(grandchild_pid_file)],
            cwd=tmp_path,
            timeout_s=30,
        )
    )
    for _ in range(200):
        if grandchild_pid_file.is_file():
            break
        await asyncio.sleep(0.01)
    assert grandchild_pid_file.is_file()
    grandchild_pid = int(grandchild_pid_file.read_text(encoding="utf-8"))
    task.cancel()
    try:
        with pytest.raises(asyncio.CancelledError):
            await task
        assert _process_is_running(grandchild_pid) is False
    finally:
        if not task.done():
            task.cancel()
        if _process_is_running(grandchild_pid):
            try:
                os.kill(grandchild_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


@pytest.mark.anyio
@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group regression")
async def test_cancellation_during_spawn_attaches_and_kills_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    grandchild_pid_file = tmp_path / "spawn-cancel-grandchild.pid"
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='utf-8');"
        "time.sleep(60)"
    )
    real_spawn = asyncio.create_subprocess_exec
    helper_spawned = asyncio.Event()
    release_spawn = asyncio.Event()

    async def _delayed_spawn(*args: str, **kwargs: object):
        process = await real_spawn(*args, **kwargs)
        helper_spawned.set()
        await release_spawn.wait()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _delayed_spawn)
    task = asyncio.create_task(
        run_command(
            [sys.executable, "-c", parent_code, str(grandchild_pid_file)],
            cwd=tmp_path,
            timeout_s=30,
        )
    )
    await helper_spawned.wait()
    for _ in range(200):
        if grandchild_pid_file.is_file():
            break
        await asyncio.sleep(0.01)
    assert grandchild_pid_file.is_file()
    grandchild_pid = int(grandchild_pid_file.read_text(encoding="utf-8"))
    task.cancel()
    release_spawn.set()
    try:
        with pytest.raises(asyncio.CancelledError):
            await task
        assert _process_is_running(grandchild_pid) is False
    finally:
        release_spawn.set()
        if not task.done():
            task.cancel()
        if _process_is_running(grandchild_pid):
            try:
                os.kill(grandchild_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


@pytest.mark.anyio
async def test_suite_timeout_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SlowSuite(SecuritySuite):
        @property
        def name(self) -> str:
            return "slow"

        def applies_to(self, tech_stack: list[str]) -> bool:
            return True

        async def run(self, project_root: str):
            await asyncio.sleep(10)
            return []

    runner = HarnessRunner(
        project_root=str(tmp_path),
        tech_stack=[],
        per_suite_timeout_s=1,
        total_timeout_s=2,
    )
    monkeypatch.setattr(runner, "_select_suites", lambda: [SlowSuite()])
    result = await runner.run_with_evidence()
    assert any(finding.pattern_id == "HARNESS-TIMEOUT" for finding in result.findings)
    assert all(finding.source == "harness" for finding in result.findings)
    assert result.dependency_audit_evidence["complete"] is True


@pytest.mark.anyio
async def test_findings_are_harness_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from omargate.analyze.deterministic.pattern_scanner import Finding

    class OneFindingSuite(SecuritySuite):
        @property
        def name(self) -> str:
            return "one"

        def applies_to(self, tech_stack: list[str]) -> bool:
            return True

        async def run(self, project_root: str):
            return [
                Finding(
                    id="X",
                    pattern_id="X",
                    severity="P3",
                    category="harness",
                    file_path="x",
                    line_start=1,
                    line_end=1,
                    snippet="",
                    message="x",
                    recommendation="x",
                    confidence=1.0,
                    source="harness",
                )
            ]

    runner = HarnessRunner(project_root=str(tmp_path), tech_stack=[])
    monkeypatch.setattr(runner, "_select_suites", lambda: [OneFindingSuite()])
    result = await runner.run_with_evidence()
    assert len(result.findings) == 1
    assert result.findings[0].source == "harness"
    assert result.dependency_audit_evidence["complete"] is True
