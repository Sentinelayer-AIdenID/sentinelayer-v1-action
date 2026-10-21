from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Mapping
from urllib.parse import urlsplit

from .detectors import ProjectFacts, detect_project_facts

if TYPE_CHECKING:
    from ..analyze.deterministic.pattern_scanner import Finding


# Harness children receive only structural process metadata. Credentials,
# provider/GitHub/OIDC variables, repository-controlled tool options, and the
# caller's home/config/cache directories are never inherited.
_HARNESS_PROCESS_ENV_KEYS = frozenset(
    {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
        "NO_COLOR",
        "FORCE_COLOR",
    }
)
_HARNESS_PROXY_KEY_GROUPS = (
    ("HTTP_PROXY", "http_proxy"),
    ("HTTPS_PROXY", "https_proxy"),
    ("ALL_PROXY", "all_proxy"),
)
_HARNESS_PROXY_ENV_KEYS = frozenset(
    key for group in _HARNESS_PROXY_KEY_GROUPS for key in group
)
_HARNESS_NO_PROXY_KEY_GROUP = ("NO_PROXY", "no_proxy")
_HARNESS_NO_PROXY_ENV_KEYS = frozenset(_HARNESS_NO_PROXY_KEY_GROUP)
_HARNESS_CA_PATH_ENV_KEYS = frozenset(
    {
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "PIP_CERT",
        "NPM_CONFIG_CAFILE",
        "npm_config_cafile",
        "CARGO_HTTP_CAINFO",
        "GIT_SSL_CAINFO",
    }
)
_HARNESS_CONNECTIVITY_ENV_KEYS = frozenset(
    _HARNESS_PROXY_ENV_KEYS | _HARNESS_NO_PROXY_ENV_KEYS | _HARNESS_CA_PATH_ENV_KEYS
)
_HARNESS_METADATA_ENV_KEYS = frozenset(
    {"LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "NO_COLOR", "FORCE_COLOR"}
)
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_MAX_PROXY_ORIGIN_CHARS = 512
_MAX_NO_PROXY_CHARS = 2048
_MAX_NO_PROXY_ENTRIES = 64
_MAX_CA_PATH_CHARS = 1024
_MAX_CA_FILE_BYTES = 1_048_576
_MAX_CA_DIRECTORY_FILES = 512
_MAX_CA_DIRECTORY_BYTES = 16_777_216
_MAX_PATH_CHARS = 32_768
_MAX_CAPTURE_BYTES = 4_194_304
_READ_CHUNK_BYTES = 65_536
_PROCESS_CLEANUP_TIMEOUT_S = 5.0
_WINDOWS_LAUNCHER_RELEASE = b"\x00"
_WINDOWS_LAUNCHER_CODE = (
    "import subprocess,sys\n"
    "try:\n"
    " data=sys.stdin.buffer.read(2)\n"
    " if data != b'\\x00': raise RuntimeError\n"
    " child=subprocess.Popen(sys.argv[1:],stdin=subprocess.DEVNULL)\n"
    " code=child.wait()\n"
    "except BaseException:\n"
    " code=125\n"
    "raise SystemExit(code)\n"
)

CommandStatus = Literal[
    "exited",
    "not_found",
    "spawn_error",
    "timed_out",
    "decode_error",
    "output_limit_exceeded",
]


class _HarnessSetupError(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _PrivateScratch:
    """Delete private tool state only after process-tree teardown is proven."""

    def __init__(self, prefix: str) -> None:
        self.path = Path(tempfile.mkdtemp(prefix=prefix))
        self._retained = False

    def __enter__(self) -> _PrivateScratch:
        return self

    def retain(self) -> None:
        self._retained = True

    def __exit__(self, *_exc: object) -> None:
        if not self._retained:
            shutil.rmtree(self.path)


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _has_control_characters(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _normalize_hostname(value: str) -> str | None:
    trailing_dot = value.endswith(".")
    candidate = value[:-1] if trailing_dot else value
    if not candidate or len(candidate) > 253:
        return None
    labels = candidate.split(".")
    if any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        return None
    normalized = ".".join(label.lower() for label in labels)
    return normalized + ("." if trailing_dot else "")


def _normalize_port(value: str) -> str | None:
    if not value.isdigit():
        return None
    port = int(value)
    return str(port) if 1 <= port <= 65535 else None


def _sanitize_proxy_origin(value: object) -> str | None:
    text = value if isinstance(value, str) else ""
    if (
        not text
        or len(text) > _MAX_PROXY_ORIGIN_CHARS
        or text != text.strip()
        or _has_control_characters(text)
    ):
        return None
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    try:
        address = ipaddress.ip_address(parsed.hostname)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        normalized = _normalize_hostname(parsed.hostname)
        if normalized is None:
            return None
        host = normalized
    authority = f"{host}:{port}" if port is not None else host
    return f"{parsed.scheme.lower()}://{authority}"


def _normalize_no_proxy_entry(value: str) -> str | None:
    if not value or len(value) > 255 or _has_control_characters(value):
        return None
    if value == "*":
        return value
    if "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return None
    if value.startswith("["):
        closing = value.find("]")
        if closing <= 1:
            return None
        remainder = value[closing + 1 :]
        port_suffix = ""
        if remainder:
            if not remainder.startswith(":"):
                return None
            port = _normalize_port(remainder[1:])
            if port is None:
                return None
            port_suffix = f":{port}"
        try:
            address = ipaddress.ip_address(value[1:closing])
        except ValueError:
            return None
        if address.version != 6:
            return None
        return f"[{address.compressed}]{port_suffix}"
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass

    host_value = value
    port_suffix = ""
    if value.count(":") == 1:
        host_value, raw_port = value.rsplit(":", 1)
        port = _normalize_port(raw_port)
        if port is None:
            return None
        port_suffix = f":{port}"
    elif ":" in value:
        return None

    prefix = ""
    if host_value.startswith("*."):
        prefix, host_value = "*.", host_value[2:]
    elif host_value.startswith("."):
        prefix, host_value = ".", host_value[1:]
    normalized = _normalize_hostname(host_value)
    if normalized is None:
        return None
    return f"{prefix}{normalized}{port_suffix}"


def _sanitize_no_proxy(value: object) -> str | None:
    text = value if isinstance(value, str) else ""
    if not text or len(text) > _MAX_NO_PROXY_CHARS:
        return None
    entries = [entry.strip() for entry in text.split(",")]
    if not entries or len(entries) > _MAX_NO_PROXY_ENTRIES or any(not entry for entry in entries):
        return None
    normalized = [_normalize_no_proxy_entry(entry) for entry in entries]
    if any(entry is None for entry in normalized):
        return None
    result = ",".join(entry for entry in normalized if entry is not None)
    return result if len(result) <= _MAX_NO_PROXY_CHARS else None


def _safe_path(source: Mapping[str, str], project_root: Path) -> str:
    raw_path = source.get("PATH", "")
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or len(raw_path) > _MAX_PATH_CHARS
        or _has_control_characters(raw_path)
    ):
        raise _HarnessSetupError("invalid_path")
    safe_entries: list[str] = []
    for raw_entry in raw_path.split(os.pathsep):
        entry = raw_entry.strip().strip('"')
        candidate = Path(entry)
        if not entry or not candidate.is_absolute():
            continue
        lexical = Path(os.path.abspath(candidate))
        if _is_within(lexical, project_root):
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_dir() or _is_within(resolved, project_root):
            continue
        normalized = str(resolved)
        if normalized not in safe_entries:
            safe_entries.append(normalized)
    if not safe_entries:
        raise _HarnessSetupError("invalid_path")
    return os.pathsep.join(safe_entries)


def _copy_bounded_metadata(
    child: dict[str, str], source: Mapping[str, str], key: str, max_chars: int
) -> None:
    value = source.get(key)
    if not isinstance(value, str) or not value:
        return
    if len(value) <= max_chars and not _has_control_characters(value):
        child[key] = value


def _configure_proxy_group(
    child: dict[str, str], source: Mapping[str, str], keys: tuple[str, ...]
) -> None:
    configured: list[tuple[str, str]] = []
    for key in keys:
        raw = source.get(key)
        if raw is None or raw == "":
            continue
        sanitized = _sanitize_proxy_origin(raw)
        if sanitized is None:
            raise _HarnessSetupError("invalid_proxy")
        configured.append((key, sanitized))
    if len({value for _, value in configured}) > 1:
        raise _HarnessSetupError("conflicting_proxy")
    for key, value in configured:
        child[key] = value


def _configure_no_proxy(child: dict[str, str], source: Mapping[str, str]) -> None:
    configured: list[tuple[str, str]] = []
    for key in _HARNESS_NO_PROXY_KEY_GROUP:
        raw = source.get(key)
        if raw is None or raw == "":
            continue
        sanitized = _sanitize_no_proxy(raw)
        if sanitized is None:
            raise _HarnessSetupError("invalid_no_proxy")
        configured.append((key, sanitized))
    if len({value for _, value in configured}) > 1:
        raise _HarnessSetupError("conflicting_no_proxy")
    for key, value in configured:
        child[key] = value


def _validated_ca_source(value: object, key: str, project_root: Path) -> Path:
    text = value if isinstance(value, str) else ""
    if (
        not text
        or len(text) > _MAX_CA_PATH_CHARS
        or text != text.strip()
        or _has_control_characters(text)
        or text.startswith(("//", "\\\\"))
    ):
        raise _HarnessSetupError("invalid_ca_path")
    candidate = Path(text)
    if not candidate.is_absolute():
        raise _HarnessSetupError("invalid_ca_path")
    lexical = Path(os.path.abspath(candidate))
    if _is_within(lexical, project_root) or candidate.is_symlink():
        raise _HarnessSetupError("invalid_ca_path")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _HarnessSetupError("invalid_ca_path") from exc
    if _is_within(resolved, project_root):
        raise _HarnessSetupError("invalid_ca_path")
    if key == "SSL_CERT_DIR":
        if not resolved.is_dir():
            raise _HarnessSetupError("invalid_ca_path")
    elif not resolved.is_file():
        raise _HarnessSetupError("invalid_ca_path")
    return resolved


def _copy_ca_source(
    source: Path,
    destination_root: Path,
    project_root: Path,
    index: int,
) -> Path:
    if source.is_file():
        if source.stat().st_size > _MAX_CA_FILE_BYTES:
            raise _HarnessSetupError("ca_material_too_large")
        destination = destination_root / f"bundle-{index}.pem"
        shutil.copyfile(source, destination)
        return destination

    entries = sorted(source.iterdir(), key=lambda entry: entry.name)
    if len(entries) > _MAX_CA_DIRECTORY_FILES:
        raise _HarnessSetupError("ca_material_too_large")
    destination = destination_root / f"directory-{index}"
    destination.mkdir()
    total_bytes = 0
    for entry in entries:
        if _has_control_characters(entry.name) or entry.is_symlink():
            raise _HarnessSetupError("invalid_ca_path")
        try:
            resolved_entry = entry.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise _HarnessSetupError("invalid_ca_path") from exc
        if not resolved_entry.is_file() or _is_within(resolved_entry, project_root):
            raise _HarnessSetupError("invalid_ca_path")
        size = resolved_entry.stat().st_size
        total_bytes += size
        if size > _MAX_CA_FILE_BYTES or total_bytes > _MAX_CA_DIRECTORY_BYTES:
            raise _HarnessSetupError("ca_material_too_large")
        shutil.copyfile(resolved_entry, destination / entry.name)
    return destination


def _configure_ca_paths(
    child: dict[str, str],
    source: Mapping[str, str],
    scratch_dir: Path,
    project_root: Path,
) -> None:
    configured_sources: dict[str, Path] = {}
    for key in _HARNESS_CA_PATH_ENV_KEYS:
        raw = source.get(key)
        if raw is None or raw == "":
            continue
        configured_sources[key] = _validated_ca_source(raw, key, project_root)
    npm_sources = {
        configured_sources[key]
        for key in ("NPM_CONFIG_CAFILE", "npm_config_cafile")
        if key in configured_sources
    }
    if len(npm_sources) > 1:
        raise _HarnessSetupError("conflicting_ca_path")
    if not configured_sources:
        return
    destination_root = scratch_dir / "ca"
    destination_root.mkdir()
    copied: dict[Path, Path] = {}
    for index, (key, source_path) in enumerate(sorted(configured_sources.items())):
        destination = copied.get(source_path)
        if destination is None:
            destination = _copy_ca_source(
                source_path,
                destination_root,
                project_root,
                index,
            )
            copied[source_path] = destination
        child[key] = str(destination)


def _harness_child_env(
    inherited: Mapping[str, str] | None = None,
    *,
    scratch_dir: Path,
    project_root: Path,
) -> dict[str, str]:
    """Build the complete secret-free environment passed to harness commands."""

    source = os.environ if inherited is None else inherited
    resolved_project = project_root.resolve(strict=True)
    resolved_scratch = scratch_dir.resolve(strict=True)
    if _is_within(resolved_scratch, resolved_project):
        raise _HarnessSetupError("unsafe_scratch_directory")

    home = resolved_scratch / "home"
    temp = resolved_scratch / "tmp"
    xdg_config = resolved_scratch / "xdg-config"
    xdg_cache = resolved_scratch / "xdg-cache"
    cargo_home = resolved_scratch / "cargo-home"
    for directory in (home, temp, xdg_config, xdg_cache, cargo_home):
        directory.mkdir()
    pip_config = resolved_scratch / "pip.conf"
    npm_config = resolved_scratch / "npmrc"
    git_config = resolved_scratch / "gitconfig"
    for config_file in (pip_config, npm_config, git_config):
        config_file.write_text("", encoding="utf-8")

    child = {
        "PATH": _safe_path(source, resolved_project),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "TMPDIR": str(temp),
        "TMP": str(temp),
        "TEMP": str(temp),
        "XDG_CONFIG_HOME": str(xdg_config),
        "XDG_CACHE_HOME": str(xdg_cache),
        "CARGO_HOME": str(cargo_home),
        "PIP_CONFIG_FILE": str(pip_config),
        "PIP_NO_INPUT": "1",
        "NPM_CONFIG_USERCONFIG": str(npm_config),
        "npm_config_userconfig": str(npm_config),
        "NPM_CONFIG_GLOBALCONFIG": str(npm_config),
        "npm_config_globalconfig": str(npm_config),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(git_config),
        "GIT_TERMINAL_PROMPT": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }
    for key in _HARNESS_METADATA_ENV_KEYS:
        _copy_bounded_metadata(child, source, key, 256)
    _copy_bounded_metadata(child, source, "PATHEXT", 1024)
    for key in ("SYSTEMROOT", "WINDIR"):
        raw = source.get(key)
        if not isinstance(raw, str) or not raw:
            continue
        candidate = Path(raw)
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if (
            candidate.is_absolute()
            and resolved.is_dir()
            and not _is_within(resolved, resolved_project)
        ):
            child[key] = str(resolved)
    for group in _HARNESS_PROXY_KEY_GROUPS:
        _configure_proxy_group(child, source, group)
    _configure_no_proxy(child, source)
    _configure_ca_paths(child, source, resolved_scratch, resolved_project)
    return child


def _resolve_executable(command: str, env: Mapping[str, str], project_root: Path) -> str:
    if not command or _has_control_characters(command):
        raise _HarnessSetupError("unsafe_executable")
    command_path = Path(command)
    if command_path.is_absolute():
        candidate_text = command
    else:
        separators = {os.sep, "/", "\\"}
        if any(separator and separator in command for separator in separators):
            raise _HarnessSetupError("unsafe_executable")
        candidate_text = shutil.which(
            command,
            path=env.get("PATH"),
        )
        if candidate_text is None:
            raise _HarnessSetupError("not_found")
    candidate = Path(candidate_text)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _HarnessSetupError("not_found") from exc
    if not resolved.is_file() or _is_within(resolved, project_root):
        raise _HarnessSetupError("unsafe_executable")
    return str(resolved)


def _direct_spawn_args(
    logical_args: list[str],
    executable: str,
    env: Mapping[str, str],
    project_root: Path,
) -> list[str]:
    """Return a wrapper-free argv for supported tools."""

    resolved = Path(executable)
    command_name = Path(logical_args[0]).stem.lower()
    suffix = resolved.suffix.lower()
    if command_name != "npm":
        if suffix in {".bat", ".cmd"}:
            raise _HarnessSetupError("unsafe_executable")
        return [executable, *logical_args[1:]]

    if suffix not in {".bat", ".cmd", ".js"}:
        return [executable, *logical_args[1:]]

    if suffix == ".js":
        if resolved.name.lower() != "npm-cli.js":
            raise _HarnessSetupError("unsafe_executable")
        npm_cli = resolved
    else:
        npm_cli = resolved.parent / "node_modules" / "npm" / "bin" / "npm-cli.js"
        try:
            npm_cli = npm_cli.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise _HarnessSetupError("not_found") from exc
        if not npm_cli.is_file() or _is_within(npm_cli, project_root):
            raise _HarnessSetupError("unsafe_executable")

    local_node = resolved.parent / ("node.exe" if os.name == "nt" else "node")
    try:
        node = local_node.resolve(strict=True)
    except (OSError, RuntimeError):
        node = Path(_resolve_executable("node", env, project_root))
    if (
        not node.is_file()
        or node.suffix.lower() in {".bat", ".cmd"}
        or _is_within(node, project_root)
    ):
        raise _HarnessSetupError("unsafe_executable")
    return [str(node), str(npm_cli), *logical_args[1:]]


async def _read_bounded(
    stream: asyncio.StreamReader | None,
    limit: int,
) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    chunks: list[bytes] = []
    captured = 0
    overflow = False
    while True:
        chunk = await stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        remaining = max(0, limit - captured)
        if remaining:
            chunks.append(chunk[:remaining])
            captured += min(len(chunk), remaining)
        if len(chunk) > remaining:
            overflow = True
    return b"".join(chunks), overflow


class _ProcessContainment:
    """Own an audit process tree until every child has been reaped or terminated."""

    def __init__(self, job_handle: int | None = None) -> None:
        self._job_handle = job_handle
        self._attached = False
        self._group_id: int | None = None

    @property
    def uses_windows_launcher(self) -> bool:
        return self._job_handle is not None

    @classmethod
    def create(cls) -> _ProcessContainment:
        if os.name != "nt":
            return cls()
        try:
            import ctypes
            from ctypes import wintypes

            class _BasicLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class _IoCounters(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong),
                ]

            class _ExtendedLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", _BasicLimitInformation),
                    ("IoInfo", _IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = (
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            )
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
            limits = _ExtendedLimitInformation()
            limits.BasicLimitInformation.LimitFlags = 0x00002000
            if not kernel32.SetInformationJobObject(
                handle,
                9,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ):
                error = ctypes.get_last_error()
                kernel32.CloseHandle(handle)
                raise OSError(error, "SetInformationJobObject failed")
            return cls(int(handle))
        except (AttributeError, ImportError, OSError, TypeError, ValueError) as exc:
            raise _HarnessSetupError("process_containment_error") from exc

    def attach(self, proc: asyncio.subprocess.Process) -> None:
        pid = getattr(proc, "pid", None)
        if not isinstance(pid, int) or pid <= 0:
            raise _HarnessSetupError("process_containment_error")
        if os.name != "nt":
            self._group_id = pid
            self._attached = True
            return
        if self._job_handle is None:
            raise _HarnessSetupError("process_containment_error")
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = (
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            )
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.AssignProcessToJobObject.argtypes = (
                wintypes.HANDLE,
                wintypes.HANDLE,
            )
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL

            process_handle = kernel32.OpenProcess(0x0001 | 0x0100, False, pid)
            if not process_handle:
                raise OSError(ctypes.get_last_error(), "OpenProcess failed")
            try:
                if not kernel32.AssignProcessToJobObject(
                    self._job_handle, process_handle
                ):
                    raise OSError(
                        ctypes.get_last_error(),
                        "AssignProcessToJobObject failed",
                    )
                self._attached = True
            finally:
                if not kernel32.CloseHandle(process_handle):
                    raise OSError(ctypes.get_last_error(), "CloseHandle failed")
        except (AttributeError, ImportError, OSError, TypeError, ValueError) as exc:
            raise _HarnessSetupError("process_containment_error") from exc

    def _windows_active_processes(self) -> int | None:
        if os.name != "nt" or self._job_handle is None:
            return None
        try:
            import ctypes
            from ctypes import wintypes

            class _BasicAccountingInformation(ctypes.Structure):
                _fields_ = [
                    ("TotalUserTime", ctypes.c_longlong),
                    ("TotalKernelTime", ctypes.c_longlong),
                    ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                    ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                    ("TotalPageFaultCount", wintypes.DWORD),
                    ("TotalProcesses", wintypes.DWORD),
                    ("ActiveProcesses", wintypes.DWORD),
                    ("TotalTerminatedProcesses", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.QueryInformationJobObject.argtypes = (
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.c_void_p,
            )
            kernel32.QueryInformationJobObject.restype = wintypes.BOOL
            accounting = _BasicAccountingInformation()
            if not kernel32.QueryInformationJobObject(
                self._job_handle,
                1,
                ctypes.byref(accounting),
                ctypes.sizeof(accounting),
                None,
            ):
                return None
            return int(accounting.ActiveProcesses)
        except (AttributeError, ImportError, TypeError, ValueError):
            return None

    async def terminate(self, proc: asyncio.subprocess.Process) -> bool:
        if os.name == "nt":
            if self._job_handle is None or not self._attached:
                return False
            active = self._windows_active_processes()
            if active == 0:
                return True
            if active is None:
                return False
            try:
                import ctypes
                from ctypes import wintypes

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.TerminateJobObject.argtypes = (
                    wintypes.HANDLE,
                    wintypes.UINT,
                )
                kernel32.TerminateJobObject.restype = wintypes.BOOL
                return bool(kernel32.TerminateJobObject(self._job_handle, 1))
            except (AttributeError, ImportError, TypeError, ValueError):
                return False
        if self._group_id is not None:
            try:
                os.killpg(self._group_id, signal.SIGKILL)
                return True
            except ProcessLookupError:
                return True
            except OSError:
                return False
        return False

    async def verify_empty(self) -> bool:
        deadline = time.monotonic() + _PROCESS_CLEANUP_TIMEOUT_S
        while True:
            if os.name == "nt":
                if not self._attached:
                    return True
                active = self._windows_active_processes()
                if active is None:
                    return False
                if active == 0:
                    return True
            elif self._group_id is None:
                return True
            else:
                try:
                    os.killpg(self._group_id, 0)
                except ProcessLookupError:
                    return True
                except OSError:
                    return False
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(0.01)

    def close(self) -> bool:
        if os.name != "nt" or self._job_handle is None:
            return True
        handle = self._job_handle
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            closed = bool(kernel32.CloseHandle(handle))
            if closed:
                self._job_handle = None
            return closed
        except (AttributeError, ImportError, TypeError, ValueError):
            return False


def _windows_launcher_executable(project_root: Path) -> str:
    lexical = Path(os.path.abspath(sys.executable))
    if _is_within(lexical, project_root):
        raise _HarnessSetupError("process_containment_error")
    try:
        resolved = lexical.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _HarnessSetupError("process_containment_error") from exc
    if (
        not resolved.is_file()
        or _is_within(resolved, project_root)
        or resolved.suffix.lower() in {".bat", ".cmd", ".ps1"}
    ):
        raise _HarnessSetupError("process_containment_error")
    return str(resolved)


def _spawn_spec(
    spawn_args: list[str],
    containment: _ProcessContainment,
    project_root: Path,
) -> tuple[list[str], dict[str, object]]:
    if containment.uses_windows_launcher:
        launcher = _windows_launcher_executable(project_root)
        return (
            [
                launcher,
                "-I",
                "-S",
                "-c",
                _WINDOWS_LAUNCHER_CODE,
                *spawn_args,
            ],
            {
                "stdin": asyncio.subprocess.PIPE,
                "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
            },
        )
    return spawn_args, {"stdin": asyncio.subprocess.DEVNULL, "start_new_session": True}


async def _release_windows_launcher(proc: asyncio.subprocess.Process) -> None:
    writer = proc.stdin
    if writer is None:
        raise _HarnessSetupError("process_containment_error")
    try:
        writer.write(_WINDOWS_LAUNCHER_RELEASE)
        await writer.drain()
        writer.close()
        wait_closed = getattr(writer, "wait_closed", None)
        if wait_closed is not None:
            await wait_closed()
    except asyncio.CancelledError:
        writer.close()
        raise
    except (BrokenPipeError, ConnectionError, OSError, RuntimeError) as exc:
        writer.close()
        raise _HarnessSetupError("process_containment_error") from exc


async def _kill_and_reap(
    proc: asyncio.subprocess.Process,
    readers: tuple[asyncio.Task[tuple[bytes, bool]], ...],
    containment: _ProcessContainment,
) -> bool:
    for reader in readers:
        if not reader.done():
            reader.cancel()
    writer = getattr(proc, "stdin", None)
    if writer is not None:
        writer.close()
    tree_terminated = await containment.terminate(proc)
    directly_terminated = proc.returncode is not None
    if not tree_terminated and proc.returncode is None:
        try:
            proc.kill()
            directly_terminated = True
        except ProcessLookupError:
            directly_terminated = True
        except OSError:
            directly_terminated = False
    try:
        await proc.wait()
    except (OSError, RuntimeError):
        directly_terminated = False
    await asyncio.gather(*readers, return_exceptions=True)
    empty = await containment.verify_empty()
    return (tree_terminated or directly_terminated) and empty


def _consume_cleanup_outcome(task: asyncio.Task[bool]) -> None:
    if not task.cancelled():
        try:
            task.exception()
        except BaseException:
            pass


async def _cleanup_after_interruption(
    proc: asyncio.subprocess.Process,
    readers: tuple[asyncio.Task[tuple[bytes, bool]], ...],
    containment: _ProcessContainment,
    scratch: _PrivateScratch,
) -> bool:
    """Reap the owned tree and close containment despite repeated cancellation."""

    cleanup = asyncio.create_task(_kill_and_reap(proc, readers, containment))
    cancelled = False
    deadline = time.monotonic() + _PROCESS_CLEANUP_TIMEOUT_S
    while not cleanup.done() and time.monotonic() < deadline:
        try:
            await asyncio.wait(
                {cleanup},
                timeout=max(0.0, deadline - time.monotonic()),
            )
        except asyncio.CancelledError:
            cancelled = True
    if cleanup.done():
        try:
            result = cleanup.result()
        except BaseException:
            result = False
    else:
        cleanup.cancel()
        cleanup.add_done_callback(_consume_cleanup_outcome)
        result = False
    close_ok = containment.close()
    proof = result and close_ok
    if not proof:
        # The child receives no credentials, and its private state is retained
        # rather than removed or reused while liveness is uncertain. Closing a
        # Windows kill-on-close Job is the final OS-enforced termination barrier.
        scratch.retain()
    if cancelled:
        if not proof:
            raise _HarnessSetupError("process_containment_error")
        raise asyncio.CancelledError
    return proof


async def _finish_spawn_after_cancellation(
    spawn_task: asyncio.Task[asyncio.subprocess.Process],
) -> asyncio.subprocess.Process | None:
    """Finish a shielded spawn so a cancelled caller cannot orphan its child."""

    while not spawn_task.done():
        try:
            await asyncio.shield(spawn_task)
        except asyncio.CancelledError:
            continue
        except (FileNotFoundError, OSError):
            return None
    try:
        return spawn_task.result()
    except (FileNotFoundError, OSError):
        return None


async def _wait_and_collect(
    proc: asyncio.subprocess.Process,
    readers: tuple[asyncio.Task[tuple[bytes, bool]], asyncio.Task[tuple[bytes, bool]]],
) -> tuple[tuple[bytes, bool], tuple[bytes, bool]]:
    await proc.wait()
    stdout_result, stderr_result = await asyncio.gather(*readers)
    return stdout_result, stderr_result


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    status: CommandStatus
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    reason_code: str | None = None
    cleanup_proven: bool = True

    @property
    def timed_out(self) -> bool:
        return self.status == "timed_out"


@dataclass(frozen=True)
class HarnessRunResult:
    findings: list[Finding]
    dependency_audit_evidence: dict[str, object]


async def run_command(
    args: list[str],
    cwd: Path,
    timeout_s: int,
    *,
    project_root: Path | None = None,
    inherited_env: Mapping[str, str] | None = None,
) -> CommandResult:
    logical_args = list(args)
    if not logical_args:
        return CommandResult(logical_args, "spawn_error", None, reason_code="empty_command")
    try:
        resolved_cwd = cwd.resolve(strict=True)
        resolved_project = (project_root or cwd).resolve(strict=True)
    except (OSError, RuntimeError):
        return CommandResult(
            logical_args,
            "spawn_error",
            None,
            reason_code="invalid_working_directory",
        )

    try:
        with _PrivateScratch(prefix="omargate-harness-") as scratch:
            scratch_dir = scratch.path.resolve(strict=True)
            if _is_within(scratch_dir, resolved_project):
                return CommandResult(
                    logical_args,
                    "spawn_error",
                    None,
                    reason_code="unsafe_scratch_directory",
                )
            try:
                child_env = _harness_child_env(
                    inherited_env,
                    scratch_dir=scratch_dir,
                    project_root=resolved_project,
                )
                executable = _resolve_executable(
                    logical_args[0],
                    child_env,
                    resolved_project,
                )
            except _HarnessSetupError as exc:
                status: CommandStatus = (
                    "not_found" if exc.reason_code == "not_found" else "spawn_error"
                )
                return CommandResult(
                    logical_args,
                    status,
                    None,
                    reason_code=exc.reason_code,
                )

            try:
                spawn_args = _direct_spawn_args(
                    logical_args,
                    executable,
                    child_env,
                    resolved_project,
                )
            except _HarnessSetupError as exc:
                spawn_status: CommandStatus = (
                    "not_found" if exc.reason_code == "not_found" else "spawn_error"
                )
                return CommandResult(
                    logical_args,
                    spawn_status,
                    None,
                    reason_code=exc.reason_code,
                )
            try:
                containment = _ProcessContainment.create()
            except _HarnessSetupError as exc:
                return CommandResult(
                    logical_args,
                    "spawn_error",
                    None,
                    reason_code=exc.reason_code,
                )
            containment_closed = False
            try:
                try:
                    owned_args, spawn_options = _spawn_spec(
                        spawn_args,
                        containment,
                        resolved_project,
                    )
                except _HarnessSetupError as exc:
                    close_ok = containment.close()
                    containment_closed = close_ok
                    return CommandResult(
                        logical_args,
                        "spawn_error",
                        None,
                        reason_code=(
                            exc.reason_code
                            if close_ok
                            else "process_containment_error"
                        ),
                    )

                spawn_task = asyncio.create_task(
                    asyncio.create_subprocess_exec(
                        *owned_args,
                        cwd=str(resolved_cwd),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=child_env,
                        **spawn_options,
                    )
                )
                try:
                    proc = await asyncio.shield(spawn_task)
                except asyncio.CancelledError:
                    cancelled_proc = await _finish_spawn_after_cancellation(
                        spawn_task
                    )
                    if cancelled_proc is not None:
                        attach_ok = True
                        try:
                            containment.attach(cancelled_proc)
                        except _HarnessSetupError:
                            attach_ok = False
                            scratch.retain()
                        cleanup_ok = await _cleanup_after_interruption(
                            cancelled_proc, (), containment, scratch
                        )
                        containment_closed = cleanup_ok
                        if not attach_ok or not cleanup_ok:
                            raise _HarnessSetupError(
                                "process_containment_error"
                            )
                    else:
                        close_ok = containment.close()
                        containment_closed = close_ok
                        if not close_ok:
                            raise _HarnessSetupError(
                                "process_containment_error"
                            )
                    raise
                except FileNotFoundError:
                    close_ok = containment.close()
                    containment_closed = close_ok
                    return CommandResult(
                        logical_args,
                        "not_found" if close_ok else "spawn_error",
                        None,
                        reason_code=(
                            "not_found"
                            if close_ok
                            else "process_containment_error"
                        ),
                    )
                except OSError:
                    close_ok = containment.close()
                    containment_closed = close_ok
                    return CommandResult(
                        logical_args,
                        "spawn_error",
                        None,
                        reason_code=(
                            "spawn_error"
                            if close_ok
                            else "process_containment_error"
                        ),
                    )

                process_attached = False
                try:
                    containment.attach(proc)
                    process_attached = True
                    if containment.uses_windows_launcher:
                        await _release_windows_launcher(proc)
                except asyncio.CancelledError:
                    if not process_attached:
                        scratch.retain()
                    cleanup_ok = await _cleanup_after_interruption(
                        proc, (), containment, scratch
                    )
                    containment_closed = cleanup_ok
                    if not process_attached or not cleanup_ok:
                        raise _HarnessSetupError("process_containment_error")
                    raise
                except _HarnessSetupError as exc:
                    if not process_attached:
                        scratch.retain()
                    cleanup_ok = await _cleanup_after_interruption(
                        proc, (), containment, scratch
                    )
                    containment_closed = cleanup_ok
                    cleanup_proven = process_attached and cleanup_ok
                    return CommandResult(
                        logical_args,
                        "spawn_error",
                        None,
                        reason_code=(
                            exc.reason_code
                            if cleanup_proven
                            else "process_containment_error"
                        ),
                        cleanup_proven=cleanup_proven,
                    )

                readers = (
                    asyncio.create_task(
                        _read_bounded(proc.stdout, _MAX_CAPTURE_BYTES)
                    ),
                    asyncio.create_task(
                        _read_bounded(proc.stderr, _MAX_CAPTURE_BYTES)
                    ),
                )
                try:
                    stdout_result, stderr_result = await asyncio.wait_for(
                        _wait_and_collect(proc, readers),
                        timeout=max(float(timeout_s), 0.0),
                    )
                except TimeoutError:
                    cleanup_ok = await _cleanup_after_interruption(
                        proc, readers, containment, scratch
                    )
                    containment_closed = cleanup_ok
                    return CommandResult(
                        logical_args,
                        "timed_out" if cleanup_ok else "spawn_error",
                        None,
                        reason_code=(
                            "timed_out"
                            if cleanup_ok
                            else "process_containment_error"
                        ),
                        cleanup_proven=cleanup_ok,
                    )
                except asyncio.CancelledError:
                    cleanup_ok = await _cleanup_after_interruption(
                        proc, readers, containment, scratch
                    )
                    containment_closed = cleanup_ok
                    if not cleanup_ok:
                        raise _HarnessSetupError("process_containment_error")
                    raise
                except Exception:
                    cleanup_ok = await _cleanup_after_interruption(
                        proc, readers, containment, scratch
                    )
                    containment_closed = cleanup_ok
                    return CommandResult(
                        logical_args,
                        "spawn_error",
                        None,
                        reason_code=(
                            "capture_error"
                            if cleanup_ok
                            else "process_containment_error"
                        ),
                        cleanup_proven=cleanup_ok,
                    )

                cleanup_ok = await _cleanup_after_interruption(
                    proc, readers, containment, scratch
                )
                containment_closed = cleanup_ok
                if not cleanup_ok:
                    return CommandResult(
                        logical_args,
                        "spawn_error",
                        None,
                        reason_code="process_containment_error",
                        cleanup_proven=False,
                    )

                stdout_b, stdout_overflow = stdout_result
                stderr_b, stderr_overflow = stderr_result
                if stdout_overflow or stderr_overflow:
                    return CommandResult(
                        logical_args,
                        "output_limit_exceeded",
                        proc.returncode,
                        reason_code="output_limit_exceeded",
                    )
                try:
                    stdout = stdout_b.decode("utf-8", errors="strict")
                    stderr = stderr_b.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    return CommandResult(
                        logical_args,
                        "decode_error",
                        proc.returncode,
                        reason_code="decode_error",
                    )
                return CommandResult(
                    logical_args,
                    "exited",
                    proc.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )
            finally:
                if not containment_closed:
                    containment.close()
    except OSError:
        return CommandResult(logical_args, "spawn_error", None, reason_code="scratch_error")


class SecuritySuite(ABC):
    @abstractmethod
    async def run(self, project_root: str) -> list[Finding]:
        raise NotImplementedError

    @abstractmethod
    def applies_to(self, tech_stack: list[str]) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError


class HarnessRunner:
    def __init__(
        self,
        project_root: str,
        tech_stack: list[str],
        *,
        pip_audit_ignore_ids: str = "",
        per_suite_timeout_s: int = 60,
        total_timeout_s: int = 180,
    ) -> None:
        self.project_root = project_root
        self.tech_stack = tech_stack or []
        self.pip_audit_ignore_ids = pip_audit_ignore_ids
        self.per_suite_timeout_s = int(per_suite_timeout_s)
        self.total_timeout_s = int(total_timeout_s)

    def _select_suites(self) -> list[SecuritySuite]:
        # Lazy import to avoid circular imports (suites import SecuritySuite/run_command).
        from .suites import (
            BuildIntegritySuite,
            ConfigHardeningSuite,
            DepAuditSuite,
            HttpSecurityHeadersSuite,
            SecretsInGitSuite,
        )

        root = Path(self.project_root)
        facts: ProjectFacts = detect_project_facts(root, self.tech_stack)

        suites: list[SecuritySuite] = [
            SecretsInGitSuite(tech_stack=self.tech_stack),
            DepAuditSuite(
                tech_stack=self.tech_stack,
                pip_audit_ignore_ids=self.pip_audit_ignore_ids,
            )
        ]

        if (
            facts.is_node
            or facts.is_python
            or facts.has_dockerfile
            or facts.has_terraform
            or facts.has_workflows
        ):
            suites.append(ConfigHardeningSuite(tech_stack=self.tech_stack))

        if facts.is_node:
            suites.append(BuildIntegritySuite(tech_stack=self.tech_stack))

        if facts.is_web:
            suites.append(HttpSecurityHeadersSuite(tech_stack=self.tech_stack))

        return suites

    def _timeout_finding(self, suite_name: str, timeout_s: int) -> Finding:
        from ..analyze.deterministic.pattern_scanner import Finding

        return Finding(
            id=f"HARNESS-TIMEOUT-{suite_name}",
            pattern_id="HARNESS-TIMEOUT",
            severity="P2",
            category="harness",
            file_path=".sentinelayer/harness",
            line_start=1,
            line_end=1,
            snippet="",
            message=f"Harness suite timed out: {suite_name}",
            recommendation=f"Re-run with more time; suite timeout was {timeout_s}s",
            confidence=1.0,
            source="harness",
        )

    def _error_finding(self, suite_name: str, exc: Exception) -> Finding:
        from ..analyze.deterministic.pattern_scanner import Finding, _truncate_snippet

        msg = _truncate_snippet(str(exc) or "unknown error", max_chars=200)
        return Finding(
            id=f"HARNESS-ERROR-{suite_name}",
            pattern_id="HARNESS-ERROR",
            severity="P2",
            category="harness",
            file_path=".sentinelayer/harness",
            line_start=1,
            line_end=1,
            snippet="",
            message=f"Harness suite error: {suite_name} ({msg})",
            recommendation="Fix the underlying error or disable run_harness for this repo",
            confidence=0.8,
            source="harness",
        )

    def _ensure_harness_source(self, finding: Finding) -> Finding:
        from ..analyze.deterministic.pattern_scanner import Finding

        if getattr(finding, "source", None) == "harness":
            return finding
        return Finding(
            id=finding.id,
            pattern_id=finding.pattern_id,
            severity=finding.severity,
            category=finding.category,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            snippet=finding.snippet,
            message=finding.message,
            recommendation=finding.recommendation,
            confidence=finding.confidence,
            source="harness",
        )

    async def run_with_evidence(self) -> HarnessRunResult:
        from .suites.dep_audit import DepAuditSuite

        suites = self._select_suites()
        findings: list[Finding] = []
        dependency_audit_evidence: dict[str, object] | None = None
        dependency_suite = next(
            (
                suite
                for suite in suites
                if isinstance(suite, DepAuditSuite)
            ),
            DepAuditSuite(
                tech_stack=self.tech_stack,
                pip_audit_ignore_ids=self.pip_audit_ignore_ids,
            ),
        )

        start = time.monotonic()
        deadline = start + max(self.total_timeout_s, 0)

        for suite in suites:
            remaining_total = max(0.0, deadline - time.monotonic())
            if remaining_total <= 0:
                if dependency_audit_evidence is None:
                    failed = dependency_suite.failure_result(
                        self.project_root,
                        "suite_not_run",
                    )
                    findings.extend(
                        self._ensure_harness_source(finding)
                        for finding in failed.findings
                    )
                    dependency_audit_evidence = failed.evidence.to_dict()
                break

            timeout_s = min(float(self.per_suite_timeout_s), remaining_total)
            try:
                if isinstance(suite, DepAuditSuite):
                    dependency_run = await asyncio.wait_for(
                        suite.run_with_evidence(self.project_root),
                        timeout=timeout_s,
                    )
                    suite_findings = dependency_run.findings
                    dependency_audit_evidence = dependency_run.evidence.to_dict()
                else:
                    suite_findings = await asyncio.wait_for(
                        suite.run(self.project_root),
                        timeout=timeout_s,
                    )
                for f in suite_findings:
                    findings.append(self._ensure_harness_source(f))
            except TimeoutError:
                if isinstance(suite, DepAuditSuite):
                    failed = suite.failure_result(
                        self.project_root,
                        "suite_timed_out",
                    )
                    findings.extend(
                        self._ensure_harness_source(finding)
                        for finding in failed.findings
                    )
                    dependency_audit_evidence = failed.evidence.to_dict()
                else:
                    findings.append(self._timeout_finding(suite.name, int(timeout_s)))
            except Exception as exc:
                if isinstance(suite, DepAuditSuite):
                    failed = suite.failure_result(
                        self.project_root,
                        "suite_error",
                    )
                    findings.extend(
                        self._ensure_harness_source(finding)
                        for finding in failed.findings
                    )
                    dependency_audit_evidence = failed.evidence.to_dict()
                else:
                    findings.append(self._error_finding(suite.name, exc))

        if dependency_audit_evidence is None:
            failed = dependency_suite.failure_result(
                self.project_root,
                "suite_not_run",
            )
            findings.extend(
                self._ensure_harness_source(finding)
                for finding in failed.findings
            )
            dependency_audit_evidence = failed.evidence.to_dict()

        return HarnessRunResult(
            findings=findings,
            dependency_audit_evidence=dependency_audit_evidence,
        )

    async def run(self) -> list[Finding]:
        return (await self.run_with_evidence()).findings
