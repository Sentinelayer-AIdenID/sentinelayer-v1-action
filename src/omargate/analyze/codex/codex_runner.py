from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any, Mapping, Optional

from ...fix_plan import ensure_fix_plan
from ..finding_contract import parse_finding_payload


# Codex needs a small amount of host process context to locate its runtime,
# configuration and temporary files.  Passing the complete Action environment
# would also pass every provider credential and GitHub/OIDC token.  Keep this
# list explicit: do not add language loader paths, proxy credentials, or broad
# prefixes such as INPUT_ / GITHUB_ / *_TOKEN.
_CODEX_PROCESS_ENV_KEYS = frozenset(
    {
        # Executable and shell discovery.
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "SHELL",
        # Home/config and temporary directories.
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "TMPDIR",
        "TMP",
        "TEMP",
        # Windows runtime discovery.
        "SYSTEMROOT",
        "WINDIR",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "OS",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "NUMBER_OF_PROCESSORS",
        # Locale/terminal behavior.  These values are not credential sources.
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        "FORCE_COLOR",
        # Codex's own configuration root is intentionally available.
        "CODEX_HOME",
    }
)


def _codex_child_env(
    *, api_key: str, model: str, inherited: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Build the complete, bounded environment passed to the Codex child."""
    source = os.environ if inherited is None else inherited
    child = {
        key: value
        for key, value in source.items()
        if key in _CODEX_PROCESS_ENV_KEYS
    }
    # These values come from validated runtime configuration, never the ambient
    # Action environment.  Both key names are required across Codex CLI builds.
    child["OPENAI_API_KEY"] = api_key
    child["CODEX_API_KEY"] = api_key
    child["CODEX_MODEL"] = model
    return child


@dataclass(frozen=True)
class CodexResult:
    findings: list[dict]
    raw_output: str
    success: bool
    duration_ms: int
    error: Optional[str] = None
    parse_errors: Optional[list[str]] = None
    no_findings_reported: bool = False


def _normalize_obj(obj: dict[str, Any]) -> dict[str, Any]:
    file_path = str(obj.get("file_path") or "").replace("\\", "/")
    line_start = int(obj.get("line_start") or 1)
    line_end = obj.get("line_end")
    if not isinstance(line_end, int):
        line_end = line_start
    category = str(obj.get("category") or "unknown")
    message = str(obj.get("message") or "").strip()
    recommendation = str(obj.get("recommendation") or "")
    fix_plan = ensure_fix_plan(
        fix_plan=obj.get("fix_plan", ""),
        recommendation=recommendation,
        message=message,
    )
    confidence_raw = obj.get("confidence", 0.8)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.8
    return {
        "id": f"{category}-{file_path}-{line_start}",
        "severity": obj.get("severity"),
        "category": category,
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "snippet": "",
        "message": message,
        "recommendation": recommendation,
        "fix_plan": fix_plan,
        "confidence": confidence,
        "source": "codex",
    }


def parse_codex_findings(text: str) -> tuple[list[dict], list[str], bool]:
    """
    Parse Codex final output as JSON, JSON array, or JSONL.

    Returns: (findings, parse_errors, no_findings_reported)
    """
    payload = parse_finding_payload(text or "")
    return (
        [_normalize_obj(item) for item in payload.findings],
        payload.parse_errors,
        payload.no_findings_reported,
    )


def extract_codex_cli_failure(stdout: str) -> Optional[str]:
    """Return the terminal error from Codex JSONL without exposing the prompt."""
    last_error: Optional[str] = None
    terminal_error: Optional[str] = None

    for line in (stdout or "").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue

        event_type = event.get("type")
        if event_type == "error" and isinstance(event.get("message"), str):
            last_error = event["message"].strip() or last_error
        elif event_type == "turn.failed":
            error = event.get("error")
            if isinstance(error, dict) and isinstance(error.get("message"), str):
                terminal_error = error["message"].strip() or terminal_error
            elif isinstance(error, str):
                terminal_error = error.strip() or terminal_error

    detail = terminal_error or last_error
    return detail[:1000] if detail else None


class CodexRunner:
    def __init__(self, api_key: str, model: str = "gpt-5.3-codex", reasoning_effort: str = "") -> None:
        self.api_key = api_key
        self.model = model
        # The pinned Codex CLI (0.98.0) rejects `max` ("expected one of none, minimal, low, medium, high, xhigh"),
        # so its highest effort stands in; the API path receives `max` unchanged.
        self.cli_reasoning_effort = "xhigh" if reasoning_effort == "max" else reasoning_effort

    def _resolve_codex_bin(self, working_dir: Path) -> Optional[str]:
        path = shutil.which("codex")
        if path:
            try:
                if Path(path).resolve().is_relative_to(working_dir.resolve()):
                    return None
            except (OSError, ValueError):
                return None
            return path
        return None

    async def run_audit(
        self,
        prompt: str,
        working_dir: str,
        sandbox: str = "read-only",
        timeout: int = 300,
    ) -> CodexResult:
        """
        Execute `codex exec` with the given prompt.

        Returns parsed findings from Codex output.
        """
        start = time.monotonic()
        wd = Path(working_dir).resolve()

        codex_bin = self._resolve_codex_bin(wd)
        if not codex_bin:
            return CodexResult(
                findings=[],
                raw_output="",
                success=False,
                duration_ms=int((time.monotonic() - start) * 1000),
                error="Codex CLI not found in PATH",
                parse_errors=None,
            )

        fd, last_msg_path_str = tempfile.mkstemp(prefix="codex_last_", suffix=".txt")
        os.close(fd)
        last_msg_path = Path(last_msg_path_str)

        cmd = [
            codex_bin,
            "exec",
            *(["-c", f"model_reasoning_effort={self.cli_reasoning_effort}"] if self.cli_reasoning_effort else []),
            "--json",
            "--sandbox",
            sandbox,
            "--model",
            self.model,
            "--cd",
            str(wd),
            "--output-last-message",
            str(last_msg_path),
            "-",
        ]

        env = _codex_child_env(api_key=self.api_key, model=self.model)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            return CodexResult(
                findings=[],
                raw_output="",
                success=False,
                duration_ms=int((time.monotonic() - start) * 1000),
                error="Codex CLI not found",
                parse_errors=None,
            )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=(prompt or "").encode("utf-8")),
                timeout=float(timeout),
            )
        except TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            stdout_b, stderr_b = await proc.communicate()
            raw_output = (
                (stdout_b or b"").decode("utf-8", errors="ignore")
                + "\n"
                + (stderr_b or b"").decode("utf-8", errors="ignore")
            ).strip()
            return CodexResult(
                findings=[],
                raw_output=raw_output,
                success=False,
                duration_ms=int((time.monotonic() - start) * 1000),
                error=f"Codex timed out after {timeout}s",
                parse_errors=None,
            )
        finally:
            # Best-effort cleanup; keep file around if read fails for debugging.
            pass

        stdout_text = (stdout_b or b"").decode("utf-8", errors="ignore")
        stderr_text = (stderr_b or b"").decode("utf-8", errors="ignore")
        raw_output = (stdout_text + "\n" + stderr_text).strip()

        duration_ms = int((time.monotonic() - start) * 1000)

        if int(proc.returncode or 0) != 0:
            error = f"Codex exited with code {proc.returncode}"
            cli_failure = extract_codex_cli_failure(stdout_text)
            if cli_failure:
                error = f"{error}: {cli_failure}"
            return CodexResult(
                findings=[],
                raw_output=raw_output,
                success=False,
                duration_ms=duration_ms,
                error=error,
                parse_errors=None,
            )

        last_message = ""
        try:
            last_message = last_msg_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            last_message = ""
        try:
            last_msg_path.unlink(missing_ok=True)
        except OSError:
            pass

        findings, parse_errors, no_findings = parse_codex_findings(last_message)
        if findings or no_findings:
            return CodexResult(
                findings=findings,
                raw_output=raw_output,
                success=True,
                duration_ms=duration_ms,
                error=None,
                parse_errors=parse_errors or [],
                no_findings_reported=no_findings,
            )

        return CodexResult(
            findings=[],
            raw_output=raw_output,
            success=False,
            duration_ms=duration_ms,
            error="Codex output was not parseable as findings JSONL",
            parse_errors=parse_errors or [],
            no_findings_reported=no_findings,
        )
