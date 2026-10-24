from __future__ import annotations

import json
import re
from pathlib import Path

from .pattern_scanner import Finding, PatternScanner, mask_secret_in_snippet

MAX_SNIPPET_CHARS = 500

# Common placeholder patterns found in .env.example / .env.template files.
# These are never real secrets and should not be flagged.
_PLACEHOLDER_RE = re.compile(
    r"your[_-]|_here$|_here[_-]|placeholder|changeme|change_this|"
    r"replace_this|example|sample|xxx+$|\.\.\.+$|YOUR[_-]|"
    r"sk_test_your|sk_live_your|pk_test_your|AKIA_your|whsec_your|re_your|"
    r"^user:pass@|^username:password@|^password$",
    re.IGNORECASE,
)


def _strip_json_comments(content: str) -> str:
    """
    Strip // and /* */ comments from JSONC while preserving string literals.

    tsconfig files commonly use JSONC, which json.loads cannot parse directly.
    """
    out: list[str] = []
    i = 0
    n = len(content)
    in_string = False
    quote_char = ""

    while i < n:
        ch = content[i]
        nxt = content[i + 1] if i + 1 < n else ""

        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(content[i + 1])
                i += 2
                continue
            if ch == quote_char:
                in_string = False
            i += 1
            continue

        if ch in {"'", '"'}:
            in_string = True
            quote_char = ch
            out.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            i += 2
            while i < n and content[i] != "\n":
                i += 1
            continue

        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (content[i] == "*" and content[i + 1] == "/"):
                i += 1
            i = i + 2 if i + 1 < n else n
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _truncate_snippet(snippet: str, max_chars: int = MAX_SNIPPET_CHARS) -> str:
    if len(snippet) <= max_chars:
        return snippet
    if max_chars <= 3:
        return snippet[:max_chars]
    return f"{snippet[: max_chars - 3]}..."


def _build_finding_id(pattern_id: str, file_path: str, line_start: int) -> str:
    return f"{pattern_id}-{file_path}-{line_start}"


class ConfigScanner:
    def __init__(self, patterns_dir: Path):
        self._pattern_scanner = PatternScanner(patterns_dir)
        self._cicd_patterns = [
            pattern for pattern in self._pattern_scanner.patterns if str(pattern.get("id", "")).startswith("CICD-")
        ]

    def _load_json_content(self, raw: str) -> dict | None:
        if not isinstance(raw, str):
            return None
        stripped = _strip_json_comments(raw)
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None

    def scan_file(
        self, file_path: Path, content: str, *, repo_root: Path | None = None
    ) -> list[Finding]:
        rel_path = file_path.as_posix()
        normalized = rel_path.replace("\\", "/")
        name = file_path.name.lower()
        findings: list[Finding] = []

        if name.startswith(".env"):
            findings.extend(self._scan_env(rel_path, content))

        if name == "package.json":
            findings.extend(self._scan_package_json(rel_path, content))

        if name in {"tsconfig.json", "jsconfig.json"}:
            findings.extend(self._scan_tsconfig(rel_path, content, repo_root=repo_root))

        if name in {"docker-compose.yml", "docker-compose.yaml"}:
            findings.extend(self._scan_docker_compose(rel_path, content))

        if normalized.startswith(".github/workflows/") or "/.github/workflows/" in normalized:
            findings.extend(
                self._pattern_scanner.scan_file_with_patterns(Path(rel_path), content, self._cicd_patterns)
            )

        return findings

    def scan_files(self, files: list[dict], repo_root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for entry in sorted(files, key=lambda item: item.get("path") or ""):
            rel_path = entry.get("path")
            if not rel_path:
                continue
            full_path = repo_root / rel_path
            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self.scan_file(Path(rel_path), content, repo_root=repo_root))
        return findings

    def _scan_env(self, file_path: str, content: str) -> list[Finding]:
        # Template / example .env files contain only placeholders — skip entirely.
        lower_path = file_path.lower()
        if any(
            lower_path.endswith(suffix)
            for suffix in (".example", ".template", ".sample", ".env.local.example")
        ):
            return []

        findings: list[Finding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                continue
            _, value = stripped.split("=", 1)
            value = value.strip().strip("'\"")
            if not value or len(value) < 8:
                continue
            # Skip obvious placeholder values (your_key_here, etc.)
            if _PLACEHOLDER_RE.search(value):
                continue
            snippet = mask_secret_in_snippet(line, "secrets")
            snippet = _truncate_snippet(snippet)
            findings.append(
                Finding(
                    id=_build_finding_id("CONF-ENV-001", file_path, line_no),
                    pattern_id="CONF-ENV-001",
                    severity="P1",
                    category="secrets",
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    snippet=snippet,
                    message="Potential secret in .env file",
                    recommendation="Do not commit .env files; use a secrets manager or local overrides",
                    confidence=1.0,
                )
            )
        return findings

    def _scan_package_json(self, file_path: str, content: str) -> list[Finding]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for section_name in ("dependencies", "devDependencies", "optionalDependencies"):
            section = data.get(section_name)
            if not isinstance(section, dict):
                continue
            for dep_name, version in section.items():
                if isinstance(version, str) and "http://" in version:
                    snippet = _truncate_snippet(f'\"{dep_name}\": \"{version}\"')
                    findings.append(
                        Finding(
                            id=_build_finding_id("CONF-PKG-001", file_path, 1),
                            pattern_id="CONF-PKG-001",
                            severity="P2",
                            category="supply-chain",
                            file_path=file_path,
                            line_start=1,
                            line_end=1,
                            snippet=snippet,
                            message="Insecure HTTP dependency source detected",
                            recommendation="Use HTTPS or a registry version instead of HTTP URLs",
                            confidence=1.0,
                        )
                    )
        return findings

    def _load_json_file(self, path: Path) -> dict | None:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        return self._load_json_content(raw)

    def _tsconfig_refs_are_strict(self, config_data: dict, file_path: str, repo_root: Path) -> bool:
        refs = config_data.get("references")
        if not isinstance(refs, list) or not refs:
            return False

        base_dir = (repo_root / file_path).parent
        checked = 0
        strict_true = 0
        for entry in refs:
            if not isinstance(entry, dict):
                continue
            ref_path = entry.get("path")
            if not isinstance(ref_path, str) or not ref_path.strip():
                continue
            ref = (base_dir / ref_path).resolve()
            if ref.is_dir():
                ref = ref / "tsconfig.json"
            if ref.suffix.lower() != ".json":
                ref = ref / "tsconfig.json"

            payload = self._load_json_file(ref)
            if payload is None:
                continue
            checked += 1
            compiler = payload.get("compilerOptions")
            strict_value = compiler.get("strict") if isinstance(compiler, dict) else None
            if strict_value is True:
                strict_true += 1

        return checked > 0 and strict_true == checked

    def _scan_tsconfig(
        self, file_path: str, content: str, *, repo_root: Path | None = None
    ) -> list[Finding]:
        data = self._load_json_content(content)
        if data is None:
            return []
        compiler = data.get("compilerOptions") if isinstance(data, dict) else None
        strict_value = None
        if isinstance(compiler, dict):
            strict_value = compiler.get("strict")
        if strict_value is True:
            return []
        if (
            strict_value is None
            and repo_root is not None
            and isinstance(data, dict)
            and self._tsconfig_refs_are_strict(data, file_path, repo_root)
        ):
            return []
        snippet = "\"strict\": false" if strict_value is False else "strict mode not enabled"
        snippet = _truncate_snippet(snippet)
        return [
            Finding(
                id=_build_finding_id("CONF-TS-001", file_path, 1),
                pattern_id="CONF-TS-001",
                severity="P2",
                category="quality",
                file_path=file_path,
                line_start=1,
                line_end=1,
                snippet=snippet,
                message="TypeScript strict mode is disabled",
                recommendation="Enable compilerOptions.strict for safer type checking",
                confidence=1.0,
            )
        ]

    def _scan_docker_compose(self, file_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        privileged_re = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
        ports_re = re.compile(
            r"^\s*-\s*['\"]?\d{1,5}:\d{1,5}(?:/(tcp|udp))?['\"]?\s*$"
        )

        for line_no, line in enumerate(content.splitlines(), start=1):
            if privileged_re.search(line):
                snippet = _truncate_snippet(line.strip())
                findings.append(
                    Finding(
                        id=_build_finding_id("CONF-DC-001", file_path, line_no),
                        pattern_id="CONF-DC-001",
                        severity="P1",
                        category="misconfig",
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        snippet=snippet,
                        message="Docker Compose privileged mode enabled",
                        recommendation="Avoid privileged containers unless absolutely required",
                        confidence=1.0,
                    )
                )
            if ports_re.search(line):
                snippet = _truncate_snippet(line.strip())
                findings.append(
                    Finding(
                        id=_build_finding_id("CONF-DC-002", file_path, line_no),
                        pattern_id="CONF-DC-002",
                        severity="P2",
                        category="exposure",
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        snippet=snippet,
                        message="Docker Compose exposes host ports",
                        recommendation="Limit exposed ports and bind to localhost where possible",
                        confidence=1.0,
                    )
                )
        return findings
