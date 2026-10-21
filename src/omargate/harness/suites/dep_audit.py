from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import shutil
import tomllib
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, Optional, TypeGuard
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version

from ...analyze.deterministic.pattern_scanner import Finding, _truncate_snippet
from ...models import (
    DEPENDENCY_AUDIT_COVERAGE_SCOPE,
    DEPENDENCY_AUDIT_INDETERMINATE_REASONS,
    DEPENDENCY_AUDIT_SCHEMA_VERSION,
)
from ..runner import (
    CommandResult,
    SecuritySuite,
    _PrivateScratch,
    _is_within,
    _sanitize_proxy_origin,
    run_command,
)


AuditState = Literal["clean", "vulnerable", "indeterminate"]
AuditEcosystem = Literal["npm", "pip", "cargo"]

_AUDIT_ECOSYSTEMS: tuple[AuditEcosystem, ...] = ("npm", "pip", "cargo")
_AUDIT_INCOMPLETE_REASONS = DEPENDENCY_AUDIT_INDETERMINATE_REASONS
_AUDIT_TOOL_METADATA = {
    "npm": (
        "HARNESS-NPM-AUDIT-INCOMPLETE",
        "npm audit",
        ".sentinelayer/harness/npm-audit",
    ),
    "pip": (
        "HARNESS-PIP-AUDIT-INCOMPLETE",
        "pip-audit",
        ".sentinelayer/harness/pip-audit",
    ),
    "cargo": (
        "HARNESS-CARGO-AUDIT-INCOMPLETE",
        "cargo audit",
        ".sentinelayer/harness/cargo-audit",
    ),
}
_NPM_SEVERITIES = frozenset({"info", "low", "moderate", "high", "critical"})
_NPM_AUDIT_REGISTRY = "https://registry.npmjs.org"
_MAX_REQUIREMENTS_BYTES = 1_048_576
_MAX_NPM_INPUT_BYTES = 33_554_432
_MAX_CARGO_INPUT_BYTES = 33_554_432
_MAX_MANIFEST_DISCOVERY_ENTRIES = 20_000
_MAX_MANIFEST_DISCOVERY_DEPTH = 12
_PYTHON_MANIFESTS = (
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "setup.py",
    "setup.cfg",
)
_MANIFESTS_BY_ECOSYSTEM: dict[AuditEcosystem, frozenset[str]] = {
    "npm": frozenset({"package.json"}),
    "pip": frozenset(_PYTHON_MANIFESTS),
    "cargo": frozenset({"Cargo.toml"}),
}
_DISCOVERY_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "target",
        "vendor",
        "venv",
    }
)
_PIP_ROUTING_CONFIG_PATHS = (
    "pip.conf",
    "pip.ini",
    "uv.toml",
    "poetry.toml",
    ".pip/pip.conf",
)
_PIP_ROUTING_ENV_KEYS = frozenset(
    {
        "PIP_CERT",
        "PIP_CLIENT_CERT",
        "PIP_CONFIG_FILE",
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "PIP_INDEX_URL",
        "PIP_NO_INDEX",
        "PIP_TRUSTED_HOST",
        "UV_DEFAULT_INDEX",
        "UV_EXTRA_INDEX_URL",
        "UV_INDEX",
        "UV_INDEX_URL",
    }
)
_PINNED_REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[A-Za-z0-9._,-]+\])?"
    r"==(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)$"
)
_REQUIREMENTS_MANIFEST_RE = re.compile(
    r"^requirements(?:[-_.][A-Za-z0-9_.-]+)?\.(?:txt|in)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DependencyAuditOutcome:
    ecosystem: AuditEcosystem
    applicable: bool
    state: AuditState | None
    vulnerability_count: int | None
    reason_code: str | None

    @classmethod
    def not_applicable(cls, ecosystem: AuditEcosystem) -> DependencyAuditOutcome:
        return cls(ecosystem, False, None, None, None)

    @classmethod
    def clean(cls, ecosystem: AuditEcosystem) -> DependencyAuditOutcome:
        return cls(ecosystem, True, "clean", 0, None)

    @classmethod
    def vulnerable(
        cls, ecosystem: AuditEcosystem, count: int
    ) -> DependencyAuditOutcome:
        return cls(ecosystem, True, "vulnerable", count, None)

    @classmethod
    def indeterminate(
        cls, ecosystem: AuditEcosystem, reason_code: str
    ) -> DependencyAuditOutcome:
        safe_reason = (
            reason_code
            if reason_code in _AUDIT_INCOMPLETE_REASONS
            else "execution_error"
        )
        return cls(ecosystem, True, "indeterminate", None, safe_reason)

    def to_dict(self) -> dict[str, object]:
        return {
            "ecosystem": self.ecosystem,
            "applicable": self.applicable,
            "state": self.state,
            "vulnerability_count": self.vulnerability_count,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class DependencyAuditEvidence:
    outcomes: tuple[DependencyAuditOutcome, ...]
    enabled: bool = True
    npm_projects: tuple[dict, ...] = ()
    discovered_npm_manifests: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return (
            len(self.outcomes) == len(_AUDIT_ECOSYSTEMS)
            and {outcome.ecosystem for outcome in self.outcomes}
            == set(_AUDIT_ECOSYSTEMS)
            and all(
                not outcome.applicable
                or outcome.state in {"clean", "vulnerable"}
                for outcome in self.outcomes
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": DEPENDENCY_AUDIT_SCHEMA_VERSION,
            "enabled": self.enabled,
            "complete": self.complete,
            "coverage_scope": dict(DEPENDENCY_AUDIT_COVERAGE_SCOPE),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
            "npm_projects": {"discovered_manifests": list(self.discovered_npm_manifests),
                             "audits": list(self.npm_projects)},
        }


@dataclass(frozen=True)
class DependencyAuditRun:
    findings: list[Finding]
    evidence: DependencyAuditEvidence


def disabled_dependency_audit_evidence() -> dict[str, object]:
    return DependencyAuditEvidence(
        tuple(
            DependencyAuditOutcome.not_applicable(ecosystem)
            for ecosystem in _AUDIT_ECOSYSTEMS
        ),
        enabled=False,
    ).to_dict()


def _is_nonnegative_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _load_strict_json(value: str) -> object:
    return json.loads(
        value,
        object_pairs_hook=_strict_object,
        parse_constant=_reject_json_constant,
        parse_float=_strict_json_float,
    )


def _canonical_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _parse_pip_vulnerability_count(
    payload: Any,
    *,
    expected_dependencies: frozenset[tuple[str, str]],
) -> Optional[int]:
    if not isinstance(payload, dict) or "error" in payload:
        return None
    dependencies = payload.get("dependencies")
    fixes = payload.get("fixes")
    if (
        not isinstance(dependencies, list)
        or not dependencies
        or not isinstance(fixes, list)
    ):
        return None

    total = 0
    observed_dependencies: set[tuple[str, str]] = set()
    observed_names: set[str] = set()
    for dependency in dependencies:
        if (
            not isinstance(dependency, dict)
            or "skip_reason" in dependency
            or not isinstance(dependency.get("name"), str)
            or not dependency.get("name")
            or not isinstance(dependency.get("version"), str)
            or not dependency.get("version")
        ):
            return None
        name = _canonical_package_name(dependency["name"])
        try:
            version = str(Version(dependency["version"]))
        except InvalidVersion:
            return None
        if name in observed_names:
            return None
        observed_names.add(name)
        observed_dependencies.add((name, version))
        vulnerabilities = dependency.get("vulns")
        if not isinstance(vulnerabilities, list):
            return None
        if any(
            not isinstance(vulnerability, dict)
            or not isinstance(vulnerability.get("id"), str)
            or not vulnerability.get("id")
            for vulnerability in vulnerabilities
        ):
            return None
        total += len(vulnerabilities)
    if observed_dependencies != expected_dependencies:
        return None
    return total


def _parse_npm_vulnerability_count(
    payload: Any,
    *,
    expected_dependency_count: int,
) -> Optional[int]:
    if not isinstance(payload, dict) or "error" in payload:
        return None
    if payload.get("auditReportVersion") != 2:
        return None
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return None
    vulnerability_counts = metadata.get("vulnerabilities")
    if not isinstance(vulnerability_counts, dict):
        return None
    if set(vulnerability_counts) != set(_NPM_SEVERITIES) | {"total"}:
        return None
    severity_counts: dict[str, int] = {}
    for severity in _NPM_SEVERITIES:
        severity_count = vulnerability_counts.get(severity)
        if not _is_nonnegative_int(severity_count):
            return None
        severity_counts[severity] = severity_count
    total = vulnerability_counts.get("total")
    if not _is_nonnegative_int(total) or sum(severity_counts.values()) != total:
        return None

    dependency_counts = metadata.get("dependencies")
    if not isinstance(dependency_counts, dict):
        return None
    required_dependency_counters = {
        "prod",
        "dev",
        "optional",
        "peer",
        "peerOptional",
        "total",
    }
    if set(dependency_counts) != required_dependency_counters:
        return None
    if any(
        not _is_nonnegative_int(dependency_counts.get(counter))
        for counter in required_dependency_counters
    ):
        return None
    if dependency_counts["peer"] != 0 or dependency_counts["peerOptional"] != 0:
        return None
    if dependency_counts["total"] != expected_dependency_count:
        return None

    records = payload.get("vulnerabilities")
    if not isinstance(records, dict):
        return None
    observed_counts = {severity: 0 for severity in _NPM_SEVERITIES}
    for record in records.values():
        if not isinstance(record, dict):
            return None
        severity = str(record.get("severity") or "").lower()
        if severity not in _NPM_SEVERITIES:
            return None
        observed_counts[severity] += 1
    if observed_counts != severity_counts:
        return None
    return total


def _parse_cargo_vulnerability_count(
    payload: Any,
    *,
    expected_dependency_count: int,
) -> Optional[int]:
    if not isinstance(payload, dict) or "error" in payload:
        return None
    database = payload.get("database")
    lockfile = payload.get("lockfile")
    settings = payload.get("settings")
    vulnerabilities = payload.get("vulnerabilities")
    if (
        not isinstance(database, dict)
        or not isinstance(lockfile, dict)
        or not isinstance(settings, dict)
        or not isinstance(vulnerabilities, dict)
    ):
        return None
    advisory_count = database.get("advisory-count")
    dependency_count = lockfile.get("dependency-count")
    if (
        not _is_nonnegative_int(advisory_count)
        or advisory_count == 0
        or not _is_nonnegative_int(dependency_count)
        or dependency_count != expected_dependency_count
    ):
        return None
    found = vulnerabilities.get("found")
    count = vulnerabilities.get("count")
    listed = vulnerabilities.get("list")
    if (
        not isinstance(found, bool)
        or not _is_nonnegative_int(count)
        or not isinstance(listed, list)
        or count != len(listed)
        or found != bool(listed)
    ):
        return None
    for item in listed:
        if not isinstance(item, dict):
            return None
        advisory = item.get("advisory")
        if (
            not isinstance(advisory, dict)
            or not isinstance(advisory.get("id"), str)
            or not advisory.get("id")
        ):
            return None
    return count


def _classify_audit_result(
    ecosystem: AuditEcosystem,
    result: CommandResult,
    parser: Callable[[Any], Optional[int]],
) -> DependencyAuditOutcome:
    status_reasons = {
        "not_found": "command_not_found",
        "spawn_error": "spawn_error",
        "timed_out": "timed_out",
        "decode_error": "decode_error",
        "output_limit_exceeded": "output_limit_exceeded",
    }
    if result.status != "exited":
        reason = (
            "process_containment_error"
            if result.status == "spawn_error"
            and result.reason_code == "process_containment_error"
            else status_reasons.get(result.status, "execution_error")
        )
        return DependencyAuditOutcome.indeterminate(
            ecosystem,
            reason,
        )
    if result.returncode == 127:
        return DependencyAuditOutcome.indeterminate(ecosystem, "exited_127")
    if result.returncode not in {0, 1}:
        return DependencyAuditOutcome.indeterminate(ecosystem, "unexpected_exit")
    if not result.stdout.strip():
        return DependencyAuditOutcome.indeterminate(ecosystem, "empty_output")
    try:
        payload = _load_strict_json(result.stdout)
    except (json.JSONDecodeError, TypeError, ValueError):
        return DependencyAuditOutcome.indeterminate(ecosystem, "invalid_json")
    if isinstance(payload, dict) and "error" in payload:
        return DependencyAuditOutcome.indeterminate(ecosystem, "error_payload")
    try:
        count = parser(payload)
    except Exception:
        return DependencyAuditOutcome.indeterminate(ecosystem, "unrecognized_schema")
    if count is None:
        return DependencyAuditOutcome.indeterminate(ecosystem, "unrecognized_schema")
    if (result.returncode == 0 and count != 0) or (
        result.returncode == 1 and count == 0
    ):
        return DependencyAuditOutcome.indeterminate(ecosystem, "exit_result_mismatch")
    if count == 0:
        return DependencyAuditOutcome.clean(ecosystem)
    return DependencyAuditOutcome.vulnerable(ecosystem, count)


def _audit_incomplete_finding(
    ecosystem: AuditEcosystem, reason: str
) -> Finding:
    code, display_name, file_path = _AUDIT_TOOL_METADATA[ecosystem]
    safe_reason = reason if reason in _AUDIT_INCOMPLETE_REASONS else "execution_error"
    return Finding(
        id=code,
        pattern_id=code,
        severity="P0",
        category="harness",
        file_path=file_path,
        line_start=1,
        line_end=1,
        snippet="",
        message=(
            f"{display_name} did not produce a complete trusted result "
            f"({safe_reason})"
        ),
        recommendation=f"Restore {display_name} and re-run Omar Gate",
        confidence=1.0,
        source="harness",
    )


def _parse_ignore_ids(raw: str) -> list[str]:
    if not raw:
        return []
    seen: set[str] = set()
    identifiers: list[str] = []
    for token in re.split(r"[,\s;]+", raw):
        value = token.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        identifiers.append(value)
    return identifiers


def _is_safe_project_file(root: Path, candidate: Path) -> bool:
    if not candidate.is_file() or candidate.is_symlink():
        return False
    try:
        return candidate.resolve(strict=True).parent == root.resolve(strict=True)
    except (OSError, RuntimeError):
        return False


def _copy_safe_project_file(
    root: Path,
    source: Path,
    destination: Path,
    *,
    max_bytes: int,
) -> bool:
    if not _is_safe_project_file(root, source):
        return False
    try:
        if source.stat().st_size > max_bytes:
            return False
        shutil.copyfile(source, destination)
    except (OSError, RuntimeError):
        return False
    return True


def _load_pinned_requirements(
    root: Path, requirements: Path
) -> frozenset[tuple[str, str]] | None:
    if not _is_safe_project_file(root, requirements):
        return None
    try:
        if requirements.stat().st_size > _MAX_REQUIREMENTS_BYTES:
            return None
        content = requirements.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None
    dependencies: dict[str, str] = {}
    pending = ""
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line, pending = pending + line, ""
        parts = line.split()
        if any(re.fullmatch(r"--hash=sha256:[a-fA-F0-9]{64}", flag) is None for flag in parts[1:]):
            return None
        line = parts[0]
        match = _PINNED_REQUIREMENT_RE.fullmatch(line)
        if match is None:
            return None
        name = _canonical_package_name(match.group("name"))
        try:
            version = str(Version(match.group("version")))
        except InvalidVersion:
            return None
        if name in dependencies:
            return None
        dependencies[name] = version
    if pending or not dependencies:
        return None
    return frozenset(dependencies.items())


def _tool_only_pyproject(path: Path) -> bool:
    """Only known static-tool configuration is outside dependency declarations."""
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_REQUIREMENTS_BYTES:
            return False
        value = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return False
    tools = value.get("tool")
    allowed = {"pytest", "ruff", "mypy", "black", "coverage", "isort", "bandit", "pyright", "pylint"}
    return set(value) == {"tool"} and isinstance(tools, dict) and bool(tools) and set(tools) <= allowed


def _prepare_python_pins(root: Path, manifests: tuple[Path, ...], scratch: Path) -> tuple[frozenset[tuple[str, str]] | None, str | None]:
    """Snapshot and audit the union of declared pins; never install target code."""
    dependencies: dict[str, str] = {}
    for index, source in enumerate(manifests):
        if source.name != "pyproject.toml" and not re.fullmatch(r"requirements(?:[-.][A-Za-z0-9_.-]+)?\.txt", source.name):
            return None, "unsupported_pip_input"
        copied = scratch / f"source-{index}.txt"
        if not _copy_safe_project_file(root, source, copied, max_bytes=_MAX_REQUIREMENTS_BYTES):
            return None, "unsafe_pip_input"
        if source.name == "pyproject.toml":
            if not _tool_only_pyproject(copied):
                return None, "unsupported_pip_input"
            continue
        parsed = _load_pinned_requirements(scratch, copied)
        if parsed is None:
            return None, "unsafe_pip_input"
        for name, version in parsed:
            if name in dependencies and dependencies[name] != version:
                return None, "unsupported_pip_input"
            dependencies[name] = version
    if not dependencies:
        return None, "unsupported_pip_input"
    (scratch / "requirements.txt").write_text(
        "".join(f"{name}=={version}\n" for name, version in sorted(dependencies.items())),
        encoding="utf-8",
    )
    return frozenset(dependencies.items()), None


def _path_declared(path: Path) -> bool:
    try:
        return path.exists() or path.is_symlink()
    except OSError:
        return True


def _manifest_ecosystems(path: Path, root: Path) -> tuple[AuditEcosystem, ...]:
    ecosystems: list[AuditEcosystem] = []
    if path.name in _MANIFESTS_BY_ECOSYSTEM["npm"]:
        ecosystems.append("npm")
    if path.name in _MANIFESTS_BY_ECOSYSTEM["cargo"]:
        ecosystems.append("cargo")
    try:
        relative = path.relative_to(root)
    except ValueError:
        return tuple(ecosystems)
    python_manifest = (
        path.name in _MANIFESTS_BY_ECOSYSTEM["pip"]
        or _REQUIREMENTS_MANIFEST_RE.fullmatch(path.name) is not None
        or (path.name.startswith("pylock.") and len(path.name) > len("pylock."))
        or (
            path.suffix.lower() in {".txt", ".in"}
            and any(part.lower() == "requirements" for part in relative.parts[:-1])
        )
    )
    if python_manifest:
        ecosystems.append("pip")
    return tuple(ecosystems)


@dataclass(frozen=True)
class _ManifestDiscovery:
    root: Path | None
    complete: bool
    npm: tuple[Path, ...]
    pip: tuple[Path, ...]
    cargo: tuple[Path, ...]

    def paths_for(self, ecosystem: AuditEcosystem) -> tuple[Path, ...]:
        return getattr(self, ecosystem)


def _discover_manifests(root: Path) -> _ManifestDiscovery:
    found: dict[AuditEcosystem, list[Path]] = {
        ecosystem: [] for ecosystem in _AUDIT_ECOSYSTEMS
    }
    try:
        resolved_root = root.resolve(strict=True)
        if not resolved_root.is_dir():
            raise OSError
    except (OSError, RuntimeError):
        return _ManifestDiscovery(None, False, (), (), ())

    complete = True
    entry_count = 0
    pending: list[tuple[Path, int]] = [(resolved_root, 0)]
    while pending:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            complete = False
            continue
        child_directories: list[Path] = []
        for entry in entries:
            if entry.name in _DISCOVERY_EXCLUDED_DIRECTORIES:
                continue
            entry_count += 1
            if entry_count > _MAX_MANIFEST_DISCOVERY_ENTRIES:
                complete = False
                pending.clear()
                break
            path = Path(entry.path)
            manifest_ecosystems = _manifest_ecosystems(path, resolved_root)
            is_manifest = bool(manifest_ecosystems)
            try:
                is_symlink = entry.is_symlink()
                is_file = entry.is_file(follow_symlinks=False)
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError:
                complete = False
                continue

            if is_manifest:
                if is_symlink or not is_file:
                    complete = False
                else:
                    for ecosystem in manifest_ecosystems:
                        found[ecosystem].append(path)

            if is_symlink:
                try:
                    if entry.is_dir(follow_symlinks=True):
                        complete = False
                except OSError:
                    complete = False
                continue
            if not is_directory:
                continue
            if depth >= _MAX_MANIFEST_DISCOVERY_DEPTH:
                complete = False
                continue
            try:
                resolved_child = path.resolve(strict=True)
            except (OSError, RuntimeError):
                complete = False
                continue
            if not _is_within(resolved_child, resolved_root):
                complete = False
                continue
            child_directories.append(resolved_child)
        pending.extend((child, depth + 1) for child in reversed(child_directories))

    return _ManifestDiscovery(
        root=resolved_root,
        complete=complete,
        npm=tuple(sorted(found["npm"])),
        pip=tuple(sorted(found["pip"])),
        cargo=tuple(sorted(found["cargo"])),
    )


def _layout_outcome(
    discovery: _ManifestDiscovery, ecosystem: AuditEcosystem
) -> DependencyAuditOutcome | None:
    if not discovery.complete or discovery.root is None:
        return DependencyAuditOutcome.indeterminate(
            ecosystem, "manifest_discovery_incomplete"
        )
    paths = discovery.paths_for(ecosystem)
    if not paths:
        return DependencyAuditOutcome.not_applicable(ecosystem)
    if any(path.parent != discovery.root for path in paths):
        return DependencyAuditOutcome.indeterminate(
            ecosystem, "unsupported_project_layout"
        )
    return None


def _load_bounded_json_file(path: Path, max_bytes: int) -> object | None:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > max_bytes:
            return None
        text = raw.decode("utf-8", errors="strict")
        return _load_strict_json(text)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return None


def _npm_input_fingerprint(root: Path, path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        if (not _is_within(path.resolve(strict=True), root)
                or not _is_safe_project_file(path.parent, path)
                or path.stat().st_size > _MAX_NPM_INPUT_BYTES):
            return None
        raw = path.read_bytes()
        return hashlib.sha256(raw).hexdigest() if len(raw) <= _MAX_NPM_INPUT_BYTES else None
    except (OSError, RuntimeError):
        return None


def _dependency_mapping(
    payload: Mapping[str, object], key: str
) -> dict[str, str] | None:
    raw = payload.get(key, {})
    if not isinstance(raw, dict):
        return None
    result: dict[str, str] = {}
    for name, specifier in raw.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(specifier, str)
            or not specifier
        ):
            return None
        result[name] = specifier
    return result


def _registry_origin(resolved_url: object) -> str | None:
    if (
        not isinstance(resolved_url, str)
        or not resolved_url
        or len(resolved_url) > 4096
    ):
        return None
    try:
        parsed = urlsplit(resolved_url)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/")
        or parsed.query
        or parsed.fragment
    ):
        return None
    origin = _sanitize_proxy_origin(f"https://{parsed.netloc}")
    return origin if origin == _NPM_AUDIT_REGISTRY else None


@dataclass(frozen=True)
class _NpmAuditInput:
    dependency_count: int
    registry_origin: str


def _load_npm_audit_input(
    package_json: Path, lockfile: Path
) -> _NpmAuditInput | None:
    package_payload = _load_bounded_json_file(package_json, _MAX_NPM_INPUT_BYTES)
    lock_payload = _load_bounded_json_file(lockfile, _MAX_NPM_INPUT_BYTES)
    if not isinstance(package_payload, dict) or not isinstance(lock_payload, dict):
        return None
    if "workspaces" in package_payload or any(
        key in package_payload for key in ("bundleDependencies", "bundledDependencies")
    ):
        return None
    lock_version = lock_payload.get("lockfileVersion")
    if not _is_nonnegative_int(lock_version) or lock_version not in {2, 3}:
        return None
    packages = lock_payload.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        return None
    root_record = packages[""]
    package_peers = _dependency_mapping(package_payload, "peerDependencies")
    lock_peers = _dependency_mapping(root_record, "peerDependencies")
    package_peer_metadata = package_payload.get("peerDependenciesMeta", {})
    lock_peer_metadata = root_record.get("peerDependenciesMeta", {})
    if (
        package_peers is None
        or lock_peers is None
        or package_peers
        or lock_peers
        or not isinstance(package_peer_metadata, dict)
        or not isinstance(lock_peer_metadata, dict)
        or package_peer_metadata
        or lock_peer_metadata
    ):
        return None
    dependency_sections = (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
    )
    declared_names: set[str] = set()
    for section in dependency_sections:
        package_dependencies = _dependency_mapping(package_payload, section)
        lock_dependencies = _dependency_mapping(root_record, section)
        if package_dependencies is None or lock_dependencies is None:
            return None
        if package_dependencies != lock_dependencies:
            return None
        declared_names.update(package_dependencies)
    for identity_key in ("name", "version"):
        package_value = package_payload.get(identity_key)
        lock_value = root_record.get(identity_key)
        if package_value is not None or lock_value is not None:
            if (
                not isinstance(package_value, str)
                or not package_value
                or package_value != lock_value
            ):
                return None

    package_paths: set[str] = set()
    origins: set[str] = set()
    dependency_count = 0
    for package_path, record in packages.items():
        if package_path == "":
            continue
        peer_dependencies = (
            _dependency_mapping(record, "peerDependencies")
            if isinstance(record, dict)
            else None
        )
        peer_metadata = (
            record.get("peerDependenciesMeta", {})
            if isinstance(record, dict)
            else None
        )
        if (
            not isinstance(package_path, str)
            or not package_path.startswith("node_modules/")
            or "\\" in package_path
            or any(part in {"", ".", ".."} for part in package_path.split("/"))
            or not isinstance(record, dict)
            or peer_dependencies is None
            or bool(peer_dependencies)
            or not isinstance(peer_metadata, dict)
            or bool(peer_metadata)
            or record.get("link") is True
            or record.get("peer") is True
            or record.get("peerOptional") is True
            or not isinstance(record.get("version"), str)
            or not record.get("version")
        ):
            return None
        origin = _registry_origin(record.get("resolved"))
        if origin is None:
            return None
        package_paths.add(package_path)
        origins.add(origin)
        dependency_count += 1
    if dependency_count == 0 or len(origins) != 1:
        return None
    if any(f"node_modules/{name}" not in package_paths for name in declared_names):
        return None
    return _NpmAuditInput(dependency_count, next(iter(origins)))


def _load_cargo_dependency_count(root: Path, lockfile: Path) -> int | None:
    if not _is_safe_project_file(root, lockfile):
        return None
    try:
        raw = lockfile.read_bytes()
        if not raw or len(raw) > _MAX_CARGO_INPUT_BYTES:
            return None
        payload = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return None
    version = payload.get("version")
    packages = payload.get("package")
    if (
        not _is_nonnegative_int(version)
        or version not in {1, 2, 3, 4}
        or not isinstance(packages, list)
        or not packages
    ):
        return None
    for package in packages:
        if (
            not isinstance(package, dict)
            or not isinstance(package.get("name"), str)
            or not package.get("name")
            or not isinstance(package.get("version"), str)
            or not package.get("version")
        ):
            return None
    return len(packages)


def _has_pip_routing_configuration(
    root: Path, environment: Mapping[str, str] | None = None
) -> bool:
    source = os.environ if environment is None else environment
    if any(source.get(key) for key in _PIP_ROUTING_ENV_KEYS):
        return True
    return any(
        _path_declared(root / relative) for relative in _PIP_ROUTING_CONFIG_PATHS
    )


def _outcome_finding(outcome: DependencyAuditOutcome) -> Optional[Finding]:
    if outcome.state == "indeterminate":
        return _audit_incomplete_finding(
            outcome.ecosystem,
            outcome.reason_code or "execution_error",
        )
    if outcome.state != "vulnerable" or outcome.vulnerability_count is None:
        return None

    count = outcome.vulnerability_count
    if outcome.ecosystem == "npm":
        return Finding(
            id="HARNESS-NPM-AUDIT",
            pattern_id="HARNESS-NPM-AUDIT",
            severity="P1",
            category="supply-chain",
            file_path="package.json",
            line_start=1,
            line_end=1,
            snippet=_truncate_snippet(f"vulnerabilities={count}", max_chars=200),
            message=f"npm audit reported {count} known vulnerabilities",
            recommendation=(
                "Update dependencies and re-run npm audit; consider npm audit fix "
                "and lockfile updates"
            ),
            confidence=0.9,
            source="harness",
        )
    if outcome.ecosystem == "pip":
        return Finding(
            id="HARNESS-PIP-AUDIT",
            pattern_id="HARNESS-PIP-AUDIT",
            severity="P1",
            category="supply-chain",
            file_path="requirements.txt",
            line_start=1,
            line_end=1,
            snippet=_truncate_snippet(f"vulnerabilities={count}", max_chars=200),
            message="pip-audit reported known vulnerabilities in Python dependencies",
            recommendation="Upgrade vulnerable dependencies and re-run pip-audit",
            confidence=0.8,
            source="harness",
        )
    return Finding(
        id="HARNESS-CARGO-AUDIT",
        pattern_id="HARNESS-CARGO-AUDIT",
        severity="P1",
        category="supply-chain",
        file_path="Cargo.toml",
        line_start=1,
        line_end=1,
        snippet=_truncate_snippet(f"count={count}", max_chars=200),
        message="cargo audit reported known vulnerabilities in Rust dependencies",
        recommendation="Update vulnerable crates and re-run cargo audit",
        confidence=0.8,
        source="harness",
    )


@dataclass
class DepAuditSuite(SecuritySuite):
    tech_stack: list[str]
    pip_audit_ignore_ids: str = ""

    @property
    def name(self) -> str:
        return "dependency_audit"

    def applies_to(self, tech_stack: list[str]) -> bool:
        return True

    async def _run_audit_command(
        self,
        *,
        ecosystem: AuditEcosystem,
        args: list[str],
        cwd: Path,
        project_root: Path,
        parser: Callable[[Any], Optional[int]],
    ) -> tuple[DependencyAuditOutcome, bool]:
        try:
            result = await run_command(
                args,
                cwd=cwd,
                timeout_s=50,
                project_root=project_root,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return (
                DependencyAuditOutcome.indeterminate(ecosystem, "execution_error"),
                False,
            )
        if not result.cleanup_proven:
            return (
                DependencyAuditOutcome.indeterminate(
                    ecosystem, "process_containment_error"
                ),
                False,
            )
        return (
            _classify_audit_result(ecosystem, result, parser),
            result.cleanup_proven,
        )

    async def _npm_audit(
        self,
        root: Path,
        discovery: _ManifestDiscovery | None = None,
        project_records: list[dict] | None = None,
    ) -> tuple[Optional[Finding], DependencyAuditOutcome]:
        """Audit every discovered independent npm project without executing it."""
        discovery = discovery or _discover_manifests(root)
        if not discovery.complete or discovery.root is None or not discovery.npm:
            outcome = _layout_outcome(discovery, "npm")
            assert outcome is not None
            return _outcome_finding(outcome), outcome
        if len(discovery.npm) > 32:
            outcome = DependencyAuditOutcome.indeterminate("npm", "manifest_discovery_incomplete")
            return _outcome_finding(outcome), outcome
        root = discovery.root
        records = project_records if project_records is not None else []
        fingerprint = partial(_npm_input_fingerprint, root)
        outcomes = []
        for manifest in sorted(discovery.npm, key=lambda path: path.relative_to(root).as_posix()):
            lock = next((path for path in (manifest.parent / "npm-shrinkwrap.json", manifest.parent / "package-lock.json")
                         if _path_declared(path)), None)
            manifest_hash, lock_hash = fingerprint(manifest), fingerprint(lock)
            payload = _load_bounded_json_file(manifest, _MAX_NPM_INPUT_BYTES) if manifest_hash else None
            empty = (isinstance(payload, dict)
                     and not any(key in payload for key in ("workspaces", "bundleDependencies", "bundledDependencies"))
                     and all(_dependency_mapping(payload, key) == {} for key in
                             ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"))
                     and payload.get("peerDependenciesMeta", {}) == {})
            mode = "registry_graph"
            if not isinstance(payload, dict):
                outcome = DependencyAuditOutcome.indeterminate("npm", "unsafe_manifest")
                mode = "incomplete"
            elif lock is None and empty:
                # No declared dependencies and no lock graph to audit. A lock,
                # if present, must still be validated and audited normally.
                outcome = DependencyAuditOutcome.clean("npm")
                mode = "empty_declared_graph"
            else:
                _, outcome = await self._npm_audit_project(manifest.parent,
                    _ManifestDiscovery(manifest.parent, True, (manifest,), (), ()))
            unchanged = fingerprint(manifest) == manifest_hash and fingerprint(lock) == lock_hash
            if outcome.state == "indeterminate":
                mode = "incomplete"
            records.append({"manifest_path": manifest.relative_to(root).as_posix(),
                            "manifest_sha256": manifest_hash,
                            "lockfile_path": lock.relative_to(root).as_posix() if lock else None,
                            "lockfile_sha256": lock_hash, "mode": mode, "input_unchanged": unchanged,
                            "outcome": outcome.to_dict()})
            outcomes.append(outcome if unchanged else DependencyAuditOutcome.indeterminate("npm", "unsafe_manifest"))
        after = _discover_manifests(root)
        for row in records:
            row["input_unchanged"] = (row["input_unchanged"]
                and fingerprint(root / row["manifest_path"]) == row["manifest_sha256"]
                and fingerprint(root / row["lockfile_path"] if row["lockfile_path"] else None) == row["lockfile_sha256"])
        changed = any(not row["input_unchanged"] for row in records)
        if changed:
            outcome = DependencyAuditOutcome.indeterminate("npm", "unsafe_manifest")
        elif not after.complete or after.npm != discovery.npm:
            outcome = DependencyAuditOutcome.indeterminate("npm", "manifest_discovery_incomplete")
        elif any(item.state == "indeterminate" for item in outcomes):
            outcome = next(item for item in outcomes if item.state == "indeterminate")
        else:
            count = sum(item.vulnerability_count or 0 for item in outcomes)
            outcome = DependencyAuditOutcome.vulnerable("npm", count) if count else DependencyAuditOutcome.clean("npm")
        return _outcome_finding(outcome), outcome

    async def _npm_audit_project(
        self,
        root: Path,
        discovery: _ManifestDiscovery | None = None,
    ) -> tuple[Optional[Finding], DependencyAuditOutcome]:
        discovery = discovery or _discover_manifests(root)
        outcome = _layout_outcome(discovery, "npm")
        if outcome is not None:
            return _outcome_finding(outcome), outcome
        assert discovery.root is not None
        root = discovery.root
        if not _is_safe_project_file(root, root / "package.json"):
            outcome = DependencyAuditOutcome.indeterminate("npm", "unsafe_manifest")
            return _outcome_finding(outcome), outcome
        lockfiles = (root / "npm-shrinkwrap.json", root / "package-lock.json")
        lockfile = next((path for path in lockfiles if _path_declared(path)), None)
        if lockfile is None:
            outcome = DependencyAuditOutcome.indeterminate("npm", "missing_lockfile")
            return _outcome_finding(outcome), outcome
        if not _is_safe_project_file(root, lockfile):
            outcome = DependencyAuditOutcome.indeterminate("npm", "unsafe_lockfile")
            return _outcome_finding(outcome), outcome

        try:
            project_root = root.resolve(strict=True)
            with _PrivateScratch(prefix="omargate-npm-audit-") as audit_scratch:
                audit_cwd = audit_scratch.path.resolve(strict=True)
                if _is_within(audit_cwd, project_root):
                    outcome = DependencyAuditOutcome.indeterminate(
                        "npm", "unsafe_working_directory"
                    )
                elif not _copy_safe_project_file(
                    project_root,
                    root / "package.json",
                    audit_cwd / "package.json",
                    max_bytes=_MAX_NPM_INPUT_BYTES,
                ):
                    outcome = DependencyAuditOutcome.indeterminate(
                        "npm", "unsafe_manifest"
                    )
                elif not _copy_safe_project_file(
                    project_root,
                    lockfile,
                    audit_cwd / lockfile.name,
                    max_bytes=_MAX_NPM_INPUT_BYTES,
                ):
                    outcome = DependencyAuditOutcome.indeterminate(
                        "npm", "unsafe_lockfile"
                    )
                else:
                    audit_input = _load_npm_audit_input(
                        audit_cwd / "package.json",
                        audit_cwd / lockfile.name,
                    )
                    if audit_input is None:
                        outcome = DependencyAuditOutcome.indeterminate(
                            "npm", "unsafe_lockfile"
                        )
                    else:
                        outcome, cleanup_proven = await self._run_audit_command(
                            ecosystem="npm",
                            args=[
                                "npm",
                                "audit",
                                "--audit-level=info",
                                "--json",
                                "--ignore-scripts",
                                "--package-lock-only",
                                "--registry",
                                audit_input.registry_origin,
                            ],
                            cwd=audit_cwd,
                            project_root=project_root,
                            parser=partial(
                                _parse_npm_vulnerability_count,
                                expected_dependency_count=(
                                    audit_input.dependency_count
                                ),
                            ),
                        )
                        if not cleanup_proven:
                            audit_scratch.retain()
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError):
            outcome = DependencyAuditOutcome.indeterminate("npm", "execution_error")
        return _outcome_finding(outcome), outcome

    async def _pip_audit(
        self,
        root: Path,
        discovery: _ManifestDiscovery | None = None,
    ) -> tuple[Optional[Finding], DependencyAuditOutcome]:
        discovery = discovery or _discover_manifests(root)
        outcome = _layout_outcome(discovery, "pip")
        if outcome is not None:
            return _outcome_finding(outcome), outcome
        assert discovery.root is not None
        root = discovery.root
        if _has_pip_routing_configuration(root):
            outcome = DependencyAuditOutcome.indeterminate(
                "pip", "unsupported_pip_input"
            )
            return _outcome_finding(outcome), outcome

        try:
            with _PrivateScratch(prefix="omargate-pip-audit-") as audit_scratch:
                audit_cwd = audit_scratch.path.resolve(strict=True)
                project_root = root.resolve(strict=True)
                if _is_within(audit_cwd, project_root):
                    outcome = DependencyAuditOutcome.indeterminate(
                        "pip", "unsafe_working_directory"
                    )
                else:
                    expected_dependencies, input_error = _prepare_python_pins(
                        project_root, discovery.paths_for("pip"), audit_cwd,
                    )
                    audit_requirements = audit_cwd / "requirements.txt"
                    if expected_dependencies is None:
                        outcome = DependencyAuditOutcome.indeterminate(
                            "pip", input_error or "unsafe_pip_input"
                        )
                    else:
                        command = [
                            "pip-audit",
                            "--strict",
                            "--disable-pip",
                            "--no-deps",
                            "-r",
                            str(audit_requirements),
                            "-f",
                            "json",
                        ]
                        for vulnerability_id in _parse_ignore_ids(
                            self.pip_audit_ignore_ids
                        ):
                            command.extend(["--ignore-vuln", vulnerability_id])
                        outcome, cleanup_proven = await self._run_audit_command(
                            ecosystem="pip",
                            args=command,
                            cwd=audit_cwd,
                            project_root=project_root,
                            parser=partial(
                                _parse_pip_vulnerability_count,
                                expected_dependencies=expected_dependencies,
                            ),
                        )
                        if not cleanup_proven:
                            audit_scratch.retain()
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError):
            outcome = DependencyAuditOutcome.indeterminate("pip", "execution_error")
        return _outcome_finding(outcome), outcome

    async def _cargo_audit(
        self,
        root: Path,
        discovery: _ManifestDiscovery | None = None,
    ) -> tuple[Optional[Finding], DependencyAuditOutcome]:
        discovery = discovery or _discover_manifests(root)
        outcome = _layout_outcome(discovery, "cargo")
        if outcome is not None:
            return _outcome_finding(outcome), outcome
        assert discovery.root is not None
        root = discovery.root
        if not _is_safe_project_file(root, root / "Cargo.toml"):
            outcome = DependencyAuditOutcome.indeterminate("cargo", "unsafe_manifest")
            return _outcome_finding(outcome), outcome
        lockfile = root / "Cargo.lock"
        if not _path_declared(lockfile):
            outcome = DependencyAuditOutcome.indeterminate("cargo", "missing_lockfile")
            return _outcome_finding(outcome), outcome
        if not _is_safe_project_file(root, lockfile):
            outcome = DependencyAuditOutcome.indeterminate("cargo", "unsafe_lockfile")
            return _outcome_finding(outcome), outcome

        try:
            project_root = root.resolve(strict=True)
            with _PrivateScratch(prefix="omargate-cargo-audit-") as audit_scratch:
                audit_cwd = audit_scratch.path.resolve(strict=True)
                if _is_within(audit_cwd, project_root):
                    outcome = DependencyAuditOutcome.indeterminate(
                        "cargo", "unsafe_working_directory"
                    )
                elif not _copy_safe_project_file(
                    project_root,
                    lockfile,
                    audit_cwd / "Cargo.lock",
                    max_bytes=_MAX_CARGO_INPUT_BYTES,
                ):
                    outcome = DependencyAuditOutcome.indeterminate(
                        "cargo", "unsafe_lockfile"
                    )
                else:
                    audit_lockfile = audit_cwd / "Cargo.lock"
                    expected_dependency_count = _load_cargo_dependency_count(
                        audit_cwd, audit_lockfile
                    )
                    if expected_dependency_count is None:
                        outcome = DependencyAuditOutcome.indeterminate(
                            "cargo", "unsafe_lockfile"
                        )
                    else:
                        outcome, cleanup_proven = await self._run_audit_command(
                            ecosystem="cargo",
                            args=[
                                "cargo-audit",
                                "audit",
                                "--file",
                                str(audit_lockfile),
                                "--json",
                            ],
                            cwd=audit_cwd,
                            project_root=project_root,
                            parser=partial(
                                _parse_cargo_vulnerability_count,
                                expected_dependency_count=(
                                    expected_dependency_count
                                ),
                            ),
                        )
                        if not cleanup_proven:
                            audit_scratch.retain()
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError):
            outcome = DependencyAuditOutcome.indeterminate("cargo", "execution_error")
        return _outcome_finding(outcome), outcome

    def failure_result(
        self, project_root: str | Path, reason: str
    ) -> DependencyAuditRun:
        root = Path(project_root)
        discovery = _discover_manifests(root)
        outcomes_list: list[DependencyAuditOutcome] = []
        for ecosystem in _AUDIT_ECOSYSTEMS:
            layout_outcome = _layout_outcome(discovery, ecosystem)
            outcomes_list.append(
                DependencyAuditOutcome.indeterminate(ecosystem, reason)
                if layout_outcome is None
                else layout_outcome
            )
        outcomes = tuple(outcomes_list)
        findings = [
            finding
            for outcome in outcomes
            if (finding := _outcome_finding(outcome)) is not None
        ]
        return DependencyAuditRun(findings, DependencyAuditEvidence(outcomes))

    async def run_with_evidence(self, project_root: str) -> DependencyAuditRun:
        root = Path(project_root)
        discovery = _discover_manifests(root)
        npm_projects: list[dict] = []
        results = await asyncio.gather(
            self._npm_audit(root, discovery, npm_projects),
            self._pip_audit(root, discovery),
            self._cargo_audit(root, discovery),
            return_exceptions=True,
        )
        findings: list[Finding] = []
        outcomes: list[DependencyAuditOutcome] = []
        for ecosystem, result in zip(_AUDIT_ECOSYSTEMS, results):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, BaseException):
                outcome = DependencyAuditOutcome.indeterminate(
                    ecosystem, "execution_error"
                )
                finding = _outcome_finding(outcome)
            else:
                finding, outcome = result
            if finding is not None:
                findings.append(finding)
            outcomes.append(outcome)
        return DependencyAuditRun(
            findings=findings,
            evidence=DependencyAuditEvidence(tuple(outcomes), npm_projects=tuple(npm_projects),
                discovered_npm_manifests=tuple(sorted(path.relative_to(discovery.root).as_posix() for path in discovery.npm))
                if discovery.root is not None else ()),
        )

    async def run(self, project_root: str) -> list[Finding]:
        return (await self.run_with_evidence(project_root)).findings
