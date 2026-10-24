from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from ..logging import OmarLogger
from ..utils import safe_read_text
from .file_classifier import classify_file
from .hotspot_detector import HOTSPOT_PATTERNS, hotspot_categories_for_path

DEFAULT_MAX_FILES = 1000
DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_IGNORE_PATTERNS = [
    "node_modules/**",
    "dist/**",
    "build/**",
    ".git/**",
    ".pytest_cache/**",
    ".mypy_cache/**",
    ".ruff_cache/**",
    ".tox/**",
    ".cache/**",
    ".sentinelayer/**",
    ".tmp-run-*/**",
    "**/*.lock",
    "tests/**",
    "**/__tests__/**",
    "**/*.spec.*",
    "**/*.test.*",
    "coverage/**",
    ".next/**",
    ".turbo/**",
    ".venv/**",
    ".env.local",
]


def run_ingest(
    repo_root: Path,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_BYTES,
    logger: OmarLogger | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    ignore_patterns = _load_ignore_patterns(repo_root)
    node_result = _run_node_mapper(repo_root, max_files, max_file_size_bytes)

    raw_files = node_result.get("files", [])
    node_stats = node_result.get("stats", {})
    binary_files = int(node_stats.get("binary_files", 0))
    too_large_files = int(node_stats.get("too_large", 0))
    truncated = bool(node_stats.get("truncated", False))

    if truncated and logger:
        logger.warning("ingest_file_limit_reached", max_files=max_files)
    if too_large_files and logger:
        logger.warning("ingest_oversized_files_skipped", count=too_large_files)

    files_out: list[dict[str, Any]] = []
    total_lines = 0
    in_scope_files = 0
    read_failures = int(node_stats.get("read_failures", 0))

    for item in raw_files:
        rel_path = item.get("path")
        if not rel_path:
            continue
        if _matches_ignore(rel_path, ignore_patterns):
            continue
        size_bytes = int(item.get("size_bytes", 0))
        if size_bytes > max_file_size_bytes:
            continue

        file_path = repo_root / rel_path
        try:
            content = safe_read_text(file_path, max_bytes=max_file_size_bytes)
        except (OSError, ValueError) as exc:
            read_failures += 1
            if logger:
                logger.warning("ingest_file_read_failed", path=str(rel_path), error=str(exc))
            continue

        classification = classify_file(rel_path)
        if classification.category == "source":
            in_scope_files += 1

        line_count = len(content.splitlines())
        total_lines += line_count

        hotspot_categories = hotspot_categories_for_path(rel_path)
        files_out.append(
            {
                "path": rel_path,
                "category": classification.category,
                "language": classification.language,
                "lines": line_count,
                "size_bytes": size_bytes,
                "is_hotspot": bool(hotspot_categories),
                "hotspot_reasons": hotspot_categories,
            }
        )

    hotspots = {category: [] for category in HOTSPOT_PATTERNS}
    for file_entry in files_out:
        for category in file_entry["hotspot_reasons"]:
            hotspots[category].append(file_entry["path"])

    text_files = len(files_out)
    total_files = text_files + binary_files

    dependencies = _detect_dependencies(repo_root)

    return {
        "schema_version": "1.0",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stats": {
            "total_files": total_files,
            "text_files": text_files,
            "binary_files": binary_files,
            "in_scope_files": in_scope_files,
            "total_lines": total_lines,
            "truncated": truncated,
            "too_large": too_large_files,
            "read_failures": read_failures,
        },
        "files": files_out,
        "hotspots": hotspots,
        "dependencies": dependencies,
    }


def _load_ignore_patterns(repo_root: Path) -> list[str]:
    ignore_path = repo_root / ".sentinelayerignore"
    patterns: list[str] = list(DEFAULT_IGNORE_PATTERNS)
    if not ignore_path.exists():
        return patterns
    try:
        raw = ignore_path.read_text(encoding="utf-8")
    except OSError:
        return patterns
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(stripped)
    return patterns


def _matches_ignore(path: str, patterns: list[str]) -> bool:
    if not patterns:
        return False
    normalized = path.replace("\\", "/")
    ignored = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        pat = pattern[1:] if negated else pattern
        pat = pat.strip()
        if not pat:
            continue
        if pat.endswith("/"):
            match = normalized.startswith(pat.rstrip("/") + "/")
        else:
            if "/" in pat:
                match = fnmatch.fnmatch(normalized, pat)
                if not match and pat.startswith("**/"):
                    alt = pat[3:]
                    match = fnmatch.fnmatch(normalized, alt) or fnmatch.fnmatch(
                        Path(normalized).name, alt
                    )
            else:
                match = fnmatch.fnmatch(Path(normalized).name, pat) or fnmatch.fnmatch(
                    normalized, pat
                )
        if match:
            ignored = not negated
    return ignored


def _run_node_mapper(repo_root: Path, max_files: int, max_file_size_bytes: int) -> dict[str, Any]:
    script_path = Path(__file__).with_name("codebase_map.mjs")
    try:
        result = subprocess.run(
            ["node", str(script_path), str(repo_root), str(max_files), str(max_file_size_bytes)],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except (FileNotFoundError, OSError):
        # Node isn't guaranteed in all environments (eg local dev/test); fall back to a
        # pure-Python mapper so ingest can still function.
        return _run_python_mapper(repo_root, max_files, max_file_size_bytes)
    except subprocess.TimeoutExpired:
        return _run_python_mapper(repo_root, max_files, max_file_size_bytes)
    if result.returncode != 0:
        stderr = result.stderr.strip() or "unknown error"
        raise RuntimeError(f"codebase_map failed: {stderr}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"codebase_map invalid JSON: {exc}") from exc


_EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    ".venv",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
}


def _is_binary_file(path: Path) -> bool:
    with path.open("rb") as f:
        chunk = f.read(4096)
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    non_text = 0
    for byte in chunk:
        if byte < 7 or (byte > 14 and byte < 32) or byte == 127:
            non_text += 1
    return (non_text / len(chunk)) > 0.3


def _run_python_mapper(repo_root: Path, max_files: int, max_file_size_bytes: int) -> dict[str, Any]:
    root = repo_root.resolve()
    stats: dict[str, Any] = {
        "total_files": 0,
        "binary_files": 0,
        "too_large": 0,
        "truncated": False,
        "read_failures": 0,
    }
    files: list[dict[str, Any]] = []

    def unreadable_directory(_error):
        stats["read_failures"] += 1

    for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable_directory):
        # Mutate dirnames in-place to prune traversal (os.walk contract).
        dirnames[:] = [
            d
            for d in dirnames
            if d not in _EXCLUDED_DIRS and not os.path.islink(os.path.join(dirpath, d))
        ]

        for name in filenames:
            if len(files) >= max_files:
                stats["truncated"] = True
                return {"root": str(root), "files": files, "stats": stats}

            full_path = Path(dirpath) / name
            if full_path.is_symlink():
                continue

            try:
                st = full_path.stat()
            except OSError:
                stats["read_failures"] += 1
                continue

            stats["total_files"] += 1
            size_bytes = int(st.st_size)
            if size_bytes > max_file_size_bytes:
                stats["too_large"] += 1
                continue

            try:
                binary = _is_binary_file(full_path)
            except OSError:
                stats["read_failures"] += 1
                continue
            if binary:
                stats["binary_files"] += 1
                continue

            try:
                rel_path = full_path.relative_to(root).as_posix()
            except ValueError:
                continue
            files.append({"path": rel_path, "size_bytes": size_bytes, "is_binary": False})

    return {"root": str(root), "files": files, "stats": stats}


def _detect_dependencies(repo_root: Path) -> dict[str, Any]:
    package_manager = "unknown"
    lockfile = ""
    direct_deps = 0
    total_deps = 0

    package_json = repo_root / "package.json"
    pnpm_lock = repo_root / "pnpm-lock.yaml"
    yarn_lock = repo_root / "yarn.lock"
    npm_lock = repo_root / "package-lock.json"
    poetry_lock = repo_root / "poetry.lock"
    pipfile_lock = repo_root / "Pipfile.lock"
    requirements = repo_root / "requirements.txt"

    if pnpm_lock.exists():
        package_manager = "pnpm"
        lockfile = pnpm_lock.name
        total_deps = _count_pnpm_lock(pnpm_lock)
    elif yarn_lock.exists():
        package_manager = "yarn"
        lockfile = yarn_lock.name
        total_deps = _count_yarn_lock(yarn_lock)
    elif npm_lock.exists():
        package_manager = "npm"
        lockfile = npm_lock.name
        total_deps = _count_npm_lock(npm_lock)
    elif package_json.exists():
        package_manager = "npm"

    if package_json.exists():
        direct_deps = _count_package_json(package_json)
        if total_deps == 0:
            total_deps = direct_deps

    if package_manager == "unknown":
        if poetry_lock.exists():
            package_manager = "poetry"
            lockfile = poetry_lock.name
            total_deps = _count_poetry_lock(poetry_lock)
            direct_deps = total_deps
        elif pipfile_lock.exists():
            package_manager = "pipenv"
            lockfile = pipfile_lock.name
            direct_deps = _count_pipfile_lock(pipfile_lock)
            total_deps = direct_deps
        elif requirements.exists():
            package_manager = "pip"
            lockfile = requirements.name
            direct_deps = _count_requirements(requirements)
            total_deps = direct_deps

    return {
        "package_manager": package_manager,
        "lockfile": lockfile,
        "direct_deps": int(direct_deps),
        "total_deps": int(total_deps),
    }


def _count_package_json(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    deps = data.get("dependencies") or {}
    dev = data.get("devDependencies") or {}
    return len(deps) + len(dev)


def _count_npm_lock(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    packages = data.get("packages")
    if isinstance(packages, dict):
        return max(len(packages) - 1, 0)
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        return len(dependencies)
    return 0


def _count_pnpm_lock(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0
    count = 0
    in_packages = False
    for line in text.splitlines():
        if line.startswith("packages:"):
            in_packages = True
            continue
        if not in_packages:
            continue
        if line and not line.startswith(" "):
            break
        if line.startswith("  /") and line.rstrip().endswith(":"):
            count += 1
    return count


def _count_yarn_lock(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0
    count = 0
    for line in text.splitlines():
        if not line or line.startswith(" "):
            continue
        if line.startswith("#"):
            continue
        if line.rstrip().endswith(":"):
            count += 1
    return count


def _count_poetry_lock(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0
    return sum(1 for line in text.splitlines() if line.strip() == "[[package]]")


def _count_pipfile_lock(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    total = 0
    for key in ("default", "develop"):
        section = data.get(key)
        if isinstance(section, dict):
            total += len(section)
    return total


def _count_requirements(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0
    count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        count += 1
    return count
