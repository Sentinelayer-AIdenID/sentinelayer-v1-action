#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REQUIRED_PATHS = [
    Path("README.md"),
    Path("LICENSE"),
    Path("action.yml"),
    Path("docs/CONFIGURATION.md"),
    Path("docs/EXAMPLES.md"),
]

RECOMMENDED_PATHS = [
    Path("docs/ARCHITECTURE.md"),
    Path("docs/RUNBOOK.md"),
    Path("docs/ADRs/README.md"),
    Path("docs/INCIDENTS/README.md"),
    Path("docs/templates/ADR_TEMPLATE.md"),
    Path("docs/templates/RUNBOOK_TEMPLATE.md"),
    Path("docs/templates/INCIDENT_TEMPLATE.md"),
]


@dataclass(frozen=True)
class FileEntry:
    path: str
    bytes: int
    modified_utc: str


def _repo_root() -> Path:
    # scripts/ is expected to live at <repo_root>/scripts/
    return Path(__file__).resolve().parents[1]


def _stat_entry(repo_root: Path, rel: Path) -> FileEntry | None:
    p = repo_root / rel
    if not p.exists() or not p.is_file():
        return None
    st = p.stat()
    modified = datetime.fromtimestamp(st.st_mtime, tz=UTC).isoformat()
    return FileEntry(path=rel.as_posix(), bytes=int(st.st_size), modified_utc=modified)


def _walk_markdown(repo_root: Path) -> list[FileEntry]:
    entries: list[FileEntry] = []
    for p in sorted(repo_root.rglob("*.md")):
        if not p.is_file():
            continue
        rel = p.relative_to(repo_root)
        entry = _stat_entry(repo_root, rel)
        if entry:
            entries.append(entry)
    return entries


def _bytes_human(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(n)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{n}B"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SentinelLayer repo documentation inventory")
    parser.add_argument("--json", action="store_true", help="Emit inventory as JSON")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when required docs are missing",
    )
    args = parser.parse_args(argv)

    repo_root = _repo_root()

    md_entries = _walk_markdown(repo_root)

    present_required: list[FileEntry] = []
    missing_required: list[str] = []
    for rel in REQUIRED_PATHS:
        entry = _stat_entry(repo_root, rel)
        if entry:
            present_required.append(entry)
        else:
            missing_required.append(rel.as_posix())

    present_recommended: list[FileEntry] = []
    missing_recommended: list[str] = []
    for rel in RECOMMENDED_PATHS:
        entry = _stat_entry(repo_root, rel)
        if entry:
            present_recommended.append(entry)
        else:
            missing_recommended.append(rel.as_posix())

    payload: dict[str, Any] = {
        "repo_root": str(repo_root),
        "required": {
            "present": [e.__dict__ for e in present_required],
            "missing": missing_required,
        },
        "recommended": {
            "present": [e.__dict__ for e in present_recommended],
            "missing": missing_recommended,
        },
        "markdown_files": [e.__dict__ for e in md_entries],
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("Documentation inventory")
        print()

        print("Required")
        for e in present_required:
            print(f"- {e.path} ({_bytes_human(e.bytes)}, modified={e.modified_utc})")
        for p in missing_required:
            print(f"- {p} (missing)")
        print()

        print("Recommended")
        for e in present_recommended:
            print(f"- {e.path} ({_bytes_human(e.bytes)}, modified={e.modified_utc})")
        for p in missing_recommended:
            print(f"- {p} (missing)")
        print()

        print("All Markdown Files")
        for e in md_entries:
            print(f"- {e.path} ({_bytes_human(e.bytes)})")

    if args.check and missing_required:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

