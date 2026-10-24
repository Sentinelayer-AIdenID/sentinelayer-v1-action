from __future__ import annotations

import re
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..utils import json_dumps, sha256_hex


def _norm_path(p: str) -> str:
    return str(p or "").replace("\\", "/")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _strip_markdown(text: str) -> str:
    if not text:
        return ""
    # Keep this intentionally simple and deterministic.
    out = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    out = re.sub(r"`([^`]*)`", r"\1", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"\1", out)
    out = re.sub(r"\*([^*]+)\*", r"\1", out)
    out = re.sub(r"_([^_]+)_", r"\1", out)
    return out


def _compact_text(value: Any, *, max_chars: int) -> str:
    text = " ".join(_strip_markdown(_safe_str(value)).split())
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def _quick_learn_value(quick_learn: Any, field: str) -> Any:
    if quick_learn is None:
        return None
    if isinstance(quick_learn, dict):
        return quick_learn.get(field)
    return getattr(quick_learn, field, None)


def _is_readme_source(source_doc: str) -> bool:
    source = _safe_str(source_doc).lower()
    return source in {"readme", "readme.md"} or source.endswith("/readme") or source.endswith(
        "/readme.md"
    )


def _ensure_sentence(text: str) -> str:
    cleaned = _safe_str(text)
    if not cleaned:
        return ""
    if cleaned[-1] in ".!?":
        return cleaned
    return f"{cleaned}."


def build_codebase_synopsis(
    *,
    codebase_snapshot: dict | None = None,
    quick_learn: Any = None,
    max_chars: int = 320,
) -> str:
    """
    Build a short project synopsis for PR comments and step summaries.

    Priority:
    1) Quick Learn context (README/manifest driven)
    2) Deterministic codebase snapshot fallback
    """
    parts: list[str] = []

    project_name = _compact_text(_quick_learn_value(quick_learn, "project_name"), max_chars=64)
    description = _compact_text(_quick_learn_value(quick_learn, "description"), max_chars=180)
    architecture = _compact_text(_quick_learn_value(quick_learn, "architecture"), max_chars=48)
    source_doc = _safe_str(_quick_learn_value(quick_learn, "source_doc"))

    stack_value = _quick_learn_value(quick_learn, "tech_stack")
    stack_items = (
        [str(item).strip() for item in stack_value if str(item).strip()]
        if isinstance(stack_value, list)
        else []
    )

    if description:
        if source_doc and _is_readme_source(source_doc):
            parts.append(_ensure_sentence(f"README: {description}"))
        else:
            parts.append(_ensure_sentence(description))
    elif project_name and project_name.lower() != "unknown":
        parts.append(f"{project_name} repository.")

    if architecture and architecture.lower() != "unknown":
        parts.append(f"Architecture: {architecture}.")

    if stack_items:
        parts.append(f"Stack: {', '.join(stack_items[:4])}.")

    entry_points = _quick_learn_value(quick_learn, "entry_points")
    if isinstance(entry_points, list):
        entries = [str(item).strip() for item in entry_points if str(item).strip()]
    else:
        entries = []
    if entries:
        parts.append(f"Entry points: {', '.join(entries[:3])}.")

    if parts:
        synopsis = " ".join(part.strip() for part in parts if part.strip())
        return _compact_text(synopsis, max_chars=max_chars)

    snapshot = codebase_snapshot or {}
    stats = snapshot.get("stats", {}) if isinstance(snapshot, dict) else {}
    languages = snapshot.get("languages", []) if isinstance(snapshot, dict) else []
    hotspots = snapshot.get("hotspots", []) if isinstance(snapshot, dict) else []

    in_scope = _safe_int(stats.get("in_scope_files"))
    loc = _safe_int(stats.get("source_loc_total"))
    if in_scope > 0:
        parts.append(f"Inferred: {in_scope} source files, {loc:,} LOC.")

    top_languages: list[str] = []
    if isinstance(languages, list):
        for item in languages[:3]:
            if not isinstance(item, dict):
                continue
            lang = _safe_str(item.get("language"))
            if lang:
                top_languages.append(lang)
    if top_languages:
        parts.append(f"Primary languages: {', '.join(top_languages)}.")

    hotspot_categories: list[str] = []
    if isinstance(hotspots, list):
        ranked = sorted(
            [row for row in hotspots if isinstance(row, dict)],
            key=lambda row: -_safe_int(row.get("count")),
        )
        for row in ranked:
            if _safe_int(row.get("count")) <= 0:
                continue
            category = _safe_str(row.get("category"))
            if category:
                hotspot_categories.append(category)
            if len(hotspot_categories) >= 3:
                break
    if hotspot_categories:
        parts.append(f"Hotspots: {', '.join(hotspot_categories)}.")

    return _compact_text(" ".join(parts).strip(), max_chars=max_chars)


def _inventory_hash(ingest_files: Iterable[dict]) -> str:
    """
    Create a stable hash for the ingest inventory.

    This is used for UI/debugging and to detect drift between deterministic stages.
    """
    lines: list[str] = []
    for f in ingest_files or []:
        if not isinstance(f, dict):
            continue
        path = f.get("path")
        if not path:
            continue
        lines.append(
            "{path}:{cat}:{lang}:{loc}:{bytes}".format(
                path=_norm_path(str(path)),
                cat=str(f.get("category") or ""),
                lang=str(f.get("language") or ""),
                loc=_safe_int(f.get("lines")),
                bytes=_safe_int(f.get("size_bytes")),
            )
        )
    lines.sort()
    return sha256_hex(("\n".join(lines)).encode("utf-8"))


def build_codebase_snapshot(
    ingest: dict,
    *,
    god_threshold_loc: int = 1000,
    max_largest_files: int = 20,
    max_god_files: int = 20,
    hotspot_examples: int = 5,
) -> dict:
    """
    Build a compact, deterministic "codebase snapshot" from INGEST.json payload.

    The snapshot is intended for:
    - PR comment UX ("what did we scan?")
    - Review brief / audit report enrichment
    - LLM prompt context (cheap, structured, bounded)
    """
    ingest = ingest or {}
    stats = ingest.get("stats", {}) if isinstance(ingest, dict) else {}
    dependencies = ingest.get("dependencies", {}) if isinstance(ingest, dict) else {}
    ingest_files = ingest.get("files", []) if isinstance(ingest, dict) else []
    hotspots = ingest.get("hotspots", {}) if isinstance(ingest, dict) else {}

    files_list: list[dict] = [f for f in ingest_files if isinstance(f, dict)]

    source_files: list[dict] = [
        f
        for f in files_list
        if str(f.get("category") or "") == "source" and f.get("path")
    ]

    source_loc_total = sum(_safe_int(f.get("lines")) for f in source_files)

    # Language breakdown (source only).
    lang_acc: dict[str, dict] = {}
    for f in source_files:
        lang = str(f.get("language") or "unknown") or "unknown"
        entry = lang_acc.setdefault(lang, {"language": lang, "files": 0, "loc": 0})
        entry["files"] += 1
        entry["loc"] += _safe_int(f.get("lines"))
    languages = sorted(
        lang_acc.values(),
        key=lambda e: (-_safe_int(e.get("loc")), str(e.get("language") or "")),
    )

    def _path_loc_rows(rows: Iterable[dict]) -> list[dict]:
        out: list[dict] = []
        for f in rows:
            path = f.get("path")
            if not path:
                continue
            out.append(
                {
                    "path": _norm_path(str(path)),
                    "lines": _safe_int(f.get("lines")),
                    "language": str(f.get("language") or "unknown"),
                }
            )
        return out

    largest_source_files = sorted(
        source_files,
        key=lambda f: (-_safe_int(f.get("lines")), _norm_path(str(f.get("path") or ""))),
    )[: max(int(max_largest_files), 0)]

    god_files = [
        f for f in source_files if _safe_int(f.get("lines")) >= int(god_threshold_loc)
    ]
    god_files = sorted(
        god_files,
        key=lambda f: (-_safe_int(f.get("lines")), _norm_path(str(f.get("path") or ""))),
    )[: max(int(max_god_files), 0)]

    # Hotspot summary.
    hotspot_rows: list[dict] = []
    if isinstance(hotspots, dict):
        for category in sorted(hotspots.keys(), key=lambda k: str(k)):
            paths = hotspots.get(category) or []
            normalized = sorted({_norm_path(str(p)) for p in paths if p})
            hotspot_rows.append(
                {
                    "category": str(category),
                    "count": len(normalized),
                    "examples": normalized[: max(int(hotspot_examples), 0)],
                }
            )

    snapshot = {
        "schema_version": "1.0",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inventory_hash_sha256": _inventory_hash(files_list),
        "stats": {
            "total_files": _safe_int(stats.get("total_files")),
            "text_files": _safe_int(stats.get("text_files")),
            "binary_files": _safe_int(stats.get("binary_files")),
            "in_scope_files": _safe_int(stats.get("in_scope_files")),
            "total_lines": _safe_int(stats.get("total_lines")),
            "source_loc_total": int(source_loc_total),
        },
        "dependencies": {
            "package_manager": str(dependencies.get("package_manager") or "unknown"),
            "lockfile": str(dependencies.get("lockfile") or ""),
            "direct_deps": _safe_int(dependencies.get("direct_deps")),
            "total_deps": _safe_int(dependencies.get("total_deps")),
        },
        "languages": [
            {
                "language": str(item.get("language") or "unknown"),
                "files": _safe_int(item.get("files")),
                "loc": _safe_int(item.get("loc")),
            }
            for item in languages
        ],
        "god_threshold_loc": int(god_threshold_loc),
        "god_files": _path_loc_rows(god_files),
        "largest_source_files": _path_loc_rows(largest_source_files),
        "hotspots": hotspot_rows,
    }

    return snapshot


def render_codebase_snapshot_md(snapshot: dict) -> str:
    """Render CODEBASE_INGEST_SUMMARY.md from a snapshot dict."""
    snapshot = snapshot or {}
    stats = snapshot.get("stats", {}) if isinstance(snapshot, dict) else {}
    deps = snapshot.get("dependencies", {}) if isinstance(snapshot, dict) else {}
    languages = snapshot.get("languages", []) if isinstance(snapshot, dict) else []
    god_files = snapshot.get("god_files", []) if isinstance(snapshot, dict) else []
    largest = snapshot.get("largest_source_files", []) if isinstance(snapshot, dict) else []
    hotspots = snapshot.get("hotspots", []) if isinstance(snapshot, dict) else []

    lines: list[str] = []
    lines.append("# Codebase Snapshot (Deterministic)")
    lines.append("")
    lines.append(
        "Inventory hash (sha256): `{}`".format(
            str(snapshot.get("inventory_hash_sha256") or "unknown")[:64]
        )
    )
    lines.append("")

    lines.append("## Stats")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Total files | {stats.get('total_files', 0)} |")
    lines.append(f"| Text files | {stats.get('text_files', 0)} |")
    lines.append(f"| Binary files | {stats.get('binary_files', 0)} |")
    lines.append(f"| In-scope files (source) | {stats.get('in_scope_files', 0)} |")
    lines.append(f"| Total lines (all text) | {stats.get('total_lines', 0)} |")
    lines.append(f"| LOC (source only) | {stats.get('source_loc_total', 0)} |")
    lines.append(f"| Package manager | {deps.get('package_manager', 'unknown')} |")
    if deps.get("lockfile"):
        lines.append(f"| Lockfile | {deps.get('lockfile')} |")
    lines.append(f"| Direct deps | {deps.get('direct_deps', 0)} |")
    lines.append(f"| Total deps | {deps.get('total_deps', 0)} |")
    lines.append("")

    lines.append("## Language Breakdown (Source Only)")
    lines.append("")
    if not languages:
        lines.append("- None")
    else:
        lines.append("| Language | Files | LOC |")
        lines.append("|---|---:|---:|")
        for item in languages[:20]:
            lines.append(
                "| {lang} | {files} | {loc} |".format(
                    lang=str(item.get("language") or "unknown"),
                    files=_safe_int(item.get("files")),
                    loc=_safe_int(item.get("loc")),
                )
            )
    lines.append("")

    lines.append("## God Components (>= {} LOC)".format(snapshot.get("god_threshold_loc", 1000)))
    lines.append("")
    if not god_files:
        lines.append("- None")
    else:
        for item in god_files[:20]:
            lines.append(f"- `{item.get('path')}` ({_safe_int(item.get('lines'))} lines)")
    lines.append("")

    lines.append("## Largest Source Files")
    lines.append("")
    if not largest:
        lines.append("- None")
    else:
        for item in largest[:20]:
            lines.append(f"- `{item.get('path')}` ({_safe_int(item.get('lines'))} lines)")
    lines.append("")

    lines.append("## Hotspots (Path-Based)")
    lines.append("")
    if not hotspots:
        lines.append("- None")
    else:
        lines.append("| Category | Count | Examples |")
        lines.append("|---|---:|---|")
        for row in hotspots[:20]:
            examples = row.get("examples") or []
            example_text = ", ".join(f"`{p}`" for p in examples[:5]) if examples else "-"
            lines.append(
                "| {cat} | {count} | {examples} |".format(
                    cat=str(row.get("category") or "unknown"),
                    count=_safe_int(row.get("count")),
                    examples=example_text,
                )
            )
    lines.append("")

    return "\n".join(lines)


def render_codebase_ingest_md(ingest: dict, snapshot: dict) -> str:
    """
    Render CODEBASE_INGEST.md (human-friendly).

    This is intentionally bounded and optimized for UI/UX, not completeness.
    The structured source of truth remains CODEBASE_INGEST.json / INGEST.json.
    """
    ingest = ingest or {}
    snapshot = snapshot or {}

    stats = snapshot.get("stats", {}) if isinstance(snapshot, dict) else {}
    deps = snapshot.get("dependencies", {}) if isinstance(snapshot, dict) else {}
    files = ingest.get("files", []) if isinstance(ingest, dict) else []

    source_files = [
        f for f in (files or []) if isinstance(f, dict) and str(f.get("category") or "") == "source"
    ]
    # Stable order: largest first, then path.
    source_files_sorted = sorted(
        source_files,
        key=lambda f: (-_safe_int(f.get("lines")), _norm_path(str(f.get("path") or ""))),
    )

    lines: list[str] = []
    lines.append("# Codebase Ingest")
    lines.append("")
    lines.append(
        "Inventory hash (sha256): `{}`".format(
            str(snapshot.get("inventory_hash_sha256") or "unknown")[:64]
        )
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(
        "- In-scope files (source): {files}".format(files=_safe_int(stats.get("in_scope_files")))
    )
    lines.append(
        "- LOC (source only): {loc}".format(loc=_safe_int(stats.get("source_loc_total")))
    )
    lines.append(
        "- Package manager: {pm}".format(pm=str(deps.get("package_manager") or "unknown"))
    )
    if deps.get("lockfile"):
        lines.append("- Lockfile: {lf}".format(lf=str(deps.get("lockfile"))))
    lines.append("")

    lines.append("## God Components (>= {} LOC)".format(snapshot.get("god_threshold_loc", 1000)))
    lines.append("")
    god_files = snapshot.get("god_files") if isinstance(snapshot, dict) else None
    if not god_files:
        lines.append("- None")
    else:
        for item in (god_files or [])[:25]:
            lines.append(f"- `{item.get('path')}` ({_safe_int(item.get('lines'))} lines)")
    lines.append("")

    lines.append("## Top 20 Largest Source Files")
    lines.append("")
    for item in (snapshot.get("largest_source_files") or [])[:20]:
        lines.append(f"- `{item.get('path')}` ({_safe_int(item.get('lines'))} lines)")
    if not snapshot.get("largest_source_files"):
        lines.append("- None")
    lines.append("")

    lines.append("## Source File Index (path, language, LOC)")
    lines.append("")
    if not source_files_sorted:
        lines.append("- None")
    else:
        # Keep this index readable; large repos will still be bounded by ingest max_files upstream.
        for f in source_files_sorted[:1500]:
            p = _norm_path(str(f.get("path") or ""))
            if not p:
                continue
            lang = str(f.get("language") or "unknown")
            loc = _safe_int(f.get("lines"))
            lines.append(f"- `{p}` ({lang}, {loc} LOC)")
        if len(source_files_sorted) > 1500:
            lines.append(f"- ... and {len(source_files_sorted) - 1500} more")
    lines.append("")

    return "\n".join(lines)


def write_codebase_ingest_artifacts(
    run_dir: Path, ingest: dict, *, snapshot: dict | None = None
) -> dict[str, Path]:
    """
    Write codebase ingest artifacts into run directory.

    Files written:
    - CODEBASE_INGEST.json (alias of INGEST.json content)
    - CODEBASE_INGEST_SUMMARY.json (compact snapshot)
    - CODEBASE_INGEST_SUMMARY.md (human-readable snapshot)
    - CODEBASE_INGEST.md (human-readable index)
    """
    run_dir.mkdir(parents=True, exist_ok=True)

    snapshot = snapshot or build_codebase_snapshot(ingest)

    out_paths: dict[str, Path] = {}

    codebase_json = run_dir / "CODEBASE_INGEST.json"
    codebase_json.write_text(json_dumps(ingest or {}), encoding="utf-8")
    out_paths[codebase_json.name] = codebase_json

    summary_json = run_dir / "CODEBASE_INGEST_SUMMARY.json"
    summary_json.write_text(json_dumps(snapshot), encoding="utf-8")
    out_paths[summary_json.name] = summary_json

    summary_md = run_dir / "CODEBASE_INGEST_SUMMARY.md"
    summary_md.write_text(render_codebase_snapshot_md(snapshot), encoding="utf-8")
    out_paths[summary_md.name] = summary_md

    ingest_md = run_dir / "CODEBASE_INGEST.md"
    ingest_md.write_text(render_codebase_ingest_md(ingest, snapshot), encoding="utf-8")
    out_paths[ingest_md.name] = ingest_md

    return out_paths
