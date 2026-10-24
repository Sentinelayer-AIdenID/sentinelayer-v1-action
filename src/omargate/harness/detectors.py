from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProjectFacts:
    is_node: bool
    is_python: bool
    is_rust: bool
    has_dockerfile: bool
    has_terraform: bool
    has_workflows: bool
    is_web: bool


def detect_project_facts(project_root: Path, tech_stack: list[str]) -> ProjectFacts:
    tech = [t.lower() for t in (tech_stack or [])]
    joined = " ".join(tech)

    is_node = (project_root / "package.json").is_file() or any(
        m in joined for m in ("node", "react", "next", "vue", "angular", "express")
    )
    is_python = any((project_root / name).is_file() for name in ("pyproject.toml", "requirements.txt", "Pipfile")) or any(
        m in joined for m in ("python", "django", "fastapi")
    )
    is_rust = (project_root / "Cargo.toml").is_file() or ("rust" in joined)

    has_dockerfile = (project_root / "Dockerfile").is_file()
    has_terraform = any(project_root.rglob("*.tf"))

    workflows_dir = project_root / ".github" / "workflows"
    has_workflows = workflows_dir.is_dir() and (
        any(workflows_dir.glob("*.yml")) or any(workflows_dir.glob("*.yaml"))
    )

    is_web = any(
        any(marker in t for marker in ("react", "next", "vue", "angular", "express", "django", "fastapi"))
        for t in tech
    )
    if not is_web:
        is_web = any(
            (project_root / name).is_file()
            for name in ("next.config.js", "next.config.mjs", "manage.py")
        )

    return ProjectFacts(
        is_node=is_node,
        is_python=is_python,
        is_rust=is_rust,
        has_dockerfile=has_dockerfile,
        has_terraform=has_terraform,
        has_workflows=has_workflows,
        is_web=is_web,
    )


def iter_text_files(
    project_root: Path,
    patterns: Iterable[str],
    exclude_dirs: Iterable[str] = (".git", "node_modules", ".venv", "venv", "dist", "build"),
    max_files: int = 200,
    max_bytes: int = 200_000,
) -> Iterator[Path]:
    excluded = {d.lower() for d in exclude_dirs}
    yielded = 0
    for pattern in patterns:
        for path in project_root.rglob(pattern):
            if yielded >= max_files:
                return
            if not path.is_file():
                continue
            parts = [p.lower() for p in path.parts]
            if any(p in excluded for p in parts):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > max_bytes:
                continue
            yielded += 1
            yield path


def read_text_best_effort(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""

