from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Optional

from ..repo_paths import plain_repo_file


_CHARS_PER_TOKEN = 4.0
_MAX_TOKENS = 600

# Scaffold/template phrases that indicate the README is boilerplate rather than describing
# what the project actually does. When matched, LLM synopsis synthesis is triggered.
_BOILERPLATE_PHRASES: tuple[str, ...] = (
    "this template provides a minimal setup",
    "minimal setup to get react working in vite",
    "currently, two official plugins are available",
    "edit src/app.tsx",
    "learn react",
    "this project was bootstrapped with create react app",
    "this project was bootstrapped with vite",
    "getting started with create react app",
    "you can learn more in the create react app documentation",
    "eject at any time by running npm run eject",
)


def is_boilerplate_description(desc: str) -> bool:
    """Return True if the description looks like scaffold/template boilerplate."""
    if not desc:
        return False
    lower = desc.lower()
    return any(phrase in lower for phrase in _BOILERPLATE_PHRASES)


def build_llm_synopsis_prompt(quick_learn: "QuickLearnSummary", largest_files: list[str]) -> str:
    """Build a concise prompt for LLM to synthesize a project synopsis from repo structure."""
    stack = ", ".join(quick_learn.tech_stack) if quick_learn.tech_stack else "undetected"
    file_lines = "\n".join(f"  {f}" for f in largest_files[:10])
    return (
        f"Repository name: {quick_learn.project_name}\n"
        f"Tech stack: {stack}\n"
        f"Largest source files:\n{file_lines}\n\n"
        f"Write ONE sentence (max 100 characters) describing what this project does. "
        f"Describe the product purpose, not the tech setup or how to run it."
    )


@dataclass
class QuickLearnSummary:
    project_name: str
    description: str  # max 100 chars
    tech_stack: list[str]
    architecture: str
    entry_points: list[str]
    source_doc: str
    raw_excerpt: str


def estimate_tokens(text: str, *, chars_per_token: float = _CHARS_PER_TOKEN) -> int:
    if not text:
        return 0
    return int(len(text) / chars_per_token)


def _truncate_to_tokens(text: str, *, max_tokens: int) -> str:
    if not text:
        return ""
    max_chars = int(max_tokens * _CHARS_PER_TOKEN)
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    clipped = text[:max_chars]
    if "\n" in clipped:
        clipped = clipped.rsplit("\n", 1)[0] + "\n"
    return clipped


def extract_quick_learn_summary(repo_root: Path) -> QuickLearnSummary:
    """
    Extract lightweight project context from common docs/manifests.

    Uses simple heuristics (no LLM).
    """
    repo_root = Path(repo_root)

    doc_candidates = [
        "README.md",
        "README",
        "docs/README.md",
        "CONTRIBUTING.md",
        "package.json",
        "pyproject.toml",
        "Cargo.toml",
    ]

    selected: Optional[str] = None
    for rel in doc_candidates:
        if plain_repo_file(repo_root, rel) is not None:
            selected = rel
            break

    # If README exists but is clearly marked deprecated/archived, prefer a manifest if present.
    if selected in {"README.md", "README", "docs/README.md"}:
        readme_excerpt = _read_markdown_excerpt(repo_root / selected)
        if _looks_outdated(readme_excerpt):
            for rel in ("package.json", "pyproject.toml", "Cargo.toml"):
                if plain_repo_file(repo_root, rel) is not None:
                    selected = rel
                    break

    if not selected:
        return QuickLearnSummary(
            project_name="unknown",
            description="",
            tech_stack=[],
            architecture="unknown",
            entry_points=[],
            source_doc="",
            raw_excerpt="",
        )

    source_path = repo_root / selected
    excerpt = ""
    structured: dict[str, Any] = {}
    if selected.endswith(".md") or selected == "README":
        excerpt = _read_markdown_excerpt(source_path)
    elif selected == "package.json":
        structured = _read_package_json(source_path)
        excerpt = _excerpt_from_package_json(structured)
    elif selected in {"pyproject.toml", "Cargo.toml"}:
        structured = _read_toml_section(
            source_path, section="project" if selected == "pyproject.toml" else "package"
        )
        excerpt = _excerpt_from_toml(selected, structured)

    excerpt = _truncate_to_tokens(excerpt, max_tokens=_MAX_TOKENS)

    project_name = _extract_project_name(selected, excerpt, structured, repo_root)
    description = _extract_description(selected, excerpt, structured)
    tech_stack = _detect_tech_stack(repo_root, excerpt, structured)
    architecture = _detect_architecture(repo_root, excerpt, structured)
    entry_points = _extract_entry_points(excerpt)

    return QuickLearnSummary(
        project_name=project_name,
        description=description,
        tech_stack=tech_stack,
        architecture=architecture,
        entry_points=entry_points,
        source_doc=selected,
        raw_excerpt=excerpt,
    )


def _looks_outdated(excerpt: str) -> bool:
    if not excerpt:
        return False
    return bool(
        re.search(
            r"\b(deprecated|archived|no longer maintained)\b",
            excerpt,
            re.IGNORECASE,
        )
    )


def _read_markdown_excerpt(path: Path) -> str:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    lines = raw.splitlines()
    lines = lines[:80]  # first 80 lines only

    ignore_titles = {
        "installation",
        "setup",
        "getting started",
        "quickstart",
        "usage",
        "contributing",
        "license",
    }

    cleaned: list[str] = []
    in_code_block = False
    skip_section = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue

        # Skip badge/image noise.
        if "shields.io" in stripped or stripped.startswith("[![") or stripped.startswith("!["):
            continue
        if stripped.startswith("<img") or stripped.startswith("<a "):
            continue

        # Skip HTML comments.
        if stripped.startswith("<!--"):
            continue

        header = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if header:
            title = header.group(2).strip().lower()
            # Normalize common heading suffix like ":"
            title = title.rstrip(":").strip()
            skip_section = any(title == t or title.startswith(f"{t} ") for t in ignore_titles)
            if skip_section:
                continue

        if skip_section:
            continue

        cleaned.append(line.rstrip())

    return "\n".join(cleaned).strip()


def _read_package_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _excerpt_from_package_json(data: dict[str, Any]) -> str:
    name = str(data.get("name") or "").strip()
    description = str(data.get("description") or "").strip()
    scripts = data.get("scripts") or {}
    script_keys: list[str] = []
    if isinstance(scripts, dict):
        script_keys = sorted(str(k) for k in scripts.keys())

    lines = ["# package.json"]
    if name:
        lines.append(f"name: {name}")
    if description:
        lines.append(f"description: {description}")
    if script_keys:
        lines.append("scripts: " + ", ".join(script_keys[:25]))
        if len(script_keys) > 25:
            lines.append(f"... and {len(script_keys) - 25} more")
    return "\n".join(lines).strip()


def _read_toml_section(path: Path, *, section: str) -> dict[str, Any]:
    try:
        import tomllib

        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    selected = data.get(section) or {}
    if not isinstance(selected, dict):
        return {}
    return selected


def _excerpt_from_toml(filename: str, section_data: dict[str, Any]) -> str:
    lines = [f"# {filename}"]
    for key in ("name", "description", "version", "requires-python"):
        val = section_data.get(key)
        if not val:
            continue
        lines.append(f"{key}: {val}")
    deps = section_data.get("dependencies")
    if isinstance(deps, list) and deps:
        dep_names = []
        for item in deps[:25]:
            if isinstance(item, str):
                dep_names.append(item.split()[0].split("==")[0].split(">=")[0])
        if dep_names:
            lines.append("dependencies: " + ", ".join(dep_names))
    return "\n".join(lines).strip()


def _extract_project_name(
    source_doc: str, excerpt: str, structured: dict[str, Any], repo_root: Path
) -> str:
    if source_doc == "package.json":
        name = str(structured.get("name") or "").strip()
        if name:
            return name
    if source_doc == "pyproject.toml":
        name = str(structured.get("name") or "").strip()
        if name:
            return name
    if source_doc == "Cargo.toml":
        name = str(structured.get("name") or "").strip()
        if name:
            return name

    for line in excerpt.splitlines():
        m = re.match(r"^#\s+(.+)$", line.strip())
        if m:
            title = m.group(1).strip()
            if title:
                return title

    return repo_root.name or "unknown"


def _extract_description(source_doc: str, excerpt: str, structured: dict[str, Any]) -> str:
    desc = ""
    if source_doc == "package.json":
        desc = str(structured.get("description") or "").strip()
    elif source_doc in {"pyproject.toml", "Cargo.toml"}:
        desc = str(structured.get("description") or "").strip()

    if not desc and excerpt:
        lines = [ln.strip() for ln in excerpt.splitlines()]
        # Skip title line and empty/badge lines; take first paragraph.
        i = 0
        if lines and lines[0].startswith("#"):
            i = 1
        while i < len(lines) and not lines[i]:
            i += 1
        para: list[str] = []
        while i < len(lines) and lines[i] and not lines[i].startswith("#"):
            para.append(lines[i])
            i += 1
        desc = " ".join(para).strip()

    desc = re.sub(r"\s+", " ", desc).strip()
    if len(desc) > 100:
        desc = desc[:100].rstrip()  # hard limit; keep simple
    return desc


def _detect_tech_stack(repo_root: Path, excerpt: str, structured: dict[str, Any]) -> list[str]:
    text = (excerpt or "").lower()
    stack: list[str] = []

    def add(item: str) -> None:
        if item not in stack:
            stack.append(item)

    pkg_json_path = plain_repo_file(repo_root, "package.json")
    pkg_json = _read_package_json(pkg_json_path) if pkg_json_path is not None else {}
    pkg_deps = {}
    if isinstance(pkg_json, dict):
        deps = pkg_json.get("dependencies") or {}
        dev_deps = pkg_json.get("devDependencies") or {}
        if not isinstance(deps, dict):
            deps = {}
        if not isinstance(dev_deps, dict):
            dev_deps = {}
        pkg_deps = {**deps, **dev_deps}

    if pkg_json_path is not None or "node" in text or "npm" in text:
        add("Node.js")
        if "typescript" in text or "typescript" in pkg_deps:
            add("TypeScript")
        elif "javascript" in text:
            add("JavaScript")

    if (repo_root / "pyproject.toml").is_file() or (repo_root / "requirements.txt").is_file():
        add("Python")

    if (repo_root / "Cargo.toml").is_file():
        add("Rust")

    if (repo_root / "go.mod").is_file() or re.search(r"\bgo(lang)?\b", text):
        add("Go")

    if (repo_root / "Dockerfile").is_file() or "docker" in text:
        add("Docker")

    if (
        (repo_root / "main.tf").is_file()
        or (repo_root / "terraform").exists()
        or (repo_root / "infrastructure").exists()
        or (repo_root / "infra").exists()
        or "terraform" in text
    ):
        add("Terraform")

    # Framework heuristics (scan excerpt + manifest sections).
    if re.search(r"\bnext\.?js\b", text) or "next" in pkg_deps:
        add("Next.js")
    if re.search(r"\breact\b", text) or "react" in pkg_deps:
        add("React")
    if re.search(r"\bvue\b", text) or "vue" in pkg_deps or "vue.js" in text:
        add("Vue")
    if re.search(r"\bangular\b", text) or "@angular/core" in pkg_deps:
        add("Angular")
    if re.search(r"\bexpress\b", text) or "express" in pkg_deps:
        add("Express")
    if re.search(r"\bdjango\b", text):
        add("Django")
        add("Python")
    if re.search(r"\bfastapi\b", text):
        add("FastAPI")
        add("Python")

    # Manifest dependencies (if available).
    deps = structured.get("dependencies")
    if isinstance(deps, list):
        dep_text = " ".join(str(d).lower() for d in deps)
        if "fastapi" in dep_text:
            add("FastAPI")
            add("Python")
        if "django" in dep_text:
            add("Django")
            add("Python")

    return stack


def _detect_architecture(repo_root: Path, excerpt: str, structured: dict[str, Any]) -> str:
    text = (excerpt or "").lower()

    if "monorepo" in text:
        return "monorepo"
    if "microservice" in text or "microservices" in text:
        return "microservices"
    if "serverless" in text:
        return "serverless"
    if "monolith" in text:
        return "monolith"

    # Repo structure heuristics for monorepo.
    pkg_json = plain_repo_file(repo_root, "package.json")
    if pkg_json is not None:
        data = _read_package_json(pkg_json)
        workspaces = data.get("workspaces")
        if isinstance(workspaces, list) and workspaces:
            return "monorepo"
        if isinstance(workspaces, dict) and workspaces.get("packages"):
            return "monorepo"
    for marker in ("pnpm-workspace.yaml", "lerna.json", "turbo.json", "nx.json"):
        if (repo_root / marker).is_file():
            return "monorepo"

    _ = structured
    return "unknown"


def _extract_entry_points(excerpt: str) -> list[str]:
    if not excerpt:
        return []

    # Capture common repo-relative paths.
    candidates: set[str] = set()

    file_pattern = re.compile(
        r"(?:(?:^|[\s`'\"]))(?:\./)?([A-Za-z0-9_./-]+\.(?:py|ts|tsx|js|jsx|go|rs|java|kt|cs|rb|php|yml|yaml|tf|sh))\b"
    )
    dir_pattern = re.compile(r"(?:(?:^|[\s`'\"]))(src|app|server|cmd|packages|services|api)(/[A-Za-z0-9_./-]+)?/?\b")

    for line in excerpt.splitlines():
        for m in file_pattern.finditer(line):
            candidates.add(m.group(1))
        for m in dir_pattern.finditer(line):
            rel = (m.group(1) + (m.group(2) or "")).rstrip("/")
            candidates.add(rel + "/")

    # Prefer short, plausible paths.
    filtered = []
    for c in candidates:
        c = c.strip().lstrip("./")
        if not c:
            continue
        if c.startswith("http"):
            continue
        if len(c) > 120:
            continue
        filtered.append(c)

    return sorted(filtered)[:15]
