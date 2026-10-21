"""Public fixtures construct credential-shaped payloads only at runtime."""
from pathlib import Path
import re


def test_public_fixture_sources_have_no_literal_provider_keys_or_pem_markers():
    patterns = [
        re.compile(r"\bsk" + r"-[A-Za-z0-9*_-]{3,}"),
        re.compile(r"\bsk" + r"_(?:live|test)_[A-Za-z0-9]{8,}"),
        re.compile(r"\bAI" + r"za[A-Za-z0-9_-]{8,}"),
        re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}"),
        re.compile(r"-----" + r"(?:BEGIN|END) (?:[A-Z]+ )*PRIVATE KEY-----"),
    ]
    root = Path(__file__).parents[2]
    violations = []
    for directory in (root / "tests", root / "scripts"):
        for path in directory.rglob("*"):
            if path.suffix not in {".py", ".json", ".yml", ".yaml", ".txt", ".md"}:
                continue
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if any(pattern.search(line) for pattern in patterns):
                    violations.append(f"{path.relative_to(root)}:{line_number}")
    # Report locations only; a failed hygiene check must not echo credentials.
    assert violations == []
