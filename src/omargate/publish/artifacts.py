from __future__ import annotations

import shutil
from pathlib import Path
from typing import Iterable

DEFAULT_ARTIFACTS = [
    "PACK_SUMMARY.json",
    "FINDINGS.jsonl",
    "INGEST.json",
    "CODEBASE_INGEST.json",
    "CODEBASE_INGEST_SUMMARY.json",
    "CODEBASE_INGEST_SUMMARY.md",
    "CODEBASE_INGEST.md",
    "REVIEW_BRIEF.md",
    "AUDIT_REPORT.md",
    "REVIEW_ROUTING.json",
    "ARTIFACT_MANIFEST.json",
]


def prepare_artifacts_for_upload(
    run_dir: Path,
    artifacts_dir: Path,
    files: Iterable[str] = DEFAULT_ARTIFACTS,
) -> Path:
    """
    Copy artifacts to a directory for GitHub Actions upload.

    These will be available for download from the workflow run.
    """
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    for filename in files:
        src = run_dir / filename
        if src.exists():
            shutil.copy2(src, artifacts_dir / filename)
    return artifacts_dir
