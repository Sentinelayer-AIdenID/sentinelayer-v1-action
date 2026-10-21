from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_artifact_manifest(
    run_dir: Path,
    run_id: str,
    tenant_id: Optional[str] = None,
    repo_id: Optional[str] = None,
) -> dict:
    """
    Generate manifest for artifact upload.

    Lists all artifacts with hashes for integrity verification.
    """
    objects = []

    # Standard artifacts
    artifact_files = [
        ("PACK_SUMMARY.json", "application/json"),
        ("FINDINGS.jsonl", "application/jsonl"),
        ("INGEST.json", "application/json"),
        ("CODEBASE_INGEST.json", "application/json"),
        ("CODEBASE_INGEST_SUMMARY.json", "application/json"),
        ("CODEBASE_INGEST_SUMMARY.md", "text/markdown"),
        ("CODEBASE_INGEST.md", "text/markdown"),
        ("REVIEW_BRIEF.md", "text/markdown"),
        ("AUDIT_REPORT.md", "text/markdown"),
        ("TYPESAFE_REVIEW.json", "application/json"),
    ]

    for filename, content_type in artifact_files:
        path = run_dir / filename
        if path.exists():
            objects.append(
                {
                    "name": filename,
                    "sha256": compute_file_hash(path),
                    "content_type": content_type,
                    "bytes": path.stat().st_size,
                }
            )

    manifest = {
        "schema_version": "1.0",
        "run_id": run_id,
        "tenant_id": tenant_id,
        "repo_id": repo_id,
        "artifact_root": f"runs/{run_id}/",
        "uploaded_at_utc": datetime.now(timezone.utc).isoformat(),
        "objects": objects,
        "retention_days": 90,
    }

    return manifest


def write_artifact_manifest(run_dir: Path, run_id: str, **kwargs) -> Path:
    """Write manifest to run directory."""
    manifest = generate_artifact_manifest(run_dir, run_id, **kwargs)
    manifest_path = run_dir / "ARTIFACT_MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path
