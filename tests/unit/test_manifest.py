from pathlib import Path

from omargate.package.manifest import (
    generate_artifact_manifest,
    write_artifact_manifest,
)


def test_manifest_lists_artifacts(tmp_path: Path):
    """Manifest includes all existing artifacts."""
    (tmp_path / "PACK_SUMMARY.json").write_text('{"test": true}')
    (tmp_path / "FINDINGS.jsonl").write_text('{"finding": 1}')

    manifest = generate_artifact_manifest(tmp_path, "test-run")

    assert manifest["run_id"] == "test-run"
    assert len(manifest["objects"]) == 2
    assert any(o["name"] == "PACK_SUMMARY.json" for o in manifest["objects"])


def test_manifest_includes_hashes(tmp_path: Path):
    """Manifest includes SHA-256 hashes."""
    (tmp_path / "PACK_SUMMARY.json").write_text('{"test": true}')

    manifest = generate_artifact_manifest(tmp_path, "test-run")

    obj = next(o for o in manifest["objects"] if o["name"] == "PACK_SUMMARY.json")
    assert "sha256" in obj
    assert len(obj["sha256"]) == 64


def test_write_manifest(tmp_path: Path):
    """Manifest written to disk."""
    (tmp_path / "PACK_SUMMARY.json").write_text("{}")

    manifest_path = write_artifact_manifest(tmp_path, "test-run")

    assert manifest_path.exists()
    assert manifest_path.name == "ARTIFACT_MANIFEST.json"


def test_manifest_retains_typed_review_evidence_with_exact_digest(tmp_path: Path):
    import hashlib

    raw = b'{"complete":false,"failure_class":"typed_review_incomplete"}\n'
    (tmp_path / "TYPESAFE_REVIEW.json").write_bytes(raw)
    objects = generate_artifact_manifest(tmp_path, "fixture")["objects"]
    assert objects == [{
        "name": "TYPESAFE_REVIEW.json", "content_type": "application/json",
        "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
    }]
