from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

from omargate.analyze.typesafe_review import (
    TypeSafeReviewIncomplete,
    build_inventory,
    verify_sources,
)
from omargate.pr_diff import PRDiffIncomplete, attest_pr_diff


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


def two_hunk_repo(tmp_path: Path) -> tuple[Path, str, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "core.autocrlf", "false")
    git(repo, "config", "user.name", "Reviewer")
    git(repo, "config", "user.email", "reviewer@example.test")
    source = repo / "package-lock.json"
    lines = [f'  "item{i}": "old",' for i in range(30)]
    source.write_text("{\n" + "\n".join(lines) + '\n  "end": true\n}\n', encoding="utf-8")
    git(repo, "add", "package-lock.json")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    lines[0] = '  "item0": "new",'
    lines[-1] = '  "item29": "new",'
    source.write_text("{\n" + "\n".join(lines) + '\n  "end": true\n}\n', encoding="utf-8")
    git(repo, "add", "package-lock.json")
    git(repo, "commit", "-qm", "head")
    head = git(repo, "rev-parse", "HEAD")
    supplied = subprocess.run(
        ["git", "diff", base, head], cwd=repo, check=True, capture_output=True,
    ).stdout.decode("utf-8")
    return repo, base, head, supplied


def test_attestation_uses_exact_commits_and_all_hunks(tmp_path: Path):
    repo, base, head, supplied = two_hunk_repo(tmp_path)
    assert supplied.count("@@ -") == 2
    verified = attest_pr_diff(repo, base_sha=base, head_sha=head, supplied_diff=supplied)
    assert verified.count("@@ -") == 2
    assert '+  "item29": "new",' in verified


def test_attestation_accepts_github_hunk_labels_but_not_changed_ranges(tmp_path: Path):
    repo, base, head, supplied = two_hunk_repo(tmp_path)
    # GitHub's PR134 diff labeled this optional hunk suffix differently from
    # local git (e.g. `def _prioritize_files(` vs `class ContextBuilder:`).
    # The hunk's numeric ranges and every content line remain authoritative.
    labeled = re.sub(
        r"^(@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@)[^\n]*$",
        r"\1 def _prioritize_files(",
        supplied,
        count=1,
        flags=re.MULTILINE,
    )
    assert labeled != supplied
    assert attest_pr_diff(repo, base_sha=base, head_sha=head, supplied_diff=labeled)

    changed_range = re.sub(r"^(@@ -)\d+", r"\g<1>999", labeled, count=1, flags=re.MULTILINE)
    with pytest.raises(PRDiffIncomplete, match="pr_diff_mismatch"):
        attest_pr_diff(repo, base_sha=base, head_sha=head, supplied_diff=changed_range)


def test_attestation_refuses_omitted_complete_later_hunk(tmp_path: Path):
    repo, base, head, supplied = two_hunk_repo(tmp_path)
    rows = supplied.splitlines(keepends=True)
    second_hunk = [index for index, row in enumerate(rows) if row.startswith("@@ -")][1]
    partial = "".join(rows[:second_hunk])
    with pytest.raises(PRDiffIncomplete, match="pr_diff_mismatch"):
        attest_pr_diff(repo, base_sha=base, head_sha=head, supplied_diff=partial)


def test_attestation_refuses_truncated_diff_at_budget(tmp_path: Path):
    repo, base, head, supplied = two_hunk_repo(tmp_path)
    with pytest.raises(PRDiffIncomplete, match="pr_diff_oversize"):
        attest_pr_diff(repo, base_sha=base, head_sha=head,
                       supplied_diff=supplied[:100], max_bytes=120)


def test_attestation_refuses_merge_checkout(tmp_path: Path):
    repo, base, head, supplied = two_hunk_repo(tmp_path)
    git(repo, "checkout", "-q", base)
    with pytest.raises(PRDiffIncomplete, match="pr_head_checkout_mismatch"):
        attest_pr_diff(repo, base_sha=base, head_sha=head, supplied_diff=supplied)


def test_attestation_fetches_bounded_shallow_history(tmp_path: Path):
    repo, base, head, supplied = two_hunk_repo(tmp_path)
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "clone", "--bare", "-q", str(repo), str(bare)], check=True)
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "--depth=1", "-q", bare.as_uri(), str(shallow)], check=True)
    assert git(shallow, "rev-parse", "HEAD") == head
    verified = attest_pr_diff(shallow, base_sha=base, head_sha=head, supplied_diff=supplied)
    assert verified.count("@@ -") == 2


def inventory_for(repo: Path, head: str, *, excluded: bool):
    lock = repo / "package-lock.json"
    evidence = None
    if excluded:
        evidence = {
            "enabled": True,
            "complete": True,
            "npm_projects": {"audits": [{
                "lockfile_path": "package-lock.json",
                "lockfile_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
                "input_unchanged": True,
                "outcome": {"ecosystem": "npm", "applicable": True, "state": "clean"},
            }]},
        }
    return build_inventory(
        repo_root=repo, ingest={"files": [{"path": "package-lock.json"}]},
        changed_files=["package-lock.json"], scan_mode="pr-diff",
        max_candidates=200, dep_audit_evidence=evidence, expected_head_sha=head,
    )


@pytest.mark.parametrize("excluded", [False, True], ids=["reviewed", "audit-excluded"])
def test_inventory_refuses_dirty_line_outside_attested_hunks(tmp_path: Path, excluded: bool):
    repo, base, head, supplied = two_hunk_repo(tmp_path)
    attest_pr_diff(repo, base_sha=base, head_sha=head, supplied_diff=supplied)
    inventory = inventory_for(repo, head, excluded=excluded)
    assert bool(inventory.policy_excluded) is excluded
    source = repo / "package-lock.json"
    source.write_text(source.read_text(encoding="utf-8").replace('"item15": "old"',
        '"item15": "UNCOMMITTED_SAFE_MASK"'), encoding="utf-8")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_commit_mismatch"):
        inventory_for(repo, head, excluded=excluded)


@pytest.mark.parametrize("excluded", [False, True], ids=["reviewed", "audit-excluded"])
def test_verification_refuses_head_replacement_after_inventory(tmp_path: Path, excluded: bool):
    repo, _base, head, _supplied = two_hunk_repo(tmp_path)
    inventory = inventory_for(repo, head, excluded=excluded)
    git(repo, "commit", "--allow-empty", "-qm", "new head")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_commit_mismatch"):
        verify_sources(repo, inventory)


def test_inventory_refuses_untracked_changed_file(tmp_path: Path):
    repo, _base, head, _supplied = two_hunk_repo(tmp_path)
    (repo / "untracked.py").write_text("safe = True\n", encoding="utf-8")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_commit_unavailable"):
        build_inventory(
            repo_root=repo, ingest={"files": [{"path": "untracked.py"}]},
            changed_files=["untracked.py"], scan_mode="pr-diff",
            max_candidates=200, expected_head_sha=head,
        )
