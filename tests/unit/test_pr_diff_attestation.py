from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from omargate.pr_diff import PRDiffIncomplete, attest_pr_diff


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


def two_hunk_repo(tmp_path: Path) -> tuple[Path, str, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
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
        ["git", "diff", base, head], cwd=repo, check=True, capture_output=True, text=True,
    ).stdout
    return repo, base, head, supplied


def test_attestation_uses_exact_commits_and_all_hunks(tmp_path: Path):
    repo, base, head, supplied = two_hunk_repo(tmp_path)
    assert supplied.count("@@ -") == 2
    verified = attest_pr_diff(repo, base_sha=base, head_sha=head, supplied_diff=supplied)
    assert verified.count("@@ -") == 2
    assert '+  "item29": "new",' in verified


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
