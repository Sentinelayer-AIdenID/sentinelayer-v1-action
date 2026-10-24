from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
import socket

import httpx
import pytest

from omargate.analyze.typesafe_review import (
    ReviewPlan,
    TypeSafeReviewIncomplete,
    build_inventory,
    review_inventory,
)
from omargate.analyze.typesafe_state import build_typed_context


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args, **_kwargs):
        raise AssertionError("state tests must not open a network connection")

    async def refuse_http(*_args, **_kwargs):
        raise AssertionError("state tests must not make an HTTP request")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(httpx.AsyncClient, "send", refuse_http)


def inventory_for(tmp_path: Path, files: dict[str, str], *, language: str | None = None):
    rows = []
    for name, text in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
        row = {"path": name}
        if language is not None:
            row["language"] = language
        rows.append(row)
    ingest = {"files": rows}
    inventory = build_inventory(
        repo_root=tmp_path, ingest=ingest, changed_files=list(files),
        scan_mode="pr-diff", max_candidates=50,
    )
    return inventory, ingest


def patch(name: str, before: str, after: str, *, context: int = 3) -> str:
    return f"diff --git a/{name} b/{name}\n" + "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="a/" + name, tofile="b/" + name, n=context,
    ))


def context_for(tmp_path, inventory, ingest, diff, findings=None):
    return build_typed_context(
        repo_root=tmp_path, inventory=inventory, ingest=ingest,
        diff_content=diff, deterministic_findings=findings or [],
    )


def test_actual_head_hunk_language_hash_and_redacted_scanner_evidence(tmp_path: Path) -> None:
    secret = "".join(('sk', '-fictional0123456789'))
    after = f"keep\napi_key = '{secret}'\ntail\n"
    inventory, ingest = inventory_for(tmp_path, {"source.py": after}, language="python")
    diff = patch("source.py", "keep\nold value\ntail\n", after)
    hits = [{
        "id": "det-1", "rule_id": "fixture-rule", "category": "fixture",
        "severity": "P2", "file_path": "source.py", "line_start": 2, "line_end": 2,
        "message": f"The fixture contains {secret}",
    }]

    result = context_for(tmp_path, inventory, ingest, diff, hits)

    assert result["diff_head_lines_verified"] is True
    assert result["removed_lines_verified"] is False
    assert set(result["candidate_context"]) == {inventory.candidates[0].candidate_id}
    row = result["candidate_context"][inventory.candidates[0].candidate_id]
    assert row["language"] == "python"
    hunk = row["diff_hunks"][0]
    raw_hunk = "\n".join(diff.splitlines()[3:])
    assert hunk["diff_hunk_sha256"] == hashlib.sha256(raw_hunk.encode()).hexdigest()
    assert (hunk["line_start"], hunk["line_end"]) == (1, 3)
    assert secret not in json.dumps(result)
    assert any(marker in hunk["diff_hunk"] for marker in (
        "[redacted", "[secret-bearing source excluded]",
    ))
    assert row["deterministic_scanner_hits"][0]["id"] == "det-1"
    assert row["deterministic_scanner_hits"][0]["severity"] == "P2"
    assert hits[0]["message"].endswith(secret)  # input was not mutated


def test_removed_comment_secret_is_excluded_from_typed_diff_context(tmp_path: Path) -> None:
    secret = "AKIA" + "1234567890ABCDEF"
    before = f"# removed historical key {secret}\nkeep = 1\n"
    after = "# removed historical key\nkeep = 1\n"
    inventory, ingest = inventory_for(tmp_path, {"source.py": after}, language="python")
    diff = patch("source.py", before, after)

    result = context_for(tmp_path, inventory, ingest, diff)

    serialized = json.dumps(result, sort_keys=True)
    assert secret not in serialized
    hunk = next(iter(result["candidate_context"].values()))["diff_hunks"][0]
    assert "[secret-bearing source excluded]" in hunk["diff_hunk"]
    raw_hunk = "\n".join(diff.splitlines()[3:])
    assert hunk["diff_hunk_sha256"] == hashlib.sha256(raw_hunk.encode()).hexdigest()


def test_secret_scanner_message_is_constant_at_typed_context_boundary(tmp_path: Path) -> None:
    secret = "arbitrary-low-entropy-private-value"
    after = "keep = 1\n"
    inventory, ingest = inventory_for(tmp_path, {"source.py": after})
    findings = [{
        "id": "secret-hit", "rule_id": "fixture", "category": "secrets",
        "severity": "P1", "file_path": "source.py", "line_start": 1,
        "line_end": 1, "message": f"scanner accidentally echoed {secret}",
    }]

    result = context_for(
        tmp_path, inventory, ingest, patch("source.py", "old = 1\n", after), findings,
    )

    serialized = json.dumps(result, sort_keys=True)
    assert secret not in serialized
    hit = next(iter(result["candidate_context"].values()))["deterministic_scanner_hits"][0]
    assert hit["message"] == "Secret-bearing scanner evidence excluded"


def test_multiple_hunks_attach_only_to_intersecting_source_candidates(tmp_path: Path) -> None:
    before = "".join(f"line {index}\n" for index in range(1, 91))
    after = before.replace("line 5\n", "changed 5\n").replace("line 75\n", "changed 75\n")
    inventory, ingest = inventory_for(tmp_path, {"source.py": after})
    hits = [
        {"id": "cross", "file_path": "source.py", "line_start": 35, "line_end": 45},
        {"id": "tail", "file_path": "source.py", "line_start": 85, "line_end": 85},
        {"id": "outside", "file_path": "source.py", "line_start": 999, "line_end": 999},
        {"id": "other", "file_path": "other.py", "line_start": 5, "line_end": 5},
    ]

    result = context_for(tmp_path, inventory, ingest, patch("source.py", before, after, context=2), hits)

    rows = [result["candidate_context"][candidate.candidate_id] for candidate in inventory.candidates]
    assert [len(row["diff_hunks"]) for row in rows] == [1, 1, 0]
    assert [[hit["id"] for hit in row["deterministic_scanner_hits"]] for row in rows] == [
        ["cross"], ["cross"], ["tail"],
    ]
    assert all(row["language"] == "py" for row in rows)


def test_complete_two_file_scope_and_new_file_addition(tmp_path: Path) -> None:
    files = {"one.py": "new one\n", "nested/two.txt": "added two\n"}
    inventory, ingest = inventory_for(tmp_path, files)
    diff = patch("one.py", "old one\n", files["one.py"]) + patch(
        "nested/two.txt", "", files["nested/two.txt"],
    )
    result = context_for(tmp_path, inventory, ingest, diff)
    assert len(result["candidate_context"]) == 2
    added = next(candidate for candidate in inventory.candidates if candidate.file_path == "nested/two.txt")
    assert result["candidate_context"][added.candidate_id]["language"] == "txt"


def test_audited_npm_lockfile_patch_is_bound_but_withheld_from_model(tmp_path: Path) -> None:
    source = "answer = 2\n"
    lock = '{"lockfileVersion": 3, "private_marker": "lock-bytes-must-stay-out"}\n'
    (tmp_path / "source.py").write_text(source, encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(lock, encoding="utf-8")
    receipt = {
        "enabled": True, "complete": True,
        "npm_projects": {"audits": [{
            "lockfile_path": "package-lock.json",
            "lockfile_sha256": hashlib.sha256((tmp_path / "package-lock.json").read_bytes()).hexdigest(),
            "input_unchanged": True,
            "outcome": {"ecosystem": "npm", "applicable": True, "state": "clean"},
        }]},
    }
    ingest = {"files": [{"path": "source.py"}]}
    inventory = build_inventory(
        repo_root=tmp_path, ingest=ingest,
        changed_files=["source.py", "package-lock.json"],
        scan_mode="pr-diff", max_candidates=50, dep_audit_evidence=receipt,
    )
    assert inventory.policy_excluded == (("package-lock.json", "dep_audit_coverage"),)
    diff = patch("source.py", "answer = 1\n", source) + patch(
        "package-lock.json", '{"lockfileVersion": 2}\n', lock,
    )
    context = context_for(tmp_path, inventory, ingest, diff)
    assert set(context["candidate_context"]) == {inventory.candidates[0].candidate_id}
    assert "lock-bytes-must-stay-out" not in json.dumps(context)
    assert context["diff_head_lines_verified"] is True

    with pytest.raises(TypeSafeReviewIncomplete, match="incomplete_typed_diff_file_coverage"):
        context_for(tmp_path, inventory, ingest, patch("source.py", "answer = 1\n", source))
    with pytest.raises(TypeSafeReviewIncomplete, match="duplicate_typed_diff_record"):
        context_for(tmp_path, inventory, ingest, diff + patch("package-lock.json", '{"lockfileVersion": 2}\n', lock))


@pytest.mark.parametrize(
    "diff", [None, "", "x" * 100_001, "😀" * 25_001],
    ids=["missing", "empty", "oversize-ascii", "oversize-utf8"],
)
def test_missing_or_utf8_oversize_diff_is_explicitly_incomplete(tmp_path: Path, diff) -> None:
    inventory, ingest = inventory_for(tmp_path, {"source.py": "new\n"})
    with pytest.raises(TypeSafeReviewIncomplete):
        context_for(tmp_path, inventory, ingest, diff)


@pytest.mark.parametrize("body", [
    "@@ -1 +1,2 @@\n-old\n+new\n",
    "@@ -1,2 +1 @@\n-old\n+new\n",
    "@@ -1 +1 @@\n-old\nnew\n",
    "@@ -1 +1 @@\n-old\n+wrong\n",
    "@@ -1 +2 @@\n-old\n+new\n",
    "@@ -1 +0 @@\n-old\n+new\n",
    "@@ -1,0 +1 @@\n-old\n+new\n",
])
def test_partial_invalid_counts_or_mismatched_head_lines_refuse(tmp_path: Path, body: str) -> None:
    inventory, ingest = inventory_for(tmp_path, {"source.py": "new\n"})
    with pytest.raises(TypeSafeReviewIncomplete):
        context_for(tmp_path, inventory, ingest, "--- a/source.py\n+++ b/source.py\n" + body)


def test_surplus_hunk_body_cannot_be_silently_dropped_after_declared_counts(tmp_path: Path) -> None:
    inventory, ingest = inventory_for(tmp_path, {"source.py": "new\nsecond\n"})
    diff = "--- a/source.py\n+++ b/source.py\n@@ -1 +1 @@\n-old\n+new\n+second\n"
    with pytest.raises(TypeSafeReviewIncomplete):
        context_for(tmp_path, inventory, ingest, diff)


@pytest.mark.parametrize("target", [
    "a/source.py", '"b/source.py"', "/dev/null", "b/other.py", "b/../source.py",
])
def test_unsupported_or_out_of_scope_patch_paths_refuse(tmp_path: Path, target: str) -> None:
    inventory, ingest = inventory_for(tmp_path, {"source.py": "new\n"})
    diff = f"--- a/source.py\n+++ {target}\n@@ -1 +1 @@\n-old\n+new\n"
    with pytest.raises(TypeSafeReviewIncomplete):
        context_for(tmp_path, inventory, ingest, diff)


def test_rename_metadata_is_not_silently_claimed_as_supported_diff(tmp_path: Path) -> None:
    inventory, ingest = inventory_for(tmp_path, {"source.py": "new\n"})
    diff = (
        "diff --git a/old.py b/source.py\nsimilarity index 50%\n"
        "rename from old.py\nrename to source.py\n--- a/old.py\n+++ b/source.py\n"
        "@@ -1 +1 @@\n-old\n+new\n"
    )
    with pytest.raises(TypeSafeReviewIncomplete):
        context_for(tmp_path, inventory, ingest, diff)


@pytest.mark.parametrize("diff", [
    "diff --git a/source.py b/source.py\nBinary files a/source.py and b/source.py differ\n",
    "diff --git a/source.py b/source.py\n@@ -1 +1 @@\n-old\n+new\n",
])
def test_binary_or_unbound_hunk_refuses(tmp_path: Path, diff: str) -> None:
    inventory, ingest = inventory_for(tmp_path, {"source.py": "new\n"})
    with pytest.raises(TypeSafeReviewIncomplete):
        context_for(tmp_path, inventory, ingest, diff)


def test_partial_file_scope_never_reports_complete_context(tmp_path: Path) -> None:
    inventory, ingest = inventory_for(tmp_path, {"one.py": "one\n", "two.py": "two\n"})
    with pytest.raises(TypeSafeReviewIncomplete):
        context_for(tmp_path, inventory, ingest, patch("one.py", "old\n", "one\n"))


def test_changed_head_hash_refuses_before_emitting_context(tmp_path: Path) -> None:
    inventory, ingest = inventory_for(tmp_path, {"source.py": "new\n"})
    (tmp_path / "source.py").write_bytes(b"different\n")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_changed_during_review"):
        context_for(tmp_path, inventory, ingest, patch("source.py", "old\n", "new\n"))


def test_source_removed_after_inventory_is_an_explicit_incomplete_result(tmp_path: Path) -> None:
    inventory, ingest = inventory_for(tmp_path, {"source.py": "new\n"})
    (tmp_path / "source.py").unlink()
    with pytest.raises(TypeSafeReviewIncomplete):
        context_for(tmp_path, inventory, ingest, patch("source.py", "old\n", "new\n"))


@pytest.mark.parametrize("location", ["1", True, 1.5])
def test_scanner_locations_are_typed_before_context_is_emitted(tmp_path: Path, location) -> None:
    inventory, ingest = inventory_for(tmp_path, {"source.py": "new\n"})
    with pytest.raises(TypeSafeReviewIncomplete, match="invalid_deterministic_location"):
        context_for(tmp_path, inventory, ingest, patch("source.py", "old\n", "new\n"), [
            {"file_path": "source.py", "line_start": location, "line_end": location},
        ])


@pytest.mark.anyio
async def test_full_typed_context_budget_refuses_before_any_client_request(tmp_path: Path) -> None:
    source = "x" * 13_000 + "\n"
    inventory, ingest = inventory_for(tmp_path, {"source.py": source})
    context = context_for(tmp_path, inventory, ingest, patch("source.py", "old\n", source))

    class Policy:
        policy_id = "fixture"
        calibration_id = "fixture"

        def plan(self, candidates):
            return ReviewPlan(
                questions={f"q{i}": {"type": "noul", "instructions": "fixture"} for i, _ in enumerate(candidates)},
                question_candidates={f"q{i}": candidate.candidate_id for i, candidate in enumerate(candidates)},
            )

        def decide(self, *_args):
            raise AssertionError("oversize state must not reach a policy decision")

    class Client:
        calls = 0

        async def rate(self, **_kwargs):
            self.calls += 1
            raise AssertionError("oversize state must not reach a provider")

    client = Client()
    with pytest.raises(TypeSafeReviewIncomplete, match="typed_context_budget_exceeded"):
        await review_inventory(
            repo_root=tmp_path, inventory=inventory, policy=Policy(), client=client,
            model="model-under-test-1.13.0", context=context,
        )
    assert client.calls == 0
