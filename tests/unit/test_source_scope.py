import subprocess
from dataclasses import replace

import pytest

from omargate.analyze.source_scope import build_source_scope, verify_source_scope
from omargate.analyze.typesafe_review import TypeSafeReviewIncomplete


@pytest.fixture
def tracked(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "core.autocrlf", "false"], check=True)
    def add(name, raw=b"value = 1\n"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        subprocess.run(["git", "-C", str(tmp_path), "add", "--", name], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "owned fixture"], check=True)
    add("src/x.py")
    return tmp_path, add


@pytest.mark.parametrize("mode", ["deep", "nightly"])
def test_whole_tracked_scope_retains_last_file_empty_hash_and_declared_exclusions(tracked, mode):
    root, add = tracked
    add("src/z.py", b"last_file = True\n")
    add("src/empty.py", b"")
    add("tests/test_x.py")
    (root / "untracked.py").write_text("outside = True\n")
    scope = build_source_scope(root, mode)
    assert set(dict(scope.source_hashes)) == {"src/x.py", "src/z.py", "src/empty.py", "tests/test_x.py"}
    assert {c.file_path for c in scope.inventory.candidates} == {"src/x.py", "src/z.py", "tests/test_x.py"}
    assert scope.exclusions == ()
    assert scope.manifest()["untracked_files"] == "outside_declared_scope"
    assert build_source_scope(root, mode) == scope
    verify_source_scope(root, scope)


def test_required_tail_mutation_and_new_tracked_file_cannot_pass(tracked):
    root, add = tracked
    add("src/z.py")
    scope = build_source_scope(root, "deep")
    (root / "src/z.py").write_text("changed = True\n")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_changed"):
        verify_source_scope(root, scope)
    (root / "src/z.py").write_bytes(b"value = 1\n")
    add("src/new.py")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_scope_changed"):
        verify_source_scope(root, scope)


def test_ignore_policy_changes_cannot_silently_reduce_coverage(tracked):
    root, add = tracked
    add(".sentinelayerignore", b"src/**\n")
    scope = build_source_scope(root, "deep")
    assert "src/x.py" in dict(scope.source_hashes)
    assert scope.ignore_patterns == ()
    (root / ".sentinelayerignore").write_text("**\n")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_changed_during_review"):
        verify_source_scope(root, scope)


@pytest.mark.parametrize("raw,code", [(b"x\0y", "unsupported_source_bytes"), (b"\xff", "unsupported_source_encoding")])
def test_required_unreadable_bytes_do_not_become_clean(tracked, raw, code):
    root, add = tracked
    add("src/z.py", raw)
    with pytest.raises(TypeSafeReviewIncomplete, match=code):
        build_source_scope(root, "deep")


def test_binary_exclusion_cannot_be_replaced_by_text(tracked):
    root, add = tracked
    add("icon.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 12)
    scope = build_source_scope(root, "deep")
    assert ("icon.png", "binary_non_text") in scope.exclusions
    (root / "icon.png").write_text("now code\n")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_changed_during_review"):
        verify_source_scope(root, scope)


@pytest.mark.parametrize("budget,kwargs", [("byte", {"max_total_bytes": 5}), ("candidate", {"max_candidates": 1})])
def test_scope_budgets_refuse_instead_of_dropping_tail(tracked, budget, kwargs):
    root, add = tracked
    add("src/z.py")
    with pytest.raises(TypeSafeReviewIncomplete, match="budget_exceeded"):
        build_source_scope(root, "deep", **kwargs)


def test_no_git_inventory_is_unknown(tmp_path):
    (tmp_path / "x.py").write_text("x = 1\n")
    with pytest.raises(TypeSafeReviewIncomplete, match="inventory_unavailable"):
        build_source_scope(tmp_path, "deep")


def test_uncommitted_source_and_normalized_crlf_cannot_claim_committed_blob_identity(tracked):
    root, _ = tracked
    path = root / "src/x.py"
    path.write_bytes(b"changed = True\n")
    with pytest.raises(TypeSafeReviewIncomplete, match="differs_from_committed_blob"):
        build_source_scope(root, "deep")
    subprocess.run(["git", "-C", str(root), "config", "core.autocrlf", "true"], check=True)
    path.write_bytes(b"value = 1\r\n")
    subprocess.run(["git", "-C", str(root), "add", "--renormalize", "src/x.py"], check=True)
    # Git normalizes this working file, so ordinary git status is clean.
    assert not subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"])
    with pytest.raises(TypeSafeReviewIncomplete, match="differs_from_committed_blob"):
        build_source_scope(root, "deep")


def test_untracked_ignore_policy_cannot_hide_required_source(tracked):
    root, _ = tracked
    (root / ".sentinelayerignore").write_text("src/**\n")
    scope = build_source_scope(root, "deep")
    assert "src/x.py" in dict(scope.source_hashes)
    assert not scope.exclusions and not scope.ignore_patterns


@pytest.mark.parametrize("name,header", [
    ("icon.png", b"\x89PNG\r\n\x1a\n"), ("icon.jpg", b"\xff\xd8\xff"),
    ("icon.jpeg", b"\xff\xd8\xff"), ("icon.ico", b"\0\0\x01\0"),
])
def test_only_declared_images_are_excluded_and_their_exact_bytes_stay_bound(tracked, name, header):
    root, add = tracked
    add(name, header + b"\xff" + b"\0" * 12)
    scope = build_source_scope(root, "deep")
    assert scope.exclusions == ((name, "binary_non_text"),)
    (root / name).write_bytes(header + b"\xff" + b"\0" * 11 + b"x")
    with pytest.raises(TypeSafeReviewIncomplete, match="source_changed_during_review"):
        verify_source_scope(root, scope)


@pytest.mark.parametrize("name,raw", [
    ("disguised.png", b"/*\0*/console.log('fixture');\n"),
    ("source.mjs", b"GIF89a\0"), ("source", b"\0unknown"),
])
def test_nul_and_image_extension_or_magic_alone_do_not_establish_a_binary(tracked, name, raw):
    root, add = tracked
    add(name, raw)
    with pytest.raises(TypeSafeReviewIncomplete, match="unsupported_source_bytes"):
        build_source_scope(root, "deep")


@pytest.mark.parametrize("name,raw", [("icon.gif", b"GIF89a\0"),
                                    ("icon.webp", b"RIFF\0\0\0\0WEBP"),
                                    ("icon.ico", b"\0\0\x01\0")])
def test_utf8_nul_bytes_under_image_magic_refuse_instead_of_excluding(tracked, name, raw):
    root, add = tracked
    add(name, raw)
    with pytest.raises(TypeSafeReviewIncomplete, match="unsupported_source_bytes"):
        build_source_scope(root, "deep")


@pytest.mark.parametrize("field", ["tracked_paths", "source_hashes", "exclusions", "git_blobs"])
def test_scope_manifest_never_serializes_credential_coordinates(tracked, field):
    root, _ = tracked
    scope = build_source_scope(root, "deep")
    name = "sk-" + "OWNEDFAKETOKEN0123456789" + ".py"
    value = (name,) if field == "tracked_paths" else ((name, "fixture"),)
    with pytest.raises(TypeSafeReviewIncomplete, match="redacted_source"):
        replace(scope, **{field: value}).manifest()
