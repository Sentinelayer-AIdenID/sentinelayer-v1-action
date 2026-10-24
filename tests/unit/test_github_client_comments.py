from __future__ import annotations

from typing import Any

from omargate.github import GitHubClient


class _FakeResponse:
    def __init__(self, payload: Any, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http status {self.status_code}")

    def json(self) -> Any:
        return self._payload


class _FakeSession:
    def __init__(self, comments: list[dict[str, Any]]):
        self._comments = comments
        self.patch_url: str | None = None
        self.patch_body: str | None = None
        self.post_url: str | None = None
        self.post_body: str | None = None

    def get(self, _url: str, **_kwargs: Any) -> _FakeResponse:
        return _FakeResponse(self._comments)

    def patch(self, url: str, json: dict[str, Any], **_kwargs: Any) -> _FakeResponse:
        self.patch_url = url
        self.patch_body = str(json.get("body") or "")
        return _FakeResponse({"html_url": "https://github.test/comments/updated"})

    def post(self, url: str, json: dict[str, Any], **_kwargs: Any) -> _FakeResponse:
        self.post_url = url
        self.post_body = str(json.get("body") or "")
        return _FakeResponse({"html_url": "https://github.test/comments/new"})


def test_create_or_update_pr_comment_matches_exact_marker_token() -> None:
    marker_gemini = "<!-- sentinelayer:omar-gate:v1:gemini:acme/demo:42 -->"
    marker_codex = "<!-- sentinelayer:omar-gate:v1:acme/demo:42 -->"
    fake_session = _FakeSession(
        comments=[
            {"id": 11, "body": f"gemini\n{marker_gemini}"},
            {"id": 22, "body": f"codex\n{marker_codex}"},
        ]
    )

    client = GitHubClient(token="token", repo="acme/demo")
    client.session = fake_session  # type: ignore[assignment]

    url = client.create_or_update_pr_comment(
        pr_number=42,
        body=f"updated codex\n{marker_codex}",
        marker_token=marker_codex,
    )

    assert url == "https://github.test/comments/updated"
    assert fake_session.patch_url is not None
    assert fake_session.patch_url.endswith("/22")
    assert fake_session.post_url is None


def test_create_or_update_pr_comment_posts_when_marker_not_found() -> None:
    marker_codex = "<!-- sentinelayer:omar-gate:v1:acme/demo:42 -->"
    fake_session = _FakeSession(
        comments=[
            {"id": 11, "body": "<!-- sentinelayer:omar-gate:v1:gemini:acme/demo:42 -->"},
        ]
    )

    client = GitHubClient(token="token", repo="acme/demo")
    client.session = fake_session  # type: ignore[assignment]

    url = client.create_or_update_pr_comment(
        pr_number=42,
        body=f"new codex\n{marker_codex}",
        marker_token=marker_codex,
    )

    assert url == "https://github.test/comments/new"
    assert fake_session.patch_url is None
    assert fake_session.post_url is not None

