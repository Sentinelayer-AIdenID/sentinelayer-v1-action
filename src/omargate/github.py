from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, List

import httpx
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .context import GitHubContext
from .fix_plan import ensure_fix_plan

GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
DEFAULT_HTTP_TIMEOUT_SECONDS = float(os.environ.get("OMAR_GITHUB_HTTP_TIMEOUT_SECONDS", "15"))
logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


MAX_PR_DIFF_BYTES = _int_env("OMAR_MAX_PR_DIFF_BYTES", 10 * 1024 * 1024)
MAX_PR_FILES_PAGES = _int_env("OMAR_PR_FILES_MAX_PAGES", 10)
MAX_PR_FILES_WARN_THRESHOLD = _int_env("OMAR_PR_FILES_WARN_THRESHOLD", 1000)

class GitHubClient:
    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo
        self.session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            # Restrict retries to idempotent methods to avoid duplicate side effects.
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "omar-gate-action",
        })

    def create_or_update_pr_comment(self, pr_number: int, body: str, marker_token: str) -> Optional[str]:
        """Idempotent update: match exact marker token; update if found else create."""
        url = f"{GITHUB_API}/repos/{self.repo}/issues/{pr_number}/comments"
        r = self.session.get(url, params={"per_page": 100}, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
        r.raise_for_status()
        comments = r.json()
        for c in comments:
            if marker_token in (c.get("body") or ""):
                patch_url = f"{GITHUB_API}/repos/{self.repo}/issues/comments/{c['id']}"
                pr = self.session.patch(
                    patch_url,
                    json={"body": body},
                    timeout=DEFAULT_HTTP_TIMEOUT_SECONDS,
                )
                pr.raise_for_status()
                try:
                    return (pr.json() or {}).get("html_url")
                except Exception:
                    return None
        cr = self.session.post(url, json={"body": body}, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
        cr.raise_for_status()
        try:
            return (cr.json() or {}).get("html_url")
        except Exception:
            return None

    def create_check_run(
        self,
        name: str,
        head_sha: str,
        conclusion: str,
        summary: str,
        title: Optional[str] = None,
        text: Optional[str] = None,
        details_url: Optional[str] = None,
        external_id: Optional[str] = None,
        annotations: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[str]:
        url = f"{GITHUB_API}/repos/{self.repo}/check-runs"
        output: Dict[str, Any] = {"title": title or name, "summary": summary}
        if text:
            output["text"] = text
        if annotations:
            output["annotations"] = annotations
        payload: Dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": output,
        }
        if details_url:
            payload["details_url"] = details_url
        if external_id:
            payload["external_id"] = external_id
        r = self.session.post(url, json=payload, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
        r.raise_for_status()
        try:
            return (r.json() or {}).get("html_url")
        except Exception:
            return None

    def list_check_runs(self, head_sha: str, check_name: Optional[str] = None) -> List[Dict[str, Any]]:
        url = f"{GITHUB_API}/repos/{self.repo}/commits/{head_sha}/check-runs"
        params: Dict[str, Any] = {"per_page": 100}
        if check_name:
            params["check_name"] = check_name
        r = self.session.get(url, params=params, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
        r.raise_for_status()
        return r.json().get("check_runs", [])

    def find_check_run_by_external_id(self, head_sha: str, external_id: str, check_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        for run in self.list_check_runs(head_sha, check_name):
            if run.get("external_id") == external_id:
                return run
        return None

    def get_pull_request(self, pr_number: int) -> Dict[str, Any]:
        url = f"{GITHUB_API}/repos/{self.repo}/pulls/{pr_number}"
        r = self.session.get(url, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
        r.raise_for_status()
        return r.json()

    def list_issue_labels(self, pr_number: int) -> List[str]:
        url = f"{GITHUB_API}/repos/{self.repo}/issues/{pr_number}/labels"
        r = self.session.get(url, params={"per_page": 100}, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
        r.raise_for_status()
        return [label.get("name", "") for label in r.json()]

    def has_label(self, pr_number: int, label: str) -> bool:
        return label in self.list_issue_labels(pr_number)

    def get_branch_protection(self, branch: str) -> Optional[Dict[str, Any]]:
        url = f"{GITHUB_API}/repos/{self.repo}/branches/{branch}/protection"
        r = self.session.get(url, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    async def get_pr_diff(self, pr_number: int) -> str:
        """Get PR diff content."""
        url = f"{GITHUB_API}/repos/{self.repo}/pulls/{pr_number}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3.diff",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "omar-gate-action",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                logger.warning("Failed to fetch PR diff: status=%d", resp.status_code)
                raise RuntimeError(f"Failed to fetch PR diff: status={resp.status_code}")

            content_length = 0
            try:
                content_length = int(resp.headers.get("Content-Length", "0"))
            except (TypeError, ValueError):
                content_length = 0
            if content_length > MAX_PR_DIFF_BYTES:
                logger.warning(
                    "PR diff payload exceeds cap (content_length=%d, cap=%d). Truncating.",
                    content_length,
                    MAX_PR_DIFF_BYTES,
                )

            text = resp.text
            text_bytes = text.encode("utf-8", errors="ignore")
            if len(text_bytes) > MAX_PR_DIFF_BYTES:
                logger.warning(
                    "PR diff exceeds %d bytes. Truncating to cap.",
                    MAX_PR_DIFF_BYTES,
                )
                text = text_bytes[:MAX_PR_DIFF_BYTES].decode("utf-8", errors="ignore")
            return text

    async def get_pr_changed_files(self, pr_number: int) -> List[str]:
        """Get list of changed file paths in PR."""
        url = f"{GITHUB_API}/repos/{self.repo}/pulls/{pr_number}/files"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "omar-gate-action",
        }
        changed_files: List[str] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            for page in range(1, MAX_PR_FILES_PAGES + 1):
                resp = await client.get(
                    url,
                    headers=headers,
                    params={"per_page": 100, "page": page},
                )
                if resp.status_code != 200:
                    raise RuntimeError(
                        f"Failed to fetch PR changed files: status={resp.status_code}, page={page}"
                    )

                files = resp.json()
                page_files = [f.get("filename", "") for f in files if f.get("filename")]
                changed_files.extend(page_files)

                if len(files) < 100:
                    break
            else:
                logger.warning(
                    "PR changed files pagination hit page cap (%d pages). Some files may be missing.",
                    MAX_PR_FILES_PAGES,
                )

        if len(changed_files) > MAX_PR_FILES_WARN_THRESHOLD:
            logger.warning(
                "PR has %d changed files (threshold=%d).",
                len(changed_files),
                MAX_PR_FILES_WARN_THRESHOLD,
            )

        return changed_files


def load_context() -> GitHubContext:
    """Load GitHub Actions context from environment."""
    return GitHubContext.from_environment()


def findings_to_annotations(findings: List[Dict[str, Any]], max_annotations: int = 50) -> List[Dict[str, Any]]:
    """Convert findings to GitHub Check Run annotations."""
    severity_to_level = {
        "P0": "failure",
        "P1": "failure",
        "P2": "warning",
        "P3": "notice",
        "P4": "notice",
    }
    annotations: List[Dict[str, Any]] = []
    for finding in findings:
        if len(annotations) >= max_annotations:
            break
        path = finding.get("file_path")
        line_start = finding.get("line_start")
        if not path or not line_start:
            continue
        line_end = finding.get("line_end") or line_start
        severity = finding.get("severity", "P3")
        annotations.append(
            {
                "path": path,
                "start_line": int(line_start),
                "end_line": int(line_end),
                "annotation_level": severity_to_level.get(severity, "notice"),
                "title": f"{severity}: {finding.get('category', 'Issue')}",
                "message": finding.get("message", "No description"),
                "raw_details": ensure_fix_plan(
                    fix_plan=finding.get("fix_plan", ""),
                    recommendation=finding.get("recommendation", ""),
                    message=finding.get("message", ""),
                ),
            }
        )
    return annotations
