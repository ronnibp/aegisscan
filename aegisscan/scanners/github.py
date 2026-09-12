"""GitHub integration.

* Fetch and scan any public (or token-readable) GitHub repository.
* Optional repository metadata posture (stars, license, visibility, branch
  protection when a token is supplied).
"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
import tempfile
import urllib.request
from urllib.error import HTTPError, URLError

from ..core.models import Finding, Severity
from ..core.utils import fetch

API = "https://api.github.com"
REPO_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+?)(?:\.git)?/?$"
    r"|^(?P<short>[\w.\-]+)/(?P<short_repo>[\w.\-]+)$"
)


def parse_repo(url: str) -> tuple:
    m = REPO_URL_RE.match(url.strip())
    if not m:
        raise ValueError(f"Not a valid GitHub repository reference: {url}")
    if m.group("owner"):
        return m.group("owner"), m.group("repo")
    return m.group("short"), m.group("short_repo")


def _headers(token: str) -> dict:
    h = {"Accept": "application/vnd.github+json", "User-Agent": "AegisScan/1.0"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _api(path: str, token: str = "") -> dict:
    req = urllib.request.Request(f"{API}{path}", headers=_headers(token))
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def repo_metadata(owner: str, repo: str, token: str = "") -> dict:
    """Best-effort repository posture metadata; never raises."""
    meta = {}
    try:
        d = _api(f"/repos/{owner}/{repo}", token)
        meta = {
            "full_name": d.get("full_name"),
            "description": d.get("description") or "",
            "visibility": "private" if d.get("private") else "public",
            "stars": d.get("stargazers_count", 0),
            "forks": d.get("forks_count", 0),
            "open_issues": d.get("open_issues_count", 0),
            "license": (d.get("license") or {}).get("spdx_id", "none"),
            "default_branch": d.get("default_branch", "main"),
            "language": d.get("language", ""),
            "has_issues": d.get("has_issues", False),
            "archived": d.get("archived", False),
            "url": d.get("html_url", ""),
        }
        if token:
            try:
                br = _api(f"/repos/{owner}/{repo}/branches/{meta['default_branch']}", token)
                meta["branch_protection"] = bool((br.get("protection") or {}).get("enabled"))
            except Exception:
                meta["branch_protection"] = "unknown"
    except Exception as e:
        meta["error"] = str(e)
    return meta


def download_repo(url_or_slug: str, token: str = "", dest_parent: str | None = None) -> tuple:
    """Download the default-branch tarball of a repo. Returns (path, metadata).

    The path is a temporary directory containing the repo contents.
    """
    owner, repo = parse_repo(url_or_slug)
    meta = repo_metadata(owner, repo, token)
    branch = meta.get("default_branch", "main")
    tar_url = f"{API}/repos/{owner}/{repo}/tarball/{branch}"

    req = urllib.request.Request(tar_url, headers=_headers(token))
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()

    parent = dest_parent or tempfile.gettempdir()
    dest = tempfile.mkdtemp(prefix="aegisscan-repo-")
    root = os.path.join(dest, "repo")
    os.makedirs(root, exist_ok=True)

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        # strip the leading "<owner>-<repo>-<sha>/" directory component
        members = []
        for m in tar.getmembers():
            parts = m.name.split("/", 1)
            if len(parts) < 2:
                continue
            m.name = parts[1]
            if m.name.strip():
                members.append(m)
        tar.extractall(root, members=members, filter="data")

    meta["downloaded_to"] = root
    return root, meta


def posture_findings(meta: dict, slug: str) -> list:
    """Findings from repository-level metadata (no content needed)."""
    findings = []
    if meta.get("visibility") == "public" and meta.get("license", "none") == "none":
        findings.append(Finding(
            scanner="github", category="Repository Posture",
            title="Public repository without a license", severity=Severity.LOW,
            target=slug, location=slug,
            description="A public repo without a license cannot be legally reused and signals an unfinished open-source posture.",
            remediation="Add an appropriate LICENSE file (MIT, Apache-2.0, ...).",
            references=["https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository"],
            mitre=["T1213"], tags=["github", "posture"], score=1.0))
    if meta.get("visibility") == "public":
        findings.append(Finding(
            scanner="github", category="Repository Posture",
            title="Repository is public", severity=Severity.INFO,
            target=slug, location=slug,
            description="All code and history is publicly readable — any committed secret is effectively compromised.",
            remediation="Ensure no secrets are committed; consider secret-scanning/push-protection on GitHub.",
            references=["https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"],
            mitre=["T1552.001"], tags=["github", "posture"], score=1.0))
    if "branch_protection" in meta and meta["branch_protection"] is False:
        findings.append(Finding(
            scanner="github", category="Repository Posture",
            title="Default branch has no protection rules", severity=Severity.MEDIUM,
            target=slug, location=slug,
            description="The default branch accepts direct pushes; a compromised or careless maintainer can ship unreviewed code to production.",
            remediation="Enable branch protection: required PR reviews, required status checks, no force pushes.",
            references=["https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches"],
            mitre=["T1195"], tags=["github", "posture"], score=5.0))
    return findings
