"""
GitHub REST API Client for automated Incident Runbook publishing.
Uses GitHub Contents API (PUT /repos/{owner}/{repo}/contents/{path}).
Handles file creation, updates (with SHA fetching), rate-limiting retries, and offline mock fallback.
"""

import os
import base64
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import requests

logger = logging.getLogger("shadow-it.github-client")

def is_github_configured() -> bool:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    repo = os.getenv("GITHUB_RUNBOOK_REPO", "").strip()
    if not token or not repo or token.startswith("ghp_placeholder") or "your-" in token:
        return False
    return True

def push_runbook_to_github(
    incident_id: str,
    resource_id: str,
    markdown_content: str,
    branch: Optional[str] = None,
    directory: Optional[str] = None
) -> Dict[str, Any]:
    """
    Pushes runbook markdown to the configured GitHub repository.
    Path: {directory}/{YYYY}/{YYYY-MM-DD}_{incident_id}_{clean_resource_id}.md
    """
    if not is_github_configured():
        logger.info(f"GitHub not configured. Skipping GitHub push for incident {incident_id}.")
        return {
            "status": "skipped",
            "html_url": None,
            "message": "GITHUB_TOKEN or GITHUB_RUNBOOK_REPO not configured (running in mock mode)"
        }

    token = os.getenv("GITHUB_TOKEN", "").strip()
    repo = os.getenv("GITHUB_RUNBOOK_REPO", "").strip() # Format: owner/repo
    target_branch = branch or os.getenv("GITHUB_RUNBOOK_BRANCH", "main")
    base_dir = (directory or os.getenv("GITHUB_RUNBOOK_DIR", "runbooks")).strip("/")

    clean_res_id = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in resource_id)
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    year_str = now.strftime("%Y")
    
    file_path = f"{base_dir}/{year_str}/{date_str}_{incident_id}_{clean_res_id}.md"
    url = f"https://api.github.com/repos/{repo}/contents/{file_path}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ShadowGuard-RunbookPusher/1.0"
    }

    # Step 1: Check if file already exists to get its SHA
    existing_sha = None
    try:
        check_resp = requests.get(f"{url}?ref={target_branch}", headers=headers, timeout=10)
        if check_resp.status_code == 200:
            existing_sha = check_resp.json().get("sha")
    except Exception as e:
        logger.warning(f"Failed to check existing file on GitHub: {e}")

    # Step 2: Prepare commit payload
    encoded_content = base64.b64encode(markdown_content.encode("utf-8")).decode("utf-8")
    commit_msg = f"chore(runbook): {'update' if existing_sha else 'add'} runbook for {incident_id} ({clean_res_id})"

    payload = {
        "message": commit_msg,
        "content": encoded_content,
        "branch": target_branch
    }
    if existing_sha:
        payload["sha"] = existing_sha

    # Step 3: Send PUT request with retry backoff
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            put_resp = requests.put(url, headers=headers, json=payload, timeout=15)
            if put_resp.status_code in (200, 201):
                data = put_resp.json()
                html_url = data.get("content", {}).get("html_url") or f"https://github.com/{repo}/blob/{target_branch}/{file_path}"
                logger.info(f"Successfully pushed runbook to GitHub: {html_url}")
                return {
                    "status": "ok",
                    "html_url": html_url,
                    "file_path": file_path,
                    "sha": data.get("content", {}).get("sha")
                }
            elif put_resp.status_code in (401, 403, 404, 422):
                err_msg = put_resp.text
                logger.error(f"GitHub API Error {put_resp.status_code} for {file_path}: {err_msg}")
                return {
                    "status": "failed",
                    "error": f"HTTP {put_resp.status_code}: {err_msg[:200]}",
                    "html_url": None
                }
            else:
                logger.warning(f"GitHub attempt {attempt} returned {put_resp.status_code}, retrying...")
                time.sleep(1.0 * attempt)
        except Exception as e:
            logger.warning(f"GitHub request exception on attempt {attempt}: {e}")
            time.sleep(1.0 * attempt)

    return {
        "status": "failed",
        "error": "Failed after 3 attempts due to network or timeout",
        "html_url": None
    }
