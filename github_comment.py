"""Posts (or updates) a single PR comment containing the scan report, using
GitHub's REST API directly via `requests`."""

import json
import os

import requests

MARKER = "<!-- secscan-report -->"


def post_or_update_comment(report: str) -> None:
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")          # e.g. "AkhilShekhar/CI-CD_SEC"
    event_path = os.environ.get("GITHUB_EVENT_PATH")

    if not (token and repo and event_path):
        print("Not running inside a GitHub PR context; skipping comment post.")
        return

    with open(event_path) as f:
        event = json.load(f)

    pr_number = event.get("pull_request", {}).get("number") or event.get("number")
    if not pr_number:
        print("No pull_request number in event payload; skipping comment post.")
        return

    api_base = f"https://api.github.com/repos/{repo}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }

    comments_url = f"{api_base}/issues/{pr_number}/comments"
    resp = requests.get(comments_url, headers=headers, timeout=30)
    resp.raise_for_status()
    existing = next((c for c in resp.json() if MARKER in c.get("body", "")), None)

    if existing:
        update_url = f"{api_base}/issues/comments/{existing['id']}"
        resp = requests.patch(update_url, headers=headers, json={"body": report}, timeout=30)
    else:
        resp = requests.post(comments_url, headers=headers, json={"body": report}, timeout=30)
    resp.raise_for_status()
