#!/usr/bin/env python3
"""Create a GitHub PR from the current branch to main.

Usage:
  GITHUB_PAT=<token> GITHUB_REPO=<owner/repo> python3 pipeline/create-pr.py [title] [head-branch] [base-branch]

Environment:
  GITHUB_PAT   — GitHub Personal Access Token (required)
  GITHUB_REPO  — GitHub repo in owner/repo format (required)
"""
import urllib.request
import urllib.error
import json
import sys
import os
import subprocess

PAT = os.environ.get("GITHUB_PAT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not PAT:
    print("ERROR: Set GITHUB_PAT env var or pass token as argument.")
    sys.exit(1)

REPO = os.environ.get("GITHUB_REPO", "")
if not REPO:
    print("ERROR: Set GITHUB_REPO env var (e.g., 'myuser/ai-detection-engineering').")
    sys.exit(1)
BASE_URL = f"https://api.github.com/repos/{REPO}"
HEADERS = {
    "Authorization": f"Bearer {PAT}",
    "Accept": "application/vnd.github+json",
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "blue-team-agent/1.0",
}


def api(method, path, data=None):
    url = BASE_URL + path
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode()), e.code


def get_current_branch():
    return subprocess.check_output(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True
    ).strip()


# Parse arguments
title = sys.argv[2] if len(sys.argv) > 2 else None
head = sys.argv[3] if len(sys.argv) > 3 else get_current_branch()
base = sys.argv[4] if len(sys.argv) > 4 else "main"

if not title:
    title = f"[Detection] {head}"

# Get commit log for PR body
try:
    log = subprocess.check_output(
        ["git", "log", f"{base}..{head}", "--oneline", "--no-merges"],
        text=True,
    ).strip()
except subprocess.CalledProcessError:
    log = "(could not generate commit log)"

BODY = f"""\
## Summary

Auto-generated PR from `{head}` to `{base}`.

## Commits

```
{log}
```

## Test plan

- [ ] Validate detection rules against live SIEM data
- [ ] Confirm TP rate > 90%, FP rate < 10%
- [ ] Review Sigma rule metadata and MITRE ATT&CK mapping
"""

resp, status = api("POST", "/pulls", {
    "title": title,
    "head": head,
    "base": base,
    "body": BODY,
})

if status == 201:
    print(f"[+] PR #{resp['number']} created: {resp['html_url']}")
elif status == 422:
    errors = resp.get("errors", [])
    if any("already exists" in str(e) for e in errors):
        print("[=] PR already exists")
    else:
        print(f"[!] Validation error: {errors}")
else:
    print(f"[!] HTTP {status}: {resp.get('message', '')} — {resp}")
