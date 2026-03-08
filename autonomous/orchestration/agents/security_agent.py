"""
Security Agent — Reviews every agent PR before human merge.
Scans for credential leaks, insecure code, overly broad queries,
dangerous exclusions, supply chain changes, and pipeline integrity.

Called by agent_runner.py. Implements run(state_manager, pr_number) interface.
"""

import datetime
import json
import os
import re
import urllib.request
import urllib.error
from pathlib import Path

import yaml

from orchestration.state import StateManager
from orchestration import learnings

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
SECURITY_DIR = AUTONOMOUS_DIR / "security"
AUDIT_LOG = SECURITY_DIR / "audit-log.jsonl"

AGENT_NAME = "security"

# ─── Helpers ──────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_scan_patterns() -> dict:
    """Load configurable scan patterns from YAML."""
    patterns_file = SECURITY_DIR / "scan-patterns.yml"
    if patterns_file.exists():
        with open(patterns_file) as f:
            return yaml.safe_load(f) or {}
    return {}


def _load_github_config() -> tuple[str, str]:
    """Load GitHub PAT from environment or .mcp.json.

    Token lookup order:
    1. GITHUB_TOKEN env var (set by GitHub Actions automatically)
    2. .mcp.json (local development, gitignored)
    """
    repo = "lsmithg12/ai-detection-engineering"

    # 1. Environment variable (GitHub Actions provides this)
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        return token, repo

    # 2. .mcp.json (local dev — file is gitignored)
    mcp_path = REPO_ROOT / ".mcp.json"
    if mcp_path.exists():
        with open(mcp_path) as f:
            mcp = json.load(f)
        for key, server in mcp.get("mcpServers", {}).items():
            if "github" in key.lower():
                env = server.get("env", {})
                token = env.get("GITHUB_PERSONAL_ACCESS_TOKEN", "")
                if token:
                    return token, repo

    return "", repo


# ─── Secret Scanning Patterns ────────────────────────────────────

DEFAULT_SECRET_PATTERNS = [
    # API keys
    (r'(?:sk|pk)[-_][a-zA-Z0-9]{20,}', "API key (sk-/pk- prefix)"),
    (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?[a-zA-Z0-9]{16,}', "API key assignment"),
    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?:aws_secret|aws_access_key)\s*[=:]\s*["\']?[a-zA-Z0-9/+=]{20,}', "AWS credential"),
    # GitHub tokens
    (r'gh[pso]_[a-zA-Z0-9]{36,}', "GitHub token"),
    (r'github_pat_[a-zA-Z0-9_]{22,}', "GitHub PAT"),
    # Private keys
    (r'BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY', "Private key"),
    # Bearer / JWT
    (r'Bearer\s+eyJ[a-zA-Z0-9_-]+\.eyJ', "JWT Bearer token"),
    # Connection strings with passwords
    (r'(?:mysql|postgres|mongodb|redis)://[^:]+:[^@\s]+@', "Connection string with credentials"),
    # Generic password assignments (but not in config.yml references)
    (r'(?:password|passwd|secret)\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded password"),
]

# ─── Scan Categories ─────────────────────────────────────────────

def scan_secrets(content: str, filepath: str, patterns: list | None = None) -> list[dict]:
    """Scan file content for hardcoded secrets."""
    findings = []
    scan_patterns = patterns or DEFAULT_SECRET_PATTERNS

    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        for pattern, description in scan_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Skip known safe patterns (config references, env var lookups)
                if _is_safe_context(line, filepath):
                    continue
                findings.append({
                    "severity": "CRITICAL",
                    "category": "Secret",
                    "file": filepath,
                    "line": line_num,
                    "finding": description,
                    "snippet": line.strip()[:120],
                })
    return findings


def _is_safe_context(line: str, filepath: str) -> bool:
    """Check if a match is in a known-safe context."""
    line_lower = line.strip().lower()
    # Comments
    if line_lower.startswith("#") or line_lower.startswith("//"):
        return True
    # Environment variable references (not hardcoded values)
    if "${" in line or "$(" in line or "os.environ" in line or "os.getenv" in line:
        return True
    # Known config files that legitimately contain lab credentials
    safe_files = ["config.yml", "docker-compose.yml", ".env.example", "setup.sh", "configure-cribl.sh"]
    if any(filepath.endswith(f) for f in safe_files):
        return True
    # Scan pattern definitions (this file itself)
    if filepath.endswith("security_agent.py") or filepath.endswith("scan-patterns.yml"):
        return True
    return False


def scan_code_security(content: str, filepath: str) -> list[dict]:
    """Scan for code security issues."""
    findings = []
    lines = content.split("\n")

    checks = [
        # Shell injection
        (r'(?:os\.system|subprocess\.call|subprocess\.Popen)\s*\([^)]*\+', "CRITICAL",
         "Potential shell injection — string concatenation in subprocess call"),
        (r'os\.system\s*\(', "WARN",
         "Use subprocess.run() instead of os.system() for better security"),
        # SSL verification disabled
        (r'verify\s*=\s*False', "WARN",
         "SSL verification disabled"),
        (r'curl\s+.*-k\b', "WARN",
         "curl with -k flag disables SSL verification"),
        # Dangerous file operations
        (r'rm\s+-rf\s+\$', "CRITICAL",
         "Recursive delete with variable path — potential path traversal"),
        (r'chmod\s+777', "WARN",
         "World-writable permissions"),
        # Overly permissive network
        (r'0\.0\.0\.0', "INFO",
         "Binding to all interfaces — verify this is intended"),
    ]

    for line_num, line in enumerate(lines, 1):
        if line.strip().startswith("#") or line.strip().startswith("//"):
            continue
        for pattern, severity, description in checks:
            if re.search(pattern, line):
                findings.append({
                    "severity": severity,
                    "category": "CodeSecurity",
                    "file": filepath,
                    "line": line_num,
                    "finding": description,
                    "snippet": line.strip()[:120],
                })
    return findings


def scan_detection_rules(content: str, filepath: str) -> list[dict]:
    """Scan Sigma/detection rules for security issues."""
    findings = []

    if not (filepath.endswith(".yml") or filepath.endswith(".yaml")):
        return findings

    try:
        rule = yaml.safe_load(content)
    except yaml.YAMLError:
        return findings

    if not isinstance(rule, dict):
        return findings

    # Check for detection rules (Sigma format)
    detection = rule.get("detection", {})
    if not detection:
        return findings

    # Check for overly broad exclusions
    filter_keys = [k for k in detection if k.startswith("filter")]
    if len(filter_keys) > 3:
        findings.append({
            "severity": "WARN",
            "category": "DetectionRule",
            "file": filepath,
            "line": 0,
            "finding": f"Rule has {len(filter_keys)} filter/exclusion blocks — may be too broad",
            "snippet": "",
        })

    # Check for process-name-only exclusions (easily evaded)
    for fk in filter_keys:
        fv = detection.get(fk, {})
        if isinstance(fv, dict) and list(fv.keys()) == ["process.name"]:
            findings.append({
                "severity": "WARN",
                "category": "DetectionRule",
                "file": filepath,
                "line": 0,
                "finding": f"Filter '{fk}' excludes by process.name only — easily evaded by renaming",
                "snippet": "",
            })

    return findings


def scan_supply_chain(content: str, filepath: str) -> list[dict]:
    """Flag supply chain changes for human review."""
    findings = []

    # New dependencies
    if filepath.endswith("requirements.txt") or filepath.endswith("package.json"):
        findings.append({
            "severity": "INFO",
            "category": "SupplyChain",
            "file": filepath,
            "line": 0,
            "finding": "Dependency file modified — review for new/changed packages",
            "snippet": "",
        })

    # Docker image changes
    if filepath.endswith("Dockerfile") or filepath.endswith("docker-compose.yml"):
        if "FROM " in content or "image:" in content:
            findings.append({
                "severity": "INFO",
                "category": "SupplyChain",
                "file": filepath,
                "line": 0,
                "finding": "Docker image reference modified — verify image source",
                "snippet": "",
            })

    # GitHub Actions
    if ".github/workflows" in filepath:
        findings.append({
            "severity": "WARN",
            "category": "SupplyChain",
            "file": filepath,
            "line": 0,
            "finding": "GitHub Actions workflow modified — runs with repo secrets, review carefully",
            "snippet": "",
        })

    # MCP config changes
    if "mcp" in filepath.lower() and filepath.endswith(".json"):
        findings.append({
            "severity": "WARN",
            "category": "SupplyChain",
            "file": filepath,
            "line": 0,
            "finding": "MCP server configuration changed — review for unauthorized tool access",
            "snippet": "",
        })

    return findings


def scan_pipeline_integrity(changed_files: list[str], pr_agent: str) -> list[dict]:
    """Verify no agent modified another agent's core logic."""
    findings = []

    agent_dirs = {
        "intel": "orchestration/agents/intel_agent.py",
        "red-team": "orchestration/agents/red_team_agent.py",
        "blue-team": "orchestration/agents/blue_team_agent.py",
        "quality": "orchestration/agents/quality_agent.py",
        "security": "orchestration/agents/security_agent.py",
    }

    for filepath in changed_files:
        normalized = filepath.replace("\\", "/")

        # Check if an agent modified another agent's code
        for agent_name, agent_path in agent_dirs.items():
            if agent_name != pr_agent and normalized.endswith(agent_path):
                findings.append({
                    "severity": "WARN",
                    "category": "PipelineIntegrity",
                    "file": filepath,
                    "line": 0,
                    "finding": f"Agent '{pr_agent}' modified '{agent_name}' agent code — cross-agent modification",
                    "snippet": "",
                })

        # Check if orchestration config was modified
        if normalized.endswith("orchestration/config.yml"):
            findings.append({
                "severity": "WARN",
                "category": "PipelineIntegrity",
                "file": filepath,
                "line": 0,
                "finding": "Orchestration config modified — check for disabled security or raised thresholds",
                "snippet": "",
            })

        # Check .gitignore changes
        if normalized.endswith(".gitignore"):
            findings.append({
                "severity": "INFO",
                "category": "PipelineIntegrity",
                "file": filepath,
                "line": 0,
                "finding": ".gitignore modified — verify .env, *.key, *.pem still excluded",
                "snippet": "",
            })

    return findings


def scan_pii(content: str, filepath: str) -> list[dict]:
    """Scan for PII or sensitive data in test cases / log samples."""
    findings = []
    lines = content.split("\n")

    checks = [
        # Real email addresses (not @example.com)
        (r'[a-zA-Z0-9._%+-]+@(?!example\.com|test\.com|localhost)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
         "INFO", "Possible real email address — use @example.com for test data"),
        # SSN pattern
        (r'\b\d{3}-\d{2}-\d{4}\b', "WARN", "Possible SSN pattern"),
        # Credit card patterns (basic)
        (r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)\d{12}\b', "WARN", "Possible credit card number"),
    ]

    # Only scan test/sample files for PII
    if not any(x in filepath.lower() for x in ["test", "sample", "fixture", "scenario"]):
        return findings

    for line_num, line in enumerate(lines, 1):
        for pattern, severity, description in checks:
            if re.search(pattern, line):
                findings.append({
                    "severity": severity,
                    "category": "PII",
                    "file": filepath,
                    "line": line_num,
                    "finding": description,
                    "snippet": line.strip()[:120],
                })
    return findings


# ─── PR Interaction ──────────────────────────────────────────────

def get_pr_changed_files(pr_number: int) -> list[dict]:
    """Fetch list of changed files from a PR via GitHub API."""
    token, repo = _load_github_config()
    if not token:
        print("  [security] No GitHub token found — cannot fetch PR files")
        return []

    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    })

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        print(f"  [security] Failed to fetch PR files: {e}")
        return []


def get_file_content_from_pr(pr_file: dict) -> str:
    """Get file content from a PR file entry. Falls back to local file."""
    filename = pr_file.get("filename", "")
    local_path = REPO_ROOT / filename
    if local_path.exists():
        return local_path.read_text(encoding="utf-8", errors="replace")
    return ""


def post_pr_comment(pr_number: int, body: str) -> bool:
    """Post a review comment on a PR."""
    token, repo = _load_github_config()
    if not token:
        print("  [security] No GitHub token — cannot post PR comment")
        return False

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
    })

    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status == 201
    except urllib.error.URLError as e:
        print(f"  [security] Failed to post PR comment: {e}")
        return False


# ─── Report Generation ───────────────────────────────────────────

def determine_verdict(findings: list[dict]) -> tuple[str, str]:
    """Determine overall scan verdict."""
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    warnings = [f for f in findings if f["severity"] == "WARN"]

    if critical:
        return "BLOCK", f"{len(critical)} critical finding(s) must be resolved before merge"
    elif warnings:
        return "WARN", f"{len(warnings)} warning(s) — review recommended"
    else:
        return "PASS", "No security issues found"


def generate_pr_comment(
    findings: list[dict],
    verdict: str,
    verdict_reason: str,
    files_scanned: int,
    pr_agent: str,
) -> str:
    """Generate structured PR comment."""
    severity_icons = {"CRITICAL": "🔴", "WARN": "🟡", "INFO": "🟢"}

    comment = f"""## Security Review — Agent PR Gate

**Scan status**: {verdict}
**Files scanned**: {files_scanned}
**Agent**: {pr_agent}

"""
    if findings:
        comment += "### Findings\n\n"
        comment += "| Severity | Category | File | Line | Finding |\n"
        comment += "|----------|----------|------|------|---------|\n"
        for f in findings:
            icon = severity_icons.get(f["severity"], "⚪")
            line_str = str(f["line"]) if f["line"] > 0 else "-"
            comment += (
                f"| {icon} {f['severity']} | {f['category']} | "
                f"{f['file']} | {line_str} | {f['finding']} |\n"
            )
    else:
        comment += "### Findings\n\nNo security issues detected.\n"

    comment += f"\n### Verdict\n\n**{verdict}**: {verdict_reason}\n"

    # Add recommendations for critical findings
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    if critical:
        comment += "\n### Recommendations\n\n"
        for f in critical:
            comment += f"- **{f['file']}:{f['line']}**: {f['finding']}\n"

    comment += f"\n---\n*Scanned by security agent on {_now_iso()}*\n"
    return comment


def log_findings(pr_number: int, agent: str, findings: list[dict]):
    """Append findings to the audit log."""
    SECURITY_DIR.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG, "a") as f:
        for finding in findings:
            entry = {
                "timestamp": _now_iso(),
                "pr_number": pr_number,
                "agent": agent,
                **finding,
                "resolved": False,
            }
            f.write(json.dumps(entry) + "\n")


# ─── Main Entry Point ────────────────────────────────────────────

def run(state_manager: StateManager, pr_number: int = None) -> dict:
    """
    Main entry point for the security agent.

    1. Load briefing + scan patterns
    2. Fetch PR changed files
    3. Run all scan categories on each file
    4. Determine verdict
    5. Post PR comment with findings
    6. Log findings to audit trail
    """
    if pr_number is None:
        print("  [security] No PR number provided — nothing to scan")
        return {"summary": "No PR to scan", "findings": [], "block": False}

    print(f"  [security] Starting security review of PR #{pr_number}")

    # 1. Load briefing
    briefing = learnings.get_briefing(AGENT_NAME)
    print(f"  [security] {briefing}")

    scan_config = _load_scan_patterns()
    custom_secret_patterns = []
    for p in scan_config.get("secret_patterns", []):
        custom_secret_patterns.append((p["regex"], p["description"]))
    secret_patterns = custom_secret_patterns or DEFAULT_SECRET_PATTERNS

    # 2. Fetch PR changed files
    pr_files = get_pr_changed_files(pr_number)
    if not pr_files:
        print("  [security] No changed files found (or API error)")
        return {"summary": f"PR #{pr_number} — no files to scan", "findings": [], "block": False}

    filenames = [f.get("filename", "") for f in pr_files]
    print(f"  [security] Scanning {len(filenames)} changed files")

    # Detect which agent created this PR (from branch name)
    pr_agent = "unknown"
    for name in ["intel", "red-team", "blue-team", "quality", "security"]:
        if any(name in fn for fn in filenames):
            pr_agent = name
            break

    # 3. Run all scans
    all_findings = []

    for pr_file in pr_files:
        filepath = pr_file.get("filename", "")
        status = pr_file.get("status", "")

        # Skip deleted files
        if status == "removed":
            continue

        content = get_file_content_from_pr(pr_file)
        if not content:
            continue

        # Run each scanner
        all_findings.extend(scan_secrets(content, filepath, secret_patterns))
        all_findings.extend(scan_code_security(content, filepath))
        all_findings.extend(scan_detection_rules(content, filepath))
        all_findings.extend(scan_supply_chain(content, filepath))
        all_findings.extend(scan_pii(content, filepath))

    # Pipeline integrity check (uses file list, not content)
    all_findings.extend(scan_pipeline_integrity(filenames, pr_agent))

    # 4. Determine verdict
    verdict, verdict_reason = determine_verdict(all_findings)

    # Summary
    by_severity = {}
    for f in all_findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    print(f"  [security] Scan complete: {verdict}")
    print(f"    Files scanned: {len(pr_files)}")
    print(f"    Findings: {len(all_findings)} "
          f"(CRITICAL: {by_severity.get('CRITICAL', 0)}, "
          f"WARN: {by_severity.get('WARN', 0)}, "
          f"INFO: {by_severity.get('INFO', 0)})")

    for f in all_findings:
        print(f"    [{f['severity']}] {f['file']}:{f['line']} — {f['finding']}")

    # 5. Post PR comment
    comment = generate_pr_comment(all_findings, verdict, verdict_reason, len(pr_files), pr_agent)
    if post_pr_comment(pr_number, comment):
        print(f"  [security] Posted review comment on PR #{pr_number}")
    else:
        print(f"  [security] Could not post comment (dry-run or API error)")

    # 6. Log findings
    if all_findings:
        log_findings(pr_number, pr_agent, all_findings)
        print(f"  [security] Logged {len(all_findings)} findings to audit log")

    summary = (
        f"PR #{pr_number}: {verdict} — "
        f"{len(all_findings)} findings across {len(pr_files)} files"
    )
    print(f"  [security] {summary}")

    return {
        "summary": summary,
        "findings": all_findings,
        "block": verdict == "BLOCK",
        "verdict": verdict,
        "files_scanned": len(pr_files),
    }
