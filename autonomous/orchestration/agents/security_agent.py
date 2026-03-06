"""
Security Agent — Reviews every agent PR before human merge.
Scans for credential leaks, overly broad queries, dangerous
exclusions, and other security issues.

Called by agent_runner.py. Implements run(state_manager, pr_number) interface.
"""

from orchestration.state import StateManager


def run(state_manager: StateManager, pr_number: int = None) -> dict:
    """
    Main entry point for the security agent.

    TODO (Phase 5):
    - Fetch PR diff via GitHub API
    - Scan for credential patterns (API keys, passwords, tokens)
    - Check Sigma rules for overly broad detection logic
    - Verify no more than 3 exclusions per rule (guardrail)
    - Check for dangerous Cribl drop rules
    - Post review comment on PR with findings
    """
    print(f"  [security] Agent stub — PR #{pr_number} (not yet implemented)")
    return {
        "summary": f"Security review of PR #{pr_number} (no-op)",
        "findings": [],
        "block": False,
    }
