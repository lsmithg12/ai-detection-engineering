"""
Intel Agent — Searches for threat intelligence, extracts TTPs,
and creates structured detection requests.

Called by agent_runner.py. Implements run(state_manager) interface.
"""

from orchestration.state import StateManager


def run(state_manager: StateManager) -> dict:
    """
    Main entry point for the intel agent.

    TODO (Phase 2):
    - Search for recent threat intel reports
    - Extract techniques, platforms, data sources
    - Create detection requests for new techniques
    - Cross-reference with Fawkes capabilities
    - Update threat-intel/digest.md
    """
    print("  [intel] Agent stub — not yet implemented.")
    return {
        "summary": "Intel agent stub executed (no-op)",
        "reports_processed": 0,
        "techniques_found": 0,
        "requests_created": 0,
    }
