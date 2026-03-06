"""
Self-Improvement Module for Patronus Agents

Each agent maintains a JSONL journal in learnings/<agent>.jsonl.
Entries track errors, inefficiencies, workarounds, and improvement ideas
discovered during runs, so future runs avoid repeating mistakes.
"""

import json
import datetime
from pathlib import Path
from typing import Optional

LEARNINGS_DIR = Path(__file__).resolve().parent.parent / "learnings"


def _journal_path(agent: str) -> Path:
    return LEARNINGS_DIR / f"{agent}.jsonl"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_journal(agent: str) -> list[dict]:
    path = _journal_path(agent)
    if not path.exists():
        return []
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def record(agent: str, run_id: str, entry_type: str, category: str,
           title: str, description: str, technique_id: str = "",
           resolved: bool = False, tags: Optional[list[str]] = None):
    """
    Append a learning entry to the agent's journal.

    entry_type: error | inefficiency | workaround | improvement | insight | resolved
    category: search | parsing | detection | deployment | validation | tuning | schema | general
    """
    LEARNINGS_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": _now_iso(),
        "agent": agent,
        "run_id": run_id,
        "type": entry_type,
        "category": category,
        "title": title,
        "description": description,
        "technique_id": technique_id,
        "resolved": resolved,
        "tags": tags or [],
    }
    with open(_journal_path(agent), "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def get_relevant_lessons(agent: str, category: str,
                         technique_id: Optional[str] = None,
                         max_entries: int = 10) -> list[dict]:
    """
    Return the most relevant past lessons for the current task.
    Filters by category, optionally by technique, prefers unresolved and recent.
    """
    entries = _read_journal(agent)

    # Filter by category
    filtered = [e for e in entries if e.get("category") == category]

    # If technique specified, boost matching entries
    if technique_id:
        technique_matches = [e for e in filtered if e.get("technique_id") == technique_id]
        others = [e for e in filtered if e.get("technique_id") != technique_id]
        filtered = technique_matches + others

    # Prioritize unresolved entries
    unresolved = [e for e in filtered if not e.get("resolved")]
    resolved = [e for e in filtered if e.get("resolved")]
    ranked = unresolved + resolved

    return ranked[:max_entries]


def get_briefing(agent: str, max_entries: int = 5) -> str:
    """
    Condensed summary of top open lessons for this agent.
    Injected at the START of every agent run.
    """
    entries = _read_journal(agent)
    unresolved = [e for e in entries if not e.get("resolved")]

    if not unresolved:
        return f"No open lessons for {agent}. Clean slate."

    # Take most recent unresolved entries
    recent = unresolved[-max_entries:]

    lines = [f"## Agent Briefing — {agent}", f"Open lessons ({len(unresolved)} total):\n"]
    for e in recent:
        prefix = f"[{e.get('type', '?').upper()}]"
        tech = f" ({e['technique_id']})" if e.get("technique_id") else ""
        lines.append(f"- {prefix} {e['title']}{tech}: {e['description']}")

    return "\n".join(lines)


def get_retrospective_prompt(agent: str, run_id: str) -> str:
    """
    Prompt string injected at the END of every agent session.
    """
    return f"""
## Retrospective — {agent} run {run_id}

Before finishing, review what happened this run. Record any errors,
inefficiencies, workarounds, or improvement ideas to learnings/{agent}.jsonl
using the learnings module.

Check:
- Did anything fail that shouldn't have?
- Did you waste tokens on something you could have avoided?
- Did you discover a better approach for future runs?
- Did you resolve a previously open issue? If so, record it as resolved.
- Any data source gaps or schema mismatches discovered?

Use: learnings.record("{agent}", "{run_id}", type, category, title, description)
""".strip()


def mark_resolved(agent: str, title: str, resolution: str = ""):
    """
    Mark a learning entry as resolved by title match.
    Rewrites the journal file with the entry updated.
    """
    entries = _read_journal(agent)
    updated = False
    for e in entries:
        if e.get("title") == title and not e.get("resolved"):
            e["resolved"] = True
            e["resolution"] = resolution
            e["resolved_date"] = _now_iso()
            updated = True
            break

    if updated:
        path = _journal_path(agent)
        with open(path, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
    return updated
