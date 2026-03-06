"""
Intel Agent — Searches for threat intelligence, extracts TTPs,
and creates structured detection requests.

Called by agent_runner.py. Implements run(state_manager) interface.

Design: This agent is meant to be run by Claude in a session. The Python
code provides the workflow skeleton and helper functions. Claude uses its
web search and analysis capabilities to fill in the actual intel data.

For autonomous (non-interactive) mode, the agent can also process
pre-downloaded reports from threat-intel/reports/.
"""

import datetime
import re
from pathlib import Path

import yaml

from orchestration.state import StateManager
from orchestration import learnings

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
REPORTS_DIR = REPO_ROOT / "threat-intel" / "reports"
DIGEST_PATH = REPO_ROOT / "threat-intel" / "digest.md"
FAWKES_TTP_PATH = REPO_ROOT / "threat-intel" / "fawkes" / "fawkes-ttp-mapping.md"

AGENT_NAME = "intel"
MAX_REPORTS = 5

# Search query templates — {month} and {year} are filled at runtime
SEARCH_QUERIES = [
    "threat actor TTPs {month} {year}",
    "MITRE ATT&CK technique used in the wild {month} {year}",
    "malware analysis report {month} {year}",
    "CISA advisory {month} {year}",
    "detection engineering blog {month} {year}",
]

PRIORITY_SOURCES = [
    "cisa.gov",
    "mandiant.com",
    "cloud.google.com/blog/topics/threat-intelligence",
    "crowdstrike.com",
    "microsoft.com/en-us/security/blog",
    "unit42.paloaltonetworks.com",
    "redcanary.com/blog",
    "elastic.co/security-labs",
    "research.splunk.com",
    "thedfirreport.com",
]


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _current_month_year() -> tuple[str, str]:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%B"), str(now.year)


def load_fawkes_techniques() -> dict[str, dict]:
    """
    Parse the Fawkes TTP mapping markdown and return a dict of
    technique_id -> {commands: [...], priority: str, description: str}
    """
    if not FAWKES_TTP_PATH.exists():
        return {}

    content = FAWKES_TTP_PATH.read_text(encoding="utf-8")
    techniques = {}

    # Parse markdown tables: | command | technique | sub-technique | description | ...
    for line in content.split("\n"):
        line = line.strip()
        if not line.startswith("|") or line.startswith("|---") or "Fawkes Command" in line:
            continue

        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) < 6:
            continue

        command = cells[0].strip("`").strip()
        technique = cells[1].strip()
        sub_technique = cells[2].strip()
        description = cells[3].strip()
        priority = cells[5].strip() if len(cells) > 5 else "Medium"

        # Build technique ID
        tid = sub_technique if sub_technique and sub_technique != "—" else technique
        if not tid.startswith("T"):
            continue

        if tid not in techniques:
            techniques[tid] = {
                "commands": [],
                "priority": priority,
                "description": description,
            }
        techniques[tid]["commands"].append(command)

    return techniques


def get_existing_coverage(state_manager: StateManager) -> set[str]:
    """Return set of technique IDs that already have detections or requests."""
    existing = set()
    for req in state_manager.list_all():
        tid = req.get("technique_id", "")
        if tid:
            existing.add(tid)
    return existing


def get_search_queries() -> list[str]:
    """Generate current search queries with month/year filled in."""
    month, year = _current_month_year()
    return [q.format(month=month, year=year) for q in SEARCH_QUERIES]


def is_priority_source(url: str) -> bool:
    """Check if a URL is from a priority source."""
    return any(source in url.lower() for source in PRIORITY_SOURCES)


def create_intel_report(
    title: str,
    source_url: str,
    date_published: str,
    threat_actors: list[str],
    platforms: list[str],
    techniques: list[dict],
    iocs: list[dict],
    raw_summary: str,
) -> Path:
    """
    Write a structured intel report YAML file.

    techniques should be a list of dicts with keys:
      id, name, description, data_sources_needed, detection_opportunity, priority

    Returns the path to the created file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Generate filename from date and title
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower())[:50].strip("-")
    filename = f"{_today()}-{slug}.yml"
    path = REPORTS_DIR / filename

    report = {
        "title": title,
        "source": source_url,
        "date_published": date_published,
        "date_ingested": _today(),
        "threat_actors": threat_actors,
        "platforms": platforms,
        "techniques": techniques,
        "iocs": iocs,
        "raw_summary": raw_summary,
    }

    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(report, f, default_flow_style=False, sort_keys=False, width=120)

    return path


def process_techniques(
    state_manager: StateManager,
    techniques: list[dict],
    intel_report_path: str,
    fawkes_map: dict[str, dict],
    existing: set[str],
) -> dict:
    """
    Process extracted techniques: create detection requests for new ones,
    cross-reference with Fawkes, skip already-covered ones.

    Returns stats dict.
    """
    stats = {
        "new_techniques": 0,
        "requests_created": [],
        "skipped_existing": 0,
        "fawkes_overlap": 0,
    }

    for tech in techniques:
        tid = tech.get("id", "")
        if not tid:
            continue

        if tid in existing:
            stats["skipped_existing"] += 1
            continue

        # Determine priority — bump to critical if Fawkes uses it
        priority = tech.get("priority", "medium").lower()
        fawkes_info = fawkes_map.get(tid)
        if fawkes_info:
            priority = "critical"
            stats["fawkes_overlap"] += 1

        try:
            state_manager.create(
                technique_id=tid,
                title=tech.get("name", f"Detection for {tid}"),
                priority=priority,
                intel_report=str(intel_report_path),
                requested_by=AGENT_NAME,
            )
            # If we have Fawkes commands, update the request
            if fawkes_info:
                state_manager.update(
                    tid, agent=AGENT_NAME,
                    fawkes_commands=fawkes_info["commands"],
                )
            existing.add(tid)
            stats["new_techniques"] += 1
            stats["requests_created"].append(tid)
            print(f"    [intel] Created request: {tid} — {tech.get('name','')} "
                  f"(priority: {priority})")
        except ValueError as e:
            print(f"    [intel] Skipped {tid}: {e}")

    return stats


def update_digest(reports_processed: list[dict], run_stats: dict):
    """
    Append to the running weekly digest at threat-intel/digest.md.
    """
    DIGEST_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = f"""
## Intel Run — {_today()}

**Reports processed**: {len(reports_processed)}
**New techniques found**: {run_stats.get('total_new', 0)}
**Detection requests created**: {run_stats.get('total_requests', 0)}
**Techniques skipped (existing)**: {run_stats.get('total_skipped', 0)}
**Fawkes overlap**: {run_stats.get('total_fawkes', 0)}

### Reports
"""
    for r in reports_processed:
        entry += f"- [{r.get('title', '?')}]({r.get('source', '')}) — "
        tech_count = len(r.get("techniques", []))
        entry += f"{tech_count} techniques\n"

    entry += "\n---\n"

    # Append or create
    if DIGEST_PATH.exists():
        existing = DIGEST_PATH.read_text(encoding="utf-8")
        content = existing + "\n" + entry
    else:
        content = "# Threat Intelligence Digest\n\n" + entry

    DIGEST_PATH.write_text(content, encoding="utf-8")


def run(state_manager: StateManager) -> dict:
    """
    Main entry point for the intel agent.

    When run by Claude in a session, Claude will:
    1. Call get_search_queries() to get the search terms
    2. Use WebSearch/WebFetch to find and read reports
    3. Call create_intel_report() for each report
    4. Call process_techniques() to create detection requests
    5. Call update_digest() to update the running digest

    When run standalone (no web search), processes any reports
    already in threat-intel/reports/ that haven't been ingested.
    """
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"  [intel] Starting intel agent run {run_id}")

    # 1. Load briefing
    briefing = learnings.get_briefing(AGENT_NAME)
    print(f"  [intel] {briefing}")

    # Check for past lessons about search/parsing
    search_lessons = learnings.get_relevant_lessons(AGENT_NAME, "search")
    parsing_lessons = learnings.get_relevant_lessons(AGENT_NAME, "parsing")
    if search_lessons:
        print(f"  [intel] {len(search_lessons)} search lessons loaded")
    if parsing_lessons:
        print(f"  [intel] {len(parsing_lessons)} parsing lessons loaded")

    # 2. Load Fawkes TTP mapping for cross-reference
    fawkes_map = load_fawkes_techniques()
    print(f"  [intel] Loaded {len(fawkes_map)} Fawkes technique mappings")

    # 3. Get existing coverage
    existing = get_existing_coverage(state_manager)
    print(f"  [intel] {len(existing)} techniques already have requests/detections")

    # 4. Generate search queries for this run
    queries = get_search_queries()
    print(f"  [intel] Search queries for this run:")
    for q in queries:
        print(f"    - {q}")

    # 5. Process any existing unprocessed reports
    reports_processed = []
    total_stats = {
        "total_new": 0,
        "total_requests": 0,
        "total_skipped": 0,
        "total_fawkes": 0,
    }

    existing_reports = sorted(REPORTS_DIR.glob("*.yml"))
    for report_path in existing_reports[:MAX_REPORTS]:
        try:
            with open(report_path, encoding="utf-8") as f:
                report = yaml.safe_load(f)
            if not report or not report.get("techniques"):
                continue

            print(f"\n  [intel] Processing: {report.get('title', report_path.name)}")
            stats = process_techniques(
                state_manager,
                report["techniques"],
                str(report_path.relative_to(REPO_ROOT)),
                fawkes_map,
                existing,
            )

            total_stats["total_new"] += stats["new_techniques"]
            total_stats["total_requests"] += len(stats["requests_created"])
            total_stats["total_skipped"] += stats["skipped_existing"]
            total_stats["total_fawkes"] += stats["fawkes_overlap"]

            reports_processed.append(report)
        except Exception as e:
            print(f"  [intel] Error processing {report_path.name}: {e}")
            learnings.record(
                AGENT_NAME, run_id, "error", "parsing",
                f"Failed to parse report: {report_path.name}",
                str(e),
            )

    # 6. Update digest
    if reports_processed:
        update_digest(reports_processed, total_stats)
        print(f"\n  [intel] Updated digest at {DIGEST_PATH}")

    # 7. Summary
    summary = (
        f"Processed {len(reports_processed)} reports, "
        f"created {total_stats['total_requests']} detection requests, "
        f"found {total_stats['total_fawkes']} Fawkes overlaps"
    )
    print(f"\n  [intel] {summary}")

    return {
        "summary": summary,
        "reports_processed": len(reports_processed),
        "techniques_found": total_stats["total_new"],
        "requests_created": total_stats["total_requests"],
        "requests_list": [],
        "skipped_existing": total_stats["total_skipped"],
        "fawkes_overlap": total_stats["total_fawkes"],
        "search_queries_used": queries,
    }
