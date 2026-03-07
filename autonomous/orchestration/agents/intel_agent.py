"""
Intel Agent — Searches for threat intelligence, extracts TTPs,
and creates structured detection requests.

Called by agent_runner.py. Implements run(state_manager) interface.

When Claude CLI is available (standalone terminal, not CI or nested session):
  1. Uses WebSearch/WebFetch tools to find new threat reports
  2. Extracts MITRE ATT&CK techniques from report content
  3. Creates structured YAML reports and detection requests

Fallback (CI, nested session, or CLI unavailable):
  Processes pre-downloaded reports from threat-intel/reports/.
"""

import datetime
import json
import re
from pathlib import Path

import yaml

from orchestration.state import StateManager
from orchestration import learnings
from orchestration import claude_llm

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


def search_web_for_intel(
    queries: list[str],
    existing_techniques: set[str],
    max_reports: int = 3,
) -> list[dict]:
    """
    Use Claude CLI with WebSearch/WebFetch to find new threat intel.

    Sends search queries to Claude, which searches the web, reads reports,
    and returns structured technique data as JSON.

    Returns a list of report dicts, each with keys:
      title, source, date_published, threat_actors, platforms, techniques, raw_summary
    """
    if not claude_llm.is_available():
        print("  [intel] Claude CLI not available — skipping web search")
        return []

    already_covered = ", ".join(sorted(existing_techniques)[:20])
    priority_sites = ", ".join(PRIORITY_SOURCES[:5])

    system_prompt = (
        "You are a threat intelligence analyst. You have access to curl via "
        "the Bash tool. Use curl to fetch web pages from threat intelligence "
        "sources. Focus on reports that describe specific MITRE ATT&CK techniques. "
        "Prefer reports from reputable sources like CISA, Mandiant, CrowdStrike, "
        "Microsoft, Unit42, Red Canary, Elastic Security Labs, and The DFIR Report. "
        "After fetching and reading reports, return your findings as a JSON array — "
        "no markdown, no explanation."
    )

    # Build a combined prompt with all queries
    queries_block = "\n".join(f"- {q}" for q in queries[:3])

    prompt = f"""Fetch recent threat intelligence reports using curl. Try these sources:
- https://www.cisa.gov/news-events/cybersecurity-advisories
- https://cloud.google.com/blog/topics/threat-intelligence
- https://unit42.paloaltonetworks.com/category/threat-research/
- https://www.microsoft.com/en-us/security/blog/
- https://thedfirreport.com/

Use curl to fetch pages and extract threat report content. For example:
  curl -sL "https://www.cisa.gov/news-events/cybersecurity-advisories" | head -500

Search context (topics of interest):
{queries_block}

Find up to {max_reports} recent threat reports (published in the last 60 days).

We already have detections for these techniques (skip them): {already_covered}

For each report found, extract:
1. The report title
2. Source URL
3. Date published
4. Threat actors mentioned
5. Target platforms (Windows, Linux, macOS, Cloud)
6. MITRE ATT&CK techniques used (ID, name, brief description, priority)
7. A 2-3 sentence summary

After gathering data, return ONLY a JSON array with this exact schema:
[{{
  "title": "Report Title",
  "source": "https://...",
  "date_published": "2026-03-01",
  "threat_actors": ["Actor Name"],
  "platforms": ["Windows"],
  "techniques": [
    {{"id": "T1059.001", "name": "PowerShell", "description": "Used PowerShell for execution", "priority": "high"}}
  ],
  "raw_summary": "Brief summary of the report..."
}}]

Your FINAL output must be ONLY valid JSON. No markdown fences, no commentary."""

    print(f"  [intel] Sending web search request to Claude CLI...")
    result = claude_llm.ask_with_web_search(
        prompt=prompt,
        agent_name="intel",
        system_prompt=system_prompt,
        timeout_seconds=180,
    )

    if not result["success"]:
        print(f"  [intel] Web search failed: {result.get('error', 'unknown')}")
        return []

    # Parse response
    response = result["response"].strip()
    # Strip markdown fences if present
    if response.startswith("```"):
        lines = response.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        response = "\n".join(lines)

    try:
        reports = json.loads(response)
        if not isinstance(reports, list):
            print(f"  [intel] Claude returned non-array JSON, wrapping")
            reports = [reports]
        print(f"  [intel] Claude found {len(reports)} reports via web search")
        return reports[:max_reports]
    except json.JSONDecodeError as e:
        print(f"  [intel] Failed to parse Claude web search response: {e}")
        print(f"  [intel] Raw response (first 500 chars): {response[:500]}")
        return []


def run(state_manager: StateManager) -> dict:
    """
    Main entry point for the intel agent.

    Flow:
    1. Load briefing, lessons, Fawkes mappings, existing coverage
    2. Generate search queries for current month
    3. If Claude CLI available: search web for new threat reports
    4. Save web reports as YAML files in threat-intel/reports/
    5. Process all reports (existing + new) — create detection requests
    6. Update digest
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

    # 5. Web search for new intel (if Claude CLI available)
    reports_processed = []
    total_stats = {
        "total_new": 0,
        "total_requests": 0,
        "total_skipped": 0,
        "total_fawkes": 0,
    }

    web_reports = search_web_for_intel(queries, existing, max_reports=3)
    for web_report in web_reports:
        try:
            title = web_report.get("title", "Untitled Report")
            print(f"\n  [intel] Saving web report: {title}")
            report_path = create_intel_report(
                title=title,
                source_url=web_report.get("source", ""),
                date_published=web_report.get("date_published", _today()),
                threat_actors=web_report.get("threat_actors", []),
                platforms=web_report.get("platforms", []),
                techniques=web_report.get("techniques", []),
                iocs=web_report.get("iocs", []),
                raw_summary=web_report.get("raw_summary", ""),
            )
            print(f"    [intel] Saved to {report_path.name}")
        except Exception as e:
            print(f"  [intel] Error saving web report: {e}")
            learnings.record(
                AGENT_NAME, run_id, "error", "web_search",
                f"Failed to save web report: {web_report.get('title', '?')}",
                str(e),
            )

    # 6. Process all reports (existing + newly downloaded)
    existing_reports = sorted(REPORTS_DIR.glob("*.yml"))
    for report_path in existing_reports[:MAX_REPORTS]:
        try:
            with open(report_path, encoding="utf-8") as f:
                report = yaml.safe_load(f)
            if not report or not report.get("techniques"):
                continue

            print(f"\n  [intel] Processing: {report.get('title', report_path.name)}")

            # If report has raw_summary but few techniques, ask Claude to extract more
            raw_summary = report.get("raw_summary", "")
            if claude_llm.is_available() and raw_summary and len(report.get("techniques", [])) < 3:
                print(f"    [intel] Asking Claude (sonnet) to extract techniques from report...")
                llm_result = claude_llm.ask_for_analysis(
                    question=(
                        "Extract MITRE ATT&CK technique IDs from this threat report summary. "
                        "Return ONLY a JSON array of objects with keys: id, name, description, priority. "
                        "Example: [{\"id\": \"T1059.001\", \"name\": \"PowerShell\", "
                        "\"description\": \"Uses PowerShell for execution\", \"priority\": \"high\"}]"
                    ),
                    context=raw_summary[:3000],
                    agent_name="intel",
                )
                if llm_result["success"]:
                    try:
                        extracted = json.loads(llm_result["response"])
                        if isinstance(extracted, list):
                            # Merge with existing, dedup by ID
                            existing_ids = {t["id"] for t in report.get("techniques", []) if "id" in t}
                            new_techs = [t for t in extracted if t.get("id") and t["id"] not in existing_ids]
                            report["techniques"].extend(new_techs)
                            if new_techs:
                                print(f"    [intel] Claude extracted {len(new_techs)} additional techniques")
                    except (json.JSONDecodeError, TypeError):
                        print(f"    [intel] Claude response was not valid JSON, skipping")

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

    # 7. Update digest
    if reports_processed:
        update_digest(reports_processed, total_stats)
        print(f"\n  [intel] Updated digest at {DIGEST_PATH}")

    # 8. Summary
    summary = (
        f"Processed {len(reports_processed)} reports "
        f"({len(web_reports)} from web search), "
        f"created {total_stats['total_requests']} detection requests, "
        f"found {total_stats['total_fawkes']} Fawkes overlaps"
    )
    print(f"\n  [intel] {summary}")

    return {
        "summary": summary,
        "reports_processed": len(reports_processed),
        "web_reports_found": len(web_reports),
        "techniques_found": total_stats["total_new"],
        "requests_created": total_stats["total_requests"],
        "requests_list": [],
        "skipped_existing": total_stats["total_skipped"],
        "fawkes_overlap": total_stats["total_fawkes"],
        "search_queries_used": queries,
    }
