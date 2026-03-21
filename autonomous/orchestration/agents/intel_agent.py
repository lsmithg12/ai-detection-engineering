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
import urllib.request
import urllib.error
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

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

MODELS_DIR = REPO_ROOT / "threat-intel" / "models"

# Search query templates — {month} and {year} are filled at runtime
# ISSUE-004: Reduced from 5 to 3 queries to stay within budget
SEARCH_QUERIES = [
    "threat actor TTPs {month} {year}",
    "MITRE ATT&CK technique used in the wild {month} {year}",
    "CISA advisory {month} {year}",
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

# Index pages to scrape for recent threat reports (ordered by report richness)
INTEL_INDEX_URLS = [
    "https://thedfirreport.com/",              # Best: full ATT&CK-mapped intrusion reports
    "https://elastic.co/security-labs",         # Good: detection-focused research
    "https://www.cisa.gov/news-events/cybersecurity-advisories",  # Mostly KEV alerts, fewer TTPs
]


class _HTMLTextExtractor(HTMLParser):
    """Extract readable text and links from HTML."""

    def __init__(self):
        super().__init__()
        self._parts: list[str] = []
        self._links: list[dict] = []
        self._skip = False
        self._href: str | None = None

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "nav", "footer", "noscript"):
            self._skip = True
        if tag == "a":
            for name, val in attrs:
                if name == "href" and val:
                    self._href = val

    def handle_endtag(self, tag):
        if tag in ("script", "style", "nav", "footer", "noscript"):
            self._skip = False
        if tag == "a":
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        text = data.strip()
        if text:
            self._parts.append(text)
            if self._href:
                self._links.append({"text": text, "href": self._href})

    def get_text(self) -> str:
        return " ".join(self._parts)

    def get_links(self) -> list[dict]:
        return self._links


def _fetch_page(url: str, max_bytes: int = 300_000, timeout: int = 30) -> dict | None:
    """Fetch a URL with Python urllib. Returns {text, links, url} or None."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes).decode("utf-8", errors="replace")
        parser = _HTMLTextExtractor()
        parser.feed(raw)
        text = re.sub(r"\s+", " ", parser.get_text()).strip()
        # Resolve relative URLs
        links = []
        for link in parser.get_links():
            href = link["href"]
            if href.startswith("#"):
                continue
            links.append({"text": link["text"], "href": urljoin(url, href)})
        return {"text": text[:15000], "links": links, "url": url}
    except Exception as e:
        print(f"    [intel] Fetch failed ({url}): {e}")
        return None


def _strip_markdown_fences(text: str) -> str:
    """Extract JSON content from Claude responses, handling fences and trailing text."""
    text = text.strip()
    # If wrapped in markdown fences, extract just the fenced block
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove opening fence line (```json, ```, etc.)
        lines = lines[1:]
        # Find closing fence and discard everything after it
        for i, line in enumerate(lines):
            if line.strip() == "```":
                lines = lines[:i]
                break
        text = "\n".join(lines)
    # If response starts with JSON, trim any trailing non-JSON text
    text = text.strip()
    if text.startswith("[") or text.startswith("{"):
        bracket = "]" if text.startswith("[") else "}"
        depth = 0
        for i, ch in enumerate(text):
            if ch in ("[", "{"):
                depth += 1
            elif ch in ("]", "}"):
                depth -= 1
                if depth == 0:
                    text = text[:i + 1]
                    break
    return text.strip()


# Data source requirements per technique category
# Maps MITRE technique prefixes to the data sources they need
TECHNIQUE_DATA_SOURCES = {
    "T1055": [{"source": "sysmon", "event_ids": [8, 10], "fields": ["process.executable", "winlog.event_data.TargetImage"]}],
    "T1053": [{"source": "sysmon", "event_ids": [1], "fields": ["process.name", "process.command_line"]}],
    "T1059": [{"source": "sysmon", "event_ids": [1], "fields": ["process.name", "process.command_line"]},
              {"source": "windows_security", "event_ids": [4104], "fields": ["powershell.file.script_block_text"]}],
    "T1547": [{"source": "sysmon", "event_ids": [13], "fields": ["registry.path", "registry.value"]},
              {"source": "sysmon", "event_ids": [11], "fields": ["file.path", "file.name"]}],
    "T1543": [{"source": "windows_system", "event_ids": [7045], "fields": ["winlog.event_data.ServiceName", "winlog.event_data.ImagePath"]}],
    "T1070": [{"source": "sysmon", "event_ids": [1], "fields": ["process.name", "process.command_line"]}],
    "T1071": [{"source": "sysmon", "event_ids": [3, 22], "fields": ["destination.ip", "destination.port", "dns.question.name"]}],
    "T1562": [{"source": "sysmon", "event_ids": [7], "fields": ["file.name", "process.executable"]}],
    "T1047": [{"source": "sysmon", "event_ids": [19, 20, 21], "fields": ["wmi.filter.name", "wmi.filter.query"]}],
    "T1046": [{"source": "sysmon", "event_ids": [3], "fields": ["destination.ip", "destination.port"]}],
    "T1027": [{"source": "sysmon", "event_ids": [1, 11], "fields": ["file.path", "process.command_line"]}],
    "T1134": [{"source": "sysmon", "event_ids": [10, 17, 18], "fields": ["winlog.event_data.TargetImage"]}],
    "T1056": [{"source": "elastic_endpoint", "event_ids": [], "fields": ["process.Ext.api.name"]}],
}


def get_data_source_requirements(technique_id: str) -> list[dict]:
    """Look up data source requirements for a technique."""
    # Try exact match first, then prefix match
    if technique_id in TECHNIQUE_DATA_SOURCES:
        return TECHNIQUE_DATA_SOURCES[technique_id]
    # Try parent technique (e.g., T1055.001 -> T1055)
    parent = technique_id.split(".")[0]
    if parent in TECHNIQUE_DATA_SOURCES:
        return TECHNIQUE_DATA_SOURCES[parent]
    return []


def check_data_source_gaps(technique_id: str) -> list[str]:
    """Check if any required data sources have known gaps.

    Reads YAML files from gaps/data-sources/ and returns list of gap IDs
    that affect the given technique.
    """
    gaps_dir = REPO_ROOT / "gaps" / "data-sources"
    if not gaps_dir.exists():
        return []

    matching_gaps = []
    for gap_file in gaps_dir.glob("*.yml"):
        try:
            with open(gap_file, encoding="utf-8") as f:
                gap = yaml.safe_load(f)
            if not gap:
                continue
            affected = gap.get("affected_techniques", [])
            # Check if this technique (or its parent) is affected
            if technique_id in affected:
                matching_gaps.append(gap.get("gap_id", gap_file.stem))
            elif technique_id.split(".")[0] in [t.split(".")[0] for t in affected]:
                matching_gaps.append(gap.get("gap_id", gap_file.stem))
        except Exception:
            continue
    return matching_gaps


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _current_month_year() -> tuple[str, str]:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%B"), str(now.year)


def load_threat_model_registry() -> dict[str, list[str]]:
    """Load all threat models from threat-intel/models/ and return a reverse index.

    Returns: {technique_id -> [model_name, ...]}
    Allows process_techniques() to tag which threat actors use each technique.
    """
    if not MODELS_DIR.exists():
        return {}

    technique_to_actors: dict[str, list[str]] = {}
    for path in sorted(MODELS_DIR.glob("*.yml")):
        if path.name == "schema.yml":
            continue
        try:
            with open(path, encoding="utf-8") as f:
                model = yaml.safe_load(f)
            if not model or "techniques" not in model:
                continue
            actor_name = model.get("name", path.stem)
            for tid in model["techniques"]:
                technique_to_actors.setdefault(tid, []).append(actor_name)
        except Exception as e:
            print(f"  [intel] Warning: could not load model {path.name}: {e}")

    print(f"  [intel] Registry: {len(technique_to_actors)} techniques across "
          f"{sum(1 for p in MODELS_DIR.glob('*.yml') if p.name != 'schema.yml')} threat models")
    return technique_to_actors


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

        # Handle compound IDs like "T1087.001/002" — split into separate entries
        # T1087.001/002 -> [T1087.001, T1087.002]
        if "/" in tid:
            base = tid.split("/")[0]          # "T1087.001"
            prefix = base.rsplit(".", 1)[0]   # "T1087"
            suffixes = tid.split("/")         # ["T1087.001", "002"]
            tids = [base]
            for s in suffixes[1:]:
                tids.append(f"{prefix}.{s}")
        else:
            tids = [tid]

        for resolved_tid in tids:
            if resolved_tid not in techniques:
                techniques[resolved_tid] = {
                    "commands": [],
                    "priority": priority,
                    "description": description,
                }
            techniques[resolved_tid]["commands"].append(command)

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
    threat_actor_registry: dict[str, list[str]] | None = None,
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

        # Build threat_actors list from registry (all models that reference this technique)
        threat_actors: list[str] = []
        if threat_actor_registry:
            threat_actors = threat_actor_registry.get(tid, [])
        # Fawkes is always in scope even if not in registry yet
        if fawkes_info and "Fawkes C2 Agent" not in threat_actors:
            threat_actors.append("Fawkes C2 Agent")

        try:
            state_manager.create(
                technique_id=tid,
                title=tech.get("name", f"Detection for {tid}"),
                priority=priority,
                intel_report=str(intel_report_path),
                requested_by=AGENT_NAME,
            )
            # Tag threat actors and Fawkes commands
            state_manager.update(
                tid, agent=AGENT_NAME,
                threat_actors=threat_actors,
            )
            # If we have Fawkes commands, update the request
            if fawkes_info:
                state_manager.update(
                    tid, agent=AGENT_NAME,
                    fawkes_commands=fawkes_info["commands"],
                )
            # Tag data source requirements (Phase 3)
            ds_requirements = get_data_source_requirements(tid)
            ds_gaps = check_data_source_gaps(tid)
            if ds_requirements:
                state_manager.update(
                    tid, agent=AGENT_NAME,
                    data_source_requirements=ds_requirements,
                )
            if ds_gaps:
                state_manager.update(
                    tid, agent=AGENT_NAME,
                    data_source_gaps=ds_gaps,
                )
                print(f"    [intel] Warning: {tid} has data source gaps: {ds_gaps}")
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
    Fetch threat intel from the web using Python urllib + Claude analysis.

    Two-phase approach (replaces single Claude CLI + curl call):
      Phase 1: Python fetches index page, extracts text + links (no Claude)
      Phase 2: Claude picks best report URLs from links (pure reasoning)
      Phase 3: Python fetches each report page (no Claude)
      Phase 4: Claude extracts MITRE techniques from report text (pure reasoning)

    This is much more reliable than the old approach because:
      - No Bash(curl:*) tool restriction or max-turns issues
      - Claude only does analysis (what it's good at), not web fetching
      - Python urllib handles redirects, encoding, timeouts natively
    """
    # Phase 1: Fetch an index page with Python
    print("  [intel] Fetching threat intel index pages...")
    index_page = None
    for url in INTEL_INDEX_URLS:
        page = _fetch_page(url)
        if page and page["links"]:
            index_page = page
            print(f"    [intel] Fetched index: {url} ({len(page['links'])} links)")
            break
        elif page:
            print(f"    [intel] Fetched {url} but found no links")

    if not index_page:
        print("  [intel] Could not fetch any index pages — skipping web search")
        return []

    # Phase 2: Ask Claude to pick the best report links (pure reasoning)
    if not claude_llm.is_available():
        print("  [intel] Claude CLI not available — skipping link analysis")
        return []

    # Build a summary of links for Claude to choose from
    link_lines = []
    for link in index_page["links"][:100]:
        href = link["href"]
        if not href.startswith("http"):
            continue
        link_lines.append(f"- [{link['text'][:80]}]({href})")
    links_summary = "\n".join(link_lines)

    if not links_summary:
        print("  [intel] No usable links found on index page")
        return []

    queries_str = ", ".join(queries[:3])
    pick_result = claude_llm.ask_for_analysis(
        question=(
            f"Pick up to {max_reports} threat intelligence report links from this list. "
            f"Topics of interest: {queries_str}. "
            "Choose specific reports or advisories — NOT category pages, nav links, or tag pages. "
            "Return ONLY a JSON array: "
            '[{"title": "Report Title", "url": "https://..."}]'
        ),
        context=f"Links from {index_page['url']}:\n{links_summary}",
        agent_name="intel",
    )

    if not pick_result["success"]:
        print(f"  [intel] Claude failed to pick links: {pick_result.get('error')}")
        return []

    try:
        resp = _strip_markdown_fences(pick_result["response"])
        picked = json.loads(resp)
        if not isinstance(picked, list):
            picked = [picked]
    except json.JSONDecodeError:
        print(f"  [intel] Could not parse link selection: {pick_result['response'][:200]}")
        return []

    print(f"  [intel] Claude selected {len(picked)} reports to fetch")

    # Phase 3 + 4: Fetch each report and extract techniques
    already_covered = ", ".join(sorted(existing_techniques)[:20])
    reports = []

    for link in picked[:max_reports]:
        url = link.get("url", "")
        title = link.get("title", "Unknown Report")
        if not url:
            continue

        print(f"    [intel] Fetching: {title[:70]}...")
        page = _fetch_page(url)
        if not page:
            continue

        print(f"    [intel] Analyzing report ({len(page['text'])} chars)...")
        extract_result = claude_llm.ask_for_analysis(
            question=(
                "Extract all MITRE ATT&CK techniques from this threat report. "
                f"Skip already-covered techniques: {already_covered}. "
                "Return ONLY a JSON object with this structure (no markdown fences): "
                '{"title": "Report Title", '
                '"source": "' + url + '", '
                '"date_published": "YYYY-MM-DD", '
                '"threat_actors": ["Actor Name"], '
                '"platforms": ["Windows"], '
                '"techniques": [{"id": "T1059.001", "name": "PowerShell", '
                '"description": "How it was used", "priority": "high"}], '
                '"raw_summary": "2-3 sentence summary of the report"}'
            ),
            context=page["text"][:10000],
            agent_name="intel",
        )

        if not extract_result["success"]:
            print(f"    [intel] Failed to analyze: {title[:60]}")
            continue

        try:
            resp = _strip_markdown_fences(extract_result["response"])
            report = json.loads(resp)
            if not report.get("source"):
                report["source"] = url
            reports.append(report)
            tech_count = len(report.get("techniques", []))
            print(f"    [intel] Extracted {tech_count} techniques from: {title[:60]}")
        except json.JSONDecodeError:
            print(f"    [intel] Could not parse analysis for: {title[:60]}")
            print(f"    [intel] Raw (first 300): {extract_result['response'][:300]}")

    return reports


def fill_fawkes_gaps(
    state_manager: StateManager,
    fawkes_map: dict[str, dict],
    existing: set[str],
    threat_actor_registry: dict[str, list[str]] | None = None,
) -> dict:
    """
    Create detection requests for Fawkes techniques that have no existing
    request. This ensures the pipeline always has work even when web search
    fails or all reports have been fully consumed.

    Returns stats dict with created/skipped counts.
    """
    stats = {
        "gap_filled": 0,
        "requests_created": [],
        "skipped_existing": 0,
    }

    for tid, info in sorted(fawkes_map.items()):
        if tid in existing:
            stats["skipped_existing"] += 1
            continue

        priority = info.get("priority", "high").lower()
        # Fawkes techniques default to at least high priority
        if priority in ("medium", "low"):
            priority = "high"

        # Build threat_actors from registry
        threat_actors: list[str] = []
        if threat_actor_registry:
            threat_actors = list(threat_actor_registry.get(tid, []))
        if "Fawkes C2 Agent" not in threat_actors:
            threat_actors.append("Fawkes C2 Agent")

        try:
            state_manager.create(
                technique_id=tid,
                title=f"Detection for {tid} — {info.get('description', 'Fawkes capability')}",
                priority=priority,
                intel_report="threat-intel/fawkes/fawkes-ttp-mapping.md",
                requested_by=AGENT_NAME,
            )
            state_manager.update(
                tid, agent=AGENT_NAME,
                threat_actors=threat_actors,
                fawkes_commands=info["commands"],
            )
            # Tag data source requirements
            ds_requirements = get_data_source_requirements(tid)
            ds_gaps = check_data_source_gaps(tid)
            if ds_requirements:
                state_manager.update(tid, agent=AGENT_NAME,
                                     data_source_requirements=ds_requirements)
            if ds_gaps:
                state_manager.update(tid, agent=AGENT_NAME,
                                     data_source_gaps=ds_gaps)
                print(f"    [intel] Warning: {tid} has data source gaps: {ds_gaps}")

            existing.add(tid)
            stats["gap_filled"] += 1
            stats["requests_created"].append(tid)
            print(f"    [intel] Gap-fill: created request for {tid} "
                  f"(Fawkes commands: {', '.join(info['commands'])})")
        except ValueError as e:
            print(f"    [intel] Skipped gap-fill {tid}: {e}")

    return stats


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

    # 2. Load Fawkes TTP mapping for cross-reference + full threat model registry
    fawkes_map = load_fawkes_techniques()
    print(f"  [intel] Loaded {len(fawkes_map)} Fawkes technique mappings")
    threat_actor_registry = load_threat_model_registry()

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
                threat_actor_registry=threat_actor_registry,
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

    # 7. Fawkes gap-fill — create requests for uncovered Fawkes techniques
    gap_stats = fill_fawkes_gaps(
        state_manager, fawkes_map, existing,
        threat_actor_registry=threat_actor_registry,
    )
    if gap_stats["gap_filled"]:
        print(f"\n  [intel] Fawkes gap-fill: created {gap_stats['gap_filled']} new requests")
        total_stats["total_new"] += gap_stats["gap_filled"]
        total_stats["total_requests"] += gap_stats["gap_filled"]
    else:
        print(f"\n  [intel] Fawkes gap-fill: all {gap_stats['skipped_existing']} techniques covered")

    # 8. Update digest
    if reports_processed:
        update_digest(reports_processed, total_stats)
        print(f"\n  [intel] Updated digest at {DIGEST_PATH}")

    # 9. Summary
    summary = (
        f"Processed {len(reports_processed)} reports "
        f"({len(web_reports)} from web search), "
        f"created {total_stats['total_requests']} detection requests "
        f"({gap_stats['gap_filled']} from Fawkes gap-fill), "
        f"found {total_stats['total_fawkes']} Fawkes overlaps"
    )
    print(f"\n  [intel] {summary}")

    return {
        "summary": summary,
        "reports_processed": len(reports_processed),
        "web_reports_found": len(web_reports),
        "techniques_found": total_stats["total_new"],
        "requests_created": total_stats["total_requests"],
        "fawkes_gap_filled": gap_stats["gap_filled"],
        "requests_list": gap_stats["requests_created"],
        "skipped_existing": total_stats["total_skipped"],
        "fawkes_overlap": total_stats["total_fawkes"],
        "search_queries_used": queries,
    }
