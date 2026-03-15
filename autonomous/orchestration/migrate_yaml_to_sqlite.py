#!/usr/bin/env python3
"""
Migrate detection request YAML files to SQLite database.

Usage:
  python orchestration/migrate_yaml_to_sqlite.py              # migrate
  python orchestration/migrate_yaml_to_sqlite.py --verify     # verify migration
  python orchestration/migrate_yaml_to_sqlite.py --dry-run    # preview only

The migration is idempotent -- safe to run multiple times.
YAML files are NOT deleted (dual-write period).
"""

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent
DB_PATH = AUTONOMOUS_DIR / "orchestration" / "state.db"
SCHEMA_PATH = AUTONOMOUS_DIR / "orchestration" / "state_schema.sql"
REQUESTS_DIR = AUTONOMOUS_DIR / "detection-requests"


def init_db(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Initialize database with schema."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    return conn


def migrate(dry_run: bool = False):
    """Read all YAML detection requests, insert into SQLite."""
    if not REQUESTS_DIR.exists():
        print(f"  No detection requests directory found at {REQUESTS_DIR}")
        return

    yml_files = sorted(REQUESTS_DIR.glob("*.yml"))
    yml_files = [f for f in yml_files if not f.name.startswith("_")]

    if not yml_files:
        print("  No YAML detection request files found.")
        return

    if dry_run:
        print(f"  [DRY-RUN] Would migrate {len(yml_files)} detection request files.")
        for f in yml_files:
            with open(f) as fh:
                data = yaml.safe_load(fh)
            if data and "technique_id" in data:
                print(f"    {f.name}: {data['technique_id']} ({data.get('status', 'UNKNOWN')})")
        return

    conn = init_db()
    migrated = 0
    skipped = 0

    for yml_file in yml_files:
        with open(yml_file) as f:
            data = yaml.safe_load(f)
        if not data or "technique_id" not in data:
            skipped += 1
            continue

        now = datetime.now(timezone.utc).isoformat()

        # Insert or replace detection
        conn.execute("""
            INSERT OR REPLACE INTO detections
            (technique_id, title, status, priority, priority_score, mitre_tactic,
             mitre_technique, f1_score, tp_count, fp_count, fn_count, tn_count,
             fp_rate, tp_rate, validation_method, rule_file, scenario_file,
             result_file, created_at, updated_at, created_by, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["technique_id"],
            data.get("title", ""),
            data.get("status", "REQUESTED"),
            data.get("priority", "medium"),
            data.get("priority_score", 0.5),
            data.get("mitre_tactic", ""),
            data.get("mitre_technique", data.get("technique_id", "")),
            data.get("f1_score"),
            data.get("tp_count", 0),
            data.get("fp_count", 0),
            data.get("fn_count", 0),
            data.get("tn_count", 0),
            data.get("fp_rate"),
            data.get("tp_rate"),
            data.get("validation_method"),
            data.get("rule_file"),
            data.get("scenario_file"),
            data.get("result_file"),
            data.get("created_at", now),
            data.get("updated_at", now),
            data.get("created_by", "migration"),
            data.get("updated_by", "migration"),
        ))

        # Insert threat actors
        for actor in data.get("threat_actors", []):
            conn.execute("""
                INSERT OR IGNORE INTO detection_threat_actors
                (technique_id, threat_actor) VALUES (?, ?)
            """, (data["technique_id"], actor))

        # Insert data sources
        for ds in data.get("data_sources", []):
            parts = ds.split(":", 1)
            source_id = parts[0]
            event_type = parts[1] if len(parts) > 1 else None
            conn.execute("""
                INSERT OR IGNORE INTO detection_data_sources
                (technique_id, source_id, event_type) VALUES (?, ?, ?)
            """, (data["technique_id"], source_id, event_type))

        # Insert state transitions from changelog/history
        for entry in data.get("changelog", data.get("history", [])):
            if isinstance(entry, dict):
                conn.execute("""
                    INSERT INTO state_transitions
                    (technique_id, from_state, to_state, agent, details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    data["technique_id"],
                    entry.get("from_state", entry.get("previous_state", "")),
                    entry.get("to_state", entry.get("status", entry.get("new_state", ""))),
                    entry.get("agent", entry.get("by", "")),
                    entry.get("details", entry.get("message", "")),
                    entry.get("timestamp", entry.get("date", now)),
                ))

        migrated += 1

    conn.commit()
    conn.close()
    print(f"  Migration complete: {migrated} detections migrated, {skipped} skipped.")
    print(f"  Database: {DB_PATH}")


def verify():
    """Compare YAML and SQLite state, report discrepancies."""
    if not DB_PATH.exists():
        print("  ERROR: Database not found. Run migration first.")
        return False

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT technique_id, status, f1_score FROM detections")
    db_state = {row["technique_id"]: dict(row) for row in cursor}
    conn.close()

    discrepancies = 0
    yaml_count = 0

    if not REQUESTS_DIR.exists():
        print("  No detection requests directory found.")
        return True

    for yml_file in sorted(REQUESTS_DIR.glob("*.yml")):
        if yml_file.name.startswith("_"):
            continue
        with open(yml_file) as f:
            data = yaml.safe_load(f)
        if not data or "technique_id" not in data:
            continue

        yaml_count += 1
        tid = data["technique_id"]

        if tid not in db_state:
            print(f"  MISSING in DB: {tid}")
            discrepancies += 1
        elif db_state[tid]["status"] != data.get("status"):
            print(f"  STATUS MISMATCH: {tid} YAML={data.get('status')} DB={db_state[tid]['status']}")
            discrepancies += 1

    # Check for entries in DB but not in YAML
    yaml_tids = set()
    for yml_file in sorted(REQUESTS_DIR.glob("*.yml")):
        if yml_file.name.startswith("_"):
            continue
        with open(yml_file) as f:
            data = yaml.safe_load(f)
        if data and "technique_id" in data:
            yaml_tids.add(data["technique_id"])

    for tid in db_state:
        if tid not in yaml_tids:
            print(f"  EXTRA in DB (not in YAML): {tid}")
            discrepancies += 1

    if discrepancies == 0:
        print(f"  Verification passed: {yaml_count} YAML files match {len(db_state)} DB records.")
        return True
    else:
        print(f"  {discrepancies} discrepancies found ({yaml_count} YAML, {len(db_state)} DB).")
        return False


def stats():
    """Print database statistics."""
    if not DB_PATH.exists():
        print("  ERROR: Database not found. Run migration first.")
        return

    conn = sqlite3.connect(str(DB_PATH))

    # Detection counts by status
    cursor = conn.execute(
        "SELECT status, COUNT(*) FROM detections GROUP BY status ORDER BY status"
    )
    print("\n  Detection Status:")
    for row in cursor:
        print(f"    {row[0]}: {row[1]}")

    # Threat actor coverage
    cursor = conn.execute(
        "SELECT threat_actor, COUNT(*) FROM detection_threat_actors GROUP BY threat_actor"
    )
    print("\n  Threat Actor Coverage:")
    for row in cursor:
        print(f"    {row[0]}: {row[1]} techniques")

    # Validation history count
    cursor = conn.execute("SELECT COUNT(*) FROM validation_history")
    print(f"\n  Validation history entries: {cursor.fetchone()[0]}")

    # Deployment count
    cursor = conn.execute(
        "SELECT siem, COUNT(*) FROM deployments WHERE status='active' GROUP BY siem"
    )
    print("\n  Active deployments:")
    for row in cursor:
        print(f"    {row[0]}: {row[1]}")

    conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Migrate detection request YAML files to SQLite database."
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="Verify migration by comparing YAML and SQLite state"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview migration without writing to database"
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Print database statistics"
    )
    args = parser.parse_args()

    if args.verify:
        success = verify()
        sys.exit(0 if success else 1)
    elif args.stats:
        stats()
    else:
        migrate(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
