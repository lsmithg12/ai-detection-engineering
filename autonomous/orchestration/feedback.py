import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# Ensure package imports work whether run standalone or as a module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestration.feedback_schema import AnalystFeedback, FeedbackRollup

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VERDICTS_PATH = REPO_ROOT / "monitoring" / "feedback" / "verdicts.jsonl"
ROLLUP_PATH = REPO_ROOT / "monitoring" / "feedback" / "rollup.jsonl"


def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _compute_hash(technique_id: str, event_id: str | None) -> str:
    raw = f"{technique_id}:{event_id or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _serialize(fb: AnalystFeedback) -> str:
    return json.dumps({
        "technique_id": fb.technique_id,
        "rule_name": fb.rule_name,
        "verdict": fb.verdict,
        "reason": fb.reason,
        "analyst": fb.analyst,
        "timestamp": fb.timestamp.isoformat(),
        "event_id": fb.event_id,
        "alert_hash": fb.alert_hash,
    })


def _deserialize(line: str) -> AnalystFeedback:
    d = json.loads(line)
    return AnalystFeedback(
        technique_id=d["technique_id"],
        rule_name=d.get("rule_name", ""),
        verdict=d["verdict"],
        reason=d.get("reason", ""),
        analyst=d.get("analyst", ""),
        timestamp=datetime.fromisoformat(d["timestamp"]),
        event_id=d.get("event_id"),
        alert_hash=d.get("alert_hash"),
    )


def record_feedback(
    technique_id: str,
    verdict: str,
    reason: str,
    analyst: str,
    event_id: Optional[str] = None,
    rule_name: str = "",
) -> AnalystFeedback:
    fb = AnalystFeedback(
        technique_id=technique_id,
        rule_name=rule_name,
        verdict=verdict,
        reason=reason,
        analyst=analyst,
        timestamp=datetime.now(tz=timezone.utc),
        event_id=event_id,
        alert_hash=_compute_hash(technique_id, event_id),
    )
    _ensure_dir(VERDICTS_PATH)
    with VERDICTS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(_serialize(fb) + "\n")
    return fb


def get_rule_feedback(technique_id: str, days: int = 30) -> list[AnalystFeedback]:
    if not VERDICTS_PATH.exists():
        return []
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)
    results: list[AnalystFeedback] = []
    with VERDICTS_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                fb = _deserialize(line)
            except (json.JSONDecodeError, KeyError):
                continue
            ts = fb.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if fb.technique_id == technique_id and ts >= cutoff:
                results.append(fb)
    return results


def compute_fp_rate(technique_id: str, days: int = 7) -> float:
    verdicts = get_rule_feedback(technique_id, days=days)
    tp = sum(1 for v in verdicts if v.verdict == "tp")
    fp = sum(1 for v in verdicts if v.verdict == "fp")
    denom = tp + fp
    if denom == 0:
        return 0.0
    return fp / denom


def check_tuning_triggers(
    threshold: float = 0.10, days: int = 7
) -> list[dict]:
    if not VERDICTS_PATH.exists():
        return []
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)

    counts: dict[str, dict[str, int]] = {}
    with VERDICTS_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                fb = _deserialize(line)
            except (json.JSONDecodeError, KeyError):
                continue
            ts = fb.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
            bucket = counts.setdefault(fb.technique_id, {"tp": 0, "fp": 0, "fn": 0})
            if fb.verdict in bucket:
                bucket[fb.verdict] += 1

    triggers: list[dict] = []
    for technique_id, c in counts.items():
        tp, fp = c["tp"], c["fp"]
        verdict_count = tp + fp + c["fn"]
        if verdict_count < 3:
            continue
        denom = tp + fp
        rate = fp / denom if denom > 0 else 0.0
        if rate > threshold:
            triggers.append({
                "technique_id": technique_id,
                "fp_rate": rate,
                "verdict_count": verdict_count,
            })
    return triggers


def compute_rollup(date: str | None = None) -> list[FeedbackRollup]:
    if date is None:
        date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

    if not VERDICTS_PATH.exists():
        return []

    buckets: dict[tuple[str, str], FeedbackRollup] = {}
    with VERDICTS_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                fb = _deserialize(line)
            except (json.JSONDecodeError, KeyError):
                continue
            ts = fb.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts.strftime("%Y-%m-%d") != date:
                continue
            key = (fb.technique_id, fb.rule_name)
            if key not in buckets:
                buckets[key] = FeedbackRollup(
                    date=date,
                    technique_id=fb.technique_id,
                    rule_name=fb.rule_name,
                )
            rollup = buckets[key]
            if fb.verdict == "tp":
                rollup.tp_count += 1
            elif fb.verdict == "fp":
                rollup.fp_count += 1
            elif fb.verdict == "fn":
                rollup.fn_count += 1

    rollups = list(buckets.values())

    if rollups:
        _ensure_dir(ROLLUP_PATH)
        existing_keys: set[str] = set()
        if ROLLUP_PATH.exists():
            with ROLLUP_PATH.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        existing_keys.add(f"{d.get('date')}:{d.get('technique_id')}")
                    except json.JSONDecodeError:
                        continue

        with ROLLUP_PATH.open("a", encoding="utf-8") as fh:
            for r in rollups:
                key_str = f"{r.date}:{r.technique_id}"
                if key_str not in existing_keys:
                    fh.write(json.dumps({
                        "date": r.date,
                        "technique_id": r.technique_id,
                        "rule_name": r.rule_name,
                        "tp_count": r.tp_count,
                        "fp_count": r.fp_count,
                        "fn_count": r.fn_count,
                    }) + "\n")

    return rollups


if __name__ == "__main__":
    print("=== Tuning Triggers (FP rate > 10%, min 3 verdicts, last 7 days) ===")
    triggers = check_tuning_triggers()
    if not triggers:
        print("  No rules exceed FP threshold.")
    else:
        for t in triggers:
            print(
                f"  {t['technique_id']}: fp_rate={t['fp_rate']:.1%}"
                f"  (n={t['verdict_count']})"
            )
