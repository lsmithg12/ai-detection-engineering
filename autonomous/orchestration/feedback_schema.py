from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AnalystFeedback:
    technique_id: str
    rule_name: str
    verdict: str  # "tp", "fp", "fn"
    reason: str
    analyst: str
    timestamp: datetime
    event_id: Optional[str] = None
    alert_hash: Optional[str] = None  # dedup key: sha256 of technique_id+event_id


@dataclass
class FeedbackRollup:
    date: str  # YYYY-MM-DD
    technique_id: str
    rule_name: str
    tp_count: int = 0
    fp_count: int = 0
    fn_count: int = 0

    @property
    def total(self) -> int:
        return self.tp_count + self.fp_count + self.fn_count

    @property
    def fp_rate(self) -> float:
        denom = self.tp_count + self.fp_count
        if denom == 0:
            return 0.0
        return self.fp_count / denom
