-- Patronus Detection Engineering State Database
-- Phase 4: Schema definition. Phase 5: Production cutover.
-- Compatible with Python sqlite3 standard library (no dependencies).

CREATE TABLE IF NOT EXISTS detections (
    technique_id    TEXT PRIMARY KEY,         -- e.g., "T1055.001"
    title           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'REQUESTED',
    priority        TEXT DEFAULT 'medium',
    priority_score  REAL DEFAULT 0.5,
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    f1_score        REAL,
    tp_count        INTEGER DEFAULT 0,
    fp_count        INTEGER DEFAULT 0,
    fn_count        INTEGER DEFAULT 0,
    tn_count        INTEGER DEFAULT 0,
    fp_rate         REAL,
    tp_rate         REAL,
    validation_method TEXT,                   -- 'elasticsearch', 'local_json', 'cribl'
    rule_file       TEXT,                     -- relative path to Sigma YAML
    scenario_file   TEXT,                     -- relative path to scenario JSON
    result_file     TEXT,                     -- relative path to result JSON
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    created_by      TEXT,
    updated_by      TEXT,

    CHECK (status IN ('REQUESTED', 'SCENARIO_BUILT', 'AUTHORED', 'VALIDATED',
                      'DEPLOYED', 'MONITORING', 'TUNED', 'RETIRED'))
);

CREATE TABLE IF NOT EXISTS detection_threat_actors (
    technique_id    TEXT NOT NULL,
    threat_actor    TEXT NOT NULL,            -- e.g., "Fawkes C2 Agent"
    PRIMARY KEY (technique_id, threat_actor),
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS detection_data_sources (
    technique_id    TEXT NOT NULL,
    source_id       TEXT NOT NULL,            -- e.g., "sysmon"
    event_type      TEXT,                     -- e.g., "eid_8"
    PRIMARY KEY (technique_id, source_id, event_type),
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS state_transitions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT NOT NULL,
    from_state      TEXT NOT NULL,
    to_state        TEXT NOT NULL,
    agent           TEXT NOT NULL,
    details         TEXT,
    timestamp       TEXT NOT NULL,
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS deployments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT NOT NULL,
    siem            TEXT NOT NULL,            -- 'elastic' or 'splunk'
    rule_id         TEXT,                     -- SIEM-assigned rule ID
    version         INTEGER DEFAULT 1,
    deployed_at     TEXT NOT NULL,
    deployed_by     TEXT,
    status          TEXT DEFAULT 'active',    -- 'active', 'disabled', 'rolled_back'
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS validation_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT NOT NULL,
    f1_score        REAL,
    tp_count        INTEGER,
    fp_count        INTEGER,
    fn_count        INTEGER,
    tn_count        INTEGER,
    method          TEXT,                     -- 'elasticsearch', 'local_json', 'cribl'
    agent           TEXT,
    timestamp       TEXT NOT NULL,
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS source_health (
    source_id       TEXT NOT NULL,
    status          TEXT NOT NULL,            -- 'healthy', 'stale', 'missing', 'degraded'
    latest_event    TEXT,
    event_count_24h INTEGER,
    missing_fields  TEXT,                     -- JSON array
    checked_at      TEXT NOT NULL,
    PRIMARY KEY (source_id, checked_at)
);

-- Phase 4.8 addition: Compliance mapping
CREATE TABLE IF NOT EXISTS detection_compliance (
    technique_id    TEXT NOT NULL,
    control_id      TEXT NOT NULL,            -- e.g., "PCI-DSS-10.6.1"
    framework       TEXT NOT NULL,            -- e.g., "PCI-DSS", "SOC2", "HIPAA"
    PRIMARY KEY (technique_id, control_id),
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status);
CREATE INDEX IF NOT EXISTS idx_transitions_technique ON state_transitions(technique_id);
CREATE INDEX IF NOT EXISTS idx_deployments_technique ON deployments(technique_id);
CREATE INDEX IF NOT EXISTS idx_validation_technique ON validation_history(technique_id);
CREATE INDEX IF NOT EXISTS idx_source_health_source ON source_health(source_id);
CREATE INDEX IF NOT EXISTS idx_compliance_framework ON detection_compliance(framework);
