CREATE TABLE IF NOT EXISTS resources (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    region TEXT,
    name TEXT,
    tags TEXT,
    owner_tag TEXT,
    public_access BOOLEAN DEFAULT 0,
    idle_days INTEGER DEFAULT 0,
    est_monthly_cost REAL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    is_flagged BOOLEAN DEFAULT 0,
    scan_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id TEXT UNIQUE NOT NULL,
    score REAL NOT NULL,
    risk_bucket TEXT NOT NULL,
    model_version TEXT NOT NULL,
    explanation TEXT,
    scored_at TIMESTAMP NOT NULL,
    FOREIGN KEY (resource_id) REFERENCES resources(id)
);

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id TEXT NOT NULL,
    sre_name TEXT, 
    status TEXT,
    action_taken TEXT,
    reason TEXT,
    slack_message_ts TEXT,
    decided_at TIMESTAMP,
    FOREIGN KEY (resource_id) REFERENCES resources(id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    type TEXT,
    region TEXT,
    account_id TEXT,
    trigger_source TEXT,
    score REAL,
    risk_tier TEXT,
    dedupe_key TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'Open',
    pipeline_status TEXT DEFAULT '{}',
    detected_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (resource_id) REFERENCES resources(id)
);

CREATE TABLE IF NOT EXISTS incident_runbooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    markdown TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    generator TEXT DEFAULT 'template',
    github_url TEXT,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id INTEGER NOT NULL,
    scheduled_time TIMESTAMP NOT NULL,
    note TEXT,
    post_to_slack BOOLEAN DEFAULT 0,
    status TEXT DEFAULT 'PENDING',
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (approval_id) REFERENCES approvals(id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id INTEGER NOT NULL,
    author_name TEXT NOT NULL,
    comment_text TEXT NOT NULL,
    post_to_slack BOOLEAN DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    FOREIGN KEY (approval_id) REFERENCES approvals(id)
);

CREATE TABLE IF NOT EXISTS account_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT,
    regions_scanned TEXT,
    regions_failed TEXT,
    metrics_json TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL
);
