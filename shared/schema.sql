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
