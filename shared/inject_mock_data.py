import sqlite3
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys

SHARED_DIR = Path(__file__).resolve().parent
DB_PATH = SHARED_DIR / "local.db"
SCHEMA_PATH = SHARED_DIR / "schema.sql"

def init_db_if_missing():
    if not DB_PATH.exists():
        import db
        db.init_db()

def inject():
    init_db_if_missing()
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        
        now = datetime.now(timezone.utc)
        old = now - timedelta(days=120)
        
        # 1. Compliant resource (Unflagged, False for ML Pipeline)
        compliant = (
            "i-compliant", "EC2", "us-east-1", "ProductionWeb",
            json.dumps({"owner": "alice", "team": "sre", "environment": "prod", "project": "frontend"}),
            "alice", 0, 0, 15.0,
            old.isoformat(), 0, now.isoformat()
        )
        
        # 2. Rogue resource (Flagged, True for ML Pipeline)
        flagged = (
            "i-rogue123", "EC2", "us-east-1", "TestScraper",
            json.dumps({"team": "dev"}), # Missing owner, environment, project
            None, 1, 45, 75.0,
            old.isoformat(), 1, now.isoformat()
        )
        
        sql = """
        INSERT OR REPLACE INTO resources (id, type, region, name, tags, owner_tag, public_access, idle_days, est_monthly_cost, created_at, is_flagged, scan_timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        conn.execute(sql, compliant)
        conn.execute(sql, flagged)
        
        conn.commit()
    print("Injected 1 compliant resource and 1 flagged (rogue) resource into the DB!")

if __name__ == "__main__":
    inject()
