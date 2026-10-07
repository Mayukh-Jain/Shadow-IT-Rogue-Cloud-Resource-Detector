"""
Database connection and initialization module using sqlite3.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

SHARED_DIR = Path(__file__).resolve().parent
DB_PATH = SHARED_DIR / "local.db"
SCHEMA_PATH = SHARED_DIR / "schema.sql"

_auto_seeded = False


def ensure_db_initialized(target_path: Path):
    """Ensures schema exists and auto-seeds mock data if resources table is empty."""
    global _auto_seeded
    if _auto_seeded:
        return
    
    needs_schema = not target_path.exists()
    if needs_schema:
        init_db(SCHEMA_PATH, target_path)

    # Check if empty
    try:
        with sqlite3.connect(str(target_path), timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            # Check if tables exist
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='resources'")
            if not cur.fetchone():
                init_db(SCHEMA_PATH, target_path)
            
            res_count = conn.execute("SELECT COUNT(*) FROM resources").fetchone()[0]
            if res_count == 0:
                from inject_mock_data import inject
                inject(target_path)
    except Exception:
        pass
    _auto_seeded = True


@contextmanager
def get_connection(db_path: Path = None):
    """Context manager for SQLite database connection."""
    target_path = db_path if db_path is not None else DB_PATH
    if target_path == DB_PATH and not _auto_seeded:
        ensure_db_initialized(target_path)

    # timeout=20.0 helps mitigate 'database is locked' errors during concurrent writes
    conn = sqlite3.connect(str(target_path), timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(schema_path: Path = None, db_path: Path = None):
    """Execute schema.sql to initialize database tables."""
    target_schema = schema_path if schema_path is not None else SCHEMA_PATH
    target_db = db_path if db_path is not None else DB_PATH
    if not target_schema.exists():
        raise FileNotFoundError(f"Schema file not found at {target_schema}")
    
    with open(target_schema, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    # Direct connection without circular ensure_db_initialized
    conn = sqlite3.connect(str(target_db), timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()
    print(f"Initialized database schema at {target_db}")


if __name__ == "__main__":
    init_db()
    from inject_mock_data import inject
    inject()
