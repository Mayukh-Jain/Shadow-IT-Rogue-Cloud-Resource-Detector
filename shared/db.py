"""
Database connection and initialization module using sqlite3.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

SHARED_DIR = Path(__file__).resolve().parent
DB_PATH = SHARED_DIR / "local.db"
SCHEMA_PATH = SHARED_DIR / "schema.sql"


@contextmanager
def get_connection(db_path: Path = DB_PATH):
    """Context manager for SQLite database connection."""
    # timeout=20.0 helps mitigate 'database is locked' errors during concurrent writes
    conn = sqlite3.connect(str(db_path), timeout=20.0)
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


def init_db(schema_path: Path = SCHEMA_PATH, db_path: Path = DB_PATH):
    """Execute schema.sql to initialize database tables."""
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found at {schema_path}")
    
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    with get_connection(db_path) as conn:
        conn.executescript(schema_sql)
    print(f"Initialized database schema at {db_path}")


if __name__ == "__main__":
    init_db()
