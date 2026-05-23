"""
database.py — SQLite setup for AccessShield
--------------------------------------------
In production you'd swap SQLite for PostgreSQL/MySQL.
The schema and security principles (hashed passwords, no plaintext secrets) stay the same.
"""

import sqlite3
import os
from flask import g, current_app

DB_PATH = "accessshield.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,       -- bcrypt hash, never plaintext
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


def get_db() -> sqlite3.Connection:
    """Return a per-request DB connection (stored in Flask's g context)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row   # access columns by name
        g.db.execute("PRAGMA journal_mode=WAL")   # better concurrency
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def init_db():
    """Create tables if they don't exist. Called once at startup."""
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"[AccessShield] Database ready at {os.path.abspath(DB_PATH)}")
