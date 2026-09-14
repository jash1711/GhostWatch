"""
GhostWatch datastore.

Four tables:
  assets         - current known state of every device ever seen
  state_history  - append-only lifecycle transitions per asset (the "story")
  events         - raw observation log (every packet-derived event)
  alerts         - everything the detector has flagged
"""
import sqlite3
import os

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    mac TEXT PRIMARY KEY,
    first_seen REAL,
    last_seen REAL,
    state TEXT,
    vendor_oui TEXT,
    vendor_full TEXT,
    ja3_hash TEXT,
    ja3_label TEXT,
    ips TEXT,
    hostnames TEXT
);

CREATE TABLE IF NOT EXISTS state_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT,
    state TEXT,
    timestamp REAL,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT,
    ip TEXT,
    event_type TEXT,
    port INTEGER,
    timestamp REAL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT,
    ip TEXT,
    alert_type TEXT,
    severity TEXT,
    confidence TEXT,
    timestamp REAL,
    detail TEXT
);
"""

def get_conn(db_path):
    dirpath = os.path.dirname(db_path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
