"""SQLite logging of alerts, per-query records and run summaries.

Schema
------
``alerts``   - one row per distinct alert (updated in place as hits accumulate)
``queries``  - one row per inspected (non-whitelisted) query, for the dashboard
``runs``     - one row per CLI run with source and aggregate counts
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from .alerts import Alert
from .features import QueryFeatures
from .parser import DNSRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT,
    started_at  REAL,
    finished_at REAL,
    total_packets  INTEGER,
    total_queries  INTEGER,
    total_alerts   INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER,
    timestamp   REAL,
    last_timestamp REAL,
    src_ip      TEXT,
    domain      TEXT,
    attack_type TEXT,
    severity    TEXT,
    detector_id TEXT,
    reason      TEXT,
    hit_count   INTEGER,
    UNIQUE(run_id, src_ip, domain, attack_type)
);
CREATE TABLE IF NOT EXISTS queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER,
    timestamp   REAL,
    src_ip      TEXT,
    query_name  TEXT,
    parent_domain TEXT,
    qtype       TEXT,
    rcode       TEXT,
    is_response INTEGER,
    entropy     REAL,
    name_length INTEGER,
    flagged     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_run ON alerts(run_id);
CREATE INDEX IF NOT EXISTS idx_queries_run ON queries(run_id);
"""


class Storage:
    """Thin SQLite wrapper. Use as a context manager or call :meth:`close`."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self.run_id: int | None = None

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start_run(self, source: str, started_at: float) -> int:
        cur = self._conn.execute(
            "INSERT INTO runs(source, started_at) VALUES (?, ?)", (source, started_at))
        self._conn.commit()
        self.run_id = int(cur.lastrowid)
        return self.run_id

    def finish_run(self, finished_at: float, total_packets: int,
                   total_queries: int, total_alerts: int) -> None:
        if self.run_id is None:
            return
        self._conn.execute(
            "UPDATE runs SET finished_at=?, total_packets=?, total_queries=?, "
            "total_alerts=? WHERE run_id=?",
            (finished_at, total_packets, total_queries, total_alerts, self.run_id))
        self._conn.commit()

    def log_query(self, record: DNSRecord, feats: QueryFeatures | None, flagged: bool) -> None:
        self._conn.execute(
            "INSERT INTO queries(run_id, timestamp, src_ip, query_name, parent_domain, "
            "qtype, rcode, is_response, entropy, name_length, flagged) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (self.run_id, record.timestamp, record.src_ip, record.query_name,
             feats.parent_domain if feats else "", record.qtype, record.rcode,
             int(record.is_response), feats.entropy if feats else 0.0,
             feats.name_length if feats else len(record.query_name), int(flagged)))

    def upsert_alert(self, alert: Alert) -> None:
        self._conn.execute(
            "INSERT INTO alerts(run_id, timestamp, last_timestamp, src_ip, domain, "
            "attack_type, severity, detector_id, reason, hit_count) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id, src_ip, domain, attack_type) DO UPDATE SET "
            "last_timestamp=excluded.last_timestamp, severity=excluded.severity, "
            "detector_id=excluded.detector_id, reason=excluded.reason, "
            "hit_count=excluded.hit_count",
            (self.run_id, alert.timestamp, alert.last_timestamp, alert.src_ip,
             alert.domain, alert.attack_type, alert.severity, alert.detector_id,
             alert.reason, alert.hit_count))

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.commit()
        finally:
            self._conn.close()
