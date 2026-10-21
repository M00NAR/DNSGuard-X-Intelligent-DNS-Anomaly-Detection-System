"""Regression tests for separate alert windows in CLI collection and SQLite."""

import sqlite3
from contextlib import closing

from dnsguard.alerts import AlertManager
from dnsguard.detectors import Finding
from dnsguard.main import RunCollector
from dnsguard.storage import Storage


def _finding(ts: float) -> Finding:
    return Finding("D1", "DNS Tunneling (payload)", "High", "10.0.0.5",
                   "evil.example", "high entropy", ts)


def test_repeated_attack_after_window_creates_second_persisted_alert(tmp_path):
    db = tmp_path / "runs.db"
    manager = AlertManager(dedupe_window_seconds=60)
    with Storage(db) as storage:
        run_id = storage.start_run("test", 0)
        collector = RunCollector(storage, log_queries=False)
        for ts in (0, 10, 200):
            alert = manager.process(_finding(ts))
            collector.on_alert(alert, alert.hit_count == 1)
        assert len(collector.alerts) == 2
        storage.commit()
    with closing(sqlite3.connect(db)) as con:
        rows = con.execute("SELECT timestamp, hit_count FROM alerts WHERE run_id=? "
                           "ORDER BY timestamp", (run_id,)).fetchall()
    assert rows == [(0.0, 2), (200.0, 1)]


def test_existing_database_is_migrated_without_losing_alerts(tmp_path):
    db = tmp_path / "old.db"
    with closing(sqlite3.connect(db)) as con:
        con.execute("""CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, timestamp REAL,
            last_timestamp REAL, src_ip TEXT, domain TEXT, attack_type TEXT,
            severity TEXT, detector_id TEXT, reason TEXT, hit_count INTEGER,
            UNIQUE(run_id, src_ip, domain, attack_type))""")
        con.execute("""INSERT INTO alerts
            (id, run_id, timestamp, last_timestamp, src_ip, domain, attack_type,
             severity, detector_id, reason, hit_count)
            VALUES (7, 1, 0, 10, '10.0.0.5', 'evil.example', 'DNS Tunneling (payload)',
                    'High', 'D1', 'old', 2)""")
        con.commit()
    with Storage(db) as storage:
        storage.run_id = 1
        second = AlertManager(60).process(_finding(200))
        storage.upsert_alert(second)
    with closing(sqlite3.connect(db)) as con:
        rows = con.execute("SELECT id, timestamp, hit_count FROM alerts "
                           "ORDER BY timestamp").fetchall()
    assert rows == [(7, 0.0, 2), (8, 200.0, 1)]

    # Opening an upgraded database again must leave both alert windows intact.
    with Storage(db):
        pass
    with closing(sqlite3.connect(db)) as con:
        assert con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2
