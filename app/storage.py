"""Persistent scan history and queryable findings."""
import json
import sqlite3
from pathlib import Path


def connect(output):
    db = sqlite3.connect(Path(output) / "scans.sqlite3", timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL,
            url TEXT NOT NULL, created_at TEXT, status TEXT NOT NULL,
            high INTEGER, medium INTEGER, low INTEGER, info INTEGER,
            alert_count INTEGER, error_count INTEGER, http_status INTEGER,
            result_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS scans_url_date ON scans(url, created_at);
        CREATE TABLE IF NOT EXISTS alerts (
            scan_id TEXT NOT NULL, rule_id TEXT, severity TEXT,
            title TEXT, details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS alerts_scan ON alerts(scan_id);
        CREATE TABLE IF NOT EXISTS errors (
            scan_id TEXT NOT NULL, code TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS errors_scan ON errors(scan_id);
        CREATE TABLE IF NOT EXISTS http_checks (
            scan_id TEXT NOT NULL, name TEXT, status TEXT,
            details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS checks_scan ON http_checks(scan_id);
    """)
    return db


def save(db, record, batch_id):
    summary = record.get("summary", {})
    findings = record.get("findings", [])
    errors = list(record.get("errors", []))
    if record.get("error"):
        errors.append(record["error"])
    errors = list(dict.fromkeys(errors))
    scan_id = record["scan_id"]
    payload = json.dumps(record, ensure_ascii=False)
    with db:
        db.execute("""INSERT OR REPLACE INTO scans VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, batch_id, record["url"], record.get("created_at"),
             record["status"], *(summary.get(k, 0) for k in ("high", "medium", "low", "info")),
             len(findings), len(errors), record.get("http_status"), payload))
        for table in ("alerts", "errors", "http_checks"):
            db.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan_id,))
        db.executemany("INSERT INTO alerts VALUES (?, ?, ?, ?, ?)",
            [(scan_id, f.get("id"), f.get("severity"), f.get("title"),
              json.dumps(f, ensure_ascii=False)) for f in findings])
        db.executemany("INSERT INTO errors VALUES (?, ?)",
                       [(scan_id, error) for error in errors])
        db.executemany("INSERT INTO http_checks VALUES (?, ?, ?, ?)",
            [(scan_id, c.get("check"), c.get("status"), json.dumps(c, ensure_ascii=False))
             for c in record.get("http_checks", [])])


def import_results(db, output):
    count = 0
    for path in Path(output).glob("batch-*/*.json"):
        if path.name == "manifest.json":
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        save(db, record, path.parent.name)
        count += 1
    return count
