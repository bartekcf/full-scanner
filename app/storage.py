"""Persistent scan history and queryable findings."""
import hashlib
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory


def connect(output):
    db = sqlite3.connect(Path(output) / "scans.sqlite3", timeout=30)
    try:
        initialize(db)
    except Exception:
        db.close()
        raise
    return db


def initialize(db):
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL,
            url TEXT NOT NULL, created_at TEXT, status TEXT NOT NULL,
            high INTEGER, medium INTEGER, low INTEGER, info INTEGER,
            alert_count INTEGER, error_count INTEGER, http_status INTEGER,
            result_json TEXT NOT NULL, json_path TEXT
        );
        CREATE INDEX IF NOT EXISTS scans_url_date ON scans(url, created_at);
        CREATE TABLE IF NOT EXISTS alerts (
            scan_id TEXT NOT NULL, rule_id TEXT, severity TEXT,
            title TEXT, page_url TEXT, details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS alerts_scan ON alerts(scan_id);
        CREATE INDEX IF NOT EXISTS alerts_by_kind
            ON alerts(scan_id, rule_id, title, severity);
        CREATE TABLE IF NOT EXISTS errors (
            scan_id TEXT NOT NULL, code TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS errors_scan ON errors(scan_id);
        CREATE TABLE IF NOT EXISTS http_checks (
            scan_id TEXT NOT NULL, name TEXT, status TEXT,
            details_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS checks_scan ON http_checks(scan_id);
        CREATE TABLE IF NOT EXISTS pdf_reports (
            scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id),
            pdf_path TEXT NOT NULL
        );
    """)
    alert_columns = {row[1] for row in db.execute("PRAGMA table_info(alerts)")}
    if "page_url" not in alert_columns:
        db.execute("ALTER TABLE alerts ADD COLUMN page_url TEXT")
    db.execute(
        "CREATE INDEX IF NOT EXISTS alerts_page ON alerts(scan_id, page_url, title, severity)"
    )
    scan_columns = {row[1] for row in db.execute("PRAGMA table_info(scans)")}
    if "json_path" not in scan_columns:
        db.execute("ALTER TABLE scans ADD COLUMN json_path TEXT")
        rows = db.execute("SELECT scan_id, batch_id, url FROM scans").fetchall()
        db.executemany(
            "UPDATE scans SET json_path = ? WHERE scan_id = ?",
            [(scan_json_path(batch, url), scan_id) for scan_id, batch, url in rows],
        )
    db.execute("""
        CREATE VIEW IF NOT EXISTS raporty AS
        SELECT s.scan_id,
               COALESCE(
                   NULLIF(TRIM(json_extract(s.result_json, '$.metadata.gmina')), ''),
                   NULLIF(TRIM(json_extract(s.result_json, '$.metadata.client_name')), '')
               ) AS gmina,
               s.url, s.created_at, s.status,
               p.pdf_path AS sciezka_pdf, s.json_path AS sciezka_json,
               s.high AS wysokie, s.medium AS srednie, s.low AS niskie,
               s.info AS informacyjne, s.alert_count AS liczba_alertow
        FROM scans s
        LEFT JOIN pdf_reports p ON p.scan_id = s.scan_id
        WHERE s.status IN ('completed', 'failed')
    """)
    if db.execute("PRAGMA user_version").fetchone()[0] < 1:
        db.execute("DROP VIEW IF EXISTS zagrozenia_wg_rodzaju")
        # Count alerts before joining scans so the grouping never sorts full result JSONs.
        db.execute("""
            CREATE VIEW zagrozenia_wg_rodzaju AS
            WITH counts AS (
                SELECT scan_id, rule_id, title, severity, COUNT(*) AS liczba
                FROM alerts
                GROUP BY scan_id, rule_id, title, severity
            )
            SELECT r.scan_id, r.gmina, r.url, r.sciezka_pdf,
                   a.rule_id AS regula, a.title AS rodzaj, a.severity AS waznosc,
                   a.liczba
            FROM counts a
            JOIN raporty r ON a.scan_id = r.scan_id
        """)
        db.execute("PRAGMA user_version = 1")
    db.commit()


def scan_json_path(batch_id, url):
    key = hashlib.sha256(url.encode()).hexdigest()
    return f"{batch_id}/{key}.json"


def save(db, record, batch_id, *, json_path=None):
    summary = record.get("summary", {})
    findings = record.get("findings", [])
    errors = list(record.get("errors", []))
    if record.get("error"):
        errors.append(record["error"])
    errors = list(dict.fromkeys(errors))
    scan_id = record["scan_id"]
    payload = json.dumps(record, ensure_ascii=False)
    with db:
        db.execute("""
            INSERT INTO scans (scan_id, batch_id, url, created_at, status,
                               high, medium, low, info, alert_count, error_count,
                               http_status, result_json, json_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                batch_id=excluded.batch_id, url=excluded.url, created_at=excluded.created_at,
                status=excluded.status, high=excluded.high, medium=excluded.medium,
                low=excluded.low, info=excluded.info, alert_count=excluded.alert_count,
                error_count=excluded.error_count, http_status=excluded.http_status,
                result_json=excluded.result_json, json_path=excluded.json_path
            """,
            (scan_id, batch_id, record["url"], record.get("created_at"),
             record["status"], *(summary.get(k, 0) for k in ("high", "medium", "low", "info")),
             len(findings), len(errors), record.get("http_status"), payload,
             json_path or scan_json_path(batch_id, record["url"])))
        for table in ("alerts", "errors", "http_checks"):
            db.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan_id,))
        db.executemany(
            """INSERT INTO alerts
               (scan_id, rule_id, severity, title, page_url, details_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(scan_id, f.get("id"), f.get("severity"), f.get("title"), f.get("url"),
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
        save(db, record, path.parent.name, json_path=path.relative_to(output).as_posix())
        count += 1
    return count



def register_report(db, output, scan_id, pdf):
    pdf = Path(pdf).resolve()
    if not pdf.is_file():
        raise FileNotFoundError(pdf)
    try:
        path = Path(os.path.relpath(pdf, Path(output).resolve())).as_posix()
    except ValueError:  # A Windows path on a different drive.
        path = pdf.as_posix()
    with db:
        result = db.execute("""
            INSERT INTO pdf_reports (scan_id, pdf_path)
            SELECT scan_id, ? FROM scans
            WHERE scan_id = ? AND status IN ('completed', 'failed')
            ON CONFLICT(scan_id) DO UPDATE SET pdf_path=excluded.pdf_path
        """, (path, scan_id))
        if result.rowcount != 1:
            raise ValueError("No finished scan in the database for this PDF")


def publish_index(db, output):
    # SQLite WAL is local to WSL. Publish a compact, immutable file for Windows readers.
    destination = Path(output) / "raporty.sqlite3"
    with TemporaryDirectory(prefix=".raporty-", dir=destination.parent) as temporary:
        snapshot = Path(temporary) / destination.name
        with db:
            # Keep both tables on the same revision and serialize concurrent publishers.
            db.execute("BEGIN IMMEDIATE")
            with closing(sqlite3.connect(snapshot)) as index, index:
                index.execute("""
                    CREATE TABLE raporty (
                        scan_id TEXT PRIMARY KEY, gmina TEXT, url TEXT, created_at TEXT,
                        status TEXT, sciezka_pdf TEXT, sciezka_json TEXT, wysokie INTEGER,
                        srednie INTEGER, niskie INTEGER, informacyjne INTEGER, liczba_alertow INTEGER
                    )
                """)
                index.execute("""
                    CREATE TABLE zagrozenia_wg_rodzaju (
                        scan_id TEXT, gmina TEXT, url TEXT, sciezka_pdf TEXT, regula TEXT,
                        rodzaj TEXT, waznosc TEXT, liczba INTEGER
                    )
                """)
                for name, placeholders in (
                    ("raporty", "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?"),
                    ("zagrozenia_wg_rodzaju", "?, ?, ?, ?, ?, ?, ?, ?"),
                ):
                    index.executemany(f"INSERT INTO {name} VALUES ({placeholders})",
                                      db.execute(f"SELECT * FROM {name}"))
            snapshot.chmod(0o600)
            snapshot.replace(destination)
