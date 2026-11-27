"""Maintain a local PostgreSQL projection of committed SQLite report data."""
import logging
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import psycopg
from psycopg import sql

from app.storage import connect

OUTPUT = Path("/output")
BATCH_SIZE = 200
logger = logging.getLogger(__name__)


def track_changes(source):
    with source:
        source.execute("BEGIN IMMEDIATE")
        source.execute("""
            CREATE TABLE IF NOT EXISTS report_changes (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL UNIQUE
            )
        """)
        for table in ("scans", "pdf_reports"):
            for event, row in (("INSERT", "NEW"), ("UPDATE", "NEW"), ("DELETE", "OLD")):
                source.execute(f"""
                    CREATE TRIGGER IF NOT EXISTS report_changes_{table}_{event.lower()}
                    AFTER {event} ON {table}
                    BEGIN
                        INSERT INTO report_changes (scan_id) VALUES ({row}.scan_id)
                        ON CONFLICT(scan_id) DO UPDATE SET seq=excluded.seq;
                    END
                """)


def configure_target(target):
    with target.transaction():
        if not target.execute("SELECT 1 FROM pg_roles WHERE rolname = 'report_viewer'").fetchone():
            target.execute("CREATE ROLE report_viewer")
        target.execute(sql.SQL("ALTER ROLE report_viewer WITH LOGIN PASSWORD {}").format(
            sql.Literal(os.environ["REPORT_DB_READER_PASSWORD"])
        ))
        target.execute("""
            CREATE TABLE IF NOT EXISTS raporty (
                scan_id text PRIMARY KEY, gmina text, url text, created_at text,
                status text, sciezka_pdf text, sciezka_json text, wysokie integer,
                srednie integer, niskie integer, informacyjne integer, liczba_alertow integer
            )
        """)
        target.execute("""
            CREATE TABLE IF NOT EXISTS report_alert_counts (
                scan_id text REFERENCES raporty(scan_id) ON DELETE CASCADE,
                regula text, rodzaj text, waznosc text, liczba bigint NOT NULL
            )
        """)
        target.execute("CREATE INDEX IF NOT EXISTS counts_scan ON report_alert_counts(scan_id)")
        target.execute("""
            CREATE OR REPLACE VIEW zagrozenia_wg_rodzaju AS
            SELECT r.scan_id, r.gmina, r.url, r.sciezka_pdf, a.regula, a.rodzaj, a.waznosc, a.liczba
            FROM report_alert_counts a
            JOIN raporty r USING (scan_id)
        """)
        target.execute("GRANT SELECT ON raporty, zagrozenia_wg_rodzaju TO report_viewer")


def read_changes(source, after):
    # Take the change cursor, reports and counts from a single SQLite read transaction.
    source.execute("BEGIN")
    try:
        if after is None:
            through = source.execute("SELECT COALESCE(MAX(seq), 0) FROM report_changes").fetchone()[0]
            scan_ids = None
            report_filter = ""
            count_filter = ""
            values = ()
        else:
            changes = source.execute("""
                SELECT seq, scan_id FROM report_changes WHERE seq > ? ORDER BY seq LIMIT ?
            """, (after, BATCH_SIZE)).fetchall()
            if not changes:
                return None
            through = changes[-1][0]
            scan_ids = [scan_id for _, scan_id in changes]
            placeholders = ", ".join("?" for _ in scan_ids)
            report_filter = f"WHERE scan_id IN ({placeholders})"
            count_filter = f"AND a.scan_id IN ({placeholders})"
            values = scan_ids
        reports = source.execute(f"""
            SELECT scan_id, gmina, url, created_at, status, sciezka_pdf, sciezka_json,
                   wysokie, srednie, niskie, informacyjne, liczba_alertow
            FROM raporty {report_filter}
        """, values).fetchall()
        counts = source.execute(f"""
            SELECT a.scan_id, a.rule_id, a.title, a.severity, COUNT(*)
            FROM alerts a JOIN scans s ON s.scan_id = a.scan_id
            WHERE s.status IN ('completed', 'failed') {count_filter}
            GROUP BY a.scan_id, a.rule_id, a.title, a.severity
        """, values).fetchall()
        return through, scan_ids, reports, counts
    finally:
        source.rollback()


def publish(target, scan_ids, reports, counts):
    with target.transaction(), target.cursor() as cursor:
        if scan_ids is None:
            cursor.execute("TRUNCATE report_alert_counts, raporty")
        else:
            cursor.execute("DELETE FROM raporty WHERE scan_id = ANY(%s)", (scan_ids,))
        cursor.executemany("""
            INSERT INTO raporty (scan_id, gmina, url, created_at, status, sciezka_pdf, sciezka_json,
                                 wysokie, srednie, niskie, informacyjne, liczba_alertow)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, reports)
        cursor.executemany("""
            INSERT INTO report_alert_counts (scan_id, regula, rodzaj, waznosc, liczba)
            VALUES (%s, %s, %s, %s, %s)
        """, counts)


def sync(target, source_path):
    identity = source_path.stat()
    after = None
    with closing(connect(source_path.parent)) as source:
        track_changes(source)
        while source_path.stat().st_ino == identity.st_ino:
            batch = read_changes(source, after)
            if batch is None:
                time.sleep(1)
                continue
            through, scan_ids, reports, counts = batch
            publish(target, scan_ids, reports, counts)
            if after is None:
                logger.info("Loaded %d scan reports", len(reports))
            after = through


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if not os.environ.get("REPORT_DB_READER_PASSWORD"):
        raise SystemExit("REPORT_DB_READER_PASSWORD is required")
    source_path = OUTPUT / "scans.sqlite3"
    while True:
        try:
            with psycopg.connect(connect_timeout=5, autocommit=True) as target:
                configure_target(target)
                sync(target, source_path)
        except (OSError, sqlite3.Error, psycopg.Error) as error:
            logger.warning("Report synchronization will retry (%s)", type(error).__name__)
            time.sleep(3)


if __name__ == "__main__":
    main()
