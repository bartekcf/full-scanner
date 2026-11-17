"""List and filter saved scan results without making network requests."""
import argparse
import json
from app.storage import connect, import_results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="/output")
    parser.add_argument("--import-json", action="store_true")
    parser.add_argument("--url", help="URL substring")
    parser.add_argument("--status", choices=["running", "completed", "failed"])
    parser.add_argument("--severity", choices=["high", "medium", "low", "info", "unknown"])
    parser.add_argument("--alert", help="Alert title substring")
    parser.add_argument("--error", help="Error code substring")
    parser.add_argument("--with-errors", action="store_true")
    parser.add_argument("--check", help="HTTP check name")
    parser.add_argument("--check-status", help="For example missing")
    parser.add_argument("--details", action="store_true", help="Include alerts, errors and HTTP checks")
    parser.add_argument("--history", action="store_true", help="Include older scans")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")
    db = connect(args.output)
    try:
        if args.import_json:
            import_results(db, args.output)
        clauses, values = [], []
        if not args.history:
            clauses.append("s.rowid = (SELECT x.rowid FROM scans x WHERE x.url=s.url ORDER BY x.created_at DESC, x.rowid DESC LIMIT 1)")
        for value, expression in [
            (args.url, "s.url LIKE ?"), (args.status, "s.status = ?"),
        ]:
            if value:
                clauses.append(expression)
                values.append("%" + value + "%" if "LIKE" in expression else value)
        if args.with_errors:
            clauses.append("s.error_count > 0")
        alert_clauses = ["a.scan_id=s.scan_id"]
        if args.severity:
            alert_clauses.append("a.severity=?")
            values.append(args.severity)
        if args.alert:
            alert_clauses.append("a.title LIKE ?")
            values.append("%" + args.alert + "%")
        if len(alert_clauses) > 1:
            clauses.append("EXISTS (SELECT 1 FROM alerts a WHERE " + " AND ".join(alert_clauses) + ")")
        if args.error:
            clauses.append("EXISTS (SELECT 1 FROM errors e WHERE e.scan_id=s.scan_id AND e.code LIKE ?)")
            values.append("%" + args.error + "%")
        check_clauses = ["c.scan_id=s.scan_id"]
        for value, column in [(args.check, "name"), (args.check_status, "status")]:
            if value:
                check_clauses.append("c." + column + "=?")
                values.append(value)
        if len(check_clauses) > 1:
            clauses.append("EXISTS (SELECT 1 FROM http_checks c WHERE " + " AND ".join(check_clauses) + ")")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        db.row_factory = __import__("sqlite3").Row
        total = db.execute("SELECT COUNT(*) FROM scans s" + where, values).fetchone()[0]
        rows = db.execute(
            "SELECT scan_id,url,status,created_at,high,medium,low,info,alert_count,error_count,http_status "
            "FROM scans s" + where +
            " ORDER BY high DESC,medium DESC,low DESC,created_at DESC LIMIT ?",
            [*values, args.limit]).fetchall()
        results = [dict(row) for row in rows]
        if args.details:
            for result in results:
                scan_id = result["scan_id"]
                result["alerts"] = [dict(r) for r in db.execute(
                    "SELECT rule_id,severity,title FROM alerts WHERE scan_id=?", (scan_id,))]
                result["errors"] = [r[0] for r in db.execute(
                    "SELECT code FROM errors WHERE scan_id=?", (scan_id,))]
                result["http_checks"] = [dict(r) for r in db.execute(
                    "SELECT name,status FROM http_checks WHERE scan_id=?", (scan_id,))]
        print(json.dumps({"total": total, "results": results},
                         ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()
