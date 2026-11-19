from __future__ import annotations

import argparse
import asyncio
import csv
import fcntl
import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from app.storage import connect, publish_index, save
from app.config import Settings, EGRESS_PROXY_URL
from app.cve import CveIntelligence
from app.egress_policy import verify_egress_proxy
from app.pipeline import run_audit
from app.url_policy import validate_target_with_addresses
from app.zap import ZapClient


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2,
                  default=lambda item: item.model_dump(mode="json"))
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


async def run(args):
    if args.csv:
        with args.csv.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if "url" not in (reader.fieldnames or []):
                raise ValueError("CSV requires a url column")
            rows = list(reader)
    else:
        rows = [{"url": args.url}]
        if args.gmina:
            rows[0]["gmina"] = args.gmina
    if any(not row.get("url", "").strip() for row in rows):
        raise ValueError("Each row requires a nonempty URL")
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    args.output.mkdir(parents=True, exist_ok=True)
    # One process owns the shared ZAP session and output directory at a time.
    with (args.output / ".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.resume:
            batch = args.resume.resolve()
            if batch.parent != args.output.resolve():
                raise ValueError("Resume directory must belong to --output")
            manifest = json.loads((batch / "manifest.json").read_text())
            if manifest["input_hash"] != digest:
                raise ValueError("Resume requires the original input")
        else:
            batch = args.output / ("batch-" + uuid.uuid4().hex)
            batch.mkdir()
            write_json(batch / "manifest.json", {
                "schema_version": 1, "created_at": now(),
                "input_hash": digest, "targets": rows,
            })
        print(f"Batch: {batch}", flush=True)
        settings = Settings.from_env(require_api_token=False)
        zap = ZapClient(settings)
        intelligence = CveIntelligence(settings.cve_cache_path,
            proxy_url=EGRESS_PROXY_URL, api_key=settings.nvd_api_key,
            github_token=settings.github_token)
        database = connect(args.output)
        failures = 0
        try:
            await verify_egress_proxy(EGRESS_PROXY_URL)
            await zap.start()
            await intelligence.start()
            for index, row in enumerate(rows, 1):
                url = row["url"].strip()
                if "://" not in url:
                    url = "https://" + url
                key = hashlib.sha256(url.encode()).hexdigest()
                path = batch / (key + ".json")
                if path.exists():
                    previous = json.loads(path.read_text())
                    if previous["status"] == "completed":
                        print(f"[{index}/{len(rows)}] skipped {url}", flush=True)
                        continue
                started = time.monotonic()
                record = {"schema_version": 1, "scan_id": uuid.uuid4().hex,
                          "url": url, "metadata": row, "created_at": now(),
                          "status": "running"}
                write_json(path, record)
                save(database, record, batch.name)
                print(f"[{index}/{len(rows)}] scanning {url}", flush=True)
                zap.raw = {}
                try:
                    normalized, addresses = await validate_target_with_addresses(
                        url, settings.dns_timeout_seconds)
                    result = await run_audit(normalized, zap, intelligence,
                        dns_addresses=addresses,
                        enable_projectdiscovery_httpx=settings.enable_projectdiscovery_httpx,
                        enable_bounded_http_fingerprint=settings.enable_bounded_http_fingerprint,
                        fingerprint_tool_timeout_seconds=settings.fingerprint_tool_timeout_seconds,
                        max_response_bytes=settings.max_response_bytes)
                    record.update(asdict(result))
                    record["status"] = "completed"
                except Exception as exc:
                    failures += 1
                    record["status"] = "failed"
                    record["error"] = getattr(exc, "code", type(exc).__name__)
                finally:
                    record.setdefault("redirects", zap.raw.get("redirects", []))
                    record["raw_zap"] = zap.raw
                    record["finished_at"] = now()
                    record["duration_seconds"] = round(time.monotonic() - started, 3)
                    write_json(path, record)
                    save(database, json.loads(path.read_text()), batch.name)
                print(f"[{index}/{len(rows)}] {record['status']} {url}", flush=True)
        finally:
            await intelligence.close()
            await zap.close()
            try:
                publish_index(database, args.output)
            finally:
                database.close()
        return 1 if failures else 0


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Local passive website scanner")
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("--url")
    targets.add_argument("--csv", type=Path)
    parser.add_argument("--gmina", help="Municipality name for --url")
    parser.add_argument("--output", type=Path, default=Path("/output"))
    parser.add_argument("--resume", type=Path, help="Existing batch directory")
    args = parser.parse_args()
    if args.gmina is not None and not args.url:
        parser.error("--gmina requires --url")
    try:
        code = asyncio.run(run(args))
    except KeyboardInterrupt:
        code = 130
    except Exception as exc:
        parser.exit(1, f"Scanner stopped: {exc}\n")
    raise SystemExit(code)


if __name__ == "__main__":
    main()
