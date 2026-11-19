from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, field_validator

from app.config import normalize_domain
from app.storage import connect, publish_index, register_report

logger = logging.getLogger("scanner.api")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCAN_OUTPUT = Path(os.environ.get("API_SCAN_OUTPUT_DIR", "/output")).resolve()
RATE_LIMIT_DB = Path(os.environ.get("API_RATE_LIMIT_DB", "/output/api-rate-limit.sqlite3"))
RATE_LIMIT = 5
RATE_WINDOW_SECONDS = 3600
MAX_REQUEST_BYTES = 4096
MAX_PDF_BYTES = 25 * 1024 * 1024
PDF_NAME = re.compile(r"[a-z0-9.-]+\.pdf\Z")
scan_slot = threading.Lock()


def required_token(name: str) -> str:
    token = os.environ.get(name, "").strip()
    if len(token) < 32:
        raise RuntimeError(f"{name} must contain at least 32 characters")
    return token


API_TOKEN = required_token("API_TOKEN")


@dataclass(frozen=True)
class ScanResult:
    record: dict
    pdf: bytes | None
    filename: str | None
    remaining: int


class ApiError(Exception):
    def __init__(self, status: int, code: str, retry_after: int | None = None):
        self.status = status
        self.code = code
        self.retry_after = retry_after
        super().__init__(code)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    domain: str

    @field_validator("domain")
    @classmethod
    def valid_domain(cls, value: str) -> str:
        try:
            return normalize_domain(value)
        except ValueError as exc:
            raise ValueError("domain must be a public fully-qualified hostname") from exc


def initialize_rate_limit_db() -> None:
    RATE_LIMIT_DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(RATE_LIMIT_DB, timeout=30) as connection:
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS api_scan_attempts ("
            "domain TEXT NOT NULL, requested_at INTEGER NOT NULL)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS api_scan_attempts_domain_time "
            "ON api_scan_attempts(domain, requested_at)"
        )


def reserve_domain_scan(domain: str) -> int:
    now = int(time.time())
    cutoff = now - RATE_WINDOW_SECONDS
    with sqlite3.connect(RATE_LIMIT_DB, timeout=30, isolation_level=None) as connection:
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM api_scan_attempts WHERE requested_at <= ?", (cutoff,))
        count = connection.execute(
            "SELECT COUNT(*) FROM api_scan_attempts WHERE domain = ? AND requested_at > ?",
            (domain, cutoff),
        ).fetchone()[0]
        if count >= RATE_LIMIT:
            oldest = connection.execute(
                "SELECT MIN(requested_at) FROM api_scan_attempts WHERE domain = ? AND requested_at > ?",
                (domain, cutoff),
            ).fetchone()[0]
            connection.execute("COMMIT")
            raise ApiError(429, "rate_limit_exceeded", max(1, oldest + RATE_WINDOW_SECONDS - now))
        connection.execute(
            "INSERT INTO api_scan_attempts(domain, requested_at) VALUES (?, ?)",
            (domain, now),
        )
        connection.execute("COMMIT")
    return RATE_LIMIT - count - 1


def _run_process(command: list[str], timeout: int, cwd: Path) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=os.environ.copy(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise ApiError(504, "scan_timed_out") from exc
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def run_scanner(domain: str) -> tuple[dict, Path]:
    timeout = int(os.environ.get("API_SCAN_TIMEOUT_SECONDS", "900"))
    url = f"https://{domain}"
    try:
        completed = _run_process(
            [sys.executable, "-m", "app.cli", "--url", url, "--output", str(SCAN_OUTPUT)],
            timeout,
            PROJECT_ROOT,
        )
    except OSError as exc:
        logger.error("Unable to start scanner process (%s)", type(exc).__name__)
        raise ApiError(502, "scanner_unavailable") from exc

    batch_lines = [line[7:] for line in completed.stdout.splitlines() if line.startswith("Batch: ")]
    if len(batch_lines) != 1:
        logger.error("Scanner returned no batch (exit=%s)", completed.returncode)
        raise ApiError(502, "scan_failed")
    batch = Path(batch_lines[0]).resolve()
    if batch.parent != SCAN_OUTPUT or not batch.is_dir():
        logger.error("Scanner returned an unexpected output path")
        raise ApiError(502, "scan_failed")

    result_path = batch / (hashlib.sha256(url.encode()).hexdigest() + ".json")
    try:
        if result_path.stat().st_size > 64 * 1024 * 1024:
            raise ApiError(502, "scan_result_too_large")
        with result_path.open(encoding="utf-8") as stream:
            record = json.load(stream)
    except ApiError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Scanner result could not be read (%s)", type(exc).__name__)
        raise ApiError(502, "scan_failed") from exc
    if not isinstance(record, dict) or record.get("url") != url:
        raise ApiError(502, "scan_failed")
    return record, batch


def render_pdf(batch: Path, scan_id: str) -> tuple[bytes, str]:
    timeout = int(os.environ.get("API_PDF_TIMEOUT_SECONDS", "180"))
    try:
        with tempfile.TemporaryDirectory(prefix=".scanner-pdf-", dir=SCAN_OUTPUT) as temporary:
            output = Path(temporary) / "pdf"
            output.mkdir(mode=0o700)
            completed = _run_process(
                [
                    "node",
                    str(PROJECT_ROOT / "reports" / "generate.mjs"),
                    "--input",
                    str(batch),
                    "--output",
                    str(output),
                ],
                timeout,
                PROJECT_ROOT / "reports",
            )
            files = list(output.glob("*.pdf"))
            if completed.returncode != 0 or len(files) != 1:
                logger.error("PDF generation failed (exit=%s)", completed.returncode)
                raise ApiError(502, "pdf_generation_failed")
            path = files[0]
            if not PDF_NAME.fullmatch(path.name) or path.stat().st_size > MAX_PDF_BYTES:
                raise ApiError(502, "pdf_result_invalid")
            pdf = path.read_bytes()
            destination = SCAN_OUTPUT / "pdf" / path.name
            destination.parent.mkdir(exist_ok=True)
            path.replace(destination)
            with closing(connect(SCAN_OUTPUT)) as db:
                register_report(db, SCAN_OUTPUT, scan_id, destination)
                publish_index(db, SCAN_OUTPUT)
            return pdf, path.name
    except ApiError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        logger.error("PDF generator unavailable (%s)", type(exc).__name__)
        raise ApiError(502, "pdf_generation_failed") from exc


def process_scan(domain: str, want_pdf: bool) -> ScanResult:
    if not scan_slot.acquire(blocking=False):
        raise ApiError(503, "scanner_busy", 15)
    try:
        remaining = reserve_domain_scan(domain)
        record, batch = run_scanner(domain)
        if not want_pdf:
            return ScanResult(record, None, None, remaining)
        pdf, filename = render_pdf(batch, record["scan_id"])
        return ScanResult(record, pdf, filename, remaining)
    finally:
        scan_slot.release()


async def require_api_token(request: Request) -> None:
    token = request.headers.get("X-API-Token", "").encode()
    if not hmac.compare_digest(token, API_TOKEN.encode()):
        raise HTTPException(status_code=401, detail="invalid_credentials")




@asynccontextmanager
async def lifespan(_: FastAPI):
    os.umask(0o077)
    SCAN_OUTPUT.mkdir(parents=True, exist_ok=True)
    initialize_rate_limit_db()
    yield


app = FastAPI(title="Local Scanner API", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Token"],
    expose_headers=["Content-Disposition", "Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
)


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    if request.method == "POST" and request.url.path in {"/api/v1/scan/json", "/api/v1/scan/pdf"}:
        raw_length = request.headers.get("content-length")
        if raw_length is None:
            return JSONResponse({"error": "content_length_required"}, status_code=411)
        try:
            length = int(raw_length)
        except ValueError:
            return JSONResponse({"error": "invalid_content_length"}, status_code=400)
        if length < 0 or length > MAX_REQUEST_BYTES:
            return JSONResponse({"error": "request_too_large"}, status_code=413)
    return await call_next(request)


@app.exception_handler(ApiError)
async def api_error_handler(_: Request, exc: ApiError):
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after is not None else None
    return JSONResponse({"error": exc.code}, status_code=exc.status, headers=headers)


def response_headers(remaining: int) -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-RateLimit-Limit": str(RATE_LIMIT),
        "X-RateLimit-Remaining": str(remaining),
    }


async def run_request(domain: str, want_pdf: bool) -> ScanResult:
    return await asyncio.to_thread(process_scan, domain, want_pdf)


@app.get("/healthz")
async def health():
    return {"status": "ok"}


@app.post("/api/v1/scan/json", dependencies=[Depends(require_api_token)])
async def scan_json(payload: ScanRequest):
    result = await run_request(payload.domain, False)
    return JSONResponse(result.record, headers=response_headers(result.remaining))


@app.post("/api/v1/scan/pdf", dependencies=[Depends(require_api_token)])
async def scan_pdf(payload: ScanRequest):
    result = await run_request(payload.domain, True)
    assert result.pdf is not None and result.filename is not None
    headers = response_headers(result.remaining)
    headers["Content-Disposition"] = f'attachment; filename="{result.filename}"'
    return Response(result.pdf, media_type="application/pdf", headers=headers)
