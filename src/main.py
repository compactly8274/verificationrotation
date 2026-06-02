"""FastAPI application for verificationrotation web service."""

import asyncio
import contextlib
import hashlib
import hmac
import io
import json
import logging
import os
import queue
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import SignatureExpired, URLSafeTimedSerializer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import select, update
from starlette.middleware.sessions import SessionMiddleware

from src.app_signatures import APP_SIGNATURES
from src.bitwarden import bw_available, bw_get_session, bw_login, bw_login_apikey, bw_status, bw_unlock
from src.config import settings
from src.crypto import decrypt_value, encrypt_value, mask_value
from src.database import async_session, init_db
from src.env_manager import read_env, write_env
from src.key_discovery import discover_keys
from src.models import DiscoveredKey, RemoteHost, RotationHistory, ScanLog, Service, SSHKey
from src.notifications import send_notification
from src.path_discovery import detect_service_paths
from src.rotator import generate_password, is_password_service, rotate
from src.scanner import ScanIndex, build_scan_index
from src.services_registry import (
    ServiceDef,
    build_detected_fetcher,
    build_detected_writer,
    load_rotate_keys_config,
)
from src.ssh_keys import delete_ssh_key, generate_ssh_key, get_ssh_key, test_ssh_connection

logger = logging.getLogger("verificationrotation")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
scan_index: Optional[ScanIndex] = None
last_scan_time: Optional[datetime] = None
scan_heartbeat: Optional[datetime] = None          # updated at scan start; None when idle
last_scan_errors: list[str] = []                   # errors from most recent scan

rotation_in_progress: Optional[dict] = None        # {service_id, started_at}
auto_rotation_running: bool = False                 # True while auto-rotate job executes

_bw_session: Optional[str] = None                  # in-memory Bitwarden session token

# Async locks to prevent race conditions on shared state
_rotation_lock = asyncio.Lock()
_scan_lock = asyncio.Lock()
_auto_rotate_lock = asyncio.Lock()

_SCAN_TIMEOUT = timedelta(minutes=settings.scan_timeout_minutes)
_ROTATION_LOCK_TIMEOUT = timedelta(minutes=10)


class _QueuedWriter(io.TextIOBase):
    """Thread-safe stdout replacement that pushes each line into a queue for SSE streaming."""

    def __init__(self, q: queue.Queue):
        self.q = q
        self._buf = ""

    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self.q.put(line)
        return len(s)

    def flush(self):
        if self._buf:
            self.q.put(self._buf)
            self._buf = ""

    def close(self):
        self.flush()


def _scan_is_running() -> bool:
    """True only if a scan heartbeat is fresh (not stale/crashed)."""
    if scan_heartbeat is None:
        return False
    return (datetime.now() - scan_heartbeat) < _SCAN_TIMEOUT


def _rotation_is_running() -> bool:
    """True only if a rotation lock is held and hasn't auto-expired."""
    if rotation_in_progress is None:
        return False
    return (datetime.now() - rotation_in_progress["started_at"]) < _ROTATION_LOCK_TIMEOUT


# ---------------------------------------------------------------------------
# Service augmentation — merge DB-detected config paths into ServiceDef objects
# ---------------------------------------------------------------------------

async def _apply_detections(services: dict) -> dict:
    """Augment services that lack auto_fetch/auto_write with DB-detected config paths."""
    async with async_session() as session:
        result = await session.execute(
            select(Service).where(Service.detected_config_path.isnot(None))
        )
        rows = result.scalars().all()

    for row in rows:
        if row.id not in services:
            continue
        svc = services[row.id]
        if svc.auto_fetch:
            continue  # YAML-defined config takes precedence
        sig = APP_SIGNATURES.get(row.id)
        if not sig or not row.detected_config_path:
            continue
        svc.auto_fetch = build_detected_fetcher(sig, row.detected_config_path)
        svc.auto_write = build_detected_writer(sig, row.detected_config_path)
        if sig.get("docker_name") and not svc.docker_name:
            svc.docker_name = sig["docker_name"]

    return services


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def verify_password(password: str) -> bool:
    if not settings.admin_password:
        return False
    # Strip whitespace/CRLF that may be introduced by some env_file parsers
    stored = settings.admin_password.strip()
    # Support bcrypt-hashed passwords ($2b$ / $2a$ prefix)
    if stored.startswith("$2b$") or stored.startswith("$2a$"):
        import bcrypt as _bcrypt
        try:
            return _bcrypt.checkpw(password.encode(), stored.encode())
        except Exception:
            return False
    # Plaintext fallback — still works but logs a warning on every login.
    # Hash your password with bcrypt and update ADMIN_PASSWORD in .env to silence this.
    logger.warning(
        "ADMIN_PASSWORD is stored in plaintext. "
        "Run: docker exec verificationrotation python3 -c \""
        "import bcrypt; print(bcrypt.hashpw(b'YOUR_PASSWORD', bcrypt.gensalt(12)).decode())"
        "\" to generate a hash, then update ADMIN_PASSWORD in your .env."
    )
    return hmac.compare_digest(password, stored)


def verify_reset_key(key: str) -> bool:
    if not settings.reset_key:
        return False
    return hmac.compare_digest(key, settings.reset_key)


def is_authenticated(request: Request) -> bool:
    return request.session.get("authenticated") is True


def require_auth(request: Request):
    if not is_authenticated(request):
        raise HTTPException(status_code=303, detail="/login")


def generate_csrf_token(request: Request) -> str:
    """Generate a CSRF token tied to the current session."""
    session_id = request.session.get("id", "")
    return _csrf_signer.dumps(session_id)


def verify_csrf_token(request: Request) -> None:
    """Verify the CSRF token from the X-CSRF-Token header.

    Raises HTTPException(403) on invalid or missing token.
    """
    token = request.headers.get("x-csrf-token", "")
    if not token:
        raise HTTPException(status_code=403, detail="Missing CSRF token")
    session_id = request.session.get("id", "")
    try:
        data = _csrf_signer.loads(token, max_age=3600)
        if data != session_id:
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
    except SignatureExpired:
        raise HTTPException(status_code=403, detail="CSRF token expired")
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def get_bw_session() -> Optional[str]:
    """Return in-memory session, falling back to env-var session, then auto-auth from config."""
    global _bw_session
    if _bw_session:
        return _bw_session
    env_session = bw_get_session()
    if env_session:
        _bw_session = env_session
        return _bw_session
    # If API key credentials are pre-configured, authenticate transparently
    if settings.bw_client_id and settings.bw_client_secret and settings.bw_master_password:
        session, err = bw_login_apikey(
            settings.bw_client_id,
            settings.bw_client_secret,
            settings.bw_master_password,
            server_url=settings.bw_server_url,
        )
        if session:
            _bw_session = session
            logger.info("Bitwarden session auto-refreshed via configured API key")
            return session
        logger.warning("Bitwarden auto-refresh failed: %s", err)
    return None


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await _seed_services()
    # Warm up Bitwarden session in a background thread — do NOT await so uvicorn
    # starts accepting requests immediately rather than waiting for bw CLI calls.
    if settings.bw_client_id and settings.bw_client_secret and settings.bw_master_password:
        def _bw_warmup():
            try:
                get_bw_session()
            except Exception:
                logger.exception("Bitwarden background auth failed at startup")
        asyncio.get_running_loop().run_in_executor(None, _bw_warmup)
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        _background_scan, "interval",
        minutes=settings.scan_interval_minutes,
        id="scan", replace_existing=True,
    )
    if settings.auto_rotate_interval_hours > 0:
        scheduler.add_job(
            _auto_rotate_stale, "interval",
            hours=settings.auto_rotate_interval_hours,
            id="auto_rotate", replace_existing=True,
        )
        logger.info("Auto-rotation enabled every %.1fh", settings.auto_rotate_interval_hours)
    scheduler.start()
    scheduler.add_job(
        _background_scan, "date",
        run_date=datetime.now() + timedelta(seconds=5),
        id="initial_scan",
    )
    yield
    scheduler.shutdown()


app = FastAPI(title="VerificationRotation", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, max_age=3600 * 24 * 7, same_site="strict", https_only=settings.cookie_https_only)

# Rate limiting
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CSRF token signing — uses the same secret key
_csrf_signer = URLSafeTimedSerializer(settings.secret_key, salt="csrf")

# Paths exempt from CSRF checks (login sets up the session, SSE is read-only)
_CSRF_EXEMPT = {"/login"}


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    """Reject mutating requests lacking a valid CSRF token, unless exempt."""
    if request.method in ("POST", "PUT", "DELETE"):
        path = request.url.path
        # Exempt login endpoints (no session yet)
        if path in _CSRF_EXEMPT:
            return await call_next(request)
        # Allow unauthenticated paths through — require_auth handles them
        if not request.session.get("authenticated"):
            return await call_next(request)
        # Authenticated mutating request — require CSRF
        token = request.headers.get("x-csrf-token", "")
        if not token:
            return JSONResponse({"detail": "Missing CSRF token"}, status_code=403)
        session_id = request.session.get("id", "")
        try:
            data = _csrf_signer.loads(token, max_age=3600)
            if data != session_id:
                return JSONResponse({"detail": "Invalid CSRF token"}, status_code=403)
        except Exception:
            return JSONResponse({"detail": "Invalid or expired CSRF token"}, status_code=403)
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


# ---------------------------------------------------------------------------
# Seed services into DB from YAML
# ---------------------------------------------------------------------------

def _db_host_to_dict(row: RemoteHost) -> dict:
    return {
        "label": row.label,
        "host": row.host,
        "user": row.user,
        "search_dirs": json.loads(row.search_dirs) if row.search_dirs else [],
        "db_refs": [tuple(r) for r in json.loads(row.db_refs)] if row.db_refs else [],
    }


async def _get_db_hosts() -> list[dict]:
    async with async_session() as session:
        result = await session.execute(select(RemoteHost))
        rows = result.scalars().all()
        return [_db_host_to_dict(r) for r in rows]


async def _seed_services():
    _, _, _, yaml_hosts, services = load_rotate_keys_config(settings.descriptions_path)
    async with async_session() as session:
        for sid, svc in services.items():
            result = await session.execute(select(Service).where(Service.id == sid))
            existing = result.scalar_one_or_none()
            if not existing:
                session.add(Service(
                    id=sid,
                    display_name=svc.display_name,
                    env_var=svc.env_var,
                    is_password=1 if is_password_service(svc) else 0,
                    settings_url=svc.settings_url,
                ))
        import sqlalchemy
        host_count = await session.execute(select(sqlalchemy.func.count(RemoteHost.id)))
        if host_count.scalar() == 0:
            for rh in yaml_hosts:
                session.add(RemoteHost(
                    label=rh["label"],
                    host=rh["host"],
                    user=rh["user"],
                    search_dirs=json.dumps(rh.get("search_dirs", [])),
                    db_refs=json.dumps(rh.get("db_refs", [])),
                ))
        await session.commit()


# ---------------------------------------------------------------------------
# Background scan
# ---------------------------------------------------------------------------

async def _background_scan():
    global scan_index, last_scan_time, scan_heartbeat, last_scan_errors
    if _scan_is_running():
        return
    if _scan_lock.locked():
        return
    async with _scan_lock:
        scan_heartbeat = datetime.now()
        started = datetime.now()
        logger.info("Background scan started")
        log = ScanLog(started_at=started, status="running")
        async with async_session() as session:
            session.add(log)
            await session.commit()
            log_id = log.id

        errors: list[str] = []
        try:
            _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
            env = read_env(settings.env_file)
            db_hosts = await _get_db_hosts()

            scan_heartbeat = datetime.now()

            # Run the synchronous scan in a thread pool so the event loop (and
            # therefore the web UI) stays responsive throughout the scan.
            index = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: build_scan_index(
                    services, env,
                    env_path=settings.env_file,
                    skip_remote=False,
                    cache_max_age=settings.cache_max_age_hours,
                    remote_hosts=db_hosts,
                ),
            )
            scan_index = index
            last_scan_time = datetime.now()
            errors = index.scan_errors or []

            if errors:
                for err in errors:
                    send_notification("scan_error", "Scanner", err)

            async with async_session() as session:
                for sid, svc in services.items():
                    if not svc.env_var:
                        continue
                    key = env.get(svc.env_var, "")
                    total_hits = 0
                    if key:
                        total_hits += len(index.local_files.get(key, []))
                        total_hits += len(index.local_dbs.get(key, []))
                        for label, d in index.remote_files.items():
                            total_hits += len(d.get(key, []))
                        for label, d in index.remote_dbs.items():
                            total_hits += len(d.get(key, []))
                    await session.execute(
                        update(Service).where(Service.id == sid).values(hit_count=total_hits)
                    )
                await session.commit()

            error_msg = "; ".join(errors) if errors else None
            status = "completed_with_errors" if errors else "completed"
            logger.info("Background scan %s (%d keys, %d errors)", status, len(index.local_files), len(errors))
            async with async_session() as session:
                await session.execute(
                    update(ScanLog).where(ScanLog.id == log_id).values(
                        completed_at=datetime.now(),
                        status=status,
                        files_scanned=sum(len(v) for v in index.local_files.values()),
                        keys_found=len(index.local_files),
                        error_message=error_msg,
                    )
                )
                await session.commit()
        except Exception as exc:
            errors = [str(exc)]
            async with async_session() as session:
                await session.execute(
                    update(ScanLog).where(ScanLog.id == log_id).values(
                        completed_at=datetime.now(),
                        status="failed",
                        error_message=str(exc),
                    )
                )
                await session.commit()
            logger.exception("Background scan failed: %s", exc)
        finally:
            last_scan_errors = errors
            scan_heartbeat = None


# ---------------------------------------------------------------------------
# Auto-rotation scheduler
# ---------------------------------------------------------------------------

async def _auto_rotate_stale():
    """Rotate stale services one-by-one; skips if any other operation is running."""
    global auto_rotation_running
    if _scan_is_running() or _rotation_is_running() or auto_rotation_running or _auto_rotate_lock.locked():
        logger.info("Auto-rotate skipped — another operation in progress")
        return
    async with _auto_rotate_lock:
        auto_rotation_running = True
        try:
            _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
            services = await _apply_detections(services)
            env = read_env(settings.env_file)
            db_hosts = await _get_db_hosts()

            async with async_session() as session:
                result = await session.execute(select(Service).where(Service.status == "stale"))
                stale_rows = result.scalars().all()

            stale_ids: list[str] = [row.id for row in stale_rows]
            async with async_session() as session:
                result = await session.execute(select(Service))
                for row in result.scalars().all():
                    if row.id not in stale_ids and row.last_rotated:
                        if (datetime.now() - row.last_rotated).days > 180:
                            stale_ids.append(row.id)

            if not stale_ids:
                logger.info("Auto-rotate: no stale services found")
                return

            logger.info("Auto-rotate: rotating %d stale service(s)", len(stale_ids))

            global scan_index
            if not scan_index:
                scan_index = await asyncio.get_running_loop().run_in_executor(
                    None,
                    lambda: build_scan_index(services, env, env_path=settings.env_file, remote_hosts=db_hosts),
                )

            # Fetch hit counts for all stale services in one query
            async with async_session() as session:
                result = await session.execute(select(Service).where(Service.id.in_(stale_ids)))
                hit_counts = {row.id: row.hit_count for row in result.scalars().all()}

            for sid in stale_ids:
                if sid not in services:
                    continue
                svc = services[sid]
                if not svc.env_var or not env.get(svc.env_var):
                    continue
                if _rotation_is_running():
                    logger.warning("Auto-rotate: rotation lock held, stopping")
                    break
                global rotation_in_progress
                rotation_in_progress = {"service_id": sid, "started_at": datetime.now()}
                try:
                    ok = rotate(
                        sid, svc, env, settings.env_file, scan_index,
                        rotation_log={},
                        dry_run=False,
                        non_interactive=True,
                        generate_passwords=True,
                        bw_session=get_bw_session(),
                        remote_hosts=db_hosts,
                        known_hits=hit_counts.get(sid, -1),
                    )
                    if ok:
                        new_hash = hashlib.sha256(env.get(svc.env_var, "").encode()).hexdigest()[:16]
                        async with async_session() as session:
                            await session.execute(
                                update(Service).where(Service.id == sid).values(
                                    last_rotated=datetime.now(), current_hash=new_hash, status="ok"
                                )
                            )
                            session.add(RotationHistory(
                                service_id=sid,
                                old_hash="",
                                new_hash=new_hash,
                                success=1,
                                message="Auto-rotated (scheduled)",
                            ))
                            await session.commit()
                    else:
                        async with async_session() as session:
                            session.add(RotationHistory(
                                service_id=sid,
                                old_hash="",
                                new_hash="",
                                success=0,
                                message="Auto-rotate failed",
                            ))
                            await session.commit()
                except Exception as exc:
                    logger.exception("Auto-rotate failed for %s: %s", sid, exc)
                    send_notification("rotation_failed", svc.display_name, str(exc), service_id=sid, source="auto-rotate")
                finally:
                    rotation_in_progress = None
        finally:
            auto_rotation_running = False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
@limiter.limit("5/minute")
async def login_post(request: Request, password: str = Form(...)):
    if verify_password(password):
        import uuid
        request.session["authenticated"] = True
        request.session["id"] = str(uuid.uuid4())
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": "Invalid password"}, status_code=401)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/api/csrf-token")
async def api_csrf_token(request: Request):
    """Return a CSRF token for the current session (requires auth)."""
    require_auth(request)
    return {"csrf_token": generate_csrf_token(request)}


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "dashboard.html", {
        "auto_rotate_hours": settings.auto_rotate_interval_hours,
    })


# ---------------------------------------------------------------------------
# API — Bitwarden
# ---------------------------------------------------------------------------

@app.get("/api/bitwarden/status")
async def api_bw_status(request: Request):
    require_auth(request)
    available = bw_available()
    cli_status = bw_status() if available else {"status": "unauthenticated", "userEmail": ""}
    session = get_bw_session()
    auto_configured = bool(settings.bw_client_id and settings.bw_client_secret and settings.bw_master_password)
    return {
        "available": available,
        "unlocked": bool(session),
        "login_status": cli_status["status"],   # unauthenticated | locked | unlocked
        "user_email": cli_status["userEmail"],
        "source": "memory" if _bw_session else ("env" if session else None),
        "auto_configured": auto_configured,  # true when .env contains all API key credentials
    }


def _validate_bw_server_url(server_url: str) -> None:
    """Reject non-HTTPS Bitwarden server URLs."""
    if not server_url:
        return
    parsed = urlparse(server_url)
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="Bitwarden server URL must use HTTPS",
        )


@app.post("/api/bitwarden/login")
@limiter.limit("5/minute")
async def api_bw_login(
    request: Request,
    email: str = Form(...),
    master_password: str = Form(...),
    server_url: str = Form(""),
    mfa_code: str = Form(""),
    mfa_method: int = Form(0),
):
    """Log in to Bitwarden (needed on first run or after container restart)."""
    require_auth(request)
    _validate_bw_server_url(server_url)
    global _bw_session
    if not bw_available():
        raise HTTPException(status_code=503, detail="Bitwarden CLI not installed")
    session, err = bw_login(email, master_password, server_url=server_url, mfa_code=mfa_code, mfa_method=mfa_method)
    if not session:
        raise HTTPException(status_code=403, detail=f"Login failed: {err}")
    _bw_session = session
    return {"success": True, "message": f"Logged in and unlocked as {email}"}


@app.post("/api/bitwarden/login-apikey")
@limiter.limit("5/minute")
async def api_bw_login_apikey(
    request: Request,
    client_id: str = Form(...),
    client_secret: str = Form(...),
    master_password: str = Form(...),
    server_url: str = Form(""),
):
    """Authenticate via Bitwarden personal API key (no MFA needed) then unlock vault."""
    require_auth(request)
    _validate_bw_server_url(server_url)
    global _bw_session
    if not bw_available():
        raise HTTPException(status_code=503, detail="Bitwarden CLI not installed")
    session, err = bw_login_apikey(client_id, client_secret, master_password, server_url=server_url)
    if not session:
        raise HTTPException(status_code=403, detail=f"API key login failed: {err}")
    _bw_session = session
    return {"success": True, "message": "Logged in via API key and unlocked vault"}


@app.get("/api/bitwarden/debug")
async def api_bw_debug(request: Request):
    """Return parsed Bitwarden status (no raw CLI output to avoid leaking vault metadata)."""
    require_auth(request)
    try:
        return {"parsed": bw_status()}
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/bitwarden/unlock")
@limiter.limit("5/minute")
async def api_bw_unlock(request: Request, master_password: str = Form(...)):
    require_auth(request)
    global _bw_session
    if not bw_available():
        raise HTTPException(status_code=503, detail="Bitwarden CLI not installed")
    cli_state = bw_status()
    if cli_state["status"] == "unauthenticated":
        raise HTTPException(
            status_code=403,
            detail="Not logged in — use Login (email + password) instead of Unlock",
        )
    session, err = bw_unlock(master_password)
    if not session:
        raise HTTPException(status_code=403, detail=f"Unlock failed: {err}")
    _bw_session = session
    return {"success": True, "message": "Bitwarden unlocked"}


@app.post("/api/bitwarden/lock")
@limiter.limit("5/minute")
async def api_bw_lock(request: Request):
    require_auth(request)
    global _bw_session
    _bw_session = None
    return {"success": True, "message": "Bitwarden session cleared"}


# ---------------------------------------------------------------------------
# API — Services
# ---------------------------------------------------------------------------

@app.get("/api/services")
async def api_services(request: Request):
    require_auth(request)
    async with async_session() as session:
        result = await session.execute(select(Service))
        rows = result.scalars().all()
        data = []
        for row in rows:
            age_days = None
            if row.last_rotated:
                age_days = (datetime.now() - row.last_rotated).days
            status = row.status or "ok"
            if age_days is not None and age_days > 180:
                status = "stale"
            data.append({
                "id": row.id,
                "display_name": row.display_name,
                "env_var": row.env_var,
                "is_password": bool(row.is_password),
                "settings_url": row.settings_url,
                "last_rotated": row.last_rotated.isoformat() if row.last_rotated else None,
                "age_days": age_days,
                "hit_count": row.hit_count,
                "status": status,
            })
        return data


@app.put("/api/services/{service_id}")
async def api_services_update(request: Request, service_id: str, settings_url: str = Form("")):
    require_auth(request)
    async with async_session() as session:
        result = await session.execute(select(Service).where(Service.id == service_id))
        row = result.scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Service not found")
        row.settings_url = settings_url
        await session.commit()
    return {"success": True}


@app.get("/api/scan-status")
async def api_scan_status(request: Request):
    require_auth(request)
    return {
        "in_progress": _scan_is_running(),
        "auto_rotation_running": auto_rotation_running,
        "rotation_in_progress": rotation_in_progress["service_id"] if _rotation_is_running() else None,
        "last_scan": last_scan_time.isoformat() if last_scan_time else None,
        "scan_errors": last_scan_errors,
        "auto_rotate_hours": settings.auto_rotate_interval_hours,
    }


@app.post("/api/rotate/{service_id}")
@limiter.limit("10/minute")
async def api_rotate(
    request: Request,
    service_id: str,
    new_value: Optional[str] = Form(None),
    dry_run: bool = Form(False),
    generate_password: bool = Form(False),
    sync_bitwarden_flag: bool = Form(False),
):
    require_auth(request)
    global scan_index, rotation_in_progress

    _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
    services = await _apply_detections(services)
    if service_id not in services:
        raise HTTPException(status_code=404, detail="Service not found")
    svc = services[service_id]

    env = read_env(settings.env_file)
    db_hosts = await _get_db_hosts()
    if not scan_index:
        scan_index = build_scan_index(services, env, env_path=settings.env_file, remote_hosts=db_hosts)

    bw_session = get_bw_session() if sync_bitwarden_flag and bw_available() else None

    # Fetch hit_count here (async) so rotate() doesn't need to do async I/O
    async with async_session() as session:
        svc_row = await session.get(Service, service_id)
        known_hits = svc_row.hit_count if svc_row else -1

    if not dry_run:
        async with _rotation_lock:
            if _rotation_is_running():
                raise HTTPException(
                    status_code=409,
                    detail=f"Rotation already in progress for '{rotation_in_progress['service_id']}'. Try again shortly.",
                )
            rotation_in_progress = {"service_id": service_id, "started_at": datetime.now()}

    logger.info("Rotating %s (dry_run=%s)", service_id, dry_run)
    rotation_log = {}
    _buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(_buf):
            ok = rotate(
                service_id, svc, env, settings.env_file, scan_index,
                rotation_log=rotation_log,
                dry_run=dry_run,
                non_interactive=True,
                generate_passwords=generate_password,
                bw_session=bw_session,
                new_key=new_value,
                remote_hosts=db_hosts,
                known_hits=known_hits,
            )
    finally:
        if not dry_run:
            rotation_in_progress = None
    rotation_output = _buf.getvalue()
    logger.info("Rotation %s %s", service_id, "succeeded" if ok else "failed")

    async with async_session() as session:
        if not dry_run:
            if ok:
                new_hash = hashlib.sha256((new_value or env.get(svc.env_var, "")).encode()).hexdigest()[:16]
                await session.execute(
                    update(Service).where(Service.id == service_id).values(
                        last_rotated=datetime.now(), current_hash=new_hash, status="ok"
                    )
                )
                session.add(RotationHistory(
                    service_id=service_id,
                    old_hash="",
                    new_hash=new_hash,
                    success=1,
                    message="Rotated via web UI",
                ))
            else:
                session.add(RotationHistory(
                    service_id=service_id,
                    old_hash="",
                    new_hash="",
                    success=0,
                    message="Rotation failed via web UI",
                ))
        await session.commit()

    return {"success": ok, "dry_run": dry_run, "log": rotation_output}


@app.get("/api/rotate/{service_id}/stream")
@limiter.limit("10/minute")
async def api_rotate_stream(
    request: Request,
    service_id: str,
    new_value: Optional[str] = None,
    dry_run: bool = False,
    generate_password: bool = False,
    sync_bitwarden_flag: bool = False,
    csrf_token: Optional[str] = None,
):
    """Stream rotation output in real-time via Server-Sent Events.

    Even though this is a GET endpoint, it performs state-changing work.
    A CSRF token must be supplied via query parameter because EventSource
    cannot set custom headers.
    """
    require_auth(request)
    global scan_index, rotation_in_progress

    # --- CSRF validation for state-changing GET ---
    if not csrf_token:
        raise HTTPException(status_code=403, detail="Missing CSRF token")
    session_id = request.session.get("id", "")
    try:
        data = _csrf_signer.loads(csrf_token, max_age=3600)
        if data != session_id:
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")

    _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
    if service_id not in services:
        raise HTTPException(status_code=404, detail="Service not found")
    svc = services[service_id]

    env = read_env(settings.env_file)
    db_hosts = await _get_db_hosts()
    if not scan_index:
        scan_index = build_scan_index(services, env, env_path=settings.env_file, remote_hosts=db_hosts)

    bw_session = get_bw_session() if sync_bitwarden_flag and bw_available() else None

    async with async_session() as session:
        svc_row = await session.get(Service, service_id)
        known_hits = svc_row.hit_count if svc_row else -1

    if not dry_run:
        async with _rotation_lock:
            if _rotation_is_running():
                raise HTTPException(
                    status_code=409,
                    detail=f"Rotation already in progress for '{rotation_in_progress['service_id']}'. Try again shortly.",
                )
            rotation_in_progress = {"service_id": service_id, "started_at": datetime.now()}

    logger.info("Streaming rotation for %s (dry_run=%s)", service_id, dry_run)
    q: queue.Queue = queue.Queue()
    ok_result = [False]

    def run_rotation():
        qw = _QueuedWriter(q)
        with contextlib.redirect_stdout(qw):
            try:
                ok_result[0] = rotate(
                    service_id, svc, env, settings.env_file, scan_index,
                    rotation_log={},
                    dry_run=dry_run,
                    non_interactive=True,
                    generate_passwords=generate_password,
                    bw_session=bw_session,
                    new_key=new_value,
                    remote_hosts=db_hosts,
                    known_hits=known_hits,
                )
            except Exception as exc:
                q.put(f"✗ Error during rotation: {exc}")
                ok_result[0] = False
            finally:
                qw.close()

    t = threading.Thread(target=run_rotation, daemon=True)
    t.start()

    async def generate():
        try:
            while t.is_alive() or not q.empty():
                try:
                    line = q.get(timeout=0.2)
                    yield f"event: log\ndata: {json.dumps({'text': line})}\n\n"
                except queue.Empty:
                    continue
            t.join()
        except GeneratorExit:
            logger.info("Client disconnected during rotation stream for %s", service_id)
            raise
        finally:
            if not dry_run:
                rotation_in_progress = None

        ok = ok_result[0]
        logger.info("Streamed rotation %s %s", service_id, "succeeded" if ok else "failed")

        if not dry_run:
            try:
                async with async_session() as session:
                    if ok:
                        new_hash = hashlib.sha256((new_value or env.get(svc.env_var, "")).encode()).hexdigest()[:16]
                        await session.execute(
                            update(Service).where(Service.id == service_id).values(
                                last_rotated=datetime.now(), current_hash=new_hash, status="ok"
                            )
                        )
                        session.add(RotationHistory(
                            service_id=service_id,
                            old_hash="",
                            new_hash=new_hash,
                            success=1,
                            message="Rotated via web UI (streamed)",
                        ))
                    else:
                        session.add(RotationHistory(
                            service_id=service_id,
                            old_hash="",
                            new_hash="",
                            success=0,
                            message="Rotation failed via web UI (streamed)",
                        ))
                    await session.commit()
            except Exception as exc:
                logger.exception("Failed to save rotation result for %s: %s", service_id, exc)

        yield f"event: done\ndata: {json.dumps({'success': ok, 'dry_run': dry_run})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/rotate-all")
@limiter.limit("2/minute")
async def api_rotate_all(
    request: Request,
    dry_run: bool = Form(False),
    generate_password: bool = Form(False),
    sync_bitwarden_flag: bool = Form(False),
):
    require_auth(request)
    global scan_index, rotation_in_progress

    _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
    services = await _apply_detections(services)
    env = read_env(settings.env_file)
    db_hosts = await _get_db_hosts()
    if not scan_index:
        scan_index = build_scan_index(services, env, env_path=settings.env_file, remote_hosts=db_hosts)

    bw_session = get_bw_session() if sync_bitwarden_flag and bw_available() else None

    # Fetch all hit counts upfront (async) so rotate() doesn't need async I/O
    async with async_session() as session:
        all_svc_rows = (await session.execute(select(Service))).scalars().all()
        hit_count_map = {row.id: row.hit_count for row in all_svc_rows}

    results = []
    eligible = [(sid, svc) for sid, svc in services.items() if svc.env_var and env.get(svc.env_var)]
    logger.info("Rotate-all starting for %d service(s) (dry_run=%s)", len(eligible), dry_run)

    if not dry_run:
        async with _rotation_lock:
            if _rotation_is_running():
                raise HTTPException(
                    status_code=409,
                    detail=f"Rotation already in progress for '{rotation_in_progress['service_id']}'.",
                )

    for sid, svc in eligible:
        if not dry_run:
            rotation_in_progress = {"service_id": sid, "started_at": datetime.now()}
        logger.info("Rotate-all: rotating %s", sid)
        try:
            ok = rotate(
                sid, svc, env, settings.env_file, scan_index,
                rotation_log={},
                dry_run=dry_run,
                non_interactive=True,
                generate_passwords=generate_password,
                bw_session=bw_session,
                remote_hosts=db_hosts,
                known_hits=hit_count_map.get(sid, -1),
            )
        finally:
            if not dry_run:
                rotation_in_progress = None
        logger.info("Rotate-all: %s %s", sid, "ok" if ok else "failed")
        results.append({"service": sid, "success": ok})
        if ok and not dry_run:
            async with async_session() as session:
                new_hash = hashlib.sha256(env.get(svc.env_var, "").encode()).hexdigest()[:16]
                await session.execute(
                    update(Service).where(Service.id == sid).values(
                        last_rotated=datetime.now(), current_hash=new_hash, status="ok"
                    )
                )
                session.add(RotationHistory(
                    service_id=sid, old_hash="", new_hash=new_hash, success=1,
                    message="Rotated via bulk rotate-all",
                ))
                await session.commit()

    return {"results": results, "dry_run": dry_run}


# ---------------------------------------------------------------------------
# API — Hosts
# ---------------------------------------------------------------------------

@app.get("/hosts", response_class=HTMLResponse)
async def hosts_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "hosts.html")


@app.get("/api/hosts")
async def api_hosts(request: Request):
    require_auth(request)
    async with async_session() as session:
        result = await session.execute(select(RemoteHost))
        rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "label": r.label,
                "host": r.host,
                "user": r.user,
                "search_dirs": json.loads(r.search_dirs) if r.search_dirs else [],
                "db_refs": json.loads(r.db_refs) if r.db_refs else [],
                "ssh_key_name": r.ssh_key_name,
                "ssh_public_key": r.ssh_public_key,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]


def _parse_json_field(value: str, field_name: str) -> str:
    """Validate and normalize a JSON form field. Returns the canonical JSON string."""
    try:
        parsed = json.loads(value)
        return json.dumps(parsed)
    except (json.JSONDecodeError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON in {field_name}: {exc}")


@app.post("/api/hosts")
async def api_hosts_create(
    request: Request,
    label: str = Form(...),
    host: str = Form(...),
    user: str = Form(...),
    search_dirs: str = Form("[]"),
    db_refs: str = Form("[]"),
):
    require_auth(request)
    search_dirs_json = _parse_json_field(search_dirs, "search_dirs")
    db_refs_json = _parse_json_field(db_refs, "db_refs")
    async with async_session() as session:
        session.add(RemoteHost(label=label, host=host, user=user, search_dirs=search_dirs_json, db_refs=db_refs_json))
        await session.commit()
    return {"success": True}


@app.put("/api/hosts/{host_id}")
async def api_hosts_update(
    request: Request,
    host_id: int,
    label: str = Form(...),
    host: str = Form(...),
    user: str = Form(...),
    search_dirs: str = Form("[]"),
    db_refs: str = Form("[]"),
):
    require_auth(request)
    search_dirs_json = _parse_json_field(search_dirs, "search_dirs")
    db_refs_json = _parse_json_field(db_refs, "db_refs")
    async with async_session() as session:
        result = await session.execute(select(RemoteHost).where(RemoteHost.id == host_id))
        row = result.scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Host not found")
        row.label = label; row.host = host; row.user = user
        row.search_dirs = search_dirs_json; row.db_refs = db_refs_json
        await session.commit()
    return {"success": True}


@app.delete("/api/hosts/{host_id}")
async def api_hosts_delete(request: Request, host_id: int):
    require_auth(request)
    async with async_session() as session:
        result = await session.execute(select(RemoteHost).where(RemoteHost.id == host_id))
        row = result.scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Host not found")
        await session.delete(row)
        await session.commit()
    return {"success": True}


@app.post("/api/hosts/{host_id}/generate-key")
async def api_hosts_generate_key(request: Request, host_id: int):
    """Generate an ed25519 key pair for this host and return the public key + setup script."""
    require_auth(request)
    async with async_session() as session:
        result = await session.execute(select(RemoteHost).where(RemoteHost.id == host_id))
        row = result.scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Host not found")
        host_addr = row.host
        user = row.user
        key_name = f"host-{host_id}"

        # Regenerate — remove any existing key first
        delete_ssh_key(key_name)
        try:
            pub_key, _ = await asyncio.get_running_loop().run_in_executor(
                None, lambda: generate_ssh_key(key_name)
            )
        except Exception as exc:
            logger.exception("SSH key generation failed for host %s", host_id)
            raise HTTPException(status_code=500, detail=f"Key generation failed: {exc}")

        row.ssh_key_name = key_name
        row.ssh_public_key = pub_key
        await session.commit()

    home = "/root" if user == "root" else f"/home/{user}"
    setup_script = (
        f"mkdir -p {home}/.ssh && chmod 700 {home}/.ssh\n"
        f"echo '{pub_key}' >> {home}/.ssh/authorized_keys\n"
        f"chmod 600 {home}/.ssh/authorized_keys"
    )
    return {"public_key": pub_key, "setup_script": setup_script, "host": host_addr, "user": user}


@app.post("/api/hosts/{host_id}/test-connection")
async def api_hosts_test_connection(request: Request, host_id: int):
    """Test SSH connectivity to this host using its generated key."""
    require_auth(request)
    async with async_session() as session:
        result = await session.execute(select(RemoteHost).where(RemoteHost.id == host_id))
        row = result.scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Host not found")
        if not row.ssh_key_name:
            raise HTTPException(status_code=400, detail="No SSH key generated — click 'Connect' first")
        key_name, user, host_addr = row.ssh_key_name, row.user, row.host

    ok, msg = await asyncio.get_running_loop().run_in_executor(
        None, lambda: test_ssh_connection(key_name, user, host_addr)
    )
    return {"connected": ok, "message": msg}


# ---------------------------------------------------------------------------
# API — SSH Keys
# ---------------------------------------------------------------------------

@app.get("/ssh-keys", response_class=HTMLResponse)
async def ssh_keys_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "ssh_keys.html")


@app.get("/api/ssh-keys")
async def api_ssh_keys(request: Request):
    require_auth(request)
    async with async_session() as session:
        result = await session.execute(select(SSHKey))
        rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "name": r.name,
                "public_key": r.public_key,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]


@app.post("/api/ssh-keys")
async def api_ssh_keys_create(request: Request, name: str = Form(...)):
    require_auth(request)
    try:
        public_key, private_path = generate_ssh_key(name)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    async with async_session() as session:
        session.add(SSHKey(name=name, public_key=public_key, private_key_path=private_path))
        await session.commit()
    return {"success": True, "public_key": public_key}


@app.delete("/api/ssh-keys/{key_id}")
async def api_ssh_keys_delete(request: Request, key_id: int):
    require_auth(request)
    async with async_session() as session:
        result = await session.execute(select(SSHKey).where(SSHKey.id == key_id))
        row = result.scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Key not found")
        delete_ssh_key(row.name)
        await session.delete(row)
        await session.commit()
    return {"success": True}


# ---------------------------------------------------------------------------
# API — Service Path Detection
# ---------------------------------------------------------------------------

@app.post("/api/detect-service-paths")
async def api_detect_service_paths(request: Request):
    """Scan DISCOVERY_SEARCH_DIRS for known service config files and persist paths."""
    require_auth(request)
    try:
        search_dirs = [
            d.strip()
            for d in settings.discovery_search_dirs.replace(":", ",").split(",")
            if d.strip()
        ]
        loop = asyncio.get_running_loop()
        detected = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: detect_service_paths(search_dirs)),
            timeout=settings.scan_timeout_minutes * 60,
        )

        results = []
        async with async_session() as session:
            for sid, config_path in detected.items():
                sig = APP_SIGNATURES.get(sid, {})
                await session.execute(
                    update(Service).where(Service.id == sid).values(
                        detected_config_path=config_path,
                        detected_config_format=sig.get("format"),
                    )
                )
                results.append({"service_id": sid, "config_path": config_path, "format": sig.get("format")})
            await session.commit()

        # Attach display names
        async with async_session() as session:
            rows = (await session.execute(select(Service))).scalars().all()
            name_map = {r.id: r.display_name for r in rows}
        for r in results:
            r["display_name"] = name_map.get(r["service_id"], r["service_id"])

        return {"detected": len(results), "results": results}
    except asyncio.TimeoutError:
        logger.error("detect-service-paths timed out after %d minutes", settings.scan_timeout_minutes)
        raise HTTPException(status_code=504, detail=f"Detection timed out after {settings.scan_timeout_minutes} minutes. Try narrowing DISCOVERY_SEARCH_DIRS.")
    except Exception as exc:
        logger.exception("detect-service-paths failed")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/detected-service-paths")
async def api_get_detected_service_paths(request: Request):
    """Return all services that have a persisted detected config path."""
    require_auth(request)
    async with async_session() as session:
        rows = (
            await session.execute(select(Service).where(Service.detected_config_path.isnot(None)))
        ).scalars().all()
        return [
            {
                "service_id": r.id,
                "display_name": r.display_name,
                "config_path": r.detected_config_path,
                "format": r.detected_config_format,
            }
            for r in rows
        ]


@app.delete("/api/detected-service-paths/{service_id}")
async def api_clear_detected_service_path(request: Request, service_id: str):
    """Remove the detected config path for a single service."""
    require_auth(request)
    async with async_session() as session:
        await session.execute(
            update(Service).where(Service.id == service_id).values(
                detected_config_path=None,
                detected_config_format=None,
            )
        )
        await session.commit()
    return {"success": True}


# ---------------------------------------------------------------------------
# API — Key Discovery
# ---------------------------------------------------------------------------

@app.get("/discovery", response_class=HTMLResponse)
async def discovery_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "discovery.html")


@app.post("/api/discover-keys")
async def api_discover_keys(
    request: Request,
    search_dirs: Optional[str] = Form(None),
):
    """Run key discovery and persist results (encrypted) in the DB."""
    require_auth(request)

    raw_dirs = search_dirs or settings.discovery_search_dirs
    dir_list = [d.strip() for d in raw_dirs.replace(":", ",").split(",") if d.strip()]

    # Validate user-supplied dirs against the configured allowed bases
    if search_dirs:  # only validate when user overrides the defaults
        allowed_bases = [Path(d.strip()).resolve() for d in settings.discovery_search_dirs.replace(":", ",").split(",") if d.strip()]
        for d in dir_list:
            dp = Path(d).resolve()
            if not any(dp.is_relative_to(ab) for ab in allowed_bases):
                raise HTTPException(400, f"Search directory {d!r} is outside allowed bases: {allowed_bases}")

    skip_set = {
        s.strip()
        for s in settings.discovery_skip_dirs.split(",")
        if s.strip()
    }

    _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
    env = read_env(settings.env_file)

    try:
        results = await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(
                None,
                lambda: discover_keys(services, env, dir_list, skip_set),
            ),
            timeout=settings.scan_timeout_minutes * 60,
        )
    except asyncio.TimeoutError:
        logger.error("discover-keys timed out after %d minutes", settings.scan_timeout_minutes)
        raise HTTPException(status_code=504, detail=f"Scan timed out after {settings.scan_timeout_minutes} minutes. Try narrowing DISCOVERY_SEARCH_DIRS.")

    stored = []
    async with async_session() as session:
        for r in results:
            encrypted = encrypt_value(r.value)
            dk = DiscoveredKey(
                service_id=r.service_id,
                env_var=r.env_var,
                display_name=r.display_name,
                value_encrypted=encrypted,
                source_file=r.source_file,
                confidence=r.confidence,
                strategy=r.strategy,
            )
            session.add(dk)
            stored.append({
                "service_id": r.service_id,
                "env_var": r.env_var,
                "display_name": r.display_name,
                "value_masked": mask_value(r.value),
                "source_file": r.source_file,
                "confidence": r.confidence,
                "strategy": r.strategy,
            })
        await session.commit()

    return {"found": len(results), "results": stored}


@app.get("/api/discovered-keys")
async def api_list_discovered_keys(request: Request):
    """Return cached discovered keys (values masked — never returned in plaintext)."""
    require_auth(request)
    async with async_session() as session:
        rows = (await session.execute(select(DiscoveredKey))).scalars().all()
        return [
            {
                "id": r.id,
                "service_id": r.service_id,
                "env_var": r.env_var,
                "display_name": r.display_name,
                "value_masked": mask_value(decrypt_value(r.value_encrypted)),
                "source_file": r.source_file,
                "confidence": r.confidence,
                "strategy": r.strategy,
                "discovered_at": r.discovered_at.isoformat() if r.discovered_at else None,
                "applied_at": r.applied_at.isoformat() if r.applied_at else None,
            }
            for r in rows
        ]


@app.post("/api/discovered-keys/{key_id}/apply")
async def api_apply_discovered_key(request: Request, key_id: int):
    """Apply a discovered key by running a full rotation to propagate it everywhere."""
    require_auth(request)
    global scan_index, rotation_in_progress

    async with async_session() as session:
        row = await session.get(DiscoveredKey, key_id)
        if not row:
            raise HTTPException(status_code=404, detail="Discovered key not found")

    plaintext = decrypt_value(row.value_encrypted)
    service_id = row.service_id

    _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
    if service_id not in services:
        raise HTTPException(status_code=404, detail=f"Service {service_id} no longer configured")

    svc = services[service_id]
    env = read_env(settings.env_file)
    db_hosts = await _get_db_hosts()
    if not scan_index:
        scan_index = build_scan_index(services, env, env_path=settings.env_file, remote_hosts=db_hosts)

    async with async_session() as session:
        svc_row = await session.get(Service, service_id)
        known_hits = svc_row.hit_count if svc_row else -1

    if _rotation_is_running() or _rotation_lock.locked():
        raise HTTPException(status_code=409, detail="Rotation already in progress. Try again shortly.")

    rotation_in_progress = {"service_id": service_id, "started_at": datetime.now()}
    logger.info("Applying discovered key for %s (%s)", service_id, row.env_var)

    _buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(_buf):
            ok = rotate(
                service_id, svc, env, settings.env_file, scan_index,
                rotation_log={},
                dry_run=False,
                non_interactive=True,
                generate_passwords=False,
                bw_session=get_bw_session() if bw_available() else None,
                new_key=plaintext,
                remote_hosts=db_hosts,
                known_hits=known_hits,
            )
    finally:
        rotation_in_progress = None
    rotation_output = _buf.getvalue()
    logger.info("Apply discovered key for %s %s", service_id, "succeeded" if ok else "failed")

    async with async_session() as session:
        row = await session.get(DiscoveredKey, key_id)
        if ok:
            new_hash = hashlib.sha256(plaintext.encode()).hexdigest()[:16]
            await session.execute(
                update(Service).where(Service.id == service_id).values(
                    last_rotated=datetime.now(), current_hash=new_hash, status="ok"
                )
            )
            session.add(RotationHistory(
                service_id=service_id,
                old_hash="",
                new_hash=new_hash,
                success=1,
                message="Applied discovered key",
            ))
            row.applied_at = datetime.now()
        else:
            session.add(RotationHistory(
                service_id=service_id,
                old_hash="",
                new_hash="",
                success=0,
                message="Discovered key apply failed",
            ))
        await session.commit()

    return {"success": ok, "env_var": row.env_var, "log": rotation_output}


@app.post("/api/discovered-keys/apply-all")
async def api_apply_all_discovered_keys(request: Request):
    """Apply all high-confidence discovered keys that haven't been applied yet."""
    require_auth(request)
    global scan_index, rotation_in_progress

    _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
    env = read_env(settings.env_file)
    db_hosts = await _get_db_hosts()
    if not scan_index:
        scan_index = build_scan_index(services, env, env_path=settings.env_file, remote_hosts=db_hosts)

    from sqlalchemy import and_
    async with async_session() as session:
        rows = (await session.execute(
            select(DiscoveredKey).where(
                and_(
                    DiscoveredKey.confidence == "high",
                    DiscoveredKey.applied_at.is_(None)
                )
            )
        )).scalars().all()

    if not rows:
        return {"results": [], "total": 0, "applied_count": 0}

    results = []
    for row in rows:
        sid = row.service_id
        if sid not in services:
            results.append({"id": row.id, "service_id": sid, "success": False, "message": "Service no longer configured"})
            continue

        if _rotation_is_running() or _rotation_lock.locked():
            results.append({"id": row.id, "service_id": sid, "success": False, "message": "Rotation already in progress"})
            break

        svc = services[sid]
        plaintext = decrypt_value(row.value_encrypted)

        async with async_session() as session:
            svc_row = await session.get(Service, sid)
            known_hits = svc_row.hit_count if svc_row else -1

        rotation_in_progress = {"service_id": sid, "started_at": datetime.now()}
        logger.info("Bulk-apply: applying discovered key for %s", sid)
        try:
            ok = rotate(
                sid, svc, env, settings.env_file, scan_index,
                rotation_log={},
                dry_run=False,
                non_interactive=True,
                generate_passwords=False,
                bw_session=get_bw_session() if bw_available() else None,
                new_key=plaintext,
                remote_hosts=db_hosts,
                known_hits=known_hits,
            )
        except Exception as exc:
            ok = False
            logger.exception("Bulk-apply error for %s: %s", sid, exc)
        finally:
            rotation_in_progress = None

        logger.info("Bulk-apply: %s %s", sid, "ok" if ok else "failed")

        async with async_session() as session:
            db_row = await session.get(DiscoveredKey, row.id)
            if ok:
                new_hash = hashlib.sha256(plaintext.encode()).hexdigest()[:16]
                await session.execute(
                    update(Service).where(Service.id == sid).values(
                        last_rotated=datetime.now(), current_hash=new_hash, status="ok"
                    )
                )
                session.add(RotationHistory(
                    service_id=sid, old_hash="", new_hash=new_hash, success=1,
                    message="Applied discovered key (bulk)",
                ))
                db_row.applied_at = datetime.now()
            else:
                session.add(RotationHistory(
                    service_id=sid, old_hash="", new_hash="", success=0,
                    message="Discovered key apply failed (bulk)",
                ))
            await session.commit()

        results.append({"id": row.id, "service_id": sid, "success": ok})

    applied_count = sum(1 for r in results if r["success"])
    return {"results": results, "total": len(results), "applied_count": applied_count}


@app.delete("/api/discovered-keys")
async def api_clear_discovered_keys(request: Request):
    """Remove all cached discovery results from the DB."""
    require_auth(request)
    from sqlalchemy import delete as sa_delete
    async with async_session() as session:
        await session.execute(sa_delete(DiscoveredKey))
        await session.commit()
    return {"success": True}


@app.post("/api/reset-password")
@limiter.limit("3/15minute")
async def api_reset_password(request: Request, reset_key: str = Form(...), new_password: str = Form(...)):
    require_auth(request)
    if not verify_reset_key(reset_key):
        raise HTTPException(status_code=403, detail="Invalid reset key")
    # Hash the new password with bcrypt and write it to .env
    import bcrypt as _bcrypt
    hashed = _bcrypt.hashpw(new_password.encode(), _bcrypt.gensalt()).decode()
    write_env(settings.env_file, {"ADMIN_PASSWORD": hashed})
    return {"success": True, "message": "Password updated. Please restart the container for the change to take effect."}
