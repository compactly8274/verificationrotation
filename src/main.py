"""FastAPI application for verificationrotation web service."""

import hashlib
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, update
from starlette.middleware.sessions import SessionMiddleware

from src.bitwarden import bw_available, bw_get_session, bw_unlock
from src.config import settings
from src.database import async_session, init_db
from src.env_manager import read_env
from src.models import RemoteHost, RotationHistory, ScanLog, Service, SSHKey
from src.notifications import send_notification
from src.rotator import generate_password, is_password_service, rotate
from src.scanner import ScanIndex, build_scan_index
from src.services_registry import ServiceDef, load_rotate_keys_config
from src.ssh_keys import delete_ssh_key, generate_ssh_key

logger = logging.getLogger("verificationrotation")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
scan_index: Optional[ScanIndex] = None
last_scan_time: Optional[datetime] = None
scan_heartbeat: Optional[datetime] = None          # updated every ~5s during scan
last_scan_errors: list[str] = []                   # errors from most recent scan

rotation_in_progress: Optional[dict] = None        # {service_id, started_at}
auto_rotation_running: bool = False                 # True while auto-rotate job executes

_SCAN_TIMEOUT = timedelta(minutes=settings.scan_timeout_minutes)
_ROTATION_LOCK_TIMEOUT = timedelta(minutes=10)


def _scan_is_running() -> bool:
    """True only if a scan is genuinely in-progress (heartbeat not stale)."""
    if scan_heartbeat is None:
        return False
    return (datetime.now() - scan_heartbeat) < _SCAN_TIMEOUT


def _rotation_is_running() -> bool:
    """True only if a rotation is in-progress and the lock hasn't expired."""
    if rotation_in_progress is None:
        return False
    age = datetime.now() - rotation_in_progress["started_at"]
    return age < _ROTATION_LOCK_TIMEOUT


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def verify_password(password: str) -> bool:
    if not settings.admin_password:
        return False
    return password == settings.admin_password


def verify_reset_key(key: str) -> bool:
    if not settings.reset_key:
        return False
    return key == settings.reset_key


def is_authenticated(request: Request) -> bool:
    return request.session.get("authenticated") is True


def require_auth(request: Request):
    if not is_authenticated(request):
        raise HTTPException(status_code=303, detail="/login")


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await _seed_services()
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
        run_date=datetime.now() + timedelta(seconds=10),
        id="initial_scan",
    )
    yield
    scheduler.shutdown()


app = FastAPI(title="VerificationRotation", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, max_age=3600 * 24 * 7)
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
    scan_heartbeat = datetime.now()
    started = datetime.now()
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

        # Refresh heartbeat before the potentially long scan
        scan_heartbeat = datetime.now()

        index = build_scan_index(
            services, env,
            env_path=settings.env_file,
            skip_remote=False,
            cache_max_age=settings.cache_max_age_hours,
            remote_hosts=db_hosts,
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
                    update(Service)
                    .where(Service.id == sid)
                    .values(hit_count=total_hits)
                )
            await session.commit()

        error_msg = "; ".join(errors) if errors else None
        status = "completed_with_errors" if errors else "completed"
        async with async_session() as session:
            await session.execute(
                update(ScanLog)
                .where(ScanLog.id == log_id)
                .values(
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
                update(ScanLog)
                .where(ScanLog.id == log_id)
                .values(
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
    """Rotate all stale services one-by-one, skipping if scan or rotation active."""
    global auto_rotation_running
    if _scan_is_running() or _rotation_is_running() or auto_rotation_running:
        logger.info("Auto-rotate skipped — another operation in progress")
        return
    auto_rotation_running = True
    try:
        _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
        env = read_env(settings.env_file)
        db_hosts = await _get_db_hosts()

        async with async_session() as session:
            result = await session.execute(
                select(Service).where(Service.status == "stale")
            )
            stale_rows = result.scalars().all()

        # Also catch services whose age_days > 180 even if status not yet updated
        stale_ids: list[str] = []
        for row in stale_rows:
            stale_ids.append(row.id)
        async with async_session() as session:
            result = await session.execute(select(Service))
            for row in result.scalars().all():
                if row.id not in stale_ids and row.last_rotated:
                    age_days = (datetime.now() - row.last_rotated).days
                    if age_days > 180:
                        stale_ids.append(row.id)

        if not stale_ids:
            logger.info("Auto-rotate: no stale services found")
            return

        logger.info("Auto-rotate: rotating %d stale service(s)", len(stale_ids))

        global scan_index
        if not scan_index:
            scan_index = build_scan_index(
                services, env,
                env_path=settings.env_file,
                remote_hosts=db_hosts,
            )

        for sid in stale_ids:
            if sid not in services:
                continue
            svc = services[sid]
            if not svc.env_var or not env.get(svc.env_var):
                continue
            # Acquire rotation lock
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
                    bw_session=None,
                    remote_hosts=db_hosts,
                )
                if ok:
                    new_hash = hashlib.sha256(env.get(svc.env_var, "").encode()).hexdigest()[:16]
                    async with async_session() as session:
                        await session.execute(
                            update(Service)
                            .where(Service.id == sid)
                            .values(last_rotated=datetime.now(), current_hash=new_hash, status="ok")
                        )
                        session.add(RotationHistory(
                            service_id=sid,
                            old_hash="",
                            new_hash=new_hash,
                            success=1,
                            message="Auto-rotated (scheduled)",
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
    return {"status": "ok", "last_scan": last_scan_time.isoformat() if last_scan_time else None}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login_post(request: Request, password: str = Form(...)):
    if verify_password(password):
        request.session["authenticated"] = True
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid password"}, status_code=401)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "auto_rotate_hours": settings.auto_rotate_interval_hours,
    })


# ---------------------------------------------------------------------------
# API
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

    # Rotation lock — reject concurrent rotations
    if not dry_run and _rotation_is_running():
        raise HTTPException(
            status_code=409,
            detail=f"Rotation already in progress for '{rotation_in_progress['service_id']}'. Try again shortly.",
        )

    _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
    if service_id not in services:
        raise HTTPException(status_code=404, detail="Service not found")
    svc = services[service_id]

    env = read_env(settings.env_file)
    db_hosts = await _get_db_hosts()
    if not scan_index:
        scan_index = build_scan_index(services, env, env_path=settings.env_file, remote_hosts=db_hosts)

    bw_session = None
    if sync_bitwarden_flag and bw_available():
        bw_session = bw_get_session()
        if not bw_session:
            bw_password = os.environ.get("BW_PASSWORD", "").strip()
            if bw_password:
                bw_session = bw_unlock(bw_password)

    if not dry_run:
        rotation_in_progress = {"service_id": service_id, "started_at": datetime.now()}

    rotation_log = {}
    try:
        ok = rotate(
            service_id, svc, env, settings.env_file, scan_index,
            rotation_log=rotation_log,
            dry_run=dry_run,
            non_interactive=True,
            generate_passwords=generate_password,
            bw_session=bw_session,
            new_key=new_value,
            remote_hosts=db_hosts,
        )
    finally:
        if not dry_run:
            rotation_in_progress = None

    async with async_session() as session:
        if ok and not dry_run:
            new_hash = hashlib.sha256((new_value or env.get(svc.env_var, "")).encode()).hexdigest()[:16]
            await session.execute(
                update(Service)
                .where(Service.id == service_id)
                .values(last_rotated=datetime.now(), current_hash=new_hash, status="ok")
            )
            session.add(RotationHistory(
                service_id=service_id,
                old_hash="",
                new_hash=new_hash,
                success=1 if ok else 0,
                message="Rotated via web UI",
            ))
        await session.commit()

    return {"success": ok, "dry_run": dry_run}


@app.post("/api/rotate-all")
async def api_rotate_all(
    request: Request,
    dry_run: bool = Form(False),
    generate_password: bool = Form(False),
    sync_bitwarden_flag: bool = Form(False),
):
    require_auth(request)
    global scan_index, rotation_in_progress

    if not dry_run and _rotation_is_running():
        raise HTTPException(
            status_code=409,
            detail=f"Rotation already in progress for '{rotation_in_progress['service_id']}'.",
        )

    _, _, _, _, services = load_rotate_keys_config(settings.descriptions_path)
    env = read_env(settings.env_file)
    db_hosts = await _get_db_hosts()
    if not scan_index:
        scan_index = build_scan_index(services, env, env_path=settings.env_file, remote_hosts=db_hosts)

    bw_session = None
    if sync_bitwarden_flag and bw_available():
        bw_session = bw_get_session()
        if not bw_session:
            bw_password = os.environ.get("BW_PASSWORD", "").strip()
            if bw_password:
                bw_session = bw_unlock(bw_password)

    results = []
    for sid, svc in services.items():
        if not svc.env_var or not env.get(svc.env_var):
            continue
        if not dry_run:
            rotation_in_progress = {"service_id": sid, "started_at": datetime.now()}
        try:
            ok = rotate(
                sid, svc, env, settings.env_file, scan_index,
                rotation_log={},
                dry_run=dry_run,
                non_interactive=True,
                generate_passwords=generate_password,
                bw_session=bw_session,
                remote_hosts=db_hosts,
            )
        finally:
            if not dry_run:
                rotation_in_progress = None
        results.append({"service": sid, "success": ok})
        if ok and not dry_run:
            async with async_session() as session:
                new_hash = hashlib.sha256(env.get(svc.env_var, "").encode()).hexdigest()[:16]
                await session.execute(
                    update(Service)
                    .where(Service.id == sid)
                    .values(last_rotated=datetime.now(), current_hash=new_hash, status="ok")
                )
                session.add(RotationHistory(
                    service_id=sid,
                    old_hash="",
                    new_hash=new_hash,
                    success=1,
                    message="Rotated via bulk rotate-all",
                ))
                await session.commit()

    return {"results": results, "dry_run": dry_run}


@app.get("/hosts", response_class=HTMLResponse)
async def hosts_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("hosts.html", {"request": request})


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
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]


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
    async with async_session() as session:
        session.add(RemoteHost(
            label=label,
            host=host,
            user=user,
            search_dirs=search_dirs,
            db_refs=db_refs,
        ))
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
    async with async_session() as session:
        result = await session.execute(select(RemoteHost).where(RemoteHost.id == host_id))
        row = result.scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Host not found")
        row.label = label
        row.host = host
        row.user = user
        row.search_dirs = search_dirs
        row.db_refs = db_refs
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


@app.get("/ssh-keys", response_class=HTMLResponse)
async def ssh_keys_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("ssh_keys.html", {"request": request})


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
        session.add(SSHKey(
            name=name,
            public_key=public_key,
            private_key_path=private_path,
        ))
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


@app.post("/api/reset-password")
async def api_reset_password(request: Request, reset_key: str = Form(...), new_password: str = Form(...)):
    if not verify_reset_key(reset_key):
        raise HTTPException(status_code=403, detail="Invalid reset key")
    return {"success": True, "message": "Password reset acknowledged. Update ADMIN_PASSWORD in your .env and restart the container."}
