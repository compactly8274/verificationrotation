"""Core rotation logic — replace secrets in files, DBs, and remote hosts."""

import hashlib
import logging
import os
import re
import secrets
import shlex
import shutil
import sqlite3
import string
import subprocess
import time
from pathlib import Path
from typing import Optional

from src.bitwarden import sync_bitwarden
from src.env_manager import read_env, write_env
from src.notifications import send_notification
from src.scanner import ScanIndex, _key_matches, _key_replace, _ssh, _validate_db_ref, build_scan_index
from src.services_registry import ServiceDef

logger = logging.getLogger("verificationrotation")


def generate_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^*&*-_+=.?"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^*&*-_+=.?" for c in pwd)):
            return pwd


def is_password_service(svc: ServiceDef) -> bool:
    if not svc.env_var:
        return False
    return svc.env_var.endswith("_PASSWORD") or "password" in svc.display_name.lower()


# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------

def _health_check(url: str, expected_key: Optional[str] = None, timeout: int = 10) -> tuple[bool, str]:
    if not url:
        return True, "No health URL configured"
    try:
        import ssl
        import urllib.request
        from src.config import settings as _s
        ctx = ssl.create_default_context()
        if _s.health_check_skip_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if expected_key and expected_key in body:
                return False, "Response still contains old key"
            return True, f"HTTP {resp.status}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------

def _backup_dir(env_path: Path) -> Path:
    ts = time.strftime("%Y%m%d_%H%M%S")
    bp = env_path.parent / ".rotate_keys_backups" / ts
    bp.mkdir(parents=True, exist_ok=True)
    return bp


def _backup_file(src: Path, backup_dir: Path) -> Path:
    dest = backup_dir / src.name
    shutil.copy2(src, dest)
    return dest


def _restore_from_backup(backup_dir: Path, targets: list[Path]) -> None:
    for target in targets:
        src = backup_dir / target.name
        if src.exists():
            shutil.copy2(src, target)
            print(f"  Restored {target} from backup")


# ---------------------------------------------------------------------------
# Docker stop / start / restart
# ---------------------------------------------------------------------------

def _docker_client():
    import docker
    return docker.from_env()


def stop_docker_container(name: str) -> bool:
    if not name:
        return False
    try:
        container = _docker_client().containers.get(name)
        container.stop(timeout=30)
        print(f"  ✓ Stopped Docker container '{name}'")
        return True
    except Exception as exc:
        print(f"  WARNING: Could not stop Docker container '{name}': {exc}")
        return False


def start_docker_container(name: str) -> bool:
    if not name:
        return False
    try:
        container = _docker_client().containers.get(name)
        container.start()
        print(f"  ✓ Started Docker container '{name}'")
        return True
    except Exception as exc:
        print(f"  WARNING: Could not start Docker container '{name}': {exc}")
        return False


def restart_docker_container(name: str) -> None:
    if not name:
        return
    try:
        container = _docker_client().containers.get(name)
        container.restart()
        print(f"  ✓ Restarted Docker container '{name}'")
    except Exception as exc:
        print(f"  WARNING: Could not restart Docker container '{name}': {exc}")


# ---------------------------------------------------------------------------
# Replace helpers
# ---------------------------------------------------------------------------

def replace_in_files(old: str, new: str, filepaths: list[str]) -> list[str]:
    changed = []
    for fp_str in filepaths:
        fp = Path(fp_str)
        try:
            text = fp.read_text(errors="ignore")
            if not _key_matches(old, text):
                continue
            updated = _key_replace(old, new, text)
            tmp = fp.with_suffix(fp.suffix + ".tmp")
            tmp.write_text(updated)
            shutil.move(str(tmp), str(fp))
            changed.append(fp_str)
        except (PermissionError, OSError) as e:
            print(f"  WARNING: Could not update {fp}: {e}")
    return changed


def replace_in_dbs(old: str, new: str, db_refs: list) -> list[str]:
    changed = []
    seen: set[tuple] = set()
    for ref in db_refs:
        db_path_str, table, col = _validate_db_ref(*ref)
        key = (db_path_str, table, col)
        if key in seen:
            continue
        seen.add(key)
        dp = Path(db_path_str)
        if not dp.exists():
            continue
        try:
            backup = dp.with_suffix(".db.bak")
            shutil.copy2(dp, backup)
            con = sqlite3.connect(dp)
            cur = con.execute(f"SELECT rowid, {col} FROM {table}")
            rows = cur.fetchall()
            updated = 0
            for rowid, blob in rows:
                if blob and _key_matches(old, blob):
                    con.execute(
                        f"UPDATE {table} SET {col}=? WHERE rowid=?",
                        (_key_replace(old, new, blob), rowid),
                    )
                    updated += 1
            if updated:
                con.commit()
                changed.append(f"{db_path_str}  ({table}.{col}, {updated} row(s))")
            else:
                backup.unlink(missing_ok=True)
            con.close()
        except Exception as e:
            print(f"  WARNING: SQLite update failed for {db_path_str}: {e}")
    return changed


def replace_in_remote_files(host: str, user: str, old: str, new: str, filepaths: list) -> list[str]:
    if not filepaths:
        return []
    # Pass secrets via stdin instead of embedding in command line
    py = """
import shutil, sys, pathlib, re, json
data = json.load(sys.stdin)
sys.stdin.close()
OLD = data["old"]
NEW = data["new"]
PAT = re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(OLD) + r'(?![A-Za-z0-9_\\-./])')
for fp_str in data["files"]:
    fp = pathlib.Path(fp_str)
    try:
        text = fp.read_text(errors='ignore')
        if PAT.search(text):
            tmp = fp.with_suffix(fp.suffix + '.tmp')
            tmp.write_text(PAT.sub(lambda _: NEW, text))
            shutil.move(str(tmp), str(fp))
            print(fp)
    except OSError as e:
        print(f'WARNING: {e}')
"""
    stdin_data = json.dumps({"old": old, "new": new, "files": filepaths})
    rc, out, err = _ssh(host, user, f"python3 -c {shlex.quote(py)}", stdin_data=stdin_data)
    if rc != 0:
        print(f"  WARNING: remote file replace on {host} failed: {err or 'ssh error'}")
        return []
    return [l for l in out.splitlines() if l and not l.startswith("WARNING")]


def replace_in_remote_dbs(host: str, user: str, old: str, new: str, db_refs: list) -> list[str]:
    if not db_refs:
        return []
    # Pass secrets via stdin instead of embedding in command line
    py = """
import sqlite3, shutil, sys, pathlib, re, json
data = json.load(sys.stdin)
sys.stdin.close()
OLD = data["old"]
NEW = data["new"]
PAT = re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(OLD) + r'(?![A-Za-z0-9_\\-./])')
seen = set()
for db_path, table, col in data["db_refs"]:
    key = (db_path, table, col)
    if key in seen: continue
    seen.add(key)
    dp = pathlib.Path(db_path)
    if not dp.exists(): continue
    try:
        backup = dp.with_suffix('.db.bak')
        shutil.copy2(dp, backup)
        con = sqlite3.connect(dp)
        rows = con.execute(f"SELECT rowid, {col} FROM {table}").fetchall()
        updated = 0
        for rowid, blob in rows:
            if blob and PAT.search(blob):
                con.execute(f"UPDATE {table} SET {col}=? WHERE rowid=?", (PAT.sub(lambda _: NEW, blob), rowid))
                updated += 1
        if updated:
            con.commit()
            print(f"{db_path}  ({table}.{col}, {updated} row(s))")
        else:
            backup.unlink(missing_ok=True)
        con.close()
    except Exception as e:
        print(f'WARNING: {e}')
"""
    stdin_data = json.dumps({"old": old, "new": new, "db_refs": [list(r) for r in db_refs]})
    rc, out, err = _ssh(host, user, f"python3 -c {shlex.quote(py)}", stdin_data=stdin_data)
    if rc != 0:
        print(f"  WARNING: remote DB replace on {host} failed: {err or 'ssh error'}")
        return []
    return [l for l in out.splitlines() if l and not l.startswith("WARNING")]


# ---------------------------------------------------------------------------
# Audit / state helpers
# ---------------------------------------------------------------------------

def _key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def log_audit(
    env_path: Path,
    service_id: str,
    old_key_hash: str,
    new_key_hash: str,
    files_changed: int,
    dbs_changed: int,
    success: bool,
    message: str = "",
) -> None:
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "service": service_id,
        "old_key_hash": old_key_hash,
        "new_key_hash": new_key_hash,
        "files_changed": files_changed,
        "dbs_changed": dbs_changed,
        "success": success,
        "message": message,
    }
    ap = env_path.parent / ".rotate_keys_audit.jsonl"
    with ap.open("a", encoding="utf-8") as fh:
        fh.write(__import__('json').dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Post-rotation verification helpers
# ---------------------------------------------------------------------------

def _rescan_for_key(key: str, file_hits: list[str], db_refs: list, remote_hosts: list[dict], remote_file_hits: dict, remote_db_hits: dict) -> list[str]:
    """Re-scan all previously-hit locations for the old key. Returns list of paths still containing it."""
    remaining = []
    for fp_str in file_hits:
        fp = Path(fp_str)
        try:
            if fp.exists() and _key_matches(key, fp.read_text(errors="ignore")):
                remaining.append(fp_str)
        except (PermissionError, OSError):
            pass
    for ref in (db_refs or []):
        db_path_str, table, col = _validate_db_ref(*ref)
        dp = Path(db_path_str)
        if not dp.exists():
            continue
        try:
            con = sqlite3.connect(f"file:{dp}?mode=ro", uri=True)
            rows = con.execute(f"SELECT {col} FROM {table}").fetchall()
            con.close()
            for (blob,) in rows:
                if blob and _key_matches(key, blob):
                    remaining.append(f"{db_path_str} ({table}.{col})")
                    break
        except Exception:
            pass
    for rh in remote_hosts:
        label = rh["label"]
        if not remote_file_hits.get(label) and not remote_db_hits.get(label):
            continue
        from src.scanner import scan_remote_files_for_keys, scan_remote_dbs_for_keys
        from src.services_registry import load_rotate_keys_config
        from src.config import settings as _s
        search_dirs, search_exts, skip_dirs, _, _ = load_rotate_keys_config(_s.descriptions_path)
        rf = scan_remote_files_for_keys(rh["host"], rh["user"], rh["search_dirs"], search_exts, skip_dirs, {key})
        rd = scan_remote_dbs_for_keys(rh["host"], rh["user"], rh["db_refs"], {key})
        remaining.extend(rf.get(key, []))
        remaining.extend(rd.get(key, []))
    return remaining


def _rollback(
    env_path: Path,
    env: dict[str, str],
    svc: "ServiceDef",
    old_key: str,
    local_new_key: str,
    changed_files: list[str],
    changed_dbs: list[str],
    backup_dir: Optional[Path],
    remote_hosts: list[dict],
    remote_file_hits: Optional[dict[str, list[str]]] = None,
    remote_db_hits: Optional[dict[str, list]] = None,
) -> None:
    """Restore files from backup and revert .env to old_key."""
    print("  ⟳ Rolling back...")
    if backup_dir:
        _restore_from_backup(backup_dir, [Path(f) for f in changed_files])

    # Also reverse any DB .bak files
    for ref in (svc.db_refs or []):
        db_path_str, _, _ = _validate_db_ref(*ref)
        dp = Path(db_path_str)
        bak = dp.with_suffix(".db.bak")
        if bak.exists():
            shutil.copy2(bak, dp)
            bak.unlink(missing_ok=True)
            print(f"  ✓ Restored DB {dp} from backup")

    # Revert in-memory files that may not have backups
    replace_in_files(local_new_key, old_key, changed_files)
    if svc.db_refs:
        replace_in_dbs(local_new_key, old_key, svc.db_refs)

    # Revert remote — use the actual remote file/DB hits, not local paths
    for rh in remote_hosts:
        label = rh["label"]
        remote_files = (remote_file_hits or {}).get(label, [])
        remote_dbs = (remote_db_hits or {}).get(label, [])
        if remote_files:
            replace_in_remote_files(rh["host"], rh["user"], local_new_key, old_key, remote_files)
        if remote_dbs:
            replace_in_remote_dbs(rh["host"], rh["user"], local_new_key, old_key, rh.get("db_refs", []))

    # Revert .env
    env[svc.env_var] = old_key
    write_env(env_path, {svc.env_var: old_key})
    print("  ✓ Rollback complete — .env restored to old key")


# ---------------------------------------------------------------------------
# Core rotate function
# ---------------------------------------------------------------------------

def rotate(
    service_id: str,
    svc: ServiceDef,
    env: dict[str, str],
    env_path: Path,
    index: "ScanIndex",
    state: Optional[dict] = None,
    rotation_log: Optional[dict] = None,
    dry_run: bool = False,
    non_interactive: bool = False,
    backup_dir: Optional[Path] = None,
    generate_passwords: bool = False,
    bw_session: Optional[str] = None,
    new_key: Optional[str] = None,
    remote_hosts: Optional[list[dict]] = None,
    known_hits: int = -1,  # -1 = unknown; caller supplies from DB to avoid async-in-sync
) -> bool:
    print(f"\n{'─'*60}")
    print(f"  {svc.display_name}")
    print(f"{'─'*60}")

    if not svc.env_var:
        print(f"  {svc.note}")
        return True

    old_key = env.get(svc.env_var, "")
    if not old_key:
        print(f"  ${svc.env_var} not set in {env_path.resolve()} — skipping")
        return True

    if svc.note:
        print(f"  Note: {svc.note}")

    if remote_hosts is None:
        from src.services_registry import load_rotate_keys_config
        _, _, _, remote_hosts, _ = load_rotate_keys_config(env_path.parent / "rotate_keys.yaml")

    # ── Pre-flight health check ───────────────────────────────────────────
    if svc.health_url:
        ok, msg = _health_check(svc.health_url)
        if not ok:
            print(f"  ✗ Pre-flight health check failed: {msg}")
            log_audit(env_path, service_id, _key_hash(old_key), "", 0, 0, False, f"Pre-flight failed: {msg}")
            send_notification("rotation_failed", svc.display_name, f"Pre-flight health check failed: {msg}", service_id=service_id)
            return False
        print(f"  ✓ Pre-flight health check passed ({msg})")

    file_hits = index.local_files.get(old_key, [])
    db_hits = index.local_dbs.get(old_key, [])
    remote_file_hits = {label: d.get(old_key, []) for label, d in index.remote_files.items() if d.get(old_key)}
    remote_db_hits = {label: d.get(old_key, []) for label, d in index.remote_dbs.items() if d.get(old_key)}

    total_hits = len(file_hits) + len(db_hits) + sum(len(v) for v in remote_file_hits.values()) + sum(len(v) for v in remote_db_hits.values())

    if file_hits:
        print(f"  Local text files ({len(file_hits)}):")
        for f in file_hits:
            print(f"    {f}")
    if db_hits:
        print(f"  Local SQLite databases ({len(db_hits)}):")
        for d in db_hits:
            print(f"    {d}")
    for label, hits in remote_file_hits.items():
        print(f"  {label} text files ({len(hits)}):")
        for f in hits:
            print(f"    {f}")
    for label, hits in remote_db_hits.items():
        print(f"  {label} SQLite databases ({len(hits)}):")
        for d in hits:
            print(f"    {d}")
    if not file_hits and not db_hits and not remote_file_hits and not remote_db_hits:
        print("  No references found outside of .env")

    has_hits = any([file_hits, db_hits, remote_file_hits, remote_db_hits])

    # ── Pre-flight: abort if key has known hits but scan finds none ───────
    # known_hits is supplied by the async caller (main.py) to avoid the
    # "event loop already running" problem with asyncio inside sync code.
    if non_interactive and not dry_run and known_hits > 0 and total_hits == 0:
        msg = f"Key has {known_hits} known reference(s) but scan found 0 — refusing to rotate (stale index?)"
        print(f"  ✗ {msg}")
        log_audit(env_path, service_id, _key_hash(old_key), "", 0, 0, False, msg)
        send_notification("rotation_failed", svc.display_name, msg, service_id=service_id)
        return False

    if non_interactive:
        if not svc.auto_fetch and (svc.settings_url or has_hits):
            print(f"  [non-interactive] Skipping — requires manual UI interaction (open {svc.settings_url or 'the service UI'} to rotate manually)")
            return True  # not a failure — just needs manual action

    if not has_hits and not svc.settings_url and not svc.auto_fetch:
        print("  No references found and no settings URL — updating .env only.")
        if dry_run:
            print(f"  [dry-run] Would update ${svc.env_var} in {env_path}")
            return True
        if generate_passwords and is_password_service(svc):
            new_key = generate_password()
            logger.info("Auto-generated password for %s", svc.env_var)
            print("  ✓ Auto-generated password (check .env for the value)")
        else:
            new_key = input("  Paste new key/password (or blank to skip): ").strip()
        if not new_key or new_key == old_key:
            print("  No change — skipping")
            return True
        env[svc.env_var] = new_key
        write_env(env_path, {svc.env_var: new_key})
        print(f"  ✓ Updated {env_path}  (${svc.env_var})")
        return True

    if not non_interactive:
        if svc.settings_url:
            print(f"\n  → Open: {svc.settings_url}")
        if generate_passwords and is_password_service(svc):
            print("  → A new password will be generated for you. Update the service, then press Enter.")
        else:
            print("  → Rotate / regenerate the key there, then press Enter.")
        input("  [Press Enter when done] ")

    local_new_key: Optional[str] = new_key
    if not local_new_key and svc.auto_fetch:
        fetched = svc.auto_fetch()
        if fetched and fetched != old_key:
            local_new_key = fetched
            logger.info("Auto-read new key from config file for %s", svc.env_var)
            print(f"  ✓ Auto-read new key from config file ({svc.env_var})")
        elif svc.auto_write and non_interactive:
            # *arr apps hold the API key in memory and write it back to config.xml on
            # graceful shutdown. Stop the container first so it can't overwrite our change.
            if svc.docker_name:
                print(f"  Stopping '{svc.docker_name}' before writing config file...")
                stop_docker_container(svc.docker_name)
            # Password services get a strong mixed-character password;
            # API-key services get a 32-char hex string matching *arr format.
            generated = generate_password() if is_password_service(svc) else secrets.token_hex(16)
            if svc.auto_write(generated):
                local_new_key = generated
                logger.info("Generated and wrote new API key for %s", svc.env_var)
                print(f"  ✓ Generated and wrote new API key to config file ({svc.env_var})")
            else:
                print(f"  ✗ auto_write failed — could not update config file for {svc.env_var}")
                if svc.docker_name:
                    start_docker_container(svc.docker_name)  # restore service even on failure
                log_audit(env_path, service_id, _key_hash(old_key), "", 0, 0, False, "auto_write to config file failed")
                send_notification("rotation_failed", svc.display_name, "auto_write to config file failed", service_id=service_id)
                return False
        else:
            local_new_key = None
            print("  Could not auto-read (key unchanged or file missing)")

    if not local_new_key:
        if generate_passwords and is_password_service(svc):
            local_new_key = generate_password()
            logger.info("Auto-generated password for %s", svc.env_var)
            print("  ✓ Auto-generated password (check .env for the value)")
            print("  → Copy this password into the service if you haven't already.")
        elif not non_interactive:
            local_new_key = input("  Paste new key/password: ").strip()

    if not local_new_key or local_new_key == old_key:
        print("  No change — skipping")
        return True

    if dry_run:
        print("\n  [dry-run] Would replace in:")
        for f in file_hits:
            print(f"    {f}")
        for d in db_hits:
            print(f"    {d}")
        for label, hits in remote_file_hits.items():
            for f in hits:
                print(f"    [{label}] {f}")
        for label, hits in remote_db_hits.items():
            for d in hits:
                print(f"    [{label}] {d}")
        print(f"  [dry-run] Would update {env_path}  (${svc.env_var})")
        return True

    # ── Ensure backup dir exists for rollback ─────────────────────────────
    if not backup_dir:
        backup_dir = _backup_dir(env_path)

    for f in file_hits:
        _backup_file(Path(f), backup_dir)
    for ref in (svc.db_refs or []):
        db_path_str, _, _ = _validate_db_ref(*ref)
        dp = Path(db_path_str)
        if dp.exists():
            _backup_file(dp, backup_dir)

    send_notification(
        "rotation_start", svc.display_name,
        f"Starting rotation for {svc.display_name}",
        service_id=service_id,
        files=len(file_hits),
        dbs=len(db_hits),
    )

    print(f"\n  Replacing in files...")
    changed_files = replace_in_files(old_key, local_new_key, file_hits)
    changed_dbs = replace_in_dbs(old_key, local_new_key, svc.db_refs) if svc.db_refs else []

    remote_changed_files: dict[str, list[str]] = {}
    remote_changed_dbs: dict[str, list[str]] = {}
    for rh in remote_hosts:
        label = rh["label"]
        hits = remote_file_hits.get(label, [])
        rcf = replace_in_remote_files(rh["host"], rh["user"], old_key, local_new_key, hits)
        rcd = replace_in_remote_dbs(rh["host"], rh["user"], old_key, local_new_key, rh["db_refs"])
        if rcf:
            remote_changed_files[label] = rcf
        if rcd:
            remote_changed_dbs[label] = rcd

    env[svc.env_var] = local_new_key
    write_env(env_path, {svc.env_var: local_new_key})

    total = (len(changed_files) + len(changed_dbs)
             + sum(len(v) for v in remote_changed_files.values())
             + sum(len(v) for v in remote_changed_dbs.values()))
    if changed_files:
        print(f"  ✓ Updated {len(changed_files)} local text file(s)")
        for f in changed_files:
            print(f"    {f}")
    if changed_dbs:
        print(f"  ✓ Updated {len(changed_dbs)} local database(s)")
        for d in changed_dbs:
            print(f"    {d}")
    for label, hits in remote_changed_files.items():
        print(f"  ✓ Updated {len(hits)} {label} text file(s)")
        for f in hits:
            print(f"    {f}")
    for label, hits in remote_changed_dbs.items():
        print(f"  ✓ Updated {len(hits)} {label} database(s)")
        for d in hits:
            print(f"    {d}")
    print(f"  ✓ Updated {env_path}  (${svc.env_var})")
    print(f"  ✓ Done — {total} location(s) updated")
    if rotation_log is not None:
        rotation_log[service_id] = time.time()

    # ── Post-rotation verification ────────────────────────────────────────
    print("  Verifying old key no longer present...")
    still_present = _rescan_for_key(old_key, file_hits, svc.db_refs, remote_hosts, remote_file_hits, remote_db_hits)
    if still_present:
        msg = f"Old key still found in {len(still_present)} location(s) after rotation — rolling back"
        print(f"  ✗ {msg}")
        for p in still_present:
            print(f"    {p}")
        _rollback(env_path, env, svc, old_key, local_new_key, changed_files, changed_dbs, backup_dir, remote_hosts, remote_file_hits=remote_file_hits, remote_db_hits=remote_db_hits)
        log_audit(env_path, service_id, _key_hash(old_key), _key_hash(local_new_key), len(changed_files), len(changed_dbs), False, f"Rolled back: {msg}")
        send_notification("rotation_rollback", svc.display_name, msg, service_id=service_id, still_present=len(still_present))
        return False
    print("  ✓ Post-rotation verification passed — old key absent everywhere")

    if svc.health_url:
        ok, msg = _health_check(svc.health_url, expected_key=old_key)
        if not ok:
            print(f"  ✗ Post-flight health check failed: {msg}")
        else:
            print(f"  ✓ Post-flight health check passed ({msg})")

    if svc.docker_name:
        restart_docker_container(svc.docker_name)

    # ── Bitwarden sync (failure is fatal when explicitly requested) ───────
    if bw_session and svc.bitwarden:
        bw_ok, bw_msg = sync_bitwarden(svc, local_new_key, bw_session, env)
        if bw_ok:
            print(f"  ✓ {bw_msg}")
        else:
            print(f"  ✗ Bitwarden sync FAILED: {bw_msg}")
            log_audit(env_path, service_id, _key_hash(old_key), _key_hash(local_new_key),
                      len(changed_files), len(changed_dbs), False, f"Bitwarden sync failed: {bw_msg}")
            send_notification("rotation_failed", svc.display_name, f"Files rotated but Bitwarden sync failed: {bw_msg}", service_id=service_id, files_changed=total)
            return False

    log_audit(env_path, service_id, _key_hash(old_key), _key_hash(local_new_key),
              len(changed_files), len(changed_dbs), True)

    send_notification(
        "rotation_success", svc.display_name,
        f"Successfully rotated {svc.display_name}",
        service_id=service_id,
        files_changed=total,
    )

    if state is not None:
        state.setdefault("completed", [])
        if service_id not in state["completed"]:
            state["completed"].append(service_id)
        state.setdefault("services", {})
        state["services"][service_id] = {
            "status": "completed",
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "old_key_hash": _key_hash(old_key),
            "new_key_hash": _key_hash(local_new_key),
        }

    return True
