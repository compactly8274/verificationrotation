"""Core rotation logic — replace secrets in files, DBs, and remote hosts."""

import hashlib
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
from src.scanner import _key_matches, _key_replace, _ssh
from src.services_registry import ServiceDef


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
        import urllib.request
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
# Docker restart
# ---------------------------------------------------------------------------

def restart_docker_container(name: str) -> None:
    if not name:
        return
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get(name)
        container.restart()
        print(f"  ✓ Restarted Docker container '{name}'")
    except docker.errors.NotFound:
        print(f"  WARNING: Docker container '{name}' not found")
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
    for db_path_str, table, col in db_refs:
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
    py = f"""
import shutil, pathlib, re
OLD = {old!r}
NEW = {new!r}
PAT = re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(OLD) + r'(?![A-Za-z0-9_\\-./])')
for fp_str in {filepaths!r}:
    fp = pathlib.Path(fp_str)
    try:
        text = fp.read_text(errors='ignore')
        if PAT.search(text):
            tmp = fp.with_suffix(fp.suffix + '.tmp')
            tmp.write_text(PAT.sub(lambda _: NEW, text))
            shutil.move(str(tmp), str(fp))
            print(fp)
    except OSError as e:
        print(f'WARNING: {{e}}')
"""
    rc, out, err = _ssh(host, user, f"python3 -c {shlex.quote(py)}")
    if rc != 0:
        print(f"  WARNING: remote file replace on {host} failed: {err or 'ssh error'}")
        return []
    return [l for l in out.splitlines() if l and not l.startswith("WARNING")]


def replace_in_remote_dbs(host: str, user: str, old: str, new: str, db_refs: list) -> list[str]:
    if not db_refs:
        return []
    py = f"""
import sqlite3, shutil, pathlib, re
OLD = {old!r}
NEW = {new!r}
PAT = re.compile(r'(?<![A-Za-z0-9_\\-./])' + re.escape(OLD) + r'(?![A-Za-z0-9_\\-./])')
seen = set()
for db_path, table, col in {db_refs!r}:
    key = (db_path, table, col)
    if key in seen: continue
    seen.add(key)
    dp = pathlib.Path(db_path)
    if not dp.exists(): continue
    try:
        backup = dp.with_suffix('.db.bak')
        shutil.copy2(dp, backup)
        con = sqlite3.connect(dp)
        rows = con.execute(f"SELECT rowid, {{col}} FROM {{table}}").fetchall()
        updated = 0
        for rowid, blob in rows:
            if blob and PAT.search(blob):
                con.execute(f"UPDATE {{table}} SET {{col}}=? WHERE rowid=?", (PAT.sub(lambda _: NEW, blob), rowid))
                updated += 1
        if updated:
            con.commit()
            print(f"{{db_path}}  ({{table}}.{{col}}, {{updated}} row(s))")
        else:
            backup.unlink(missing_ok=True)
        con.close()
    except Exception as e:
        print(f'WARNING: {{e}}')
"""
    rc, out, err = _ssh(host, user, f"python3 -c {shlex.quote(py)}")
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

    if svc.health_url:
        ok, msg = _health_check(svc.health_url)
        if not ok:
            print(f"  ✗ Pre-flight health check failed: {msg}")
            log_audit(env_path, service_id, _key_hash(old_key), "", 0, 0, False, f"Pre-flight failed: {msg}")
            return False
        print(f"  ✓ Pre-flight health check passed ({msg})")

    file_hits = index.local_files.get(old_key, [])
    db_hits = index.local_dbs.get(old_key, [])
    remote_file_hits = {label: d.get(old_key, []) for label, d in index.remote_files.items() if d.get(old_key)}
    remote_db_hits = {label: d.get(old_key, []) for label, d in index.remote_dbs.items() if d.get(old_key)}

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

    if non_interactive:
        if not svc.auto_fetch and (svc.settings_url or has_hits):
            print(f"  [non-interactive] Skipping — requires manual UI interaction")
            log_audit(env_path, service_id, _key_hash(old_key), "", 0, 0, False, "Skipped in non-interactive mode")
            return False

    if not has_hits and not svc.settings_url and not svc.auto_fetch:
        print("  No references found and no settings URL — updating .env only.")
        if dry_run:
            print(f"  [dry-run] Would update ${svc.env_var} in {env_path}")
            return True
        if generate_passwords and is_password_service(svc):
            new_key = generate_password()
            print(f"  ✓ Auto-generated password: {new_key[:6]}...{new_key[-4:]}")
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
        local_new_key = svc.auto_fetch()
        if local_new_key and local_new_key != old_key:
            masked = local_new_key[:6] + "..." + local_new_key[-4:]
            print(f"  ✓ Auto-read new key from config file: {masked}")
        else:
            local_new_key = None
            print("  Could not auto-read (key unchanged or file missing)")

    if not local_new_key:
        if generate_passwords and is_password_service(svc):
            local_new_key = generate_password()
            print(f"  ✓ Auto-generated password: {local_new_key[:6]}...{local_new_key[-4:]}")
            print(f"  → Copy this password into the service if you haven't already.")
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

    if backup_dir:
        for f in file_hits:
            _backup_file(Path(f), backup_dir)
        for db_path_str, _, _ in (svc.db_refs or []):
            dp = Path(db_path_str)
            if dp.exists():
                _backup_file(dp, backup_dir)

    print(f"\n  Replacing in files...")
    changed_files = replace_in_files(old_key, local_new_key, file_hits)
    changed_dbs = replace_in_dbs(old_key, local_new_key, svc.db_refs) if svc.db_refs else []

    remote_changed_files: dict[str, list[str]] = {}
    remote_changed_dbs: dict[str, list[str]] = {}
    if remote_hosts is None:
        from src.services_registry import load_rotate_keys_config
        _, _, _, remote_hosts, _ = load_rotate_keys_config(Path("rotate_keys.yaml"))
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

    if svc.health_url:
        ok, msg = _health_check(svc.health_url, expected_key=old_key)
        if not ok:
            print(f"  ✗ Post-flight health check failed: {msg}")
        else:
            print(f"  ✓ Post-flight health check passed ({msg})")

    if svc.docker_name:
        restart_docker_container(svc.docker_name)

    if bw_session and svc.bitwarden:
        bw_ok, bw_msg = sync_bitwarden(svc, local_new_key, bw_session, env)
        if bw_ok:
            print(f"  ✓ {bw_msg}")
        else:
            print(f"  ⚠ Bitwarden sync skipped: {bw_msg}")

    log_audit(env_path, service_id, _key_hash(old_key), _key_hash(local_new_key),
              len(changed_files), len(changed_dbs), True)

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
