#!/usr/bin/env python3
"""web_ui.py — Browser dashboard for key rotation.

Usage:
    pip install flask
    python3 web_ui.py [--port 8765] [--env /path/to/.env]
"""

import argparse
import importlib.util
import io
import json
import queue
import sys
import threading
import time
from pathlib import Path

try:
    from flask import Flask, Response, jsonify, request, stream_with_context
except ImportError:
    print("Flask not installed. Run:  pip install flask")
    sys.exit(1)

# ── Load rotate_keys without running main() ──────────────────────────────────
_HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("rotate_keys", _HERE / "rotate_keys.py")
rk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rk)

SERVICES     = rk.SERVICES
SEARCH_DIRS  = rk.SEARCH_DIRS
SKIP_DIRS    = rk.SKIP_DIRS
REMOTE_HOSTS = rk.REMOTE_HOSTS

app = Flask(__name__)
_ENV_PATH: Path = Path(".env")
_lock = threading.Lock()
_scan_index = None   # type: ignore


def _env() -> dict:
    return rk.read_env(_ENV_PATH)


# ── SSE helpers ──────────────────────────────────────────────────────────────

def _sse(event: str, data: str) -> str:
    return f"event: {event}\ndata: {data}\n\n"

def _log(msg: str) -> str:
    return _sse("log", msg.rstrip().replace("\n", " | "))

def _done(obj: dict) -> str:
    return _sse("done", json.dumps(obj))


class _Capture(io.TextIOBase):
    def __init__(self, q: queue.Queue):
        self._q = q
    def write(self, s: str) -> int:
        if s and s.strip():
            self._q.put(_log(s.rstrip()))
        return len(s)
    def flush(self): pass


def _sse_stream(worker):
    q: queue.Queue = queue.Queue()
    def _run():
        try:
            worker(q)
        except Exception as exc:
            q.put(_log(f"ERROR: {exc}"))
            q.put(_done({"error": str(exc)}))
        finally:
            q.put(None)
    threading.Thread(target=_run, daemon=True).start()
    def _gen():
        while True:
            item = q.get()
            if item is None:
                break
            yield item
    return Response(stream_with_context(_gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/services")
def api_services():
    env = _env()
    rlog = rk.load_rotation_log()
    out = []
    for sid, svc in SERVICES.items():
        val = env.get(svc.env_var, "") if svc.env_var else ""
        age = rk.days_since_rotated(sid, rlog)
        masked = ((val[:4] + "…" + val[-4:]) if len(val) > 8 else "***") if val else ""
        out.append({
            "id": sid,
            "display_name": svc.display_name.split("←")[0].strip(),
            "env_var": svc.env_var or "",
            "settings_url": svc.settings_url or "",
            "has_key": bool(val),
            "masked": masked,
            "auto_fetch": svc.auto_fetch is not None,
            "auto_write": svc.auto_write is not None,
            "has_db_refs": bool(svc.db_refs),
            "note": svc.note or "",
            "days_since_rotated": age,
            "priority": sid in ("npm", "pangolin", "miniflux"),
        })
    return jsonify(out)


@app.route("/api/services/<sid>/fetch-key")
def api_fetch_key(sid: str):
    svc = SERVICES.get(sid)
    if not svc:
        return jsonify({"error": "unknown service"}), 404
    if not svc.auto_fetch:
        return jsonify({"error": "no auto_fetch configured"}), 400
    try:
        val = svc.auto_fetch()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    if not val:
        return jsonify({"error": "returned nothing"}), 404
    env = _env()
    current = env.get(svc.env_var, "") if svc.env_var else ""
    masked = (val[:4] + "…" + val[-4:]) if len(val) > 8 else "***"
    return jsonify({"value": val, "masked": masked, "matches_env": val == current})


@app.route("/api/audit")
def api_audit():
    ap = rk._audit_path(_ENV_PATH)
    entries = []
    if ap.exists():
        for line in ap.read_text().splitlines():
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
    entries.reverse()
    return jsonify(entries)


@app.route("/api/discover")
def api_discover():
    if not rk._AUTO_DISCOVER_AVAILABLE:
        def _err(q):
            q.put(_log("Auto-discover unavailable — src/ package missing."))
            q.put(_done({"results": []}))
        return _sse_stream(_err)

    def _worker(q):
        import contextlib
        env = _env()
        results = []
        with contextlib.redirect_stdout(_Capture(q)):
            try:
                detected = rk.detect_service_paths(SEARCH_DIRS)
                for sid, config_path in detected.items():
                    if sid not in SERVICES:
                        continue
                    svc = SERVICES[sid]
                    sig = getattr(rk, "APP_SIGNATURES", {}).get(sid)
                    if not sig:
                        continue
                    changed = False
                    if svc.auto_fetch is None:
                        f = rk.build_detected_fetcher(sig, config_path)
                        if f:
                            svc.auto_fetch = f
                            changed = True
                    if svc.auto_write is None:
                        w = rk.build_detected_writer(sig, config_path)
                        if w:
                            svc.auto_write = w
                    if changed:
                        q.put(_log(f"✓ {svc.display_name} → {config_path}"))
            except Exception as exc:
                q.put(_log(f"Path detection error: {exc}"))

            try:
                from src.key_discovery import discover_keys
                for r in discover_keys(SERVICES, env, SEARCH_DIRS, SKIP_DIRS):
                    masked = (r.value[:4] + "…" + r.value[-4:]) if len(r.value) > 8 else "***"
                    q.put(_log(f"{r.display_name}: [{masked}] via {r.strategy} ← {r.source_file}"))
                    results.append({
                        "service_id": r.service_id, "display_name": r.display_name,
                        "env_var": r.env_var, "masked": masked,
                        "source_file": r.source_file, "confidence": r.confidence,
                        "strategy": r.strategy, "host": "local",
                    })
            except Exception as exc:
                q.put(_log(f"Key discovery error: {exc}"))

            if REMOTE_HOSTS:
                try:
                    from src.key_discovery import discover_remote_keys
                    for rhost in REMOTE_HOSTS:
                        label = rhost.get("label", rhost.get("host", "?"))
                        host = rhost.get("host", "")
                        if not host:
                            continue
                        q.put(_log(f"Scanning {label} ({host})..."))
                        try:
                            for r in discover_remote_keys(
                                host=host, user=rhost.get("user", "root"),
                                services=SERVICES, env=env,
                                search_dirs=rhost.get("search_dirs", SEARCH_DIRS),
                                key_path=rhost.get("key_path"),
                            ):
                                masked = (r.value[:4] + "…" + r.value[-4:]) if len(r.value) > 8 else "***"
                                q.put(_log(f"[{label}] {r.display_name}: [{masked}] ← {r.source_file}"))
                                results.append({
                                    "service_id": r.service_id, "display_name": r.display_name,
                                    "env_var": r.env_var, "masked": masked,
                                    "source_file": r.source_file, "confidence": r.confidence,
                                    "strategy": r.strategy, "host": label,
                                })
                        except Exception as exc:
                            q.put(_log(f"WARNING: {label} failed: {exc}"))
                except ImportError:
                    pass

        q.put(_done({"results": results}))

    return _sse_stream(_worker)


@app.route("/api/scan")
def api_scan():
    def _worker(q):
        import contextlib
        global _scan_index
        env = _env()
        with contextlib.redirect_stdout(_Capture(q)):
            try:
                idx = rk.build_scan_index(SERVICES, env, env_path=_ENV_PATH,
                                           skip_remote=False, no_cache=True)
                with _lock:
                    _scan_index = idx
                hits = []
                for key, files in idx.local_files.items():
                    for sid, svc in SERVICES.items():
                        if svc.env_var and env.get(svc.env_var) == key:
                            for f in files:
                                hits.append({"sid": sid, "name": svc.display_name,
                                             "path": f, "type": "file", "host": "local"})
                for key, dbs in idx.local_dbs.items():
                    for sid, svc in SERVICES.items():
                        if svc.env_var and env.get(svc.env_var) == key:
                            for d in dbs:
                                hits.append({"sid": sid, "name": svc.display_name,
                                             "path": d, "type": "db", "host": "local"})
                for label, km in idx.remote_files.items():
                    for key, files in km.items():
                        for sid, svc in SERVICES.items():
                            if svc.env_var and env.get(svc.env_var) == key:
                                for f in files:
                                    hits.append({"sid": sid, "name": svc.display_name,
                                                 "path": f, "type": "file", "host": label})
                for label, km in idx.remote_dbs.items():
                    for key, dbs in km.items():
                        for sid, svc in SERVICES.items():
                            if svc.env_var and env.get(svc.env_var) == key:
                                for d in dbs:
                                    hits.append({"sid": sid, "name": svc.display_name,
                                                 "path": d, "type": "db", "host": label})
                q.put(_done({"hits": hits}))
            except Exception as exc:
                q.put(_log(f"ERROR: {exc}"))
                q.put(_done({"error": str(exc), "hits": []}))

    return _sse_stream(_worker)


@app.route("/api/services/<sid>/rotate", methods=["POST"])
def api_rotate(sid: str):
    svc = SERVICES.get(sid)
    if not svc:
        return jsonify({"error": "unknown service"}), 404

    body = request.get_json(silent=True) or {}
    new_key = body.get("new_key", "").strip()
    dry_run = bool(body.get("dry_run", False))
    auto_write_en = bool(body.get("auto_write", False))

    if not new_key:
        return jsonify({"error": "new_key is required"}), 400

    def _worker(q):
        import contextlib
        global _scan_index
        env = _env()
        old_key = env.get(svc.env_var, "") if svc.env_var else ""

        with contextlib.redirect_stdout(_Capture(q)):
            if not old_key:
                q.put(_log(f"${svc.env_var} not set in .env"))
                q.put(_done({"success": False, "reason": "no_old_key"}))
                return
            if new_key == old_key:
                q.put(_log("New key matches current key — no change needed"))
                q.put(_done({"success": False, "reason": "same_key"}))
                return

            with _lock:
                idx = _scan_index

            if idx is None:
                q.put(_log("Building scan index..."))
                idx = rk.build_scan_index(SERVICES, env, env_path=_ENV_PATH,
                                           skip_remote=False, no_cache=True)
                with _lock:
                    _scan_index = idx

            file_hits = idx.local_files.get(old_key, [])
            db_refs = svc.db_refs or []

            if dry_run:
                q.put(_log(f"[dry-run] Would update {len(file_hits)} file(s), {len(db_refs)} DB ref(s)"))
                for f in file_hits:
                    q.put(_log(f"  file: {f}"))
                for dr in db_refs:
                    q.put(_log(f"  db:   {dr[0]}"))
                q.put(_done({"success": True, "dry_run": True}))
                return

            if svc.auto_write and auto_write_en:
                ok = svc.auto_write(new_key)
                q.put(_log("✓ Auto-wrote to service config" if ok
                           else "WARNING: auto-write to config failed"))

            changed_f = rk.replace_in_files(old_key, new_key, file_hits)
            if changed_f:
                q.put(_log(f"✓ {len(changed_f)} local file(s) updated"))
                for f in changed_f:
                    q.put(_log(f"  {f}"))

            changed_d = rk.replace_in_dbs(old_key, new_key, db_refs)
            if changed_d:
                q.put(_log(f"✓ {len(changed_d)} local DB(s) updated"))
                for d in changed_d:
                    q.put(_log(f"  {d}"))

            for rhost in REMOTE_HOSTS:
                label = rhost["label"]
                rh_hits = idx.remote_files.get(label, {}).get(old_key, [])
                rcf = rk.replace_in_remote_files(rhost["host"], rhost["user"],
                                                  old_key, new_key, rh_hits)
                rcd = rk.replace_in_remote_dbs(rhost["host"], rhost["user"],
                                                old_key, new_key, rhost["db_refs"])
                if rcf:
                    q.put(_log(f"✓ {len(rcf)} {label} file(s) updated"))
                if rcd:
                    q.put(_log(f"✓ {len(rcd)} {label} DB(s) updated"))

            env[svc.env_var] = new_key
            rk.write_env(_ENV_PATH, {svc.env_var: new_key})
            q.put(_log(f"✓ .env updated  (${svc.env_var})"))

            for _mirror in getattr(rk, "ENV_MIRRORS", []):
                _mp = Path(_mirror)
                if _mp.parent.exists():
                    rk.write_env(_mp, {svc.env_var: new_key})
                    q.put(_log(f"✓ Mirrored → {_mp}"))

            rk.log_audit(_ENV_PATH, sid, rk._key_hash(old_key), rk._key_hash(new_key),
                         len(changed_f), len(changed_d), True)
            rlog = rk.load_rotation_log()
            rlog[sid] = time.time()
            rk.save_rotation_log(rlog)

            with _lock:
                _scan_index = None

            q.put(_log("✓ Done"))
            q.put(_done({"success": True}))

    return _sse_stream(_worker)


# ── HTML frontend ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return _HTML


_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Key Rotation</title>
<style>
:root {
  --bg:     #0f1117;
  --bg2:    #1a1d27;
  --bg3:    #232637;
  --border: #2e3146;
  --text:   #e2e4f0;
  --text2:  #8b8fa8;
  --accent: #5865f2;
  --accent2:#4752c4;
  --green:  #3ba55c;
  --red:    #ed4245;
  --yellow: #faa61a;
  --r:      8px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:14px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
#app{display:flex;flex-direction:column;height:100vh}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:16px}
header h1{font-size:16px;font-weight:600}
#env-status{color:var(--text2);font-size:13px}
nav{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 20px;display:flex;gap:2px}
.nav-btn{background:none;border:none;color:var(--text2);cursor:pointer;padding:10px 14px;font-size:13px;font-weight:500;border-bottom:2px solid transparent;transition:color .15s,border-color .15s}
.nav-btn:hover{color:var(--text)}
.nav-btn.active{color:var(--text);border-bottom-color:var(--accent)}
main{flex:1;overflow-y:auto;padding:20px}
.tab{display:none}
.tab.active{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);padding:14px;display:flex;flex-direction:column;gap:8px}
.card.priority{border-left:3px solid var(--red)}
.card-header{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}
.card-name{font-weight:600;font-size:14px;line-height:1.3}
.card-envvar{font-family:monospace;font-size:11px;color:var(--text2)}
.card-meta{display:flex;flex-wrap:wrap;gap:4px}
.badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:500}
.bg{background:var(--bg3);color:var(--text2)}
.bgreen{background:#1a3a25;color:#4ade80}
.bred{background:#3a1a1a;color:#f87171}
.bblue{background:#1a2040;color:#93c5fd}
.byellow{background:#3a2e0a;color:#fde68a}
.masked{font-family:monospace;font-size:12px;color:var(--text2)}
.note{font-size:12px;color:var(--yellow);line-height:1.4}
.card-actions{display:flex;gap:6px;margin-top:4px;flex-wrap:wrap}
.age{font-size:12px}
button,.btn{cursor:pointer;border:none;border-radius:6px;font-size:13px;font-weight:500;padding:6px 12px;transition:background .15s,opacity .15s;white-space:nowrap;font-family:inherit}
.bp{background:var(--accent);color:#fff}
.bp:hover{background:var(--accent2)}
.bs{background:var(--bg3);color:var(--text);border:1px solid var(--border)}
.bs:hover{background:var(--border)}
.sm{padding:4px 10px;font-size:12px}
button:disabled,.btn:disabled{opacity:.5;cursor:not-allowed}
.log-wrap{background:#0b0d14;border:1px solid var(--border);border-radius:var(--r);padding:12px;font-family:monospace;font-size:12px;line-height:1.6;max-height:300px;overflow-y:auto;white-space:pre-wrap;color:#b0b8d0;margin-top:12px}
.lok{color:#4ade80}
.lwarn{color:var(--yellow)}
.lerr{color:#f87171}
.tbl{width:100%;border-collapse:collapse;margin-top:12px}
.tbl th{text-align:left;padding:8px 12px;font-size:12px;font-weight:600;color:var(--text2);border-bottom:1px solid var(--border);background:var(--bg2)}
.tbl td{padding:8px 12px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:top}
.tbl tr:hover td{background:var(--bg3)}
.sec-hdr{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.sec-hdr h2{font-size:15px;font-weight:600}
.sec-hdr p{color:var(--text2);font-size:13px}
#modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;align-items:center;justify-content:center}
#modal-overlay.open{display:flex}
#modal{background:var(--bg2);border:1px solid var(--border);border-radius:12px;width:560px;max-width:95vw;max-height:90vh;overflow-y:auto;padding:24px}
#modal h2{font-size:16px;margin-bottom:4px}
.modal-sub{color:var(--text2);font-size:13px;margin-bottom:16px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.frow{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.frow label{font-size:12px;color:var(--text2);font-weight:500}
input[type=text],input[type=password]{background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font-size:13px;font-family:monospace;width:100%}
input[type=text]:focus,input[type=password]:focus{outline:none;border-color:var(--accent)}
.chk-row{display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:10px}
.chk-row input[type=checkbox]{cursor:pointer;width:15px;height:15px;accent-color:var(--accent)}
.m-actions{display:flex;gap:8px;margin-top:16px;flex-wrap:wrap}
#kw{display:flex;gap:8px}
#kw input{flex:1}
#toast{position:fixed;bottom:20px;right:20px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px 16px;font-size:13px;z-index:200;opacity:0;transition:opacity .3s;max-width:300px}
#toast.show{opacity:1}
#toast.ok{border-left:3px solid var(--green)}
#toast.err{border-left:3px solid var(--red)}
.empty{color:var(--text2);font-size:13px;padding:20px 0;text-align:center}
</style>
</head>
<body>
<div id="app">
  <header>
    <h1>Key Rotation</h1>
    <span id="env-status">Loading...</span>
  </header>
  <nav>
    <button class="nav-btn active" onclick="showTab('services')">Services</button>
    <button class="nav-btn" onclick="showTab('discover')">Auto-Discover</button>
    <button class="nav-btn" onclick="showTab('scan')">Scan</button>
    <button class="nav-btn" onclick="showTab('audit')">Audit Log</button>
  </nav>
  <main>
    <div id="tab-services" class="tab active">
      <div class="sec-hdr">
        <h2>Services</h2>
        <button class="btn bs sm" onclick="loadServices()">Refresh</button>
      </div>
      <div id="cards" class="cards"><div class="empty">Loading...</div></div>
    </div>

    <div id="tab-discover" class="tab">
      <div class="sec-hdr">
        <h2>Auto-Discover</h2>
        <p>Scan appdata directories for service config files and detect current key values.</p>
      </div>
      <button id="btn-discover" class="btn bp" onclick="runDiscover()">Run Auto-Discover</button>
      <div id="discover-log" class="log-wrap" style="display:none"></div>
      <div id="discover-results"></div>
    </div>

    <div id="tab-scan" class="tab">
      <div class="sec-hdr">
        <h2>Reference Scan</h2>
        <p>Walk all config files and databases to find where each key is referenced.</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <button id="btn-scan" class="btn bp" onclick="runScan()">Run Full Scan</button>
        <span id="scan-info" style="font-size:12px;color:var(--text2)"></span>
      </div>
      <div id="scan-log" class="log-wrap" style="display:none"></div>
      <div id="scan-results"></div>
    </div>

    <div id="tab-audit" class="tab">
      <div class="sec-hdr">
        <h2>Audit Log</h2>
        <button class="btn bs sm" onclick="loadAudit()">Refresh</button>
      </div>
      <div id="audit-content"></div>
    </div>
  </main>
</div>

<div id="modal-overlay">
  <div id="modal">
    <h2 id="m-title"></h2>
    <div class="modal-sub">
      <code id="m-envvar"></code>
      <a id="m-url" href="#" target="_blank" style="display:none">Open Settings &#8599;</a>
    </div>
    <div id="m-note" style="display:none" class="note"></div>
    <div style="height:10px"></div>
    <div class="frow">
      <label>New key / password</label>
      <div id="kw">
        <input type="password" id="new-key" placeholder="Paste or auto-fetch below">
        <button class="btn bs sm" onclick="toggleReveal()">Show</button>
      </div>
    </div>
    <div id="af-row" style="display:none;margin-bottom:14px">
      <button id="btn-af" class="btn bs sm" onclick="doAutoFetch()">Auto-fetch from config</button>
      <span id="af-status" style="font-size:12px;color:var(--text2);margin-left:8px"></span>
    </div>
    <div class="chk-row">
      <input type="checkbox" id="chk-dry">
      <label for="chk-dry">Dry run (show what would change without writing)</label>
    </div>
    <div id="aw-row" class="chk-row" style="display:none">
      <input type="checkbox" id="chk-aw">
      <label for="chk-aw">Auto-write new key back to service config file</label>
    </div>
    <div class="m-actions">
      <button class="btn bp" id="btn-rotate" onclick="doRotate()">Rotate Key</button>
      <button class="btn bs" onclick="closeModal()">Cancel</button>
    </div>
    <div id="rotate-log" class="log-wrap" style="display:none"></div>
  </div>
</div>

<div id="toast"></div>

<script>
let _sid = null;
const TABS = ['services','discover','scan','audit'];

function showTab(name) {
  document.querySelectorAll('.tab').forEach(e => e.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelectorAll('.nav-btn')[TABS.indexOf(name)].classList.add('active');
  if (name === 'audit') loadAudit();
}

let _tt = null;
function toast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'show ' + (type || 'ok');
  if (_tt) clearTimeout(_tt);
  _tt = setTimeout(() => { el.className = ''; }, 3500);
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function appendLog(el, text, forceClass) {
  const t = String(text).trim();
  const d = document.createElement('div');
  if (forceClass) { d.className = forceClass; }
  else if (t.startsWith('✓') || t.startsWith('Done') || t.toLowerCase().includes('complete'))
    d.className = 'lok';
  else if (t.startsWith('WARNING') || t.startsWith('[dry-run]'))
    d.className = 'lwarn';
  else if (t.startsWith('ERROR') || t.startsWith('✗'))
    d.className = 'lerr';
  d.textContent = t;
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}

// ── Services ──────────────────────────────────────────────────────────────────
let _svcCache = [];

async function loadServices() {
  const res = await fetch('/api/services');
  _svcCache = await res.json();
  let kc = 0, tc = 0;
  _svcCache.forEach(s => { if (s.env_var) { tc++; if (s.has_key) kc++; } });
  document.getElementById('env-status').textContent = kc + '/' + tc + ' keys loaded';

  const grid = document.getElementById('cards');
  grid.innerHTML = '';
  _svcCache.forEach(svc => {
    const card = document.createElement('div');
    card.className = 'card' + (svc.priority ? ' priority' : '');

    let badges = svc.env_var
      ? (svc.has_key ? '<span class="badge bgreen">key set</span>' : '<span class="badge bred">no key</span>')
      : '<span class="badge bg">no env var</span>';
    if (svc.auto_fetch) badges += '<span class="badge bblue">auto-fetch</span>';
    if (svc.auto_write) badges += '<span class="badge bblue">auto-write</span>';
    if (svc.has_db_refs) badges += '<span class="badge bg">db refs</span>';
    if (svc.priority) badges += '<span class="badge byellow">priority</span>';

    let ageHtml = '';
    if (svc.days_since_rotated != null) {
      const d = Math.round(svc.days_since_rotated);
      const c = d > 90 ? 'var(--red)' : d > 30 ? 'var(--yellow)' : 'var(--text2)';
      ageHtml = '<span class="age" style="color:' + c + '">Rotated ' + d + 'd ago</span>';
    }

    let actions = '';
    if (svc.env_var) actions += '<button class="btn bp sm" onclick="openModal(\'' + svc.id + '\')">Rotate</button>';
    if (svc.settings_url) actions += '<a class="btn bs sm" href="' + esc(svc.settings_url) + '" target="_blank">Settings &#8599;</a>';

    card.innerHTML =
      '<div class="card-header"><div>' +
        '<div class="card-name">' + esc(svc.display_name) + '</div>' +
        (svc.env_var ? '<div class="card-envvar">$' + svc.env_var + '</div>' : '') +
      '</div>' +
      (svc.masked ? '<span class="masked">' + svc.masked + '</span>' : '') +
      '</div>' +
      '<div class="card-meta">' + badges + '</div>' +
      ageHtml +
      (svc.note ? '<div class="note">' + esc(svc.note) + '</div>' : '') +
      '<div class="card-actions">' + actions + '</div>';
    grid.appendChild(card);
  });
}

// ── Modal ─────────────────────────────────────────────────────────────────────
function openModal(sid) {
  const svc = _svcCache.find(s => s.id === sid);
  if (!svc) return;
  _sid = sid;
  document.getElementById('m-title').textContent = svc.display_name;
  document.getElementById('m-envvar').textContent = svc.env_var ? '$' + svc.env_var : '';
  const urlEl = document.getElementById('m-url');
  if (svc.settings_url) { urlEl.href = svc.settings_url; urlEl.style.display = ''; }
  else { urlEl.style.display = 'none'; }
  const noteEl = document.getElementById('m-note');
  if (svc.note) { noteEl.textContent = svc.note; noteEl.style.display = ''; }
  else { noteEl.style.display = 'none'; }
  document.getElementById('af-row').style.display = svc.auto_fetch ? '' : 'none';
  document.getElementById('aw-row').style.display = svc.auto_write ? '' : 'none';
  document.getElementById('af-status').textContent = '';
  document.getElementById('new-key').value = '';
  document.getElementById('new-key').type = 'password';
  document.querySelector('#kw button').textContent = 'Show';
  document.getElementById('chk-dry').checked = false;
  document.getElementById('chk-aw').checked = false;
  document.getElementById('rotate-log').style.display = 'none';
  document.getElementById('rotate-log').innerHTML = '';
  document.getElementById('btn-rotate').disabled = false;
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  _sid = null;
}

document.getElementById('modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('modal-overlay')) closeModal();
});

function toggleReveal() {
  const inp = document.getElementById('new-key');
  const btn = inp.nextElementSibling;
  if (inp.type === 'password') { inp.type = 'text'; btn.textContent = 'Hide'; }
  else { inp.type = 'password'; btn.textContent = 'Show'; }
}

async function doAutoFetch() {
  if (!_sid) return;
  const btn = document.getElementById('btn-af');
  const st = document.getElementById('af-status');
  btn.disabled = true;
  st.textContent = 'Fetching...';
  try {
    const res = await fetch('/api/services/' + _sid + '/fetch-key');
    const d = await res.json();
    if (d.error) { st.textContent = 'Error: ' + d.error; }
    else {
      document.getElementById('new-key').value = d.value;
      document.getElementById('new-key').type = 'text';
      document.querySelector('#kw button').textContent = 'Hide';
      st.textContent = d.matches_env ? '(matches current .env)' : 'Fetched: ' + d.masked;
    }
  } catch(e) { st.textContent = 'Request failed'; }
  btn.disabled = false;
}

function doRotate() {
  if (!_sid) return;
  const newKey = document.getElementById('new-key').value.trim();
  if (!newKey) { toast('Enter or auto-fetch a new key first', 'err'); return; }
  const dryRun = document.getElementById('chk-dry').checked;
  const autoWrite = document.getElementById('chk-aw').checked;

  const logEl = document.getElementById('rotate-log');
  logEl.innerHTML = '';
  logEl.style.display = '';
  document.getElementById('btn-rotate').disabled = true;

  fetch('/api/services/' + _sid + '/rotate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({new_key: newKey, dry_run: dryRun, auto_write: autoWrite}),
  }).then(res => {
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '', evt = '', dataLines = [];
    function pump() {
      reader.read().then(({done, value}) => {
        if (done) return;
        buf += dec.decode(value, {stream: true});
        const parts = buf.split('\\n');
        buf = parts.pop();
        for (const line of parts) {
          if (line.startsWith('event: ')) { evt = line.slice(7).trim(); }
          else if (line.startsWith('data: ')) { dataLines.push(line.slice(6)); }
          else if (line === '') {
            if (evt === 'log') appendLog(logEl, dataLines.join('\\n'));
            else if (evt === 'done') {
              const d = JSON.parse(dataLines.join(''));
              if (d.success) {
                toast(dryRun ? 'Dry run complete' : 'Key rotated!');
                if (!dryRun) { setTimeout(() => { closeModal(); loadServices(); }, 800); }
              } else {
                toast('Rotation failed: ' + (d.reason || d.error || 'unknown error'), 'err');
              }
              document.getElementById('btn-rotate').disabled = false;
            }
            evt = ''; dataLines = [];
          }
        }
        pump();
      });
    }
    pump();
  }).catch(e => {
    appendLog(logEl, 'Connection error: ' + e, 'lerr');
    document.getElementById('btn-rotate').disabled = false;
  });
}

// ── Discover ──────────────────────────────────────────────────────────────────
function runDiscover() {
  const btn = document.getElementById('btn-discover');
  const logEl = document.getElementById('discover-log');
  const resEl = document.getElementById('discover-results');
  btn.disabled = true;
  logEl.innerHTML = '';
  logEl.style.display = '';
  resEl.innerHTML = '';

  const es = new EventSource('/api/discover');
  es.addEventListener('log', e => appendLog(logEl, e.data));
  es.addEventListener('done', e => {
    es.close(); btn.disabled = false;
    const d = JSON.parse(e.data);
    if (d.error) { appendLog(logEl, 'ERROR: ' + d.error, 'lerr'); return; }
    const r = d.results || [];
    if (r.length) {
      let h = '<table class="tbl"><thead><tr><th>Service</th><th>Env Var</th><th>Value</th><th>Strategy</th><th>Confidence</th><th>Host</th><th>Source</th></tr></thead><tbody>';
      r.forEach(x => {
        h += '<tr><td>' + esc(x.display_name) + '</td><td><code>$' + x.env_var + '</code></td>' +
          '<td><code>' + x.masked + '</code></td><td>' + x.strategy + '</td>' +
          '<td><span class="badge ' + (x.confidence === 'high' ? 'bgreen' : 'byellow') + '">' + x.confidence + '</span></td>' +
          '<td>' + esc(x.host) + '</td>' +
          '<td style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(x.source_file) + '">' + esc(x.source_file) + '</td></tr>';
      });
      h += '</tbody></table>';
      resEl.innerHTML = h;
    } else {
      resEl.innerHTML = '<p class="empty">No differences found — all service keys match .env.</p>';
    }
    loadServices();
  });
  es.onerror = () => { es.close(); btn.disabled = false; };
}

// ── Scan ──────────────────────────────────────────────────────────────────────
function runScan() {
  const btn = document.getElementById('btn-scan');
  const logEl = document.getElementById('scan-log');
  const resEl = document.getElementById('scan-results');
  btn.disabled = true;
  logEl.innerHTML = '';
  logEl.style.display = '';
  resEl.innerHTML = '';
  document.getElementById('scan-info').textContent = '';

  const es = new EventSource('/api/scan');
  es.addEventListener('log', e => appendLog(logEl, e.data));
  es.addEventListener('done', e => {
    es.close(); btn.disabled = false;
    const d = JSON.parse(e.data);
    if (d.error) { appendLog(logEl, 'ERROR: ' + d.error, 'lerr'); return; }
    const hits = d.hits || [];
    document.getElementById('scan-info').textContent = hits.length + ' reference(s) found';
    if (hits.length) {
      const byS = {};
      hits.forEach(h => { if (!byS[h.sid]) byS[h.sid] = {name: h.name, hits: []}; byS[h.sid].hits.push(h); });
      let html = '<table class="tbl"><thead><tr><th>Service</th><th>Type</th><th>Host</th><th>Path</th></tr></thead><tbody>';
      Object.values(byS).forEach(g => {
        g.hits.forEach((h, i) => {
          html += '<tr>' +
            (i === 0 ? '<td rowspan="' + g.hits.length + '" style="font-weight:500">' + esc(g.name) + '</td>' : '') +
            '<td><span class="badge ' + (h.type === 'file' ? 'bblue' : 'byellow') + '">' + h.type + '</span></td>' +
            '<td>' + esc(h.host) + '</td>' +
            '<td style="font-family:monospace;font-size:12px">' + esc(h.path) + '</td></tr>';
        });
      });
      html += '</tbody></table>';
      resEl.innerHTML = html;
    } else {
      resEl.innerHTML = '<p class="empty">No key references found in scanned files.</p>';
    }
  });
  es.onerror = () => { es.close(); btn.disabled = false; };
}

// ── Audit ─────────────────────────────────────────────────────────────────────
async function loadAudit() {
  const res = await fetch('/api/audit');
  const entries = await res.json();
  const el = document.getElementById('audit-content');
  if (!entries.length) { el.innerHTML = '<p class="empty">No audit entries yet.</p>'; return; }
  let h = '<table class="tbl"><thead><tr><th>Time</th><th>Service</th><th>Files</th><th>DBs</th><th>Result</th><th>Note</th></tr></thead><tbody>';
  entries.forEach(e => {
    h += '<tr><td style="white-space:nowrap;font-size:12px">' + esc(e.timestamp) + '</td>' +
      '<td>' + esc(e.service) + '</td><td>' + e.files_changed + '</td><td>' + e.dbs_changed + '</td>' +
      '<td><span class="badge ' + (e.success ? 'bgreen' : 'bred') + '">' + (e.success ? 'ok' : 'failed') + '</span></td>' +
      '<td style="font-size:12px">' + esc(e.message||'') + '</td></tr>';
  });
  h += '</tbody></table>';
  el.innerHTML = h;
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadServices();
</script>
</body>
</html>"""


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    global _ENV_PATH
    p = argparse.ArgumentParser(description="Key Rotation Web UI")
    p.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765)")
    p.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    p.add_argument("--env", default=str(rk.DEFAULT_ENV), help="Path to .env file")
    args = p.parse_args()
    _ENV_PATH = Path(args.env)
    print(f"  Key Rotation Web UI  →  http://localhost:{args.port}")
    print(f"  .env: {_ENV_PATH.resolve()}")
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
