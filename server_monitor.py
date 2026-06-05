#!/usr/bin/env python3
"""server_monitor.py — Live status endpoint for Glance extension widgets.

Serves HTML fragments for Unraid (GraphQL API) and TrueNAS (REST API).
Glance fetches these via the 'extension' widget type with a 1-minute cache.

Usage:
    python server_monitor.py [--port 8081] [--config PATH]
"""

import argparse
import http.server
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CACHE_TTL = int(os.environ.get("CACHE_TTL", "60"))


# ---------------------------------------------------------------------------
# Simple thread-safe cache
# ---------------------------------------------------------------------------

class _Cache:
    def __init__(self) -> None:
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, key: str, ttl: int) -> Optional[Any]:
        with self._lock:
            entry = self._data.get(key)
            if entry and (time.time() - entry["ts"]) < ttl:
                return entry["data"]
        return None

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = {"data": value, "ts": time.time()}

    def get_stale(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._data.get(key)
            return entry["data"] if entry else None


_cache = _Cache()


# ---------------------------------------------------------------------------
# Shared HTML helpers
# ---------------------------------------------------------------------------

_CSS = """
<style>
  .sm-card { font-family: inherit; font-size: 0.9em; color: var(--color-text-base, #e2e8f0); }
  .sm-header { display: flex; justify-content: space-between; align-items: baseline;
               margin-bottom: 8px; }
  .sm-title { font-weight: 600; }
  .sm-sub { color: var(--color-text-subdue, #94a3b8); font-size: 0.85em; }
  .sm-bar-bg { background: var(--color-background-widget, #334155);
               border-radius: 4px; height: 6px; margin-bottom: 10px; overflow: hidden; }
  .sm-bar-fill { height: 100%; border-radius: 4px; background: #4ade80; }
  .sm-bar-fill.warn { background: #fb923c; }
  .sm-bar-fill.crit { background: #f87171; }
  table.sm-table { width: 100%; border-collapse: collapse; font-size: 0.83em; }
  table.sm-table th { color: var(--color-text-subdue, #94a3b8); text-align: left;
                      padding-bottom: 5px; font-weight: 500; }
  table.sm-table td { padding: 2px 4px 2px 0; vertical-align: middle; }
  .ok   { color: #4ade80; }
  .warn { color: #fb923c; }
  .err  { color: #f87171; }
  .dim  { color: var(--color-text-subdue, #94a3b8); }
</style>
"""


def _error_card(message: str) -> str:
    return f"{_CSS}<div class='sm-card'><span class='err'>⚠ {message}</span></div>"


def _bar_class(pct: int) -> str:
    if pct >= 90:
        return "crit"
    if pct >= 75:
        return "warn"
    return ""


def _temp_class(temp: int) -> str:
    if temp >= 55:
        return "err"
    if temp >= 45:
        return "warn"
    return "ok"


# ---------------------------------------------------------------------------
# Unraid GraphQL API
# ---------------------------------------------------------------------------

_UNRAID_QUERY = """
{
  array {
    state
    capacity { kilobytes { used free total } }
    parities { id name temp status numErrors }
    disks    { id name temp status numErrors }
    caches   { id name temp status numErrors }
  }
  vars { version name }
}
"""

# Extended query: includes CPU load/temperature (supported on newer Unraid API versions).
# Falls back to _UNRAID_QUERY if the server returns GraphQL errors.
_UNRAID_QUERY_WITH_CPU = """
{
  array {
    state
    capacity { kilobytes { used free total } }
    parities { id name temp status numErrors }
    disks    { id name temp status numErrors }
    caches   { id name temp status numErrors }
  }
  vars { version name }
  cpuLoad { load temp }
}
"""


def _fetch_unraid(url: str, api_key: str) -> dict:
    h = {"X-Api-Key": api_key, "Content-Type": "application/json"}
    gql = f"{url.rstrip('/')}/graphql"
    for query in (_UNRAID_QUERY_WITH_CPU, _UNRAID_QUERY):
        resp = requests.post(gql, json={"query": query}, headers=h, timeout=8, verify=False)
        resp.raise_for_status()
        body = resp.json()
        if "errors" not in body:
            return body.get("data", {})
    raise RuntimeError("Unraid GraphQL: all queries returned errors")


def _render_unraid(data: dict, server_name: str) -> str:
    array = data.get("array", {})
    state = array.get("state", "unknown")
    state_class = "ok" if state == "STARTED" else "err"

    cap = (array.get("capacity") or {}).get("kilobytes", {})
    total = int(cap.get("total", 0))
    used = int(cap.get("used", 0))
    used_tb = used / (1024 ** 3)
    total_tb = total / (1024 ** 3)
    used_pct = round(used / total * 100) if total else 0

    all_disks = (
        [("P", d) for d in array.get("parities", [])]
        + [("", d) for d in array.get("disks", [])]
        + [("C", d) for d in array.get("caches", [])]
    )

    rows = ""
    for prefix, disk in all_disks:
        name = disk.get("name") or disk.get("id", "")
        if prefix:
            name = f"{prefix}:{name}"
        status = disk.get("status", "") or ""
        temp = disk.get("temp") or 0
        errors = disk.get("numErrors") or 0
        is_ok = "OK" in status and errors == 0
        disk_class = "ok" if is_ok else ("dim" if not status else "err")
        temp_str = f"{temp}°C" if temp else "—"
        temp_cls = _temp_class(temp) if temp else "dim"
        rows += (
            f"<tr>"
            f"<td>{name}</td>"
            f"<td class='{disk_class}'>{status or '—'}</td>"
            f"<td class='{temp_cls}'>{temp_str}</td>"
            f"</tr>"
        )

    vars_data = data.get("vars") or {}
    label = vars_data.get("name", server_name)
    version = vars_data.get("version", "")

    # CPU temperature (from extended query, may be absent)
    cpu_load = data.get("cpuLoad") or {}
    cpu_temp = cpu_load.get("temp")
    cpu_temp_html = (
        f"<span class='{_temp_class(cpu_temp)}' style='font-size:0.85em'>CPU {cpu_temp}°C</span>"
        if cpu_temp else ""
    )

    # Hottest disk temperature summary
    disk_temps = [d.get("temp") for _, d in all_disks if d.get("temp")]
    max_disk = max(disk_temps) if disk_temps else None
    max_disk_html = (
        f"<span class='{_temp_class(max_disk)}' style='font-size:0.85em'>Disk max {max_disk}°C</span>"
        if max_disk else ""
    )

    temp_badges = " &nbsp;·&nbsp; ".join(x for x in [cpu_temp_html, max_disk_html] if x)
    temp_line = f"<div style='margin-bottom:6px'>{temp_badges}</div>" if temp_badges else ""

    bc = _bar_class(used_pct)
    return f"""{_CSS}
<div class="sm-card">
  <div class="sm-header">
    <span class="sm-title">{label}</span>
    <span class="{state_class}">{state}</span>
  </div>
  <div class="sm-sub">Array: {used_tb:.1f} TB / {total_tb:.1f} TB ({used_pct}%)</div>
  <div class="sm-bar-bg"><div class="sm-bar-fill {bc}" style="width:{used_pct}%"></div></div>
  {temp_line}<table class="sm-table">
    <tr><th>Disk</th><th>Status</th><th>Temp</th></tr>
    {rows}
  </table>
  <div class="sm-sub" style="margin-top:6px">Unraid {version}</div>
</div>"""


# ---------------------------------------------------------------------------
# TrueNAS REST API
# ---------------------------------------------------------------------------

def _fetch_truenas(url: str, api_key: str) -> dict:
    base = url.rstrip("/")
    h = {"Authorization": f"Bearer {api_key}"}

    pools = requests.get(f"{base}/api/v2.0/pool", headers=h, timeout=8, verify=False).json()
    sys_info = requests.get(f"{base}/api/v2.0/system/info", headers=h, timeout=8, verify=False).json()
    alerts = requests.get(f"{base}/api/v2.0/alert/list", headers=h, timeout=8, verify=False).json()

    disk_temps: dict = {}
    try:
        temp_resp = requests.post(
            f"{base}/api/v2.0/disk/temperature",
            json={"names": [], "powermode": "NEVER"},
            headers={**h, "Content-Type": "application/json"},
            timeout=15, verify=False,
        )
        if temp_resp.ok:
            disk_temps = temp_resp.json() or {}
    except Exception:
        pass

    return {"pools": pools, "system": sys_info, "alerts": alerts, "disk_temps": disk_temps}


def _render_truenas(data: dict, server_name: str) -> str:
    sys_info = data.get("system") or {}
    hostname = sys_info.get("hostname", server_name)
    version = (sys_info.get("version") or "")[:40]

    pools = data.get("pools") or []
    active_alerts = [
        a for a in (data.get("alerts") or [])
        if a.get("level") not in ("INFO", "NOTICE")
    ]

    rows = ""
    for pool in pools:
        name = pool.get("name", "")
        status = pool.get("status", "")
        healthy = pool.get("healthy", False)
        size_b = pool.get("size") or 0
        free_b = pool.get("free") or 0
        used_b = size_b - free_b
        size_tb = size_b / (1024 ** 4)
        used_tb = used_b / (1024 ** 4)
        used_pct = round(used_b / size_b * 100) if size_b else 0
        pool_class = "ok" if healthy else "err"
        bc = _bar_class(used_pct)
        rows += (
            f"<tr>"
            f"<td>{name}</td>"
            f"<td class='{pool_class}'>{status}</td>"
            f"<td class='dim'>{used_tb:.1f}/{size_tb:.1f} TB</td>"
            f"</tr>"
            f"<tr><td colspan='3' style='padding-bottom:4px'>"
            f"<div class='sm-bar-bg' style='margin:2px 0 0'>"
            f"<div class='sm-bar-fill {bc}' style='width:{used_pct}%'></div>"
            f"</div></td></tr>"
        )

    # Disk temperatures
    disk_temps = data.get("disk_temps") or {}
    temp_rows = ""
    if disk_temps:
        sorted_temps = sorted(
            ((k, v) for k, v in disk_temps.items() if v is not None),
            key=lambda x: x[1], reverse=True,
        )
        for dname, temp in sorted_temps:
            tc = _temp_class(temp)
            temp_rows += f"<tr><td>{dname}</td><td class='{tc}'>{temp}°C</td></tr>"

    temps_section = ""
    if temp_rows:
        temps_section = f"""
  <div style="margin-top:10px">
    <table class="sm-table">
      <tr><th>Disk</th><th>Temp</th></tr>
      {temp_rows}
    </table>
  </div>"""

    alert_html = ""
    if active_alerts:
        first = (active_alerts[0].get("formatted") or active_alerts[0].get("text", ""))[:80]
        alert_html = (
            f"<div class='err' style='margin-top:6px;font-size:0.83em'>"
            f"⚠ {len(active_alerts)} alert(s): {first}"
            f"</div>"
        )

    return f"""{_CSS}
<div class="sm-card">
  <div class="sm-header">
    <span class="sm-title">{hostname}</span>
    <span class="sm-sub">{version}</span>
  </div>
  <table class="sm-table">
    <tr><th>Pool</th><th>Status</th><th>Usage</th></tr>
    {rows}
  </table>
  {alert_html}{temps_section}
</div>"""


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

_SERVER_CONFIG: list[dict] = []

_FETCHERS = {
    "unraid": (_fetch_unraid, _render_unraid),
    "truenas": (_fetch_truenas, _render_truenas),
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default access log
        logging.debug("HTTP " + fmt, *args)

    def _send(self, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")

        if path in ("/health", ""):
            self._send("ok")
            return

        slug = path.lstrip("/")
        server = next((s for s in _SERVER_CONFIG if s["slug"] == slug), None)

        if server is None:
            self._send(_error_card(f"Unknown endpoint: /{slug}"), 404)
            return

        cache_key = f"server:{slug}"
        html = _cache.get(cache_key, CACHE_TTL)

        if html is None:
            fetch_fn, render_fn = _FETCHERS.get(server["type"], (None, None))
            if fetch_fn is None:
                html = _error_card(f"Unknown server type: {server['type']}")
            else:
                try:
                    raw = fetch_fn(server["url"], server["api_key"])
                    html = render_fn(raw, server["name"])
                    _cache.set(cache_key, html)
                except Exception as exc:
                    logging.warning("Failed to fetch %s: %s", slug, exc)
                    stale = _cache.get_stale(cache_key)
                    html = stale if stale else _error_card(
                        f"Could not reach {server['name']}: {type(exc).__name__}"
                    )

        self._send(html)


def run_server(port: int, servers: list[dict]) -> None:
    global _SERVER_CONFIG
    _SERVER_CONFIG = servers
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    logging.info("Server monitor listening on :%d with %d server(s)", port, len(servers))
    for s in servers:
        logging.info("  /%s → %s (%s)", s["slug"], s["url"], s["type"])
    srv.serve_forever()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live server stats for Glance extension widgets")
    parser.add_argument("--port", type=int, default=int(os.environ.get("MONITOR_PORT", "8081")))
    parser.add_argument(
        "--config",
        default=os.environ.get("DESCRIPTIONS_PATH", "descriptions.yaml"),
        metavar="PATH",
    )
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    config_path = Path(args.config)
    if not config_path.exists():
        logging.error("Config not found: %s", config_path)
        sys.exit(1)

    data = yaml.safe_load(config_path.read_text())
    servers = []
    for srv in (data.get("servers") or []):
        api_key_env = srv.get("api_key_env")
        api_key = os.environ.get(api_key_env, "") if api_key_env else srv.get("api_key", "")
        slug = (srv.get("slug") or srv["name"].lower().replace(" ", "-"))
        servers.append({
            "name": srv["name"],
            "type": srv["type"],
            "url": srv["url"].rstrip("/"),
            "api_key": api_key,
            "slug": slug,
        })

    run_server(args.port, servers)


if __name__ == "__main__":
    main()
