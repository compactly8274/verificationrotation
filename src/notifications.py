"""Fire-and-forget webhook notifications for rotation events."""

import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any

from src.config import settings

_COLORS = {
    "rotation_start": 0x3498DB,       # blue
    "rotation_success": 0x2ECC71,     # green
    "rotation_failed": 0xE74C3C,      # red
    "rotation_rollback": 0xF39C12,    # orange/yellow
    "scan_error": 0xE67E22,           # orange
}

_GOTIFY_PRIORITIES = {
    "rotation_start": 3,
    "rotation_success": 3,
    "rotation_failed": 8,
    "rotation_rollback": 7,
    "scan_error": 6,
}


def _post(url: str, payload: dict, headers: dict | None = None) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _build_discord(event: str, service: str, detail: str, extra: dict) -> dict:
    color = _COLORS.get(event, 0x95A5A6)
    fields = [{"name": k, "value": str(v), "inline": True} for k, v in extra.items() if v is not None]
    return {
        "embeds": [{
            "title": f"{event.replace('_', ' ').title()} — {service}",
            "description": detail,
            "color": color,
            "fields": fields,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
    }


def _build_slack(event: str, service: str, detail: str, extra: dict) -> dict:
    colors = {
        "rotation_success": "good",
        "rotation_failed": "danger",
        "rotation_rollback": "warning",
        "scan_error": "warning",
    }
    color = colors.get(event, "#95A5A6")
    fields = [{"title": k, "value": str(v), "short": True} for k, v in extra.items() if v is not None]
    return {
        "attachments": [{
            "color": color,
            "title": f"{event.replace('_', ' ').title()} — {service}",
            "text": detail,
            "fields": fields,
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }


def _build_gotify(event: str, service: str, detail: str, extra: dict) -> dict:
    lines = [detail] + [f"**{k}**: {v}" for k, v in extra.items() if v is not None]
    return {
        "title": f"{event.replace('_', ' ').title()} — {service}",
        "message": "\n".join(lines),
        "priority": _GOTIFY_PRIORITIES.get(event, 5),
    }


def send_notification(
    event: str,
    service: str,
    detail: str = "",
    **extra: Any,
) -> None:
    """Send a webhook notification. Never raises — failures are logged to stderr."""
    url = settings.webhook_url
    if not url:
        return
    wtype = settings.webhook_type.lower()
    try:
        if wtype == "discord":
            payload = _build_discord(event, service, detail, extra)
            _post(url, payload)
        elif wtype == "slack":
            payload = _build_slack(event, service, detail, extra)
            _post(url, payload)
        elif wtype == "gotify":
            payload = _build_gotify(event, service, detail, extra)
            _post(url, payload)
        else:
            payload = {
                "event": event,
                "service": service,
                "detail": detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **extra,
            }
            _post(url, payload)
    except Exception as exc:
        print(f"[notifications] Failed to send {event} webhook: {exc}", file=sys.stderr)
