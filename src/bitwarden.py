"""Bitwarden CLI integration — search, update, and create vault items."""

import json
import os
import subprocess
from typing import Optional

from src.services_registry import ServiceDef


def bw_available() -> bool:
    try:
        subprocess.run(["bw", "--version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


def bw_get_session() -> Optional[str]:
    session = os.environ.get("BW_SESSION", "").strip()
    if session:
        try:
            subprocess.run(
                ["bw", "sync", "--session", session],
                capture_output=True, check=True, timeout=30,
            )
            return session
        except Exception:
            pass
    return None


def bw_unlock(master_password: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["bw", "unlock", master_password, "--raw"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def bw_search_item(session: str, item_name: Optional[str] = None, uri: Optional[str] = None) -> Optional[dict]:
    search_term = item_name or uri
    if not search_term:
        return None
    try:
        result = subprocess.run(
            ["bw", "list", "items", "--search", search_term, "--session", session],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None
        items = json.loads(result.stdout)
        if not items:
            return None
        if uri:
            for item in items:
                login = item.get("login", {})
                uris = login.get("uris", [])
                for u in uris:
                    if uri in (u.get("uri", "") or ""):
                        return item
        return items[0]
    except Exception:
        return None


def bw_update_password(session: str, item_id: str, new_password: str, field: str = "password") -> bool:
    try:
        result = subprocess.run(
            ["bw", "get", "item", item_id, "--session", session],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return False
        item = json.loads(result.stdout)
        if field == "password":
            item.setdefault("login", {})["password"] = new_password
        else:
            fields = item.get("fields", [])
            for f in fields:
                if f.get("name") == field:
                    f["value"] = new_password
                    break
            else:
                fields.append({"name": field, "value": new_password, "type": 0})
            item["fields"] = fields
        encoded = subprocess.run(
            ["bw", "encode"],
            input=json.dumps(item), capture_output=True, text=True, timeout=30,
        )
        if encoded.returncode != 0:
            return False
        save_result = subprocess.run(
            ["bw", "edit", "item", item_id, encoded.stdout.strip(), "--session", session],
            capture_output=True, text=True, timeout=30,
        )
        return save_result.returncode == 0
    except Exception:
        return False


def bw_create_item(session: str, name: str, password: str, uri: Optional[str] = None, username: Optional[str] = None) -> Optional[dict]:
    """Create a new Bitwarden login item. Returns the created item or None."""
    try:
        # Get templates
        item_tpl = subprocess.run(
            ["bw", "get", "template", "item", "--session", session],
            capture_output=True, text=True, timeout=30,
        )
        login_tpl = subprocess.run(
            ["bw", "get", "template", "item.login", "--session", session],
            capture_output=True, text=True, timeout=30,
        )
        if item_tpl.returncode != 0 or login_tpl.returncode != 0:
            return None
        item = json.loads(item_tpl.stdout)
        login = json.loads(login_tpl.stdout)
        login["password"] = password
        if username:
            login["username"] = username
        if uri:
            login["uris"] = [{"match": None, "uri": uri}]
        item["type"] = 1  # Login
        item["name"] = name
        item["login"] = login
        encoded = subprocess.run(
            ["bw", "encode"],
            input=json.dumps(item), capture_output=True, text=True, timeout=30,
        )
        if encoded.returncode != 0:
            return None
        create_result = subprocess.run(
            ["bw", "create", "item", encoded.stdout.strip(), "--session", session],
            capture_output=True, text=True, timeout=30,
        )
        if create_result.returncode == 0:
            return json.loads(create_result.stdout)
        return None
    except Exception:
        return None


def sync_bitwarden(svc: ServiceDef, new_value: str, session: str, env: dict[str, str] | None = None) -> tuple[bool, str]:
    """Sync a rotated secret to Bitwarden. Creates item if missing."""
    cfg = svc.bitwarden
    if not cfg:
        return False, "No bitwarden config for this service"
    item_name = cfg.get("item_name", "")
    uri = cfg.get("uri", svc.settings_url or "")
    field = cfg.get("field", "password")
    item = bw_search_item(session, item_name=item_name or None, uri=uri or None)
    if item:
        ok = bw_update_password(session, item["id"], new_value, field=field)
        if ok:
            return True, f"Updated Bitwarden item '{item.get('name', item['id'])}'"
        return False, "Bitwarden edit command failed"
    # Create new item
    username = ""
    if svc.env_var.endswith("_PASSWORD"):
        user_var = svc.env_var.replace("_PASSWORD", "_USERNAME")
        if user_var in env:
            username = env[user_var]
    created = bw_create_item(session, name=item_name or svc.display_name, password=new_value, uri=uri, username=username or None)
    if created:
        return True, f"Created Bitwarden item '{created.get('name', item_name)}'"
    return False, "Bitwarden create item failed"
