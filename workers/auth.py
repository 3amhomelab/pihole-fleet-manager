#!/usr/bin/env python3
"""Optional admin login gate for the whole web UI/API. Off by default (matches
the PIHOLE_VIP/EXTERNAL_DHCP_SOURCE pattern elsewhere in this app — inert
until explicitly turned on). Toggled from the Setup page: switching it on
prompts for a password once, which is then persisted the same way setup.py's
SSH key is — written straight back into the bind-mounted host .env
(ADMIN_PASSWORD) so it survives container recreation, not just the /data
volume.

The Flask session secret is generated once and kept in /data so existing
sessions survive a redeploy; only a fresh /data volume forces everyone to
log in again."""
import json
import os
import secrets
import threading

from workers import activity_log

STATE_FILE    = os.environ.get("AUTH_STATE_FILE", "/data/auth.json")
SECRET_FILE   = os.environ.get("AUTH_SECRET_FILE", "/data/flask_secret")
HOST_ENV_FILE = os.environ.get("HOST_ENV_FILE", "/config/host.env")

_lock = threading.Lock()


def _load() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"enabled": False}


def _save(data: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, STATE_FILE)


def get_secret_key() -> str:
    os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE) as f:
            key = f.read().strip()
        if key:
            return key
    key = secrets.token_hex(32)
    with open(SECRET_FILE, "w") as f:
        f.write(key)
    return key


def is_enabled() -> bool:
    with _lock:
        return bool(_load().get("enabled"))


def _write_password_to_host_env(password: str) -> None:
    """Same in-place-write approach as setup.py's key write-back — the bind
    mount's target inode can't be replaced via rename() from inside the
    container, so this edits the file directly rather than write-tmp+rename."""
    if not os.path.exists(HOST_ENV_FILE):
        return
    try:
        with open(HOST_ENV_FILE) as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if line.startswith("ADMIN_PASSWORD="):
                lines[i] = f"ADMIN_PASSWORD={password}\n"
                break
        else:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(f"ADMIN_PASSWORD={password}\n")
        with open(HOST_ENV_FILE, "w") as f:
            f.writelines(lines)
    except Exception as e:
        print(f"[auth] Could not write password back to host .env: {e}")


def enable(password: str) -> tuple:
    if not password:
        return False, "Password required"
    with _lock:
        data = _load()
        data["enabled"] = True
        data["password"] = password
        _save(data)
    _write_password_to_host_env(password)
    activity_log.log("auth", "Admin login enabled")
    return True, None


def disable() -> None:
    with _lock:
        data = _load()
        data["enabled"] = False
        _save(data)
    activity_log.log("auth", "Admin login disabled")


def check_password(password: str) -> bool:
    with _lock:
        data = _load()
    stored = data.get("password") or os.environ.get("ADMIN_PASSWORD", "")
    return bool(stored) and secrets.compare_digest(password, stored)
