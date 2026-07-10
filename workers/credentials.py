#!/usr/bin/env python3
"""Single source of truth for the two cluster-wide credentials every worker
needs to talk to Pi-hole nodes: the v6 admin password (API auth) and the
SSH user (config pushes, reboots, upgrades). Same pattern as nodes.py —
JSON-backed so a change from the Getting Started wizard applies immediately
across every loop, mirrored back to the stack's .env for persistence/
`docker compose config` visibility, but the env var itself is only ever
read once more: to seed this file on first boot.

Before this existed, PIHOLE_ADMIN_PASSWORD/PIHOLE_SSH_USER were plain
module-level constants read from os.environ at import time — changing them
via the wizard wrote the new value to .env, but the already-running process
kept using the old one until a container restart, which silently broke the
wizard's own very next step (SSH Trust using whatever SSH user was set
moments before)."""
import json
import os
import threading

from workers import activity_log, host_env

DATA_FILE = os.environ.get("CREDENTIALS_FILE", "/data/credentials.json")

_lock = threading.Lock()


def _read() -> dict:
    """Unlocked — only call with _lock already held (see get_ssh_user/
    get_admin_password/set_ssh_user/set_admin_password below);
    threading.Lock isn't reentrant, so a locked caller must never go through
    a locked public function itself (this bit nodes.py before — same fix)."""
    if not os.path.exists(DATA_FILE):
        data = {
            "ssh_user": os.environ.get("PIHOLE_SSH_USER", "root"),
            "admin_password": os.environ.get("PIHOLE_ADMIN_PASSWORD", ""),
        }
        _save(data)
        return data
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {
            "ssh_user": os.environ.get("PIHOLE_SSH_USER", "root"),
            "admin_password": os.environ.get("PIHOLE_ADMIN_PASSWORD", ""),
        }


def _save(data: dict) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, DATA_FILE)
    host_env.write_vars({
        "PIHOLE_SSH_USER": data.get("ssh_user", "root"),
        "PIHOLE_ADMIN_PASSWORD": data.get("admin_password", ""),
    })


def get_ssh_user() -> str:
    with _lock:
        return _read().get("ssh_user") or "root"


def get_admin_password() -> str:
    with _lock:
        return _read().get("admin_password") or ""


def set_ssh_user(user: str) -> None:
    with _lock:
        data = _read()
        data["ssh_user"] = (user or "root").strip()
        _save(data)
    activity_log.log("credentials", f"SSH user changed to '{data['ssh_user']}'")


def set_admin_password(password: str) -> None:
    if not password:
        return
    with _lock:
        data = _read()
        data["admin_password"] = password
        _save(data)
    activity_log.log("credentials", "Pi-hole admin password changed")
