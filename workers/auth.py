#!/usr/bin/env python3
"""Admin login gate for the whole web UI/API. Enabled by default on a fresh
install (no state file yet) — but the gate only actually locks anyone out
once a password has been set (see has_password()/is_active() below), so
first boot never traps you behind a login you can't satisfy. Setting a
password (Setup page, or the wizard's Admin Login step) activates it and
authenticates the current session in the same step.

Existing deployments that explicitly disabled login before this change keep
their choice — the "on by default" behavior only applies when STATE_FILE
doesn't exist yet.

The password itself is stored as a salted hash (werkzeug's
generate_password_hash/check_password_hash) — it's only ever compared, never
replayed, so there's no reason to keep it recoverable at rest. Older
installs that still have a plaintext "password" key are migrated to a hash
in place the first time it's used to log in successfully.

ADMIN_PASSWORD in .env remains supported as a plaintext fallback purely for
pre-seeding a fresh deploy by hand (before any UI interaction has happened)
— that's the user's own file, not a copy this app writes back.

The Flask session secret is generated once and kept in /data so existing
sessions survive a redeploy; only a fresh /data volume forces everyone to
log in again."""
import json
import os
import secrets
import threading

from werkzeug.security import check_password_hash, generate_password_hash

from workers import activity_log

STATE_FILE    = os.environ.get("AUTH_STATE_FILE", "/data/auth.json")
SECRET_FILE   = os.environ.get("AUTH_SECRET_FILE", "/data/flask_secret")

_lock = threading.Lock()


def _load() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"enabled": True}


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


def has_password() -> bool:
    with _lock:
        data = _load()
    return bool(data.get("password_hash") or data.get("password") or os.environ.get("ADMIN_PASSWORD"))


def is_active() -> bool:
    """Whether the login gate actually enforces anything right now. Enabled
    but with no password configured yet is deliberately non-blocking — that
    combination only happens on a fresh install before Setup/wizard has been
    used, and gating it would lock everyone out with no way in."""
    return is_enabled() and has_password()


def enable(password: str) -> tuple:
    if not password:
        return False, "Password required"
    with _lock:
        data = _load()
        data["enabled"] = True
        data["password_hash"] = generate_password_hash(password)
        data.pop("password", None)
        _save(data)
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

    password_hash = data.get("password_hash")
    if password_hash:
        return check_password_hash(password_hash, password)

    legacy = data.get("password")
    if legacy:
        ok = secrets.compare_digest(password, legacy)
        if ok:
            with _lock:
                data = _load()
                data["password_hash"] = generate_password_hash(password)
                data.pop("password", None)
                _save(data)
        return ok

    stored = os.environ.get("ADMIN_PASSWORD", "")
    return bool(stored) and secrets.compare_digest(password, stored)
