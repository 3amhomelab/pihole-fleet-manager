#!/usr/bin/env python3
"""Single shared Pi-hole v6 API session cache + HTTP helpers, used by every
worker module that talks to a Pi-hole node's REST API.

Before this existed, ~13 worker modules each kept their own independent
copy of this exact same auth/session-cache/retry logic — since Pi-hole's
FTL API enforces a hard cap on concurrent sessions
(webserver.api.max_sessions), this single app alone could hold up to one
session *per module, per node* open at once (13 modules x 3 nodes = up to
39 sessions), none of them ever released. That's what "API seats exceeded"
when trying to log into Pi-hole's own web UI was actually caused by — this
app was quietly consuming nearly all the available seats. Consolidating to
one shared session per node cuts that by ~13x."""
import threading

import requests

from workers import credentials

_sid_cache = {}
_sid_lock = threading.Lock()


def auth(ip: str, password: str | None = None) -> str:
    """Authenticates fresh and replaces the cached session for this node.
    Most callers don't need this directly — api_get/api_patch/etc. call it
    automatically on a cache miss or expired session."""
    if password is None:
        password = credentials.get_admin_password()
    try:
        r = requests.post(f"http://{ip}/api/auth", json={"password": password}, timeout=8)
        r.raise_for_status()
        sid = r.json().get("session", {}).get("sid", "")
        with _sid_lock:
            _sid_cache[ip] = sid
        return sid
    except Exception:
        return ""


def _request(method: str, ip: str, path: str, password=None, timeout=10, **kwargs):
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = auth(ip, password)
        if not sid:
            return None
        try:
            r = requests.request(method, f"http://{ip}/api{path}", headers={"sid": sid}, timeout=timeout, **kwargs)
            if r.status_code == 401 and attempt == 0:
                with _sid_lock:
                    _sid_cache.pop(ip, None)
                continue
            r.raise_for_status()
            return r.json() if r.content else {}
        except Exception:
            return None
    return None


def api_get(ip: str, path: str, params: dict | None = None, password: str | None = None):
    return _request("GET", ip, path, password=password, params=params)


def api_patch(ip: str, path: str, body: dict, password: str | None = None):
    return _request("PATCH", ip, path, password=password, json=body, timeout=15)


def api_post(ip: str, path: str, body: dict | None = None, password: str | None = None, timeout: int = 15):
    return _request("POST", ip, path, password=password, json=body, timeout=timeout)


def api_put(ip: str, path: str, body: dict, password: str | None = None):
    return _request("PUT", ip, path, password=password, json=body, timeout=15)


def api_delete(ip: str, path: str, password: str | None = None, ok_statuses=(200, 204)) -> bool:
    """Unlike the other verbs, a DELETE's success statuses are caller-
    dependent — e.g. lease_conflicts.py wants a 404 (already gone) treated
    as success too, since that's still the desired end state."""
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = auth(ip, password)
        if not sid:
            return False
        try:
            r = requests.delete(f"http://{ip}/api{path}", headers={"sid": sid}, timeout=10)
            if r.status_code == 401 and attempt == 0:
                invalidate(ip)
                continue
            return r.status_code in ok_statuses
        except Exception:
            return False
    return False


def invalidate(ip: str) -> None:
    """Drops the cached session for a node without an explicit API logout
    call — Pi-hole sessions already expire server-side on their own, and an
    explicit DELETE /api/auth would cost another round trip for no real
    benefit here; this just stops this app from trying a stale sid."""
    with _sid_lock:
        _sid_cache.pop(ip, None)
