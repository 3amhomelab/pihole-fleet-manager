#!/usr/bin/env python3
"""Staggered blocklist (gravity) updates: `pihole -g`/`/api/action/gravity`
can silently under-deliver — a blocklist URL that's briefly unreachable gets
silently skipped/cached rather than erroring, and Pi-hole gives no reliable
success signal beyond "the command exited 0". If every node updates gravity
on the same schedule, a bad update (or a genuinely blocked-upstream list)
degrades the whole fleet's blocking at once with nothing pointing at it.

This runs one node per day (mirrors updater.py's rotation, offset to a
different hour so the two schedules don't collide), and after each update
compares the node's own total blocklist domain count (summed across all
enabled block lists via /api/lists) against what it was before — a large
drop is flagged as a probable partial-update failure rather than assumed to
be a successful, smaller blocklist."""
import json
import os
import threading
import time
from datetime import datetime, timedelta, time as dtime, timezone

import requests

from workers import activity_log, backup, credentials, maintenance, nodes, notify

GRAVITY_HOUR     = int(os.environ.get("GRAVITY_UPDATE_HOUR", "4"))  # UTC hour; offset from PIHOLE_UPDATER_HOUR (3) on purpose
DROP_THRESHOLD_PCT = float(os.environ.get("GRAVITY_DROP_THRESHOLD_PERCENT", "10"))
STATE_FILE       = os.environ.get("GRAVITY_STATE_FILE", "/data/gravity_state.json")
MAX_HISTORY      = 30

_sid_cache  = {}
_sid_lock   = threading.Lock()
_state_lock = threading.Lock()
_node_state = {}   # ip -> {last_domain_count, last_run, history: [...]}
_running    = {}   # ip -> bool
_rotation   = {"last_day": -1, "next_idx": 0}


def _now_iso():
    return datetime.now().isoformat()


# --- Pi-hole v6 API ---

def _auth(ip):
    try:
        r = requests.post(f"http://{ip}/api/auth", json={"password": credentials.get_admin_password()}, timeout=8)
        r.raise_for_status()
        sid = r.json().get("session", {}).get("sid", "")
        with _sid_lock:
            _sid_cache[ip] = sid
        return sid
    except Exception:
        return ""


def _api_get(ip, path):
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = _auth(ip)
        if not sid:
            return None
        try:
            r = requests.get(f"http://{ip}/api{path}", headers={"sid": sid}, timeout=10)
            if r.status_code == 401 and attempt == 0:
                with _sid_lock:
                    _sid_cache.pop(ip, None)
                continue
            r.raise_for_status()
            return r.json()
        except Exception:
            return None
    return None


def _api_post_gravity(ip):
    """Blocking — Pi-hole streams gravity's log as the response body and only
    returns once the update actually finishes, so this needs a generous timeout."""
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = _auth(ip)
        if not sid:
            return None
        try:
            r = requests.post(f"http://{ip}/api/action/gravity", headers={"sid": sid}, timeout=300)
            if r.status_code == 401 and attempt == 0:
                with _sid_lock:
                    _sid_cache.pop(ip, None)
                continue
            r.raise_for_status()
            return r.text
        except Exception:
            return None
    return None


def _domain_count(ip) -> int | None:
    lists = _api_get(ip, "/lists")
    if lists is None:
        return None
    return sum(l.get("number") or 0 for l in lists.get("lists", []) if l.get("type") == "block" and l.get("enabled"))


# --- State persistence ---

def _load_state():
    global _rotation
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
        _rotation = data.get("rotation", {"last_day": -1, "next_idx": 0})
        with _state_lock:
            _node_state.update(data.get("nodes", {}))
    except Exception:
        pass


def _save_state():
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with _state_lock:
            nodes = {ip: dict(v) for ip, v in _node_state.items()}
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"rotation": _rotation, "nodes": nodes}, f, indent=2)
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        print(f"[gravity] state save failed: {e}")


def _record(ip, status, count=None, reason=""):
    with _state_lock:
        node = _node_state.setdefault(ip, {"history": []})
        entry = {"ts": _now_iso(), "result": status}
        if count is not None:
            entry["domain_count"] = count
        if reason:
            entry["reason"] = reason
        node["history"].append(entry)
        if len(node["history"]) > MAX_HISTORY:
            node["history"] = node["history"][-MAX_HISTORY:]
        node["last_run"] = entry["ts"]
        if count is not None:
            node["last_domain_count"] = count
    _save_state()

    if status == "updated":
        activity_log.log("gravity", f"{ip} gravity updated — {count} domain(s)")
    elif status == "dropped":
        activity_log.log("gravity", f"{ip} gravity domain count dropped {reason} — possible partial update failure", level="warning")
        notify.send("gravity_drop", f"{ip} gravity domain count dropped {reason} — possible partial update failure", "warning")
    elif status == "failed":
        activity_log.log("gravity", f"{ip} gravity update failed" + (f": {reason}" if reason else ""), level="error")
        notify.send("gravity_failed", f"{ip} gravity update failed" + (f": {reason}" if reason else ""), "error")


def _next_auto_time(ip: str) -> str | None:
    ips = nodes.get_ips()
    if ip not in ips:
        return None
    n = len(ips)
    idx = ips.index(ip)
    next_idx = _rotation.get("next_idx", 0) % n
    slots_until = (idx - next_idx) % n

    now = datetime.utcnow()
    already_ran_today = _rotation.get("last_day", -1) == now.timetuple().tm_yday
    base_date = now.date()
    if already_ran_today or now.hour > GRAVITY_HOUR:
        base_date += timedelta(days=1)
    fire_date = base_date + timedelta(days=slots_until)
    return datetime.combine(fire_date, dtime(hour=GRAVITY_HOUR), tzinfo=timezone.utc).isoformat()


def get_state() -> dict:
    with _state_lock:
        result = {}
        for ip in nodes.get_ips():
            node = dict(_node_state.get(ip, {"history": []}))
            node["running"] = bool(_running.get(ip))
            node["next_auto"] = _next_auto_time(ip)
            result[ip] = node
        return result


# --- Update execution ---

def _run_gravity(ip) -> tuple:
    """Returns (status, count, reason)."""
    try:
        backup.take_backup("pre-gravity")
    except Exception as e:
        print(f"[gravity] pre-gravity backup snapshot failed (continuing anyway): {e}")

    before = _node_state.get(ip, {}).get("last_domain_count")
    output = _api_post_gravity(ip)
    if output is None:
        return "failed", None, "gravity API call failed"

    after = _domain_count(ip)
    if after is None:
        return "failed", None, "could not read domain count after update"

    if before and after < before * (1 - DROP_THRESHOLD_PCT / 100):
        pct = round((1 - after / before) * 100, 1)
        return "dropped", after, f"{before} → {after} ({pct}% drop)"
    return "updated", after, ""


def _do_gravity(ip):
    _running[ip] = True
    try:
        status, count, reason = _run_gravity(ip)
        _record(ip, status, count, reason)
    finally:
        _running[ip] = False


def trigger_gravity(ip: str) -> tuple:
    if ip not in nodes.get_ips():
        return False, "Invalid target"
    if _running.get(ip):
        return False, "Gravity update already in progress"
    threading.Thread(target=_do_gravity, args=(ip,), daemon=True).start()
    return True, "Gravity update started"


# --- Background loop ---

def _gravity_loop():
    print(f"[gravity] Staggered gravity updates — fires at {GRAVITY_HOUR:02d}:00 UTC, one node/day, "
          f"drop threshold {DROP_THRESHOLD_PCT}%")
    _load_state()

    while True:
        now   = datetime.utcnow()
        today = now.timetuple().tm_yday

        ips = nodes.get_ips()
        if now.hour == GRAVITY_HOUR and today != _rotation["last_day"] and ips:
            _rotation["last_day"] = today
            idx    = _rotation.get("next_idx", 0) % len(ips)
            target = ips[idx]

            if maintenance.is_under_maintenance(target):
                print(f"[gravity] Slot {idx+1}/{len(ips)}: {target} is in maintenance mode — skipping, will retry next cycle")
                _rotation["next_idx"] = (idx + 1) % len(ips)
                _save_state()
                time.sleep(60)
                continue

            print(f"[gravity] Slot {idx+1}/{len(ips)}: updating {target}")

            _running[target] = True
            try:
                status, count, reason = _run_gravity(target)
                _record(target, status, count, reason)
                _rotation["next_idx"] = (idx + 1) % len(ips)
                _save_state()
            finally:
                _running[target] = False

        time.sleep(60)


def start():
    threading.Thread(target=_gravity_loop, daemon=True, name="pihole-gravity").start()
