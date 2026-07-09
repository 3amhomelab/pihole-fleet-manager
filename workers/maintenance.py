#!/usr/bin/env python3
"""Per-node maintenance mode: temporarily pauses this app's own automated
tooling (health-monitor auto-reboot, DHCP failover enforcement, replication,
staggered gravity/software auto-rotation) for one node, so working on it by
hand doesn't get fought by the very automation meant to keep the fleet
healthy — e.g. SSH-rebooting a node mid-change, or flipping its DHCP state
back while testing. Always auto-expires (no "leave it on forever" option) so
a forgotten toggle can't silently disable monitoring for good."""
import json
import os
import threading
from datetime import datetime, timedelta

from workers import activity_log

STATE_FILE = os.environ.get("MAINTENANCE_STATE_FILE", "/data/maintenance.json")
MAX_MINUTES = 24 * 60

_lock = threading.Lock()


def _load() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, STATE_FILE)


def is_under_maintenance(ip: str) -> bool:
    with _lock:
        data = _load()
        until = data.get(ip)
        if not until:
            return False
        return datetime.now() < datetime.fromisoformat(until)


def get_state() -> dict:
    with _lock:
        data = _load()
        now = datetime.now()
        return {ip: until for ip, until in data.items() if datetime.fromisoformat(until) > now}


def set_maintenance(ip: str, minutes: int) -> dict:
    minutes = max(1, min(MAX_MINUTES, int(minutes)))
    until = (datetime.now() + timedelta(minutes=minutes)).isoformat()
    with _lock:
        data = _load()
        data[ip] = until
        _save(data)
    activity_log.log("maintenance", f"{ip} put into maintenance mode for {minutes} minute(s) (until {until})")
    return {"ip": ip, "until": until}


def clear_maintenance(ip: str) -> None:
    with _lock:
        data = _load()
        if data.pop(ip, None) is not None:
            _save(data)
    activity_log.log("maintenance", f"{ip} taken out of maintenance mode")
