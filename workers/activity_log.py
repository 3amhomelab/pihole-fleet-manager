#!/usr/bin/env python3
"""Persistent activity feed: every worker calls log() when it makes a change
or finishes a sync/push run, so the Log page has one place to see what
happened across VLANs, hosts, replication, and pushes."""
import json
import os
import threading
from datetime import datetime

LOG_FILE   = os.environ.get("ACTIVITY_LOG_FILE", "/data/activity.json")
MAX_EVENTS = 500

_lock   = threading.Lock()
_events = []


def _load():
    global _events
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE) as f:
                _events = json.load(f)
        except (json.JSONDecodeError, OSError):
            _events = []


def _save():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    tmp = LOG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(_events, f, indent=2)
    os.replace(tmp, LOG_FILE)


_load()


def log(category: str, message: str, level: str = "info") -> None:
    with _lock:
        _events.append({
            "ts": datetime.now().isoformat(),
            "category": category,
            "level": level,
            "message": message,
        })
        if len(_events) > MAX_EVENTS:
            del _events[: len(_events) - MAX_EVENTS]
        _save()


def get_events(limit: int = 200, category: str = "") -> list:
    with _lock:
        events = [e for e in _events if not category or e["category"] == category]
        return list(reversed(events[-limit:]))
