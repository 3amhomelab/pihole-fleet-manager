#!/usr/bin/env python3
"""DHCP active/standby enforcement.

Pi-hole's embedded DHCP server has no concept of the keepalived VIP that
already exists in front of these nodes for DNS — DHCP is broadcast-based (a
client's DHCPDISCOVER has no destination IP to filter on), so keepalived
moving the VIP address around does nothing to stop every node's DHCP server
from independently answering every broadcast. Confirmed on this cluster:
`dhcp.active = true` on all 3 nodes simultaneously, with no notify_master/
notify_backup hook in keepalived.conf tying DHCP state to VRRP role at all.

This worker polls each node over SSH for whether it currently holds the VIP
(the same signal keepalived itself uses for DNS), and enforces that only that
one node has `dhcp.active = true` via the Pi-hole v6 API — re-asserting the
desired state every tick rather than only reacting to a detected change, so a
manually-flipped node (or one that missed a previous patch) gets corrected on
the next pass too."""
import json
import os
import subprocess
import threading
from collections import deque
from datetime import datetime

import requests

from workers import activity_log, credentials, maintenance, nodes

PIHOLE_VIP  = os.environ.get("PIHOLE_VIP", "").strip()
SSH_KEY     = os.environ.get("PIHOLE_SSH_KEY", "/data/ssh/pihole_key")
STATE_FILE  = os.environ.get("DHCP_FAILOVER_STATE_FILE", "/data/dhcp_failover.json")
CHECK_INTERVAL_SECS = int(os.environ.get("DHCP_FAILOVER_CHECK_INTERVAL_SECS", "15"))
MAX_HISTORY = 20

_SSH_OPTS = ["-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=8", "-o", "BatchMode=yes"]

_sid_cache = {}
_sid_lock  = threading.Lock()

_status_lock = threading.Lock()
_status = {"status": "idle", "message": "", "timestamp": None, "log": [],
           "active_node": None, "history": [], "enabled": False}


# --- Enabled/disabled toggle + active-node history (persisted) ---

def _load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                data = json.load(f)
            data.setdefault("enabled", False)
            data.setdefault("active_node", None)
            data.setdefault("history", [])
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return {"enabled": False, "active_node": None, "history": []}


def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_FILE)


def is_enabled() -> bool:
    return _load_state()["enabled"]


def set_enabled(enabled: bool) -> dict:
    state = _load_state()
    state["enabled"] = bool(enabled)
    _save_state(state)
    activity_log.log("failover", f"DHCP failover management {'enabled' if enabled else 'disabled'}")
    return state


def get_state() -> dict:
    state = _load_state()
    with _status_lock:
        state.update({k: _status[k] for k in ("status", "message", "timestamp", "log")})
    state["vip_configured"] = bool(PIHOLE_VIP)
    return state


# --- VIP master detection (same signal keepalived itself uses for DNS) ---

def _detect_vip_master() -> str | None:
    for ip in nodes.get_ips():
        try:
            proc = subprocess.run(
                ["ssh", *_SSH_OPTS, f"{credentials.get_ssh_user()}@{ip}", f"ip addr show | grep -q '{PIHOLE_VIP}/' && echo yes"],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0 and "yes" in proc.stdout:
                return ip
        except Exception:
            continue
    return None


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


def _set_dhcp_active(ip, active: bool) -> bool:
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = _auth(ip)
        if not sid:
            return False
        try:
            r = requests.patch(f"http://{ip}/api/config", json={"config": {"dhcp": {"active": active}}},
                                headers={"sid": sid}, timeout=15)
            if r.status_code == 401 and attempt == 0:
                with _sid_lock:
                    _sid_cache.pop(ip, None)
                continue
            r.raise_for_status()
            return True
        except Exception:
            return False
    return False


def _get_dhcp_active(ip) -> bool | None:
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = _auth(ip)
        if not sid:
            return None
        try:
            r = requests.get(f"http://{ip}/api/config/dhcp/active", headers={"sid": sid}, timeout=10)
            if r.status_code == 401 and attempt == 0:
                with _sid_lock:
                    _sid_cache.pop(ip, None)
                continue
            r.raise_for_status()
            return bool(r.json().get("config", {}).get("dhcp", {}).get("active"))
        except Exception:
            return None
    return None


# --- Status ---

def _set_status(status, message, log):
    with _status_lock:
        _status["status"], _status["message"] = status, message
        _status["timestamp"] = datetime.now().isoformat()
        _status["log"] = list(log)


def _record_history(state: dict, old: str | None, new: str) -> None:
    state["history"].append({"ts": datetime.now().isoformat(), "from": old, "to": new})
    if len(state["history"]) > MAX_HISTORY:
        del state["history"][: len(state["history"]) - MAX_HISTORY]


# --- Enforcement loop ---

def _tick(log_fn) -> None:
    state = _load_state()
    if not state["enabled"]:
        return
    ips = nodes.get_ips()
    if not PIHOLE_VIP or not ips:
        log_fn("PIHOLE_VIP or PIHOLE_IPS not configured — skipping")
        return

    master = _detect_vip_master()
    if not master:
        log_fn("Could not determine current VIP master — skipping this tick")
        return

    if master != state["active_node"]:
        log_fn(f"VIP master is {master} (was {state['active_node']}) — moving DHCP")
        activity_log.log("failover", f"DHCP active node moving to {master} (was {state['active_node']})")
        _record_history(state, state["active_node"], master)
        state["active_node"] = master
        _save_state(state)

    # Re-assert every tick, not just on a detected change — corrects a node
    # that was manually re-enabled, or missed a previous patch attempt.
    for ip in ips:
        if maintenance.is_under_maintenance(ip):
            log_fn(f"{ip}: in maintenance mode, skipping enforcement")
            continue
        want_active = (ip == master)
        current = _get_dhcp_active(ip)
        if current is None:
            log_fn(f"{ip}: unreachable, skipping")
            continue
        if current != want_active:
            ok = _set_dhcp_active(ip, want_active)
            verb = "Enabled" if want_active else "Disabled"
            if ok:
                log_fn(f"{verb} DHCP on {ip}")
                activity_log.log("failover", f"{verb} DHCP on {ip} (VIP master: {master})")
            else:
                log_fn(f"Failed to set dhcp.active={want_active} on {ip}")
                activity_log.log("failover", f"Failed to set dhcp.active={want_active} on {ip}", level="error")


def _loop():
    while True:
        log = deque(maxlen=100)

        def step(msg):
            log.append(msg)
            _set_status("running", msg, log)

        try:
            _tick(step)
            _set_status("idle", "Checked", log)
        except Exception as e:
            _set_status("error", str(e), list(log))
            activity_log.log("failover", f"DHCP failover check failed: {e}", level="error")

        threading.Event().wait(CHECK_INTERVAL_SECS)


def start():
    threading.Thread(target=_loop, daemon=True, name="dhcp-failover").start()
