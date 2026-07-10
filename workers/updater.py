#!/usr/bin/env python3
"""Pi-hole software auto-updater: daily round-robin `pihole -up` across all
nodes (one per day), plus on-demand manual upgrade, with retries and history.
Moved here from Network-Health, which still owns DNS health monitoring and
node auto-recovery — this module assumes a node is reachable and just skips
it for the day (retrying the next scheduled run) if its API isn't responding,
rather than trying to reboot/recover it itself."""
import json
import os
import subprocess
import threading
import time
from datetime import datetime, timedelta, time as dtime, timezone

from workers import activity_log, backup, credentials, maintenance, monitor, nodes, notify, pihole_api

SSH_KEY         = os.environ.get("PIHOLE_SSH_KEY", "/data/ssh/pihole_key")
UPDATER_HOUR    = int(os.environ.get("PIHOLE_UPDATER_HOUR", "3"))     # UTC hour
UPGRADE_RETRIES = int(os.environ.get("UPGRADE_RETRIES", "3"))
VERSION_POLL_SECS = int(os.environ.get("UPDATER_VERSION_POLL_SECS", "3600"))
STATE_FILE      = os.environ.get("UPDATER_STATE_FILE", "/data/updater_state.json")
MAX_HISTORY     = 30

_SSH_OPTS = ["-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=15", "-o", "BatchMode=yes"]

_state_lock = threading.Lock()
_node_state = {}       # ip -> {version_current, version_latest, version_update_available, last_upgraded, history: [...]}
_upgrade_running = {}  # ip -> bool
_rotation = {"last_day": -1, "next_idx": 0, "halted": False, "halted_reason": ""}
POST_UPGRADE_WAIT_SECS = int(os.environ.get("UPDATER_POST_UPGRADE_WAIT_SECS", "90"))


def _now_iso():
    return datetime.now().isoformat()


# --- Pi-hole v6 API (shared session cache — see pihole_api.py) ---

def _get_version(ip) -> dict:
    """Fetch Pi-hole core version from /info/version."""
    data = pihole_api.api_get(ip, "/info/version")
    if not data:
        return {}
    core    = data.get("version", {}).get("core", {})
    current = (core.get("local") or {}).get("version", "")
    latest  = (core.get("remote") or {}).get("version", "")
    if not current:
        return {}
    return {
        "version_current":          current,
        "version_latest":           latest or current,
        "version_update_available": bool(latest and latest != current),
    }


# --- State persistence ---

def _load_state():
    global _rotation
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
        _rotation = data.get("rotation", {"last_day": -1, "next_idx": 0, "halted": False, "halted_reason": ""})
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
        print(f"[updater] state save failed: {e}")


def _record(ip, status, reason=""):
    with _state_lock:
        node = _node_state.setdefault(ip, {"history": []})
        entry = {"ts": _now_iso(), "result": status}
        if reason:
            entry["reason"] = reason
        if node.get("version_current"):
            entry["version_current"] = node["version_current"]
        if node.get("version_update_available") and node.get("version_latest"):
            entry["version_latest"] = node["version_latest"]
        node["history"].append(entry)
        if len(node["history"]) > MAX_HISTORY:
            node["history"] = node["history"][-MAX_HISTORY:]
        if status == "upgraded":
            node["last_upgraded"] = entry["ts"]
    _save_state()

    if status == "upgraded":
        activity_log.log("updater", f"{ip} upgraded and rebooted")
    elif status == "upgrade_health_failed":
        activity_log.log("updater", f"{ip} upgraded but failed its post-upgrade health check" + (f": {reason}" if reason else ""), level="error")
        notify.send("updater_health_failed", f"{ip} upgraded but failed its post-upgrade health check" + (f": {reason}" if reason else "") + " — auto-updater rotation halted", "error")
    elif status == "failed":
        activity_log.log("updater", f"{ip} upgrade failed" + (f": {reason}" if reason else ""), level="error")
        notify.send("updater_failed", f"{ip} upgrade failed" + (f": {reason}" if reason else "") + " — auto-updater rotation halted", "error")


def _post_upgrade_check(ip: str) -> tuple:
    """Waits for the post-upgrade reboot to land, then runs the same
    confirm-before-declaring-down probe the health monitor itself uses. A
    bad release can look like a clean `pihole -up` exit and still leave DNS
    broken — this is what stops that from silently rolling across every
    node in the fleet, one per day, via the round-robin below."""
    time.sleep(POST_UPGRADE_WAIT_SECS)
    result = monitor.check_node_health(ip)
    return result["ok"], result.get("reason", "")


def get_halted() -> dict:
    return {"halted": bool(_rotation.get("halted")), "reason": _rotation.get("halted_reason", "")}


def resume_rotation() -> None:
    _rotation["halted"] = False
    _rotation["halted_reason"] = ""
    _save_state()
    activity_log.log("updater", "Auto-updater rotation resumed manually")


def _next_auto_time(ip: str) -> str | None:
    """When the daily round-robin will next reach this node, given the
    current rotation position — one node's turn comes up per day at
    UPDATER_HOUR UTC, regardless of whether it ends up needing an upgrade."""
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
    if already_ran_today or now.hour > UPDATER_HOUR:
        base_date += timedelta(days=1)
    fire_date = base_date + timedelta(days=slots_until)
    return datetime.combine(fire_date, dtime(hour=UPDATER_HOUR), tzinfo=timezone.utc).isoformat()


def get_state() -> dict:
    with _state_lock:
        result = {}
        for ip in nodes.get_ips():
            node = dict(_node_state.get(ip, {"history": []}))
            node["upgrade_running"] = bool(_upgrade_running.get(ip))
            node["next_auto"] = _next_auto_time(ip)
            result[ip] = node
        return result


# --- Upgrade execution ---

def _run_upgrade(ip) -> tuple:
    try:
        backup.take_backup("pre-upgrade")
    except Exception as e:
        print(f"[updater] pre-upgrade backup snapshot failed (continuing anyway): {e}")

    reason = ""
    for attempt in range(UPGRADE_RETRIES):
        try:
            proc = subprocess.run(
                ["ssh"] + _SSH_OPTS + [f"{credentials.get_ssh_user()}@{ip}", "sudo pihole -up"],
                capture_output=True, text=True, timeout=300,
            )
            output = proc.stdout + proc.stderr
            if proc.returncode != 0:
                reason = f"exit {proc.returncode}"
            elif "updated" in output.lower():
                subprocess.run(["ssh"] + _SSH_OPTS + [f"{credentials.get_ssh_user()}@{ip}", "sudo reboot"],
                                capture_output=True, text=True, timeout=15)
                return "upgraded", ""
            else:
                return "up_to_date", ""
        except subprocess.TimeoutExpired:
            reason = "timeout"
        except Exception as e:
            reason = str(e)[:80]
        if attempt < UPGRADE_RETRIES - 1:
            time.sleep(10)
    return "failed", reason


def _is_up_to_date(ip) -> bool:
    with _state_lock:
        node = _node_state.get(ip, {})
        return bool(node.get("version_current") and node.get("version_latest")
                    and not node.get("version_update_available", True))


def _do_upgrade(ip):
    _upgrade_running[ip] = True
    try:
        status, reason = _run_upgrade(ip)
        if status == "upgraded":
            healthy, health_reason = _post_upgrade_check(ip)
            if not healthy:
                status, reason = "upgrade_health_failed", health_reason
        _record(ip, status, reason)
        version = _get_version(ip)
        if version:
            with _state_lock:
                _node_state.setdefault(ip, {"history": []}).update(version)
    finally:
        _upgrade_running[ip] = False


def trigger_upgrade(ip: str) -> tuple:
    if ip not in nodes.get_ips():
        return False, "Invalid target"
    if _upgrade_running.get(ip):
        return False, "Upgrade already in progress"
    if _is_up_to_date(ip):
        return False, "Version up to date"
    threading.Thread(target=_do_upgrade, args=(ip,), daemon=True).start()
    return True, "Upgrade started"


# --- Background loops ---

def _poll_versions_loop():
    while True:
        for ip in nodes.get_ips():
            version = _get_version(ip)
            if version:
                with _state_lock:
                    _node_state.setdefault(ip, {"history": []}).update(version)
        time.sleep(VERSION_POLL_SECS)


def _updater_loop():
    print(f"[updater] Daily updater — fires at {UPDATER_HOUR:02d}:00 UTC, retries={UPGRADE_RETRIES}")
    _load_state()

    while True:
        now   = datetime.utcnow()
        today = now.timetuple().tm_yday
        ips = nodes.get_ips()

        if now.hour == UPDATER_HOUR and today != _rotation["last_day"] and ips and not _rotation.get("halted"):
            _rotation["last_day"] = today
            idx    = _rotation.get("next_idx", 0) % len(ips)
            target = ips[idx]

            if maintenance.is_under_maintenance(target):
                print(f"[updater] Slot {idx+1}/{len(ips)}: {target} is in maintenance mode — skipping, will retry next cycle")
                _rotation["next_idx"] = (idx + 1) % len(ips)
                _save_state()
                time.sleep(60)
                continue

            print(f"[updater] Slot {idx+1}/{len(ips)}: checking {target}")

            _upgrade_running[target] = True
            try:
                version = _get_version(target)
                if version:
                    with _state_lock:
                        _node_state.setdefault(target, {"history": []}).update(version)
                else:
                    print(f"[updater] {target} API not responding — skipping today, will retry next cycle")
                    _rotation["next_idx"] = (idx + 1) % len(ips)
                    _save_state()
                    _upgrade_running[target] = False
                    time.sleep(60)
                    continue

                if _is_up_to_date(target):
                    print(f"[updater] {target} already up to date — skipping")
                    _record(target, "up_to_date")
                    _rotation["next_idx"] = (idx + 1) % len(ips)
                else:
                    status, reason = _run_upgrade(target)
                    if status == "upgraded":
                        healthy, health_reason = _post_upgrade_check(target)
                        if not healthy:
                            status, reason = "upgrade_health_failed", health_reason
                    _record(target, status, reason)
                    version = _get_version(target)
                    if version:
                        with _state_lock:
                            _node_state.setdefault(target, {"history": []}).update(version)

                    if status in ("failed", "upgrade_health_failed"):
                        # Don't advance the rotation — a bad release must not silently
                        # roll on to the next node the following day. Requires a manual
                        # "Resume rotation" once the node is confirmed fixed.
                        _rotation["halted"] = True
                        _rotation["halted_reason"] = f"{target}: {status}" + (f" ({reason})" if reason else "")
                    else:
                        _rotation["next_idx"] = (idx + 1) % len(ips)

                _save_state()
            finally:
                _upgrade_running[target] = False

        time.sleep(60)


def start():
    threading.Thread(target=_updater_loop, daemon=True, name="pihole-updater").start()
    threading.Thread(target=_poll_versions_loop, daemon=True, name="pihole-updater-poll").start()
