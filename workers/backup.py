#!/usr/bin/env python3
"""Point-in-time fleet backups + rollback. Captures, per node, everything
replication.py and recovery.py already know how to read/write: the
replication-managed config.toml scalar paths, static DHCP reservations,
groups, per-client group assignments, adlists, and domain allow/deny
overrides — the same fields multi-master replication keeps in sync, just
snapshotted to a file instead of pushed live.

Multi-master replication faithfully propagates mistakes too: a bad setting
changed on one node wins the recency contest and lands on every node, and
recovery.py can't help because every "healthy peer" now has the same bad
config. A snapshot taken right before every replication push, gravity
update, and software upgrade — plus an optional daily/weekly/monthly one —
means there's always something to roll back to.

Reuses replication.py's underscore-prefixed API helpers directly, same
precedent as recovery.py; only imports gravity.py lazily inside
restore_snapshot (called at rollback time, not import time) to avoid a
top-level import cycle, since gravity.py/updater.py/replication.py each
lazily import THIS module to call take_backup() before their own risky
action — see the deferred `from workers import backup` inside each."""
import json
import os
import threading
import time
import urllib.parse
from datetime import datetime, timedelta

from workers import activity_log, notify, replication
from workers import nodes as fleet_nodes

BACKUP_DIR     = os.environ.get("BACKUP_DIR", "/data/backups")
SETTINGS_FILE  = os.environ.get("BACKUP_SETTINGS_FILE", "/data/backup_settings.json")
MAX_KEEP       = 5
LOOP_INTERVAL_SECS = 300

_lock   = threading.Lock()
_status = {"status": "idle", "message": "", "timestamp": None, "log": []}
_status_lock = threading.Lock()

_SCHEDULE_SECS = {"off": 0, "daily": 86400, "weekly": 7 * 86400, "monthly": 30 * 86400}


# --- Settings (retention count + schedule) ---

def _load_settings() -> dict:
    try:
        with open(SETTINGS_FILE) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        data = {}
    return {
        "keep": max(1, min(MAX_KEEP, int(data.get("keep", MAX_KEEP)))),
        "schedule": data.get("schedule") if data.get("schedule") in _SCHEDULE_SECS else "off",
        "last_scheduled_run": data.get("last_scheduled_run"),
    }


def _save_settings(settings: dict) -> None:
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(settings, f, indent=2)
    os.replace(tmp, SETTINGS_FILE)


def get_settings() -> dict:
    with _lock:
        return _load_settings()


def set_settings(keep: int, schedule: str) -> dict:
    if schedule not in _SCHEDULE_SECS:
        schedule = "off"
    with _lock:
        settings = _load_settings()
        settings["keep"] = max(1, min(MAX_KEEP, int(keep)))
        settings["schedule"] = schedule
        _save_settings(settings)
    activity_log.log("backup", f"Backup settings updated: keep={settings['keep']}, schedule={schedule}")
    return settings


# --- Status (mirrors the job status/log pattern used elsewhere) ---

def _set_status(status, message, log):
    with _status_lock:
        _status["status"], _status["message"] = status, message
        _status["timestamp"] = datetime.now().isoformat()
        _status["log"] = list(log)


def get_status() -> dict:
    with _status_lock:
        return dict(_status)


# --- Capture ---

def _capture_config(ip):
    cfg_resp = replication._api_get(ip, "/config")
    if cfg_resp is None:
        return None
    cfg = cfg_resp.get("config", {})
    scalars = {}
    for path in replication._SCALAR_PATHS:
        val, found = replication._get_path(cfg, path)
        if found:
            scalars[path] = val
    return {"scalars": scalars, "hosts": cfg.get("dhcp", {}).get("hosts", [])}


def _names(group_ids, id_to_name):
    return [id_to_name.get(gid, f"#{gid}") for gid in (group_ids or [])]


def _capture_node(ip) -> dict | None:
    config = _capture_config(ip)
    if config is None:
        return None
    groups = replication._fetch_groups(ip) or {}
    id_to_name = {g["id"]: n for n, g in groups.items()}
    clients = replication._fetch_clients(ip) or {}
    lists = replication._fetch_lists(ip) or {}
    domains = replication._fetch_domains(ip) or {}
    return {
        "config": config,
        "groups": {n: {"enabled": g["enabled"], "comment": g.get("comment", "")} for n, g in groups.items()},
        "clients": {cid: {"comment": c.get("comment", ""), "groups": _names(c.get("groups"), id_to_name)}
                    for cid, c in clients.items()},
        "lists": {addr: {"type": l["type"], "enabled": l.get("enabled", True), "comment": l.get("comment", ""),
                          "groups": _names(l.get("groups"), id_to_name)}
                  for addr, l in lists.items()},
        "domains": {key: {"type": d["type"], "kind": d["kind"], "domain": d["domain"],
                           "enabled": d.get("enabled", True), "comment": d.get("comment", ""),
                           "groups": _names(d.get("groups"), id_to_name)}
                    for key, d in domains.items()},
    }


def _snapshot_path(name: str) -> str:
    return os.path.join(BACKUP_DIR, f"{name}.json")


def _apply_retention(keep: int) -> None:
    names = sorted(n[:-5] for n in os.listdir(BACKUP_DIR) if n.endswith(".json")) if os.path.isdir(BACKUP_DIR) else []
    for old in names[:-keep] if keep > 0 else names:
        try:
            os.remove(_snapshot_path(old))
        except OSError:
            pass


def take_backup(trigger: str = "manual") -> tuple:
    """Synchronous — callers (manual button, or the pre-action hooks in
    replication/gravity/updater) block until the snapshot is actually saved.
    A snapshot taken right before a risky action is only useful if it's
    guaranteed to have landed before that action's first write."""
    log = []

    def step(msg):
        log.append(msg)
        _set_status("running", msg, log)

    ips = fleet_nodes.get_ips()
    if not ips:
        _set_status("error", "No PIHOLE_IPS configured", log)
        return False, "No PIHOLE_IPS configured"

    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        nodes = {}
        for ip in ips:
            step(f"Capturing {ip}")
            captured = _capture_node(ip)
            nodes[ip] = captured if captured is not None else {"error": "unreachable"}

        ok_count = sum(1 for n in nodes.values() if "error" not in n)
        if ok_count == 0:
            _set_status("error", "No nodes were reachable — nothing captured", log)
            return False, "No nodes were reachable"

        name = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        data = {"ts": datetime.now().isoformat(), "trigger": trigger, "nodes": nodes}
        tmp = _snapshot_path(name) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, _snapshot_path(name))

        settings = get_settings()
        _apply_retention(settings["keep"])

        step(f"Saved snapshot {name} ({ok_count}/{len(ips)} node(s) captured)")
        _set_status("success", f"Backup '{name}' saved ({ok_count}/{len(ips)} node(s))", log)
        activity_log.log("backup", f"Snapshot '{name}' taken ({trigger}) — {ok_count}/{len(ips)} node(s) captured")
        return True, name
    except Exception as e:
        _set_status("error", str(e), log)
        activity_log.log("backup", f"Snapshot failed ({trigger}): {e}", level="error")
        return False, str(e)


def list_backups() -> list:
    if not os.path.isdir(BACKUP_DIR):
        return []
    out = []
    for fname in os.listdir(BACKUP_DIR):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(BACKUP_DIR, fname)
        try:
            with open(path) as f:
                data = json.load(f)
            out.append({
                "name": fname[:-5],
                "ts": data.get("ts"),
                "trigger": data.get("trigger", "manual"),
                "nodes": list(data.get("nodes", {}).keys()),
                "node_ok_count": sum(1 for n in data.get("nodes", {}).values() if "error" not in n),
            })
        except (OSError, json.JSONDecodeError):
            continue
    out.sort(key=lambda b: b["name"], reverse=True)
    return out


# --- Rollback ---

def _restore_node(ip: str, snap: dict, step) -> list:
    errors = []
    for path, val in snap["config"]["scalars"].items():
        patch = {}
        replication._set_path(patch, path, val)
        if replication._api_patch(ip, "/config", {"config": patch}) is None:
            errors.append(f"{ip}: failed to restore {path}")
    if replication._api_patch(ip, "/config", {"config": {"dhcp": {"hosts": snap["config"]["hosts"]}}}) is None:
        errors.append(f"{ip}: failed to restore dhcp.hosts")
    step(f"Restored settings + static reservations on {ip}")

    for name, g in snap["groups"].items():
        if replication._api_post(ip, "/groups", {"name": name, "enabled": g["enabled"], "comment": g.get("comment", "")}) is None:
            errors.append(f"{ip}: failed to restore group '{name}'")

    tgt_groups = replication._fetch_groups(ip) or {}
    name_to_id = {n: g["id"] for n, g in tgt_groups.items()}

    for cid, c in snap["clients"].items():
        ids = [name_to_id[n] for n in c["groups"] if n in name_to_id]
        if replication._api_post(ip, "/clients", {"client": cid, "comment": c.get("comment", ""), "groups": ids}) is None:
            errors.append(f"{ip}: failed to restore client '{cid}'")
    step(f"Restored {len(snap['groups'])} group(s), {len(snap['clients'])} client assignment(s) on {ip}")

    tgt_lists = replication._fetch_lists(ip) or {}
    for addr, l in snap["lists"].items():
        ids = [name_to_id[n] for n in l["groups"] if n in name_to_id]
        body = {"address": addr, "type": l["type"], "enabled": l["enabled"], "comment": l.get("comment", ""), "groups": ids}
        exists = addr in tgt_lists
        result = (replication._api_put(ip, f"/lists/{urllib.parse.quote(addr, safe='')}", body)
                  if exists else replication._api_post(ip, "/lists", body))
        if result is None:
            errors.append(f"{ip}: failed to restore adlist '{addr}'")

    tgt_domains = replication._fetch_domains(ip) or {}
    for key, d in snap["domains"].items():
        ids = [name_to_id[n] for n in d["groups"] if n in name_to_id]
        body = {"domain": d["domain"], "enabled": d["enabled"], "comment": d.get("comment", ""), "groups": ids}
        path_suffix = f"/domains/{d['type']}/{d['kind']}"
        exists = key in tgt_domains
        result = (replication._api_put(ip, f"{path_suffix}/{urllib.parse.quote(d['domain'], safe='')}", body)
                  if exists else replication._api_post(ip, path_suffix, body))
        if result is None:
            errors.append(f"{ip}: failed to restore domain override '{d['domain']}'")
    step(f"Restored {len(snap['lists'])} adlist(s), {len(snap['domains'])} domain override(s) on {ip}")

    from workers import gravity  # deferred — see module docstring
    gravity.trigger_gravity(ip)
    return errors


def rollback(name: str, target_ip: str | None = None) -> None:
    threading.Thread(target=_do_rollback, args=(name, target_ip), daemon=True).start()


def _do_rollback(name: str, target_ip: str | None):
    log = []

    def step(msg):
        log.append(msg)
        _set_status("running", msg, log)

    try:
        with open(_snapshot_path(name)) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _set_status("error", f"Could not read snapshot '{name}': {e}", log)
        return

    targets = [target_ip] if target_ip else list(data.get("nodes", {}).keys())
    errors = []
    for ip in targets:
        snap = data.get("nodes", {}).get(ip)
        if not snap or "error" in snap:
            errors.append(f"{ip}: not captured in this snapshot, skipped")
            continue
        step(f"Rolling back {ip} to snapshot '{name}'")
        errors += _restore_node(ip, snap, step)

    if errors:
        _set_status("error", f"Rollback completed with {len(errors)} error(s): {'; '.join(errors)}", log)
        activity_log.log("backup", f"Rollback to '{name}' completed with errors: {'; '.join(errors)}", level="error")
        notify.send("backup_rollback_errors", f"Rollback to snapshot '{name}' completed with errors: {'; '.join(errors)}", "error")
    else:
        _set_status("success", f"Rolled back {', '.join(targets)} to snapshot '{name}'", log)
        activity_log.log("backup", f"Rolled back {', '.join(targets)} to snapshot '{name}'")


def delete_backup(name: str) -> tuple:
    path = _snapshot_path(name)
    if not os.path.isfile(path):
        return False, "Snapshot not found"
    os.remove(path)
    activity_log.log("backup", f"Snapshot '{name}' deleted")
    return True, None


# --- Scheduled backups (daily/weekly/monthly) ---

def _schedule_due(settings: dict) -> bool:
    secs = _SCHEDULE_SECS.get(settings["schedule"], 0)
    if secs <= 0:
        return False
    last = settings.get("last_scheduled_run")
    if not last:
        return True
    return (datetime.now() - datetime.fromisoformat(last)) >= timedelta(seconds=secs)


def _schedule_loop():
    while True:
        settings = get_settings()
        if _schedule_due(settings):
            take_backup(trigger="scheduled")
            with _lock:
                settings = _load_settings()
                settings["last_scheduled_run"] = datetime.now().isoformat()
                _save_settings(settings)
        time.sleep(LOOP_INTERVAL_SECS)


def start():
    threading.Thread(target=_schedule_loop, daemon=True, name="backup-schedule").start()
