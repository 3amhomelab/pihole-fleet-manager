#!/usr/bin/env python3
"""One-way "clone a healthy node onto a target" recovery action — e.g. after a
node was wiped/reprovisioned and needs to be brought back into the fleet.

Pi-hole's own Teleporter backup is config-only and nowhere near a full
gravity.db/pihole-FTL.db backup, so restoring a freshly reprovisioned node
from an actual live peer is far more complete and current than restoring
from any Teleporter archive. Unlike replication.py's multi-master merge
(which compares every node and keeps whichever changed most recently), this
is a deliberate one-way overwrite — target := source, no recency comparison,
because a fresh/wiped node has nothing worth preserving.

Reuses replication.py's and pihole_push.py's own API/SSH helpers directly
(including their underscore-prefixed ones) rather than re-implementing the
same HTTP/SSH plumbing a third time — this is all one codebase, not a
library boundary."""
import threading
from collections import deque
from datetime import datetime

from workers import activity_log, gravity, pihole_push, replication, store

_status_lock = threading.Lock()
_status = {"status": "idle", "message": "", "timestamp": None, "log": []}


def _set_status(status, message, log):
    with _status_lock:
        _status["status"], _status["message"] = status, message
        _status["timestamp"] = datetime.now().isoformat()
        _status["log"] = list(log)


def get_status() -> dict:
    with _status_lock:
        return dict(_status)


def _clone_settings(source: str, target: str, step) -> list:
    """Overwrites every replication-managed scalar path + dhcp.hosts on
    target with source's current value."""
    cfg_resp = replication._api_get(source, "/config")
    if cfg_resp is None:
        return [f"could not read config from {source}"]
    cfg = cfg_resp.get("config", {})

    errors = []
    options = replication._load_options()
    for path in replication._SCALAR_PATHS:
        if not options.get(path, True):
            continue
        val, found = replication._get_path(cfg, path)
        if not found:
            continue
        patch = {}
        replication._set_path(patch, path, val)
        if replication._api_patch(target, "/config", {"config": patch}) is None:
            errors.append(f"failed to set {path} on {target}")
    step(f"Cloned settings from {source}")

    if options.get(replication.HOSTS_PATH, True):
        hosts = cfg.get("dhcp", {}).get("hosts", [])
        if replication._api_patch(target, "/config", {"config": {"dhcp": {"hosts": hosts}}}) is None:
            errors.append(f"failed to set dhcp.hosts on {target}")
        step("Cloned static DHCP reservations")
    return errors


def _clone_groups_and_clients(source: str, target: str, step) -> list:
    errors = []
    src_groups = replication._fetch_groups(source)
    if src_groups is None:
        return [f"could not read groups from {source}"]
    for name, g in src_groups.items():
        if replication._api_post(target, "/groups", {"name": name, "enabled": g["enabled"], "comment": g.get("comment", "")}) is None:
            errors.append(f"failed to create group '{name}' on {target}")
    step(f"Cloned {len(src_groups)} group(s)")

    tgt_groups = replication._fetch_groups(target) or {}
    name_to_id = {n: g["id"] for n, g in tgt_groups.items()}
    id_to_name_src = {g["id"]: n for n, g in src_groups.items()}

    src_clients = replication._fetch_clients(source)
    if src_clients is None:
        errors.append(f"could not read clients from {source}")
        return errors
    for client_id, c in src_clients.items():
        names = [id_to_name_src.get(gid) for gid in c.get("groups", [])]
        ids = [name_to_id[n] for n in names if n and n in name_to_id]
        if replication._api_post(target, "/clients", {"client": client_id, "comment": c.get("comment", ""), "groups": ids}) is None:
            errors.append(f"failed to assign client {client_id} on {target}")
    step(f"Cloned {len(src_clients)} client group assignment(s)")
    return errors


def _clone_vlan_push(target: str, step) -> list:
    vlans = store.list_vlans()
    errors = []
    content = pihole_push.render_conf(vlans)
    ok, err = pihole_push._ssh_write_file(target, content)
    if not ok:
        return [f"dnsmasq.d write failed: {err}"]
    if not pihole_push._enable_etc_dnsmasq_d(target):
        errors.append("could not enable etc_dnsmasq_d")
    ok, err = pihole_push._ssh_reload_dns(target)
    if not ok:
        errors.append(f"restartdns failed: {err}")
    ok, err = pihole_push._sync_hostnames(target, vlans)
    if not ok:
        errors.append(f"hostname sync failed: {err}")
    step("Pushed VLAN DHCP scopes + hostname records to target")
    return errors


def clone_node(source: str, target: str) -> None:
    threading.Thread(target=_do_clone, args=(source, target), daemon=True).start()


def _do_clone(source, target):
    log = deque(maxlen=200)

    def step(msg):
        log.append(msg)
        _set_status("running", msg, log)

    if source == target:
        _set_status("error", "Source and target must be different nodes", [])
        return

    try:
        errors = []
        errors += _clone_settings(source, target, step)
        errors += _clone_groups_and_clients(source, target, step)
        errors += _clone_vlan_push(target, step)

        step("Triggering gravity update on target")
        gravity.trigger_gravity(target)

        if errors:
            _set_status("error", f"Completed with {len(errors)} error(s): {'; '.join(errors)}", log)
            activity_log.log("recovery", f"Cloned {source} → {target} with errors: {'; '.join(errors)}", level="error")
        else:
            _set_status("success", f"Cloned {source} → {target}", log)
            activity_log.log("recovery", f"Cloned {source} → {target} successfully")
    except Exception as e:
        _set_status("error", str(e), list(log))
        activity_log.log("recovery", f"Clone {source} → {target} failed: {e}", level="error")
