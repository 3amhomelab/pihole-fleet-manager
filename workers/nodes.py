#!/usr/bin/env python3
"""Single source of truth for the fleet's Pi-hole node IP list. Every other
worker module calls get_ips() instead of reading PIHOLE_IPS from the
environment directly, so adding/removing a node from the Setup page takes
effect immediately across every loop (monitor, replication, updater,
gravity, failover, ...) with no container recreate needed.

Seeded once from the PIHOLE_IPS env var on first run (so existing
deployments keep working with zero config changes), then this JSON file
becomes authoritative — env var edits after that point are ignored. Kept in
sync back into the bind-mounted host .env (same write-back technique as
setup.py's SSH key and auth.py's password) purely so `docker compose config`
and anyone reading .env by hand still see the real list; the app itself
never reads PIHOLE_IPS from the environment again after first boot."""
import ipaddress
import json
import os
import threading

from workers import activity_log, host_env

DATA_FILE = os.environ.get("NODES_FILE", "/data/nodes.json")

_lock = threading.Lock()


def _seed_from_env() -> list:
    return [ip.strip() for ip in os.environ.get("PIHOLE_IPS", "").split(",") if ip.strip()]


def _save(ips: list) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"ips": ips}, f, indent=2)
    os.replace(tmp, DATA_FILE)
    host_env.write_vars({"PIHOLE_IPS": ",".join(ips)})


def get_ips() -> list:
    with _lock:
        if not os.path.exists(DATA_FILE):
            ips = _seed_from_env()
            _save(ips)
            return ips
        try:
            with open(DATA_FILE) as f:
                return json.load(f).get("ips", [])
        except (OSError, json.JSONDecodeError):
            return _seed_from_env()


def add_ip(ip: str) -> tuple:
    ip = (ip or "").strip()
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return None, f"Invalid IPv4 address: {ip}"
    with _lock:
        ips = get_ips()
        if ip in ips:
            return None, f"{ip} is already in the fleet"
        ips.append(ip)
        _save(ips)
    activity_log.log("nodes", f"Added {ip} to the fleet")
    return ips, None


def remove_ip(ip: str) -> tuple:
    with _lock:
        ips = get_ips()
        if ip not in ips:
            return None, f"{ip} is not in the fleet"
        ips = [i for i in ips if i != ip]
        _save(ips)
    activity_log.log("nodes", f"Removed {ip} from the fleet")
    return ips, None
