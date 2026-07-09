#!/usr/bin/env python3
"""Manages Pi-hole's own primary DHCP scope: static reservation CRUD against
the first PIHOLE_IPS node. Moved here from Network-Health so this app is the
one place that manages Pi-hole DHCP scopes — the primary scope and the extra
VLAN scopes alike. Propagating a reservation change to the other nodes is
handled by workers.replication's multi-master merge, triggered right after
each write here — this module no longer does its own one-way push."""
import os
import threading

import requests

from workers import activity_log, replication

PIHOLE_IPS      = [ip.strip() for ip in os.environ.get("PIHOLE_IPS", "").split(",") if ip.strip()]
PIHOLE_API_HOST = PIHOLE_IPS[0] if PIHOLE_IPS else ""
PIHOLE_PASS     = os.environ.get("PIHOLE_ADMIN_PASSWORD", "")

_sid_cache = {}
_sid_lock  = threading.Lock()


# --- Pi-hole v6 API ---

def _auth(ip):
    try:
        r = requests.post(f"http://{ip}/api/auth", json={"password": PIHOLE_PASS}, timeout=8)
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


def _api_patch(ip, path, body):
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = _auth(ip)
        if not sid:
            return None
        try:
            r = requests.patch(f"http://{ip}/api{path}", json=body, headers={"sid": sid}, timeout=15)
            if r.status_code == 401 and attempt == 0:
                with _sid_lock:
                    _sid_cache.pop(ip, None)
                continue
            r.raise_for_status()
            return r.json()
        except Exception:
            return None
    return None


# --- Reservation CRUD (writes to the primary node only) ---

def get_config(ip: str = None) -> dict:
    ip = ip or PIHOLE_API_HOST
    if not ip:
        return {}
    data = _api_get(ip, "/config/dhcp")
    return (data or {}).get("config", {}).get("dhcp", {})


def get_leases() -> list:
    """Active DHCP leases merged across every node (each Pi-hole runs its own
    DHCP server and only knows the leases it personally handed out)."""
    merged = {}
    for node_ip in PIHOLE_IPS:
        node_leases = (_api_get(node_ip, "/dhcp/leases") or {}).get("leases", [])
        for lease in node_leases:
            key = lease.get("ip") or lease.get("hwaddr")
            if key and key not in merged:
                merged[key] = lease
    return list(merged.values())


def get_reservations(ip: str = None) -> list:
    """Current primary-scope reservations as {mac, ip, hostname} dicts."""
    parsed = []
    for h in get_config(ip).get("hosts", []):
        parts = h.split(",")
        if len(parts) >= 2 and parts[1].strip():
            parsed.append({
                "mac": parts[0].strip(),
                "ip": parts[1].strip(),
                "hostname": parts[2].strip() if len(parts) > 2 else "",
            })
    return parsed


def add_or_update_reservation(mac: str, ip: str, hostname: str = "") -> tuple:
    full = _api_get(PIHOLE_API_HOST, "/config")
    if not full:
        return False, "Failed to fetch config from Pi-hole"

    dhcp  = full.get("config", {}).get("dhcp", {})
    hosts = dhcp.get("hosts", [])
    mac_u = mac.upper()
    name  = (hostname or "").strip()
    new_entry = f"{mac_u},{ip},{name}"

    is_update = any(h.split(",")[0].upper() == mac_u for h in hosts)
    new_hosts = [h for h in hosts if h.split(",")[0].upper() != mac_u]
    new_hosts.append(new_entry)
    dhcp["hosts"] = new_hosts

    result = _api_patch(PIHOLE_API_HOST, "/config", {"config": {"dhcp": dhcp}})
    if result is None:
        return False, "PATCH to Pi-hole failed"
    verb = "Updated" if is_update else "Added"
    activity_log.log("host", f"{verb} host {mac_u} ({ip}{f', {name}' if name else ''}) in primary scope")
    replication.trigger_sync()
    return True, None


def delete_reservation(ip: str) -> tuple:
    full = _api_get(PIHOLE_API_HOST, "/config")
    if not full:
        return False, "Failed to fetch config from Pi-hole"

    dhcp      = full.get("config", {}).get("dhcp", {})
    hosts     = dhcp.get("hosts", [])
    new_hosts = [h for h in hosts if h.split(",")[1].strip() != ip]

    if len(new_hosts) == len(hosts):
        return False, f"No static reservation found for {ip}"

    dhcp["hosts"] = new_hosts
    result = _api_patch(PIHOLE_API_HOST, "/config", {"config": {"dhcp": dhcp}})
    if result is None:
        return False, "PATCH to Pi-hole failed"
    activity_log.log("host", f"Removed reservation for {ip} from primary scope")
    replication.trigger_sync()
    return True, None


def update_reservation_mac(ip: str, new_mac: str) -> tuple:
    full = _api_get(PIHOLE_API_HOST, "/config")
    if not full:
        return False, "Failed to fetch config from Pi-hole"

    dhcp  = full.get("config", {}).get("dhcp", {})
    hosts = dhcp.get("hosts", [])

    new_hosts = []
    updated   = False
    for h in hosts:
        parts = h.split(",")
        if len(parts) >= 2 and parts[1].strip() == ip:
            parts[0] = new_mac
            new_hosts.append(",".join(parts))
            updated = True
        else:
            new_hosts.append(h)

    if not updated:
        return False, f"No static reservation found for {ip}"

    dhcp["hosts"] = new_hosts
    result = _api_patch(PIHOLE_API_HOST, "/config", {"config": {"dhcp": dhcp}})
    if result is None:
        return False, "PATCH to Pi-hole failed"
    activity_log.log("host", f"Changed MAC for {ip} to {new_mac} in primary scope")
    replication.trigger_sync()
    return True, None
