#!/usr/bin/env python3
"""Detects a known Pi-hole footgun: giving a client a static DHCP reservation
doesn't retroactively evict a dynamic lease it already holds — the lease
database can keep answering with the old IP until it's manually cleared (or
FTL restarted), so a "reserved" client can silently keep the wrong address.

Polls every node's own active leases directly (rather than reusing
primary_dhcp.get_leases, which merges across nodes and discards which node a
lease actually came from) so a detected conflict can be cleared on the exact
node it's stale on."""
import os
import threading

import requests

from workers import activity_log, primary_dhcp, store

PIHOLE_IPS  = [ip.strip() for ip in os.environ.get("PIHOLE_IPS", "").split(",") if ip.strip()]
PIHOLE_PASS = os.environ.get("PIHOLE_ADMIN_PASSWORD", "")

_sid_cache = {}
_sid_lock  = threading.Lock()


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


def _api_delete(ip, path) -> bool:
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = _auth(ip)
        if not sid:
            return False
        try:
            r = requests.delete(f"http://{ip}/api{path}", headers={"sid": sid}, timeout=10)
            if r.status_code == 401 and attempt == 0:
                with _sid_lock:
                    _sid_cache.pop(ip, None)
                continue
            # 404 means the lease is already gone — that's the desired end state too
            return r.status_code in (200, 204, 404)
        except Exception:
            return False
    return False


def _all_reservations() -> dict:
    """mac (upper) -> reserved ip, across the primary scope and every VLAN."""
    reservations = {}
    for h in primary_dhcp.get_reservations():
        if h.get("mac"):
            reservations[h["mac"].upper()] = h["ip"]
    for v in store.list_vlans():
        if v.get("is_primary"):
            continue
        for h in v.get("hosts", []):
            if h.get("mac"):
                reservations[h["mac"].upper()] = h["ip"]
    return reservations


def check_conflicts() -> list:
    """[{mac, reserved_ip, leased_ip, node}] for every static reservation
    whose mac currently has an active lease at a *different* IP on some node."""
    reservations = _all_reservations()
    if not reservations:
        return []

    conflicts = []
    for ip in PIHOLE_IPS:
        leases = _api_get(ip, "/dhcp/leases")
        if leases is None:
            continue
        for lease in leases.get("leases", []):
            mac = (lease.get("hwaddr") or "").upper()
            leased_ip = lease.get("ip")
            if not mac or not leased_ip:
                continue
            reserved_ip = reservations.get(mac)
            if reserved_ip and reserved_ip != leased_ip:
                conflicts.append({"mac": mac, "reserved_ip": reserved_ip, "leased_ip": leased_ip, "node": ip})
    return conflicts


def clear_conflict(node: str, leased_ip: str) -> tuple:
    """Clears the stale lease on the given node and reloads DNS/DHCP so the
    reservation actually takes effect on the client's next renewal."""
    if node not in PIHOLE_IPS:
        return False, "Unknown node"
    if not _api_delete(node, f"/dhcp/leases/{leased_ip}"):
        return False, "Could not clear lease via API"
    activity_log.log("dhcp", f"Cleared stale lease {leased_ip} on {node}")
    return True, None
