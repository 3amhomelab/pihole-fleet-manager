#!/usr/bin/env python3
"""Optional client-name sync for setups where Pi-hole handles DNS only and
DHCP is actually served by a different platform (UniFi, pfSense, OPNsense).
In that topology Pi-hole never sees a DHCP lease, so it has no hostname for
any client — every device shows up as "Unknown" in its own UI. This pulls
the client name/MAC/IP list from the external DHCP source and publishes it
as local DNS (dns.hosts) records on every Pi-hole node, the same way
hostnames.py does for this app's own VLAN-managed DHCP.

Entirely inert unless EXTERNAL_DHCP_SOURCE is set — this whole module is a
no-op by default, same pattern as dhcp_failover.py's PIHOLE_VIP gate.

Only a UniFi OS (UDM-family) controller is implemented. It has NOT been
exercised against a live controller (this homelab doesn't run one) — the
auth flow (POST /api/auth/login, cookie + X-CSRF-Token) and client list
endpoint (GET /proxy/network/api/s/<site>/stat/sta) match UniFi OS's
documented API shape, but a self-hosted "classic" UniFi Network Application
(no /proxy/network prefix, different port) will need SOURCE_KIND handling
added rather than assumed to work. Treat this integration as best-effort
until someone verifies it against real hardware."""
import ipaddress
import json
import os
import threading
import time
from datetime import datetime

import requests

from workers import activity_log, nodes, pihole_api

SOURCE_KIND   = os.environ.get("EXTERNAL_DHCP_SOURCE", "").strip().lower()  # "" (disabled) or "unifi"
POLL_SECS     = int(os.environ.get("EXTERNAL_DHCP_POLL_SECS", "300"))
STATE_FILE    = os.environ.get("EXTERNAL_DHCP_STATE_FILE", "/data/external_dhcp_state.json")

UNIFI_HOST     = os.environ.get("UNIFI_HOST", "").strip()
UNIFI_USER     = os.environ.get("UNIFI_USER", "").strip()
UNIFI_PASSWORD = os.environ.get("UNIFI_PASSWORD", "")
UNIFI_SITE     = os.environ.get("UNIFI_SITE", "default").strip()

_status_lock = threading.Lock()
_status = {"status": "idle", "message": "", "timestamp": None, "clients_found": 0}


def is_enabled() -> bool:
    return SOURCE_KIND == "unifi" and bool(UNIFI_HOST and UNIFI_USER and UNIFI_PASSWORD)


def get_status() -> dict:
    with _status_lock:
        d = dict(_status)
    d["enabled"] = is_enabled()
    d["source_kind"] = SOURCE_KIND or None
    return d


def _set_status(status, message, clients_found=None):
    with _status_lock:
        _status["status"], _status["message"] = status, message
        _status["timestamp"] = datetime.now().isoformat()
        if clients_found is not None:
            _status["clients_found"] = clients_found


# --- UniFi OS client fetch ---

def _fetch_unifi_clients() -> list | None:
    """[{ "mac": ..., "ip": ..., "hostname": ... }] of currently-active
    wired+wireless clients known to the controller, or None on failure."""
    session = requests.Session()
    session.verify = False  # UniFi controllers are almost always self-signed
    try:
        r = session.post(f"https://{UNIFI_HOST}/api/auth/login",
                          json={"username": UNIFI_USER, "password": UNIFI_PASSWORD}, timeout=10)
        r.raise_for_status()
        csrf = r.headers.get("X-CSRF-Token") or session.cookies.get("csrf_token")
        headers = {"X-CSRF-Token": csrf} if csrf else {}

        r = session.get(f"https://{UNIFI_HOST}/proxy/network/api/s/{UNIFI_SITE}/stat/sta",
                         headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json().get("data", [])
    except Exception as e:
        activity_log.log("external_dhcp", f"UniFi client fetch failed: {e}", level="error")
        return None

    clients = []
    for c in data:
        mac = c.get("mac")
        ip = c.get("ip") or c.get("fixed_ip")
        hostname = c.get("name") or c.get("hostname")
        if mac and ip and hostname:
            clients.append({"mac": mac.upper(), "ip": ip, "hostname": hostname})
    return clients


def _fetch_clients() -> list | None:
    if SOURCE_KIND == "unifi":
        return _fetch_unifi_clients()
    return None


# --- Managed dns.hosts merge (tracks previously-published IPs, since these
# clients can be on any subnet — not scoped by VLAN like hostnames.py) ---

def _load_previous_ips() -> set:
    try:
        with open(STATE_FILE) as f:
            return set(json.load(f).get("published_ips", []))
    except Exception:
        return set()


def _save_previous_ips(ips: set) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"published_ips": sorted(ips)}, f, indent=2)
    os.replace(tmp, STATE_FILE)


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def merge(current_hosts: list, clients: list, previously_published: set) -> tuple:
    """Drops any line whose IP was published by a *previous* run of this
    module (so a client that moved IP or disappeared doesn't leave a stale
    record), keeps everything else untouched, then adds the current set.
    Returns (merged_lines, newly_published_ip_set)."""
    kept = [line for line in (current_hosts or [])
            if not (line.split(None, 1) and line.split(None, 1)[0] in previously_published)]
    fresh = [f"{c['ip']} {c['hostname']}" for c in clients if _valid_ip(c["ip"])]
    return kept + fresh, {c["ip"] for c in clients if _valid_ip(c["ip"])}


# --- Pi-hole push (shared session cache — see pihole_api.py) ---


def sync_now() -> tuple:
    if not is_enabled():
        return False, "Not configured (EXTERNAL_DHCP_SOURCE/UNIFI_* unset)"

    clients = _fetch_clients()
    if clients is None:
        _set_status("error", "Could not fetch client list from external source")
        return False, "Could not fetch client list"

    previously_published = _load_previous_ips()
    newly_published = {c["ip"] for c in clients if _valid_ip(c["ip"])}
    failed = []
    for ip in nodes.get_ips():
        current = pihole_api.api_get(ip, "/config/dns/hosts")
        if current is None:
            failed.append(ip)
            continue
        existing = current.get("config", {}).get("dns", {}).get("hosts", [])
        merged, _ = merge(existing, clients, previously_published)
        if pihole_api.api_patch(ip, "/config", {"config": {"dns": {"hosts": merged}}}) is None:
            failed.append(ip)

    _save_previous_ips(newly_published)

    if failed:
        _set_status("error", f"Failed on: {', '.join(failed)}", len(clients))
        activity_log.log("external_dhcp", f"External DHCP sync failed on {', '.join(failed)}", level="error")
        return False, f"Failed on {', '.join(failed)}"

    _set_status("success", f"Synced {len(clients)} client(s)", len(clients))
    activity_log.log("external_dhcp", f"Synced {len(clients)} client(s) from {SOURCE_KIND}")
    return True, None


def _loop():
    while True:
        if is_enabled():
            sync_now()
        time.sleep(POLL_SECS)


def start():
    threading.Thread(target=_loop, daemon=True, name="external-dhcp-sync").start()
