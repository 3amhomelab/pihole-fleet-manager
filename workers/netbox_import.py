#!/usr/bin/env python3
"""One-way import of VLAN scopes + static host reservations from NetBox
(IPAM+DCIM), mirroring the existing "scan a node's live dnsmasq.d config"
import flow in pihole_push.py/store.py — same preview-then-apply shape, just
sourced from NetBox instead of a Pi-hole node.

Mapping (the "standard IPAM+DCIM" approach): a NetBox VLAN's associated
Prefix supplies the subnet; every IP Address inside that prefix that's
assigned to a Device or VM interface with a MAC address becomes a static
host reservation (hostname from the IP's dns_name, falling back to the
parent device/VM's name). Gateway and the DHCP-issuable range aren't
modeled in NetBox, so both are a best-effort guess (first usable host as
gateway, everything from the 10th usable host onward as the range) meant to
be reviewed/edited on the VLANs page after import, not trusted blindly.

Read-only against NetBox — this never writes anything back to it."""
import ipaddress
import os

import requests

NETBOX_URL   = os.environ.get("NETBOX_URL", "").rstrip("/")
NETBOX_TOKEN = os.environ.get("NETBOX_TOKEN", "")
NETBOX_VERIFY_SSL = os.environ.get("NETBOX_VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes")
TIMEOUT = 15


def configured() -> bool:
    return bool(NETBOX_URL and NETBOX_TOKEN)


def _headers():
    return {"Authorization": f"Token {NETBOX_TOKEN}", "Accept": "application/json"}


def _get_all(path: str, params: dict | None = None) -> list:
    """Follows NetBox's {count, next, previous, results} pagination."""
    url = f"{NETBOX_URL}{path}"
    results = []
    while url:
        r = requests.get(url, headers=_headers(), params=params, timeout=TIMEOUT, verify=NETBOX_VERIFY_SSL)
        r.raise_for_status()
        data = r.json()
        results.extend(data.get("results", []))
        url = data.get("next")
        params = None  # already encoded into `next`
    return results


def _get_one(path: str):
    r = requests.get(f"{NETBOX_URL}{path}", headers=_headers(), timeout=TIMEOUT, verify=NETBOX_VERIFY_SSL)
    r.raise_for_status()
    return r.json()


def _interface_mac(assigned_object_type: str, assigned_object_id: int) -> str:
    """mac_address lives directly on the interface in NetBox <4.2; 4.2+ moved
    it to a separate MACAddress object referenced by primary_mac_address —
    this checks both so it works either way."""
    if assigned_object_type == "dcim.interface":
        iface = _get_one(f"/api/dcim/interfaces/{assigned_object_id}/")
    elif assigned_object_type == "virtualization.vminterface":
        iface = _get_one(f"/api/virtualization/interfaces/{assigned_object_id}/")
    else:
        return ""
    mac = iface.get("mac_address") or ""
    if not mac:
        primary = iface.get("primary_mac_address")
        if isinstance(primary, dict):
            mac = primary.get("mac_address") or ""
    return mac.upper() if mac else ""


def _hostname_for(ip_obj: dict) -> str:
    if ip_obj.get("dns_name"):
        return ip_obj["dns_name"]
    assigned = ip_obj.get("assigned_object") or {}
    device = assigned.get("device") or assigned.get("virtual_machine") or {}
    return device.get("name") or ""


def _vlan_hosts(prefix_id: int) -> tuple:
    """Returns (hosts, skipped_count) for every IP in the prefix that has a
    resolvable MAC address via its assigned device/VM interface."""
    hosts, skipped = [], 0
    for ip_obj in _get_all(f"/api/ipam/prefixes/{prefix_id}/ip-addresses/"):
        assigned_type = ip_obj.get("assigned_object_type")
        assigned_id = ip_obj.get("assigned_object_id")
        if not assigned_type or not assigned_id:
            skipped += 1
            continue
        try:
            mac = _interface_mac(assigned_type, assigned_id)
        except Exception:
            mac = ""
        if not mac:
            skipped += 1
            continue
        ip = ip_obj["address"].split("/")[0]
        hosts.append({"mac": mac, "ip": ip, "hostname": _hostname_for(ip_obj)})
    return hosts, skipped


def _guess_gateway_and_range(net: "ipaddress.IPv4Network") -> tuple:
    hosts = list(net.hosts())
    if len(hosts) < 3:
        return str(net.network_address), str(net.network_address), str(net.broadcast_address)
    gateway = str(hosts[0])
    range_start = str(hosts[9]) if len(hosts) > 10 else str(hosts[1])
    range_end = str(hosts[-1])
    return gateway, range_start, range_end


def preview(existing_vlans: list) -> tuple:
    """Returns (candidates, error). Each candidate matches the shape
    store.create_vlan()/add_or_update_host() expect, plus already_exists —
    matched by subnet+prefix since NetBox's ids don't correspond to
    anything in the local store."""
    if not configured():
        return [], "NETBOX_URL/NETBOX_TOKEN not configured"

    existing_nets = set()
    for v in existing_vlans:
        try:
            existing_nets.add(str(ipaddress.ip_network(f"{v['subnet']}/{v['prefix']}", strict=False)))
        except (KeyError, ValueError):
            continue

    candidates = []
    for vlan in _get_all("/api/ipam/vlans/"):
        prefixes = _get_all("/api/ipam/prefixes/", params={"vlan_id": vlan["id"]})
        if not prefixes:
            continue
        prefix = prefixes[0]
        try:
            net = ipaddress.ip_network(prefix["prefix"], strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue  # this app's VLAN scopes are IPv4-only throughout

        hosts, skipped = _vlan_hosts(prefix["id"])
        gateway, range_start, range_end = _guess_gateway_and_range(net)
        candidates.append({
            "name": vlan.get("name") or f"VLAN {vlan.get('vid')}",
            "vlan_tag": vlan.get("vid"),
            "subnet": str(net.network_address),
            "prefix": net.prefixlen,
            "gateway": gateway,
            "range_start": range_start,
            "range_end": range_end,
            "lease_time": "12h",
            "hosts": hosts,
            "hosts_skipped": skipped,
            "already_exists": str(net) in existing_nets,
        })
    return candidates, None


def apply_import(vlans: list) -> tuple:
    """vlans: list of candidate dicts as returned by preview(). Creates each
    as a new VLAN scope via the same validated store.create_vlan() path the
    manual "add VLAN" form uses, then adds its hosts — never store.import_vlan
    (which skips validation, meant for already-valid dnsmasq-sourced data)."""
    from workers import store  # deferred: keeps this module import-order-agnostic, no cycle either way

    imported, errors = [], []
    for v in vlans:
        vlan, error = store.create_vlan(v)
        if error:
            errors.append(f"{v.get('name')}: {error}")
            continue
        host_errors = 0
        for h in v.get("hosts", []):
            _, err = store.add_or_update_host(vlan["id"], h["mac"], h["ip"], h.get("hostname", ""))
            if err:
                host_errors += 1
        imported.append(f"{v['name']}: {len(v.get('hosts', [])) - host_errors}/{len(v.get('hosts', []))} host(s)")
    return imported, errors
