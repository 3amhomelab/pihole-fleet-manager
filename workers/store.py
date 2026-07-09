#!/usr/bin/env python3
"""VLAN + per-VLAN host reservation store (JSON-backed, /data/vlans.json)."""
import ipaddress
import json
import os
import re
import threading

from workers import activity_log

DATA_FILE = os.environ.get("DATA_FILE", "/data/vlans.json")

_lock = threading.Lock()

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}$")


# --- Persistence ---

def _load():
    if not os.path.exists(DATA_FILE):
        return {"vlans": []}
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"vlans": []}


def _save(data):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, DATA_FILE)


# --- Validation helpers ---

def valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac or ""))


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def network_of(vlan: dict) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{vlan['subnet']}/{vlan['prefix']}", strict=False)


def netmask_of(vlan: dict) -> str:
    return str(network_of(vlan).netmask)


def primary_vlan_from_config(pihole_config: dict) -> dict | None:
    """Builds the 'primary' VLAN dict (metadata only, no side effects) from a
    live Pi-hole /config/dhcp response. Shared by ensure_primary_vlan (which
    persists it) and the node-scan preview (which just wants to show it)."""
    if not pihole_config or not pihole_config.get("start"):
        return None
    try:
        net = ipaddress.ip_network(
            f"{pihole_config['start']}/{pihole_config.get('netmask', '255.255.255.0')}", strict=False)
    except ValueError:
        return None

    return {
        "id": "primary",
        "name": "Primary (existing Pi-hole scope)",
        "vlan_tag": None,
        "is_primary": True,
        "subnet": str(net.network_address),
        "prefix": net.prefixlen,
        "gateway": pihole_config.get("router", ""),
        "range_start": pihole_config.get("start", ""),
        "range_end": pihole_config.get("end", ""),
        "lease_time": f"{pihole_config.get('leaseTime', '24')}h" if str(pihole_config.get("leaseTime", "")).isdigit() else str(pihole_config.get("leaseTime") or "24h"),
        "hosts": [],
    }


def ensure_primary_vlan(pihole_config: dict) -> dict | None:
    """On first connect, mirror Pi-hole's own existing DHCP scope into the store
    as a reference VLAN (id='primary'), so it shows up in the VLANs list. Its
    `hosts` are always computed fresh from Pi-hole at request time (see
    merge_dynamic_hosts below) rather than persisted here — this just seeds the
    metadata (subnet/gateway/range). No-op if it already exists."""
    vlan = primary_vlan_from_config(pihole_config)
    if vlan is None:
        return None

    with _lock:
        data = _load()
        if any(v.get("id") == "primary" for v in data["vlans"]):
            return None
        data["vlans"].insert(0, vlan)
        _save(data)
        return vlan


def sync_primary_meta(pihole_config: dict) -> None:
    """Keep the primary VLAN's subnet/gateway/range metadata in sync with
    Pi-hole's live config (hosts are handled separately, computed fresh)."""
    if not pihole_config:
        return
    with _lock:
        data = _load()
        primary = next((v for v in data["vlans"] if v.get("id") == "primary"), None)
        if primary is None:
            return
        primary["range_start"] = pihole_config.get("start", primary["range_start"])
        primary["range_end"] = pihole_config.get("end", primary["range_end"])
        primary["gateway"] = pihole_config.get("router", primary["gateway"])
        _save(data)


def merge_dynamic_hosts(vlan: dict, static_hosts: list, leases: list) -> list:
    """static_hosts + any active lease inside this VLAN's subnet that isn't
    already a static reservation, tagged dynamic=True for display."""
    reserved_ips  = {h["ip"] for h in static_hosts}
    reserved_macs = {h["mac"].upper() for h in static_hosts}
    net = network_of(vlan)

    dynamic = []
    for lease in (leases or []):
        ip  = lease.get("ip", "")
        mac = (lease.get("hwaddr") or "").upper()
        if not ip or ip in reserved_ips or mac in reserved_macs:
            continue  # already a static reservation — don't duplicate
        try:
            if ipaddress.IPv4Address(ip) not in net:
                continue
        except ValueError:
            continue
        name = lease.get("name") or ""
        dynamic.append({"mac": mac, "ip": ip, "hostname": "" if name == "*" else name, "dynamic": True})

    return static_hosts + dynamic


# --- VLAN CRUD ---

def list_vlans() -> list:
    with _lock:
        return _load()["vlans"]


def get_vlan(vlan_id: str) -> dict | None:
    with _lock:
        for v in _load()["vlans"]:
            if v["id"] == vlan_id:
                return v
        return None


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "vlan"


def create_vlan(fields: dict) -> tuple:
    name        = (fields.get("name") or "").strip()
    vlan_tag    = fields.get("vlan_tag")
    subnet      = (fields.get("subnet") or "").strip()
    prefix      = fields.get("prefix")
    gateway     = (fields.get("gateway") or "").strip()
    range_start = (fields.get("range_start") or "").strip()
    range_end   = (fields.get("range_end") or "").strip()
    lease_time  = (fields.get("lease_time") or "12h").strip()
    cf_domain   = (fields.get("cf_domain") or "").strip()
    group_name  = (fields.get("group_name") or "").strip()

    if not name:
        return None, "Name is required"
    try:
        prefix = int(prefix)
        net = ipaddress.ip_network(f"{subnet}/{prefix}", strict=False)
    except (ValueError, TypeError):
        return None, "Invalid subnet/prefix"
    for label, ip in (("gateway", gateway), ("range_start", range_start), ("range_end", range_end)):
        if not valid_ip(ip):
            return None, f"Invalid {label}: {ip}"
        if ipaddress.IPv4Address(ip) not in net:
            return None, f"{label} {ip} is not inside {net}"
    if cf_domain and not _DOMAIN_RE.match(cf_domain):
        return None, f"Invalid conditional-forwarding domain: {cf_domain}"

    with _lock:
        data = _load()
        vlan_id = _slugify(name)
        base_id = vlan_id
        n = 2
        existing_ids = {v["id"] for v in data["vlans"]}
        while vlan_id in existing_ids:
            vlan_id = f"{base_id}-{n}"
            n += 1

        for v in data["vlans"]:
            if v.get("is_primary"):
                # The primary scope's subnet describes the whole existing flat LAN —
                # new VLANs are meant to carve routed subnets out of that same space,
                # so it's excluded from the overlap check (still applied between
                # extra VLANs themselves, to keep those mutually exclusive).
                continue
            other_net = network_of(v)
            if net.overlaps(other_net):
                return None, f"Subnet overlaps existing VLAN '{v['name']}' ({other_net})"
            if vlan_tag and v.get("vlan_tag") == vlan_tag:
                return None, f"VLAN tag {vlan_tag} already used by '{v['name']}'"

        vlan = {
            "id": vlan_id,
            "name": name,
            "vlan_tag": vlan_tag,
            "subnet": str(net.network_address),
            "prefix": prefix,
            "gateway": gateway,
            "range_start": range_start,
            "range_end": range_end,
            "lease_time": lease_time,
            "cf_domain": cf_domain,
            "group_name": group_name,
            "hosts": [],
        }
        data["vlans"].append(vlan)
        _save(data)
        activity_log.log("vlan", f"Created VLAN '{name}' ({net})" + (f", tag {vlan_tag}" if vlan_tag else ""))
        return vlan, None


def import_vlan(vlan: dict) -> tuple:
    """Adds an already-fully-formed VLAN dict (parsed back from a node's live
    dnsmasq.d config, see pihole_push.parse_conf) to the store. Same dedupe/
    overlap rules as create_vlan, but skips form validation since this is
    reconstructed from a config that was already valid when first written."""
    with _lock:
        data = _load()
        if any(v["id"] == vlan["id"] for v in data["vlans"]):
            return None, f"'{vlan['id']}' already exists locally"

        net = network_of(vlan)
        for v in data["vlans"]:
            if v.get("is_primary"):
                continue
            if net.overlaps(network_of(v)):
                return None, f"Subnet overlaps existing VLAN '{v['name']}' ({network_of(v)})"

        data["vlans"].append(vlan)
        _save(data)
        activity_log.log("vlan", f"Imported VLAN '{vlan['name']}' ({net}) from node config")
        return vlan, None


def update_vlan(vlan_id: str, fields: dict) -> tuple:
    with _lock:
        data = _load()
        vlan = next((v for v in data["vlans"] if v["id"] == vlan_id), None)
        if not vlan:
            return None, "VLAN not found"
        if "cf_domain" in fields and fields["cf_domain"] and not _DOMAIN_RE.match(fields["cf_domain"]):
            return None, f"Invalid conditional-forwarding domain: {fields['cf_domain']}"

        changed = []
        for key in ("name", "vlan_tag", "gateway", "range_start", "range_end", "lease_time"):
            if key in fields and fields[key] not in (None, "") and fields[key] != vlan.get(key):
                vlan[key] = fields[key]
                changed.append(key)
        # cf_domain/group_name are allowed to be explicitly cleared (empty string), unlike the fields above
        for key in ("cf_domain", "group_name"):
            if key in fields and fields[key] != vlan.get(key, ""):
                vlan[key] = fields[key]
                changed.append(key)
        _save(data)
        if changed:
            activity_log.log("vlan", f"Updated VLAN '{vlan['name']}': {', '.join(changed)}")
        return vlan, None


def delete_vlan(vlan_id: str) -> tuple:
    if vlan_id == "primary":
        return False, "Can't delete the primary Pi-hole scope from here"
    with _lock:
        data = _load()
        vlan = next((v for v in data["vlans"] if v["id"] == vlan_id), None)
        if not vlan:
            return False, "VLAN not found"
        data["vlans"] = [v for v in data["vlans"] if v["id"] != vlan_id]
        _save(data)
        activity_log.log("vlan", f"Deleted VLAN '{vlan['name']}'")
        return True, None


# --- Host CRUD (scoped to a VLAN) ---

def add_or_update_host(vlan_id: str, mac: str, ip: str, hostname: str = "") -> tuple:
    mac = (mac or "").strip().upper()
    ip  = (ip or "").strip()
    hostname = (hostname or "").strip()

    if not valid_mac(mac):
        return None, f"Invalid MAC address: {mac}"
    if not valid_ip(ip):
        return None, f"Invalid IP address: {ip}"

    with _lock:
        data = _load()
        vlan = next((v for v in data["vlans"] if v["id"] == vlan_id), None)
        if not vlan:
            return None, "VLAN not found"

        net = network_of(vlan)
        if ipaddress.IPv4Address(ip) not in net:
            return None, f"{ip} is not inside {vlan['name']}'s subnet ({net})"

        for other in data["vlans"]:
            if other["id"] == vlan_id:
                continue
            for h in other["hosts"]:
                if h["ip"] == ip:
                    return None, f"{ip} already assigned in VLAN '{other['name']}'"

        conflict = next((h for h in vlan["hosts"] if h["ip"] == ip and h["mac"] != mac), None)
        if conflict:
            return None, f"{ip} already reserved for {conflict['mac']} in this VLAN"

        is_update = any(h["mac"] == mac for h in vlan["hosts"])
        vlan["hosts"] = [h for h in vlan["hosts"] if h["mac"] != mac]
        vlan["hosts"].append({"mac": mac, "ip": ip, "hostname": hostname})
        _save(data)
        verb = "Updated" if is_update else "Added"
        activity_log.log("host", f"{verb} host {mac} ({ip}{f', {hostname}' if hostname else ''}) in VLAN '{vlan['name']}'")
        return vlan, None


def delete_host(vlan_id: str, ip: str) -> tuple:
    with _lock:
        data = _load()
        vlan = next((v for v in data["vlans"] if v["id"] == vlan_id), None)
        if not vlan:
            return False, "VLAN not found"
        before = len(vlan["hosts"])
        vlan["hosts"] = [h for h in vlan["hosts"] if h["ip"] != ip]
        if len(vlan["hosts"]) == before:
            return False, "Host not found"
        _save(data)
        activity_log.log("host", f"Removed host {ip} from VLAN '{vlan['name']}'")
        return True, None


def update_host_mac(vlan_id: str, ip: str, new_mac: str) -> tuple:
    new_mac = (new_mac or "").strip().upper()
    if not valid_mac(new_mac):
        return None, f"Invalid MAC address: {new_mac}"

    with _lock:
        data = _load()
        vlan = next((v for v in data["vlans"] if v["id"] == vlan_id), None)
        if not vlan:
            return None, "VLAN not found"

        host = next((h for h in vlan["hosts"] if h["ip"] == ip), None)
        if not host:
            return None, f"No reservation found for {ip}"

        host["mac"] = new_mac
        _save(data)
        activity_log.log("host", f"Changed MAC for {ip} to {new_mac} in VLAN '{vlan['name']}'")
        return vlan, None
