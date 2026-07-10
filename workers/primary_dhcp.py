#!/usr/bin/env python3
"""Manages Pi-hole's own primary DHCP scope: static reservation CRUD against
the first PIHOLE_IPS node. Moved here from Network-Health so this app is the
one place that manages Pi-hole DHCP scopes — the primary scope and the extra
VLAN scopes alike. Propagating a reservation change to the other nodes is
handled by workers.replication's multi-master merge, triggered right after
each write here — this module no longer does its own one-way push."""
from workers import activity_log, nodes, pihole_api, replication


def _primary_host() -> str:
    ips = nodes.get_ips()
    return ips[0] if ips else ""


# --- Reservation CRUD (writes to the primary node only) ---

def get_config(ip: str = None) -> dict:
    ip = ip or _primary_host()
    if not ip:
        return {}
    data = pihole_api.api_get(ip, "/config/dhcp")
    return (data or {}).get("config", {}).get("dhcp", {})


def get_leases() -> list:
    """Active DHCP leases merged across every node (each Pi-hole runs its own
    DHCP server and only knows the leases it personally handed out)."""
    merged = {}
    for node_ip in nodes.get_ips():
        node_leases = (pihole_api.api_get(node_ip, "/dhcp/leases") or {}).get("leases", [])
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
    full = pihole_api.api_get(_primary_host(), "/config")
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

    result = pihole_api.api_patch(_primary_host(), "/config", {"config": {"dhcp": dhcp}})
    if result is None:
        return False, "PATCH to Pi-hole failed"
    verb = "Updated" if is_update else "Added"
    activity_log.log("host", f"{verb} host {mac_u} ({ip}{f', {name}' if name else ''}) in primary scope")
    replication.trigger_sync()
    return True, None


def delete_reservation(ip: str) -> tuple:
    full = pihole_api.api_get(_primary_host(), "/config")
    if not full:
        return False, "Failed to fetch config from Pi-hole"

    dhcp      = full.get("config", {}).get("dhcp", {})
    hosts     = dhcp.get("hosts", [])
    new_hosts = [h for h in hosts if h.split(",")[1].strip() != ip]

    if len(new_hosts) == len(hosts):
        return False, f"No static reservation found for {ip}"

    dhcp["hosts"] = new_hosts
    result = pihole_api.api_patch(_primary_host(), "/config", {"config": {"dhcp": dhcp}})
    if result is None:
        return False, "PATCH to Pi-hole failed"
    activity_log.log("host", f"Removed reservation for {ip} from primary scope")
    replication.trigger_sync()
    return True, None


def update_reservation_mac(ip: str, new_mac: str) -> tuple:
    full = pihole_api.api_get(_primary_host(), "/config")
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
    result = pihole_api.api_patch(_primary_host(), "/config", {"config": {"dhcp": dhcp}})
    if result is None:
        return False, "PATCH to Pi-hole failed"
    activity_log.log("host", f"Changed MAC for {ip} to {new_mac} in primary scope")
    replication.trigger_sync()
    return True, None
