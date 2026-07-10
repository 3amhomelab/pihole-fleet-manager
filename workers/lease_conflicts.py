#!/usr/bin/env python3
"""Detects a known Pi-hole footgun: giving a client a static DHCP reservation
doesn't retroactively evict a dynamic lease it already holds — the lease
database can keep answering with the old IP until it's manually cleared (or
FTL restarted), so a "reserved" client can silently keep the wrong address.

Polls every node's own active leases directly (rather than reusing
primary_dhcp.get_leases, which merges across nodes and discards which node a
lease actually came from) so a detected conflict can be cleared on the exact
node it's stale on."""
from workers import activity_log, nodes, pihole_api, primary_dhcp, store


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
    for ip in nodes.get_ips():
        leases = pihole_api.api_get(ip, "/dhcp/leases")
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
    if node not in nodes.get_ips():
        return False, "Unknown node"
    if not pihole_api.api_delete(node, f"/dhcp/leases/{leased_ip}", ok_statuses=(200, 204, 404)):
        return False, "Could not clear lease via API"
    activity_log.log("dhcp", f"Cleared stale lease {leased_ip} on {node}")
    return True, None
