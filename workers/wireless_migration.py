#!/usr/bin/env python3
"""Auto-migrates a device's static reservation from the primary scope to the
"wireless" VLAN once it's actually seen connecting there.

A client with an existing primary-scope reservation (10.0.x.x) doesn't get
moved just because the wireless VLAN exists — it has to actually show up
with a live (dynamic, unreserved) lease inside the wireless subnet first.
Once that happens, its old primary reservation is deleted and replaced with
a new wireless-scope reservation at the same host/third/fourth octets, just
under 10.1.x.x instead of 10.0.x.x (mirroring the mapping already used when
the wireless VLAN's own scope was first carved out). This lets static IPs
be migrated to the new VLAN gradually, one device at a time, as each
physically moves onto that network, rather than all at once."""
import threading

from workers import activity_log, pihole_push, primary_dhcp, store

CHECK_INTERVAL_SECS = 60
WIRELESS_VLAN_ID = "wireless"


def _map_ip(primary_ip: str) -> str | None:
    """10.0.x.y -> 10.1.x.y. None if primary_ip isn't in that shape."""
    octets = primary_ip.split(".")
    if len(octets) != 4 or octets[0] != "10" or octets[1] != "0":
        return None
    return f"10.1.{octets[2]}.{octets[3]}"


def check_and_migrate() -> list:
    """Runs one pass; returns [{mac, old_ip, new_ip, hostname}] for whatever
    got migrated this pass (mainly for tests/manual invocation — the
    background loop itself only cares about the activity_log entries)."""
    wireless = store.get_vlan(WIRELESS_VLAN_ID)
    if not wireless:
        return []

    primary_by_mac = {h["mac"].upper(): h for h in primary_dhcp.get_reservations() if h.get("mac")}
    if not primary_by_mac:
        return []

    leases = primary_dhcp.get_leases()
    dynamic_wireless = [h for h in store.merge_dynamic_hosts(wireless, wireless["hosts"], leases)
                         if h.get("dynamic")]
    existing_wireless_ips = {h["ip"] for h in wireless["hosts"]}

    migrated = []
    for dyn in dynamic_wireless:
        mac = dyn["mac"].upper()
        match = primary_by_mac.get(mac)
        if not match:
            continue

        old_ip = match["ip"]
        new_ip = _map_ip(old_ip)
        if not new_ip:
            activity_log.log("wireless-migration",
                              f"{mac}: primary IP {old_ip} isn't in the expected 10.0.x.x shape, skipping",
                              level="error")
            continue
        if new_ip in existing_wireless_ips:
            activity_log.log("wireless-migration",
                              f"{mac}: mapped IP {new_ip} is already used in the wireless scope, skipping",
                              level="error")
            continue

        hostname = match.get("hostname", "")
        ok, error = primary_dhcp.delete_reservation(old_ip)
        if not ok:
            activity_log.log("wireless-migration",
                              f"{mac}: failed to remove primary reservation {old_ip}: {error}",
                              level="error")
            continue

        store.add_or_update_host(WIRELESS_VLAN_ID, mac, new_ip, hostname)
        existing_wireless_ips.add(new_ip)
        activity_log.log("wireless-migration",
                          f"Moved {mac}{f' ({hostname})' if hostname else ''} "
                          f"from primary ({old_ip}) to wireless ({new_ip}) — seen connected there")
        migrated.append({"mac": mac, "old_ip": old_ip, "new_ip": new_ip, "hostname": hostname})

    if migrated:
        pihole_push.trigger_push()
    return migrated


def _loop():
    while True:
        try:
            check_and_migrate()
        except Exception as e:
            activity_log.log("wireless-migration", f"Migration check failed: {e}", level="error")
        threading.Event().wait(CHECK_INTERVAL_SECS)


def start():
    threading.Thread(target=_loop, daemon=True, name="wireless-migration").start()
