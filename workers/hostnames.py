#!/usr/bin/env python3
"""Publishes per-VLAN static-host hostnames as Pi-hole local DNS records
(config.dns.hosts), so a device's DHCP hostname resolves fleet-wide — across
every VLAN, and across every physical node — rather than only being known to
whichever single node's dnsmasq instance actually handed out that device's
lease. (Each of the 3 Pi-hole nodes keeps its own independent lease/hostname
state; a query landing on a node other than the one that issued a client's
lease has no way to resolve that client's hostname without this.)

dns.hosts entries are plain "<ip> <hostname>" strings, and dns.hosts is
already one of the config paths replication.py keeps in sync across nodes
(the "dns_records" group) — this module only generates the VLAN-derived
subset of that list; replication's existing merge logic is what actually
keeps the result consistent everywhere afterward.

Only entries whose IP falls inside one of our own managed (non-primary) VLAN
subnets are ever added or removed here — anything else already in dns.hosts
(a manually-added entry, anything for the primary/native scope, etc.) is left
completely alone, so this can never clobber an unrelated custom record."""
import ipaddress

from workers import store


def _managed_networks(vlans: list) -> list:
    return [store.network_of(v) for v in vlans if not v.get("is_primary")]


def _line_ip(line: str) -> str:
    return line.split(None, 1)[0] if line and line.split(None, 1) else ""


def _is_managed_ip(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def compute_entries(vlans: list) -> list:
    """"<ip> <hostname>" for every host with a hostname set, across every
    non-primary VLAN. Static reservations only — an entry is only as stable
    as the IP it's pinned to, so dynamic/unreserved leases are intentionally
    excluded (they'd churn every time DHCP hands out a different address)."""
    entries = []
    for v in vlans:
        if v.get("is_primary"):
            continue
        for h in v.get("hosts", []):
            if h.get("hostname") and not h.get("dynamic"):
                entries.append(f"{h['ip']} {h['hostname']}")
    return entries


def merge(current_hosts: list, vlans: list) -> list:
    """Drops any existing entry whose IP falls inside a managed VLAN subnet
    (so a rename/removal doesn't leave a stale record behind), then adds the
    freshly computed set. Everything outside our managed subnets — including
    every primary-scope and manually-added entry — passes through untouched."""
    networks = _managed_networks(vlans)
    kept = [line for line in (current_hosts or []) if not _is_managed_ip(_line_ip(line), networks)]
    return kept + compute_entries(vlans)
