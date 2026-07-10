#!/usr/bin/env python3
"""Pre-flight checks run before a fleet-wide push, to catch known footguns
before they get propagated to every node at once — rather than trusting that
whatever's in the store/API right now is safe to fan out."""
import ipaddress

import requests

from workers import store


# --- DHCP scope validation (gate before pihole_push writes dnsmasq.d) ---

def validate_vlans(vlans: list) -> list:
    """Full pairwise overlap check + range/subnet containment across every
    VLAN currently in the store. store.create_vlan/import_vlan already check
    a new VLAN against the existing set at write time, but this re-validates
    the whole set right before a push — catches drift from hand-edited data
    files or bugs in earlier validation, so one bad scope can't get faned out
    to every node at once."""
    errors = []
    extra = [v for v in vlans if not v.get("is_primary")]

    for v in extra:
        try:
            net = store.network_of(v)
        except (KeyError, ValueError) as e:
            errors.append(f"VLAN '{v.get('name', v.get('id'))}': invalid subnet/prefix ({e})")
            continue
        for label, ip in (("gateway", v.get("gateway")), ("range_start", v.get("range_start")),
                           ("range_end", v.get("range_end"))):
            if not store.valid_ip(ip):
                errors.append(f"VLAN '{v['name']}': invalid {label} '{ip}'")
                continue
            if ipaddress.IPv4Address(ip) not in net:
                errors.append(f"VLAN '{v['name']}': {label} {ip} is outside {net}")
        for h in v.get("hosts", []):
            if not store.valid_ip(h.get("ip")):
                errors.append(f"VLAN '{v['name']}': host {h.get('mac')} has invalid IP '{h.get('ip')}'")
            elif ipaddress.IPv4Address(h["ip"]) not in net:
                errors.append(f"VLAN '{v['name']}': host {h['ip']} is outside its own subnet ({net})")

    for i, a in enumerate(extra):
        for b in extra[i + 1:]:
            try:
                if store.network_of(a).overlaps(store.network_of(b)):
                    errors.append(f"VLAN '{a['name']}' and '{b['name']}' have overlapping subnets")
            except (KeyError, ValueError):
                pass  # already reported above

    return errors


# --- Node group/blocklist health (informational — surfaced, not blocking) ---
# Guards against a known Pi-hole footgun (github.com/pi-hole/pi-hole#4066):
# an empty/disabled default group silently stops all blocking on a node,
# with nothing in the UI calling it out.

_sid_cache = {}


def _auth(ip, password):
    try:
        r = requests.post(f"http://{ip}/api/auth", json={"password": password}, timeout=8)
        r.raise_for_status()
        sid = r.json().get("session", {}).get("sid", "")
        _sid_cache[ip] = sid
        return sid
    except Exception:
        return ""


def _api_get(ip, path, password):
    for attempt in range(2):
        sid = _sid_cache.get(ip, "") or _auth(ip, password)
        if not sid:
            return None
        try:
            r = requests.get(f"http://{ip}/api{path}", headers={"sid": sid}, timeout=10)
            if r.status_code == 401 and attempt == 0:
                _sid_cache.pop(ip, None)
                continue
            r.raise_for_status()
            return r.json()
        except Exception:
            return None
    return None


def check_node_group_health(ip: str, password: str) -> list:
    """Returns a list of warning strings for this node (empty = healthy)."""
    warnings = []

    groups = _api_get(ip, "/groups", password)
    if groups is None:
        return [f"{ip}: could not reach API to check group health"]
    default_group = next((g for g in groups.get("groups", []) if g.get("id") == 0), None)
    if default_group is None:
        warnings.append(f"{ip}: no default group (id 0) found")
    elif not default_group.get("enabled", True):
        warnings.append(f"{ip}: default group is disabled — blocking is silently off for any client without another group")

    lists = _api_get(ip, "/lists", password)
    if lists is None:
        warnings.append(f"{ip}: could not reach API to check adlists")
    else:
        has_active_blocklist = any(
            l.get("type") == "block" and l.get("enabled") and 0 in (l.get("groups") or [])
            for l in lists.get("lists", [])
        )
        if not has_active_blocklist:
            warnings.append(f"{ip}: no enabled blocklist is attached to the default group — blocking has no effect")

    return warnings
