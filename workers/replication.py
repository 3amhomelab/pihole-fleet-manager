#!/usr/bin/env python3
"""Multi-master replication: compares Pi-hole settings and the DHCP scope
(including static reservations) across every configured node, and for
anything that differs, keeps whichever node's value changed most recently
and pushes it to the rest.

Pi-hole's API doesn't expose a per-field modification time, so "most
recently changed" is approximated with our own change-detection ledger:
each run fetches the current value from every node and compares it to what
we saw there last time. Only when a node's value has moved do we stamp a
new changed_at for it. This means two edits landing in the same run window
(auto-interval, the primary-scope trigger, or a manual click) are tied and
resolved by a fixed, deterministic node order rather than true wall-clock
order — accuracy is bounded by how often this runs."""
import ipaddress
import json
import os
import threading
import urllib.parse
from collections import deque
from datetime import datetime

import requests

from workers import activity_log, credentials, gravity, maintenance, nodes, validate

OPTIONS_FILE    = os.environ.get("REPLICATION_OPTIONS_FILE", "/data/replication.json")
AUTO_FILE       = os.environ.get("REPLICATION_AUTO_FILE", "/data/replication_auto.json")
LEDGER_FILE     = os.environ.get("REPLICATION_LEDGER_FILE", "/data/replication_ledger.json")
CHECK_INTERVAL_SECS = 30  # how often the loop wakes up to check whether auto-replication is due

HOSTS_PATH = "dhcp.hosts"  # merged specially (mac-keyed union) rather than as a plain scalar
CLIENT_GROUPS_PATH = "clients.groups"  # pseudo-path: gates group/client reconciliation (gravity.db, not config.toml)
ADLISTS_PATH = "lists.adlists"    # pseudo-path: gates adlist (blocklist/allowlist URL) reconciliation
DOMAINS_PATH = "domains.overrides"  # pseudo-path: gates individual domain allow/deny reconciliation

# --- Groups: each maps a user-facing toggle to specific config.* paths ---
GROUPS = [
    {"id": "dhcp_scope", "category": "DHCP", "label": "Scope range & timing",
     "desc": "Active state, start/end range, router, netmask, lease time",
     "paths": ["dhcp.active", "dhcp.start", "dhcp.end", "dhcp.router", "dhcp.netmask", "dhcp.leaseTime"],
     "default": True},
    {"id": "dhcp_hosts", "category": "DHCP", "label": "Static reservations (hosts)",
     "desc": "Mac-keyed static DHCP reservations — merged from every node; if the same host "
             "was changed on more than one node, the most recently changed one wins",
     "paths": [HOSTS_PATH], "default": True},
    {"id": "dhcp_flags", "category": "DHCP", "label": "DHCP behavior flags",
     "desc": "Rapid commit, IPv6, multi-DNS, logging, ignore unknown clients",
     "paths": ["dhcp.rapidCommit", "dhcp.ipv6", "dhcp.multiDNS", "dhcp.logging", "dhcp.ignoreUnknownClients"],
     "default": True},

    {"id": "dns_upstreams", "category": "DNS", "label": "Upstream DNS servers",
     "desc": "The external resolvers Pi-hole forwards to",
     "paths": ["dns.upstreams"], "default": True},
    {"id": "dns_records", "category": "DNS", "label": "Local DNS records",
     "desc": "Custom A records (hosts) and CNAME records",
     "paths": ["dns.hosts", "dns.cnameRecords"], "default": True},
    {"id": "dns_forwarding", "category": "DNS", "label": "Conditional forwarding",
     "desc": "Reverse-lookup servers for internal domains",
     "paths": ["dns.revServers"], "default": True},
    {"id": "dns_behavior", "category": "DNS", "label": "DNS behavior",
     "desc": "domain-needed, expand-hosts, DNSSEC, interface, EDNS0ECS, bogus-priv, CNAME inspection, block ESNI",
     "paths": ["dns.domainNeeded", "dns.expandHosts", "dns.dnssec", "dns.interface", "dns.EDNS0ECS",
               "dns.bogusPriv", "dns.CNAMEdeepInspect", "dns.blockESNI", "dns.domain.name", "dns.domain.local"],
     "default": True},
    {"id": "dns_blocking", "category": "DNS", "label": "Blocking state",
     "desc": "Whether blocking is active, and its mode — off by default so you can pause blocking on one node without it silently flipping everywhere",
     "paths": ["dns.blocking.active", "dns.blocking.mode"], "default": False},
    {"id": "dns_ratelimit", "category": "DNS", "label": "Rate-limiting",
     "paths": ["dns.rateLimit.count", "dns.rateLimit.interval"], "default": True},

    {"id": "misc_dnsmasq", "category": "General", "label": "Custom dnsmasq snippets",
     "desc": "etc_dnsmasq_d flag + dnsmasq_lines — needed for the VLAN push feature",
     "paths": ["misc.etc_dnsmasq_d", "misc.dnsmasq_lines"], "default": True},
    {"id": "misc_privacy", "category": "General", "label": "Privacy level",
     "paths": ["misc.privacylevel"], "default": True},
    {"id": "resolver_names", "category": "General", "label": "Hostnames / reverse resolution",
     "paths": ["resolver.resolveIPv4", "resolver.resolveIPv6", "resolver.macNames",
               "resolver.networkNames", "resolver.refreshNames"],
     "default": True},

    {"id": "client_groups", "category": "Clients", "label": "Groups & client assignments",
     "desc": "Reconciles Pi-hole's group definitions and per-client group membership across nodes, "
             "matched by name/client id rather than raw id (group ids are assigned locally per node, "
             "so the same group can have a different id on each one). Off by default — unlike the "
             "settings above, this creates missing groups on other nodes automatically.",
     "paths": [CLIENT_GROUPS_PATH], "default": False},

    {"id": "adlists", "category": "Blocklists", "label": "Adlists (blocklist/allowlist URLs)",
     "desc": "Reconciles gravity.db adlist URLs (both block and allow lists) across nodes, matched by "
             "address rather than raw id. This is what actually keeps 'which domains get blocked' "
             "consistent fleet-wide — without it, a VIP that can answer from any node means you never "
             "know whether a domain will be blocked. Off by default — like client groups, this creates "
             "missing adlists on other nodes automatically, and triggers a gravity update on any node "
             "it changes (otherwise the new list wouldn't take effect until that node's next scheduled "
             "gravity run, up to a day away).",
     "paths": [ADLISTS_PATH], "default": False},
    {"id": "domain_overrides", "category": "Blocklists", "label": "Domain allow/deny overrides",
     "desc": "Reconciles individual exact/regex domain allow and deny entries (gravity.db), matched by "
             "type+kind+domain. Off by default, same reasoning as adlists — also triggers a gravity "
             "update on any node it changes.",
     "paths": [DOMAINS_PATH], "default": False},
]

_sid_cache = {}
_sid_lock  = threading.Lock()

_status = {"status": "idle", "message": "", "timestamp": None, "log": []}
_status_lock = threading.Lock()
_event = threading.Event()


# --- Toggle state persistence (per individual config path) ---

_PATH_DEFAULT = {p: g["default"] for g in GROUPS for p in g["paths"]}
_ALL_PATHS    = list(_PATH_DEFAULT.keys())
_SCALAR_PATHS = [p for p in _ALL_PATHS if p not in (HOSTS_PATH, CLIENT_GROUPS_PATH, ADLISTS_PATH, DOMAINS_PATH)]


def _load_options() -> dict:
    if os.path.exists(OPTIONS_FILE):
        try:
            with open(OPTIONS_FILE) as f:
                saved = json.load(f)
        except (json.JSONDecodeError, OSError):
            saved = {}
    else:
        saved = {}
    return {p: saved.get(p, _PATH_DEFAULT[p]) for p in _ALL_PATHS}


def _save_options(options: dict) -> None:
    os.makedirs(os.path.dirname(OPTIONS_FILE), exist_ok=True)
    tmp = OPTIONS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(options, f, indent=2)
    os.replace(tmp, OPTIONS_FILE)


def get_groups() -> list:
    options = _load_options()
    return [
        {"id": g["id"], "category": g["category"], "label": g["label"], "desc": g.get("desc", ""),
         "paths": [{"path": p, "enabled": options[p]} for p in g["paths"]]}
        for g in GROUPS
    ]


def set_options(updates: dict) -> dict:
    options = _load_options()
    changed = []
    for path, enabled in updates.items():
        if path in _PATH_DEFAULT and options.get(path) != bool(enabled):
            options[path] = bool(enabled)
            changed.append(f"{path}={'on' if enabled else 'off'}")
    _save_options(options)
    if changed:
        activity_log.log("replication", f"Replication options updated: {', '.join(changed)}")
    return options


# --- Auto-replication interval (persisted so it survives restarts) ---

_auto_lock = threading.Lock()


def _load_auto() -> dict:
    if os.path.exists(AUTO_FILE):
        try:
            with open(AUTO_FILE) as f:
                data = json.load(f)
            return {
                "interval_minutes": int(data.get("interval_minutes") or 0),
                "last_run": data.get("last_run"),
            }
        except (json.JSONDecodeError, OSError, ValueError, TypeError):
            pass
    return {"interval_minutes": 0, "last_run": None}


def _save_auto(auto: dict) -> None:
    os.makedirs(os.path.dirname(AUTO_FILE), exist_ok=True)
    tmp = AUTO_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(auto, f, indent=2)
    os.replace(tmp, AUTO_FILE)


def get_auto_config() -> dict:
    with _auto_lock:
        return _load_auto()


def set_auto_interval(minutes: int) -> dict:
    """Setting the interval (re)starts the countdown from now, whether it's
    being enabled, disabled, or just changed to a different value."""
    minutes = max(0, int(minutes))
    with _auto_lock:
        auto = {"interval_minutes": minutes, "last_run": datetime.now().isoformat()}
        _save_auto(auto)
    activity_log.log(
        "replication",
        f"Auto-replication set to every {minutes} minute(s)" if minutes else "Auto-replication disabled",
    )
    return auto


def _mark_auto_run() -> None:
    with _auto_lock:
        auto = _load_auto()
        auto["last_run"] = datetime.now().isoformat()
        _save_auto(auto)


# --- Change-detection ledger (approximates "last modified" per node/path) ---

def _load_ledger() -> dict:
    if os.path.exists(LEDGER_FILE):
        try:
            with open(LEDGER_FILE) as f:
                data = json.load(f)
            data.setdefault("scalars", {})
            data.setdefault("hosts", {})
            data.setdefault("groups", {})
            data.setdefault("client_groups", {})
            data.setdefault("adlists", {})
            data.setdefault("domains", {})
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return {"scalars": {}, "hosts": {}, "groups": {}, "client_groups": {}, "adlists": {}, "domains": {}}


def _save_ledger(ledger: dict) -> None:
    os.makedirs(os.path.dirname(LEDGER_FILE), exist_ok=True)
    tmp = LEDGER_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(ledger, f, indent=2)
    os.replace(tmp, LEDGER_FILE)


def _pick_winner(nodes: list, node_values: dict, ledger_entry: dict, now_iso: str) -> tuple:
    """Stamp changed_at for any node whose value differs from what the ledger
    last recorded there, then return (winner_entry, updated_ledger_entry,
    node_ips_whose_current_value_isn't_the_winner).

    Ties on changed_at prefer a present value over an absent one — the most
    common tie is a brand-new path/mac we've never seen before, where every
    node gets stamped with the same "just observed" time in one run; without
    this, node order alone could pick a node that doesn't have the value yet
    and wipe out a change that only ever existed on one node.

    The caller must copy winner_entry into updated[ip] for every stale node it
    successfully patches — otherwise that node's next observed value (which
    now matches the winner only because we just wrote it) looks like a brand
    new independent edit and corrupts recency ordering on the next run."""
    updated = {}
    for ip in nodes:
        val = node_values[ip]
        prev = ledger_entry.get(ip)
        if prev is None or prev.get("value") != val:
            updated[ip] = {"value": val, "changed_at": now_iso}
        else:
            updated[ip] = prev
    winner_ip = max(nodes, key=lambda ip: (updated[ip]["changed_at"], updated[ip]["value"] is not None))
    winner_entry = updated[winner_ip]
    stale = [ip for ip in nodes if node_values[ip] != winner_entry["value"]]
    return winner_entry, updated, stale


# --- Pi-hole v6 API ---

def _auth(ip):
    try:
        r = requests.post(f"http://{ip}/api/auth", json={"password": credentials.get_admin_password()}, timeout=8)
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


def _api_post(ip, path, body):
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = _auth(ip)
        if not sid:
            return None
        try:
            r = requests.post(f"http://{ip}/api{path}", json=body, headers={"sid": sid}, timeout=15)
            if r.status_code == 401 and attempt == 0:
                with _sid_lock:
                    _sid_cache.pop(ip, None)
                continue
            r.raise_for_status()
            return r.json()
        except Exception:
            return None
    return None


def _api_put(ip, path, body):
    for attempt in range(2):
        with _sid_lock:
            sid = _sid_cache.get(ip, "")
        if not sid:
            sid = _auth(ip)
        if not sid:
            return None
        try:
            r = requests.put(f"http://{ip}/api{path}", json=body, headers={"sid": sid}, timeout=15)
            if r.status_code == 401 and attempt == 0:
                with _sid_lock:
                    _sid_cache.pop(ip, None)
                continue
            r.raise_for_status()
            return r.json()
        except Exception:
            return None
    return None


# --- Path helpers ---

def _get_path(d: dict, path: str):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None, False
        cur = cur[part]
    return cur, True


def _set_path(d: dict, path: str, value) -> None:
    parts = path.split(".")
    cur = d
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


# --- DHCP hosts (static reservations) parsing, mac-keyed ---

def _parse_hosts(lines: list) -> dict:
    parsed = {}
    for h in lines or []:
        parts = h.split(",")
        if len(parts) >= 2 and parts[1].strip():
            mac = parts[0].strip().upper()
            parsed[mac] = {"ip": parts[1].strip(), "hostname": parts[2].strip() if len(parts) > 2 else ""}
    return parsed


def _render_hosts(hosts: dict) -> list:
    ordered = sorted(hosts.items(), key=lambda kv: ipaddress.ip_address(kv[1]["ip"]), reverse=True)
    return [f"{mac},{entry['ip']}" + (f",{entry['hostname']}" if entry.get("hostname") else "")
            for mac, entry in ordered]


# --- Sync ---

def _set_status(status, message, log):
    with _status_lock:
        _status["status"], _status["message"] = status, message
        _status["timestamp"] = datetime.now().isoformat()
        _status["log"] = list(log)


def get_status() -> dict:
    with _status_lock:
        return dict(_status)


def trigger_sync():
    _event.set()


def _auto_due(auto: dict) -> bool:
    if auto["interval_minutes"] <= 0:
        return False
    if not auto["last_run"]:
        return True
    elapsed = (datetime.now() - datetime.fromisoformat(auto["last_run"])).total_seconds()
    return elapsed >= auto["interval_minutes"] * 60


def _fetch_groups(ip):
    resp = _api_get(ip, "/groups")
    return None if resp is None else {g["name"]: g for g in resp.get("groups", [])}


def _fetch_clients(ip):
    resp = _api_get(ip, "/clients")
    return None if resp is None else {c["client"]: c for c in resp.get("clients", [])}


def _merge_groups_and_clients(nodes: list, step) -> tuple:
    """Reconciles Pi-hole's group definitions and per-client group membership
    across nodes. Group ids are assigned locally per node — the same group
    created independently on two nodes can end up with two different ids —
    so everything here is matched by NAME (groups) or client identifier
    (mac/ip string, already stable), and ids are only ever used as the final
    translation step immediately before writing back to one specific node."""
    now_iso = datetime.now().isoformat()
    applied, verify_failures = [], []

    step("Fetching groups from every node")
    node_groups = {ip: g for ip in nodes if (g := _fetch_groups(ip)) is not None}
    group_nodes = [ip for ip in nodes if ip in node_groups]
    if len(group_nodes) < 2:
        return applied, verify_failures

    ledger = _load_ledger()
    all_names = set().union(*(set(g.keys()) for g in node_groups.values()))
    for name in all_names:
        values = {ip: ((node_groups[ip][name]["enabled"], node_groups[ip][name].get("comment", ""))
                       if name in node_groups[ip] else None) for ip in group_nodes}
        entry = ledger["groups"].setdefault(name, {})
        winner_entry, updated_entry, stale = _pick_winner(group_nodes, values, entry, now_iso)
        if winner_entry["value"] is not None:
            enabled, comment = winner_entry["value"]
            for ip in stale:
                if _api_post(ip, "/groups", {"name": name, "enabled": enabled, "comment": comment}) is not None:
                    applied.append(f"group '{name}' → {ip}")
                    updated_entry[ip] = dict(winner_entry)
                    refreshed = _fetch_groups(ip)  # so client translation below sees the new group
                    if refreshed is not None:
                        node_groups[ip] = refreshed
        ledger["groups"][name] = updated_entry

    name_to_id = {ip: {n: g["id"] for n, g in node_groups[ip].items()} for ip in group_nodes}
    id_to_name = {ip: {g["id"]: n for n, g in node_groups[ip].items()} for ip in group_nodes}

    step("Fetching clients from every node")
    node_clients = {ip: c for ip in group_nodes if (c := _fetch_clients(ip)) is not None}
    client_nodes = [ip for ip in group_nodes if ip in node_clients]
    if len(client_nodes) < 2:
        _save_ledger(ledger)
        return applied, verify_failures

    all_clients = set().union(*(set(c.keys()) for c in node_clients.values()))
    for client_id in all_clients:
        values = {}
        for ip in client_nodes:
            c = node_clients[ip].get(client_id)
            if c is None:
                values[ip] = None
                continue
            names = tuple(sorted(id_to_name[ip].get(gid, f"#{gid}") for gid in c.get("groups", [])))
            values[ip] = (names, c.get("comment", ""))
        entry = ledger["client_groups"].setdefault(client_id, {})
        winner_entry, updated_entry, stale = _pick_winner(client_nodes, values, entry, now_iso)
        if winner_entry["value"] is not None:
            names, comment = winner_entry["value"]
            for ip in stale:
                ids = [name_to_id[ip][n] for n in names if n in name_to_id[ip]]
                missing = [n for n in names if n not in name_to_id[ip]]
                if missing:
                    verify_failures.append(f"client_groups: {client_id} on {ip} missing group(s) {missing}")
                if _api_post(ip, "/clients", {"client": client_id, "comment": comment, "groups": ids}) is not None:
                    applied.append(f"client '{client_id}' groups → {ip}")
                    updated_entry[ip] = dict(winner_entry)
                    confirm = _fetch_clients(ip)
                    confirmed = (confirm or {}).get(client_id)
                    confirmed_names = tuple(sorted(
                        id_to_name[ip].get(gid, f"#{gid}") for gid in (confirmed or {}).get("groups", [])
                    )) if confirmed else None
                    if confirmed_names != names:
                        verify_failures.append(f"client_groups: {client_id} on {ip} did not verify after push")
        ledger["client_groups"][client_id] = updated_entry

    _save_ledger(ledger)
    return applied, verify_failures


def _fetch_lists(ip):
    """{address: list_dict}, keyed by address alone (not address+type) — in
    practice the same URL is essentially never used as both a block and an
    allow list, so this is an acceptable simplification of gravity.db's real
    (address, type) compound key."""
    resp = _api_get(ip, "/lists")
    return None if resp is None else {l["address"]: l for l in resp.get("lists", [])}


def _fetch_domains(ip):
    """{'type|kind|domain': domain_dict} — exact/regex allow/deny overrides."""
    resp = _api_get(ip, "/domains")
    if resp is None:
        return None
    return {f"{d['type']}|{d['kind']}|{d['domain']}": d for d in resp.get("domains", [])}


def _merge_adlists_and_domains(nodes: list, step, adlists_enabled: bool, domains_enabled: bool) -> tuple:
    """Reconciles gravity.db adlists and individual domain allow/deny overrides
    across nodes — this is what actually keeps "is this domain blocked"
    consistent fleet-wide, which the config.toml-only replication above
    doesn't touch at all. Same name/address-matched approach as
    _merge_groups_and_clients (ids are per-node local), and reuses that
    function's group-name translation logic independently here since either
    of these two toggles can be on without client_groups being on."""
    if not adlists_enabled and not domains_enabled:
        return [], [], set()

    now_iso = datetime.now().isoformat()
    applied, verify_failures = [], []
    changed_nodes = set()

    step("Fetching groups from every node (for adlist/domain group assignment)")
    node_groups = {ip: g for ip in nodes if (g := _fetch_groups(ip)) is not None}
    group_nodes = [ip for ip in nodes if ip in node_groups]
    if len(group_nodes) < 2:
        return applied, verify_failures, changed_nodes

    name_to_id = {ip: {n: g["id"] for n, g in node_groups[ip].items()} for ip in group_nodes}
    id_to_name = {ip: {g["id"]: n for n, g in node_groups[ip].items()} for ip in group_nodes}

    def _group_names(ip, group_ids):
        return tuple(sorted(id_to_name[ip].get(gid, f"#{gid}") for gid in (group_ids or [])))

    def _group_ids(ip, names, warn_ctx):
        ids = [name_to_id[ip][n] for n in names if n in name_to_id[ip]]
        missing = [n for n in names if n not in name_to_id[ip]]
        if missing:
            verify_failures.append(f"{warn_ctx} on {ip}: missing group(s) {missing}, assigned without them")
        return ids

    ledger = _load_ledger()

    if adlists_enabled:
        step("Fetching adlists from every node")
        node_lists = {ip: l for ip in group_nodes if (l := _fetch_lists(ip)) is not None}
        list_nodes = [ip for ip in group_nodes if ip in node_lists]
        if len(list_nodes) >= 2:
            all_addrs = set().union(*(set(l.keys()) for l in node_lists.values()))
            for addr in all_addrs:
                values = {}
                for ip in list_nodes:
                    l = node_lists[ip].get(addr)
                    values[ip] = None if l is None else (
                        l["type"], l.get("enabled", True), l.get("comment", ""), _group_names(ip, l.get("groups")))
                entry = ledger["adlists"].setdefault(addr, {})
                winner_entry, updated_entry, stale = _pick_winner(list_nodes, values, entry, now_iso)
                if winner_entry["value"] is not None:
                    ltype, enabled, comment, names = winner_entry["value"]
                    for ip in stale:
                        ids = _group_ids(ip, names, f"adlist '{addr}'")
                        body = {"address": addr, "type": ltype, "enabled": enabled, "comment": comment, "groups": ids}
                        exists = addr in node_lists[ip]
                        result = (_api_put(ip, f"/lists/{urllib.parse.quote(addr, safe='')}", body)
                                  if exists else _api_post(ip, "/lists", body))
                        if result is not None:
                            applied.append(f"adlist '{addr}' → {ip}")
                            updated_entry[ip] = dict(winner_entry)
                            changed_nodes.add(ip)
                ledger["adlists"][addr] = updated_entry
        _save_ledger(ledger)

    if domains_enabled:
        step("Fetching domain overrides from every node")
        node_domains = {ip: d for ip in group_nodes if (d := _fetch_domains(ip)) is not None}
        dom_nodes = [ip for ip in group_nodes if ip in node_domains]
        if len(dom_nodes) >= 2:
            all_keys = set().union(*(set(d.keys()) for d in node_domains.values()))
            for key in all_keys:
                dtype, kind, domain = key.split("|", 2)
                values = {}
                for ip in dom_nodes:
                    d = node_domains[ip].get(key)
                    values[ip] = None if d is None else (
                        d.get("enabled", True), d.get("comment", ""), _group_names(ip, d.get("groups")))
                entry = ledger["domains"].setdefault(key, {})
                winner_entry, updated_entry, stale = _pick_winner(dom_nodes, values, entry, now_iso)
                if winner_entry["value"] is not None:
                    enabled, comment, names = winner_entry["value"]
                    for ip in stale:
                        ids = _group_ids(ip, names, f"domain '{domain}'")
                        body = {"domain": domain, "enabled": enabled, "comment": comment, "groups": ids}
                        exists = key in node_domains[ip]
                        path_suffix = f"/domains/{dtype}/{kind}"
                        result = (_api_put(ip, f"{path_suffix}/{urllib.parse.quote(domain, safe='')}", body)
                                  if exists else _api_post(ip, path_suffix, body))
                        if result is not None:
                            applied.append(f"domain '{domain}' ({dtype}/{kind}) → {ip}")
                            updated_entry[ip] = dict(winner_entry)
                            changed_nodes.add(ip)
                ledger["domains"][key] = updated_entry
        _save_ledger(ledger)

    return applied, verify_failures, changed_nodes


def _merge_run(step) -> list:
    """Fetches config from every reachable node, merges each enabled scalar
    path and (if enabled) the dhcp.hosts reservation list, and pushes the
    winning value out to any node that's behind. Returns the list of applied
    change descriptions; raises RuntimeError on unrecoverable failure."""
    now_iso = datetime.now().isoformat()
    options = _load_options()
    enabled_paths = [p for p in _SCALAR_PATHS if options.get(p, True)]
    hosts_enabled = options.get(HOSTS_PATH, True)
    client_groups_enabled = options.get(CLIENT_GROUPS_PATH, False)
    adlists_enabled = options.get(ADLISTS_PATH, False)
    domains_enabled = options.get(DOMAINS_PATH, False)
    if not enabled_paths and not hosts_enabled and not client_groups_enabled and not adlists_enabled and not domains_enabled:
        raise RuntimeError("No settings enabled")

    all_ips = nodes.get_ips()
    sync_ips = [ip for ip in all_ips if not maintenance.is_under_maintenance(ip)]
    if len(sync_ips) < len(all_ips):
        step(f"Skipping node(s) in maintenance mode: {', '.join(ip for ip in all_ips if ip not in sync_ips)}")

    step(f"Fetching config from {len(sync_ips)} node(s)")
    configs = {}
    for ip in sync_ips:
        cfg = _api_get(ip, "/config")
        if cfg is not None:
            configs[ip] = cfg.get("config", {})
    nodes = [ip for ip in sync_ips if ip in configs]
    unreachable = [ip for ip in sync_ips if ip not in configs]
    if unreachable:
        step(f"Skipping unreachable node(s): {', '.join(unreachable)}")
    if len(nodes) < 2:
        raise RuntimeError("Fewer than 2 Pi-holes reachable — nothing to compare")

    step("Taking pre-replication backup snapshot")
    from workers import backup  # deferred: backup.py imports this module at its own top level
    try:
        backup.take_backup("pre-replication")
    except Exception as e:
        step(f"Pre-replication backup snapshot failed (continuing anyway): {e}")

    step("Checking default-group/blocklist health on each node")
    health_warnings = []
    for ip in nodes:
        health_warnings.extend(validate.check_node_group_health(ip, credentials.get_admin_password()))
    if health_warnings:
        step("Health warning(s): " + "; ".join(health_warnings))
        activity_log.log("replication", f"Node health check found issue(s): {'; '.join(health_warnings)}", level="warning")

    ledger = _load_ledger()
    applied = []
    verify_failures = []

    for path in enabled_paths:
        values, all_found = {}, True
        for ip in nodes:
            val, found = _get_path(configs[ip], path)
            if not found:
                all_found = False
                break
            values[ip] = val
        if not all_found:
            continue  # not present in this Pi-hole version on at least one node
        entry = ledger["scalars"].setdefault(path, {})
        winner_entry, updated_entry, stale = _pick_winner(nodes, values, entry, now_iso)
        for ip in stale:
            patch = {}
            _set_path(patch, path, winner_entry["value"])
            if _api_patch(ip, "/config", {"config": patch}) is not None:
                updated_entry[ip] = dict(winner_entry)
                applied.append(f"{path} → {ip}")
                # Read back what actually landed rather than trusting the API's
                # 200 response — Pi-hole can silently reject/coerce a value
                # (e.g. a malformed one) while still returning success.
                confirm = _api_get(ip, "/config")
                confirmed_val, found = _get_path(confirm.get("config", {}), path) if confirm else (None, False)
                if not found or confirmed_val != winner_entry["value"]:
                    verify_failures.append(f"{path} on {ip} (expected {winner_entry['value']!r}, read back {confirmed_val!r})")
        ledger["scalars"][path] = updated_entry

    if hosts_enabled:
        node_hosts = {ip: _parse_hosts(configs[ip].get("dhcp", {}).get("hosts", [])) for ip in nodes}
        all_macs = set().union(*node_hosts.values()) if node_hosts else set()
        merged = {}
        ledger_hosts = ledger["hosts"]
        mac_meta = {}  # mac -> (winner_entry, updated_entry, stale_ips)
        for mac in all_macs:
            values = {ip: node_hosts[ip].get(mac) for ip in nodes}
            entry = ledger_hosts.setdefault(mac, {})
            winner_entry, updated_entry, stale = _pick_winner(nodes, values, entry, now_iso)
            mac_meta[mac] = (winner_entry, updated_entry, stale)
            if winner_entry["value"] is not None:
                merged[mac] = winner_entry["value"]
        for ip in nodes:
            if node_hosts[ip] == merged:
                continue
            if _api_patch(ip, "/config", {"config": {"dhcp": {"hosts": _render_hosts(merged)}}}) is not None:
                applied.append(f"dhcp.hosts → {ip} ({len(merged)} reservation(s))")
                for winner_entry, updated_entry, stale in mac_meta.values():
                    if ip in stale:
                        updated_entry[ip] = dict(winner_entry)
                confirm = _api_get(ip, "/config")
                confirmed_hosts = _parse_hosts(confirm.get("config", {}).get("dhcp", {}).get("hosts", [])) if confirm else None
                if confirmed_hosts != merged:
                    verify_failures.append(f"dhcp.hosts on {ip} did not match after push")
        for mac, (_winner_entry, updated_entry, _stale) in mac_meta.items():
            ledger_hosts[mac] = updated_entry

    _save_ledger(ledger)

    if client_groups_enabled:
        step("Reconciling groups and client group assignments")
        g_applied, g_verify_failures = _merge_groups_and_clients(nodes, step)
        applied.extend(g_applied)
        verify_failures.extend(g_verify_failures)

    if adlists_enabled or domains_enabled:
        step("Reconciling adlists and/or domain overrides")
        a_applied, a_verify_failures, changed_nodes = _merge_adlists_and_domains(
            nodes, step, adlists_enabled, domains_enabled)
        applied.extend(a_applied)
        verify_failures.extend(a_verify_failures)
        for ip in changed_nodes:
            step(f"Triggering gravity update on {ip} so adlist/domain changes take effect")
            gravity.trigger_gravity(ip)

    return applied, verify_failures


# --- Drift check (read-only — reports disagreement across nodes without
# pushing/patching anything or touching the ledger; complements _merge_run's
# auto-repair with an on-demand "are we actually in sync right now" view) ---

_drift_status = {"status": "idle", "message": "", "timestamp": None, "log": [], "findings": []}
_drift_status_lock = threading.Lock()
_drift_event = threading.Event()


def _set_drift_status(status, message, log, findings=None):
    with _drift_status_lock:
        _drift_status["status"], _drift_status["message"] = status, message
        _drift_status["timestamp"] = datetime.now().isoformat()
        _drift_status["log"] = list(log)
        if findings is not None:
            _drift_status["findings"] = findings


def get_drift_status() -> dict:
    with _drift_status_lock:
        return dict(_drift_status)


def trigger_drift_check():
    _drift_event.set()


def _check_drift(step) -> list:
    options = _load_options()
    enabled_paths = [p for p in _SCALAR_PATHS if options.get(p, True)]
    hosts_enabled = options.get(HOSTS_PATH, True)
    adlists_enabled = options.get(ADLISTS_PATH, False)
    domains_enabled = options.get(DOMAINS_PATH, False)

    all_ips = nodes.get_ips()
    drift_ips = [ip for ip in all_ips if not maintenance.is_under_maintenance(ip)]
    if len(drift_ips) < len(all_ips):
        step(f"Excluding node(s) in maintenance mode: {', '.join(ip for ip in all_ips if ip not in drift_ips)}")
    step(f"Fetching config from {len(drift_ips)} node(s)")
    configs = {}
    for ip in drift_ips:
        cfg = _api_get(ip, "/config")
        if cfg is not None:
            configs[ip] = cfg.get("config", {})
    nodes = [ip for ip in drift_ips if ip in configs]
    unreachable = [ip for ip in drift_ips if ip not in configs]
    findings = [f"{ip}: unreachable" for ip in unreachable]
    if len(nodes) < 2:
        findings.append("Fewer than 2 Pi-holes reachable — nothing to compare")
        return findings

    for path in enabled_paths:
        values = {}
        for ip in nodes:
            val, found = _get_path(configs[ip], path)
            values[ip] = val if found else "<missing>"
        if len(set(map(str, values.values()))) > 1:
            findings.append(f"{path} differs: " + ", ".join(f"{ip}={values[ip]!r}" for ip in nodes))

    if hosts_enabled:
        node_hosts = {ip: _parse_hosts(configs[ip].get("dhcp", {}).get("hosts", [])) for ip in nodes}
        first = node_hosts[nodes[0]]
        if any(node_hosts[ip] != first for ip in nodes[1:]):
            findings.append("dhcp.hosts (static reservations) differ between nodes: " +
                             ", ".join(f"{ip}={len(node_hosts[ip])} entries" for ip in nodes))

    if adlists_enabled:
        node_lists = {ip: l for ip in nodes if (l := _fetch_lists(ip)) is not None}
        if len(node_lists) >= 2:
            simplified = {ip: {addr: (l["type"], l.get("enabled", True)) for addr, l in lists.items()}
                          for ip, lists in node_lists.items()}
            first = next(iter(simplified.values()))
            if any(v != first for v in simplified.values()):
                findings.append("Adlists differ between nodes: " +
                                 ", ".join(f"{ip}={len(simplified[ip])} entries" for ip in node_lists))

    if domains_enabled:
        node_domains = {ip: d for ip in nodes if (d := _fetch_domains(ip)) is not None}
        if len(node_domains) >= 2:
            simplified = {ip: {k: d.get("enabled", True) for k, d in doms.items()}
                          for ip, doms in node_domains.items()}
            first = next(iter(simplified.values()))
            if any(v != first for v in simplified.values()):
                findings.append("Domain allow/deny overrides differ between nodes: " +
                                 ", ".join(f"{ip}={len(simplified[ip])} entries" for ip in node_domains))

    return findings


def _drift_loop():
    while True:
        _drift_event.wait()
        _drift_event.clear()

        if len(nodes.get_ips()) < 2:
            _set_drift_status("error", "Only one Pi-hole configured — nothing to compare", [], [])
            continue

        log = deque(maxlen=200)

        def step(msg):
            log.append(msg)
            _set_drift_status("running", msg, log)

        try:
            findings = _check_drift(step)
            if findings:
                step(f"Found {len(findings)} discrepanc(y/ies)")
                _set_drift_status("error", f"{len(findings)} discrepanc(y/ies) found", log, findings)
                activity_log.log("replication", f"Drift check found discrepancies: {'; '.join(findings)}", level="warning")
            else:
                step("All enabled settings match across every reachable node")
                _set_drift_status("success", "No drift detected", log, [])
                activity_log.log("replication", "Drift check — no discrepancies found")
        except Exception as e:
            _set_drift_status("error", str(e), list(log), [])
            activity_log.log("replication", f"Drift check failed: {e}", level="error")


def _sync_loop():
    while True:
        triggered = _event.wait(timeout=CHECK_INTERVAL_SECS)
        _event.clear()

        auto = _load_auto()
        if not triggered and not _auto_due(auto):
            continue

        source = "manual" if triggered else "auto"

        if len(nodes.get_ips()) < 2:
            if source == "manual":
                _set_status("error", "Only one Pi-hole configured — nothing to compare", [])
            continue

        _mark_auto_run()
        log = deque(maxlen=200)

        def step(msg):
            log.append(msg)
            _set_status("running", msg, log)

        try:
            applied, verify_failures = _merge_run(step)
            if verify_failures:
                step(f"Verification FAILED for {len(verify_failures)} change(s): " + "; ".join(verify_failures))
                activity_log.log(
                    "replication",
                    f"{source.capitalize()} replication push did not verify: {'; '.join(verify_failures)}",
                    level="error",
                )
            if applied:
                step(f"Applied {len(applied)} change(s): " + "; ".join(applied))
                status = "error" if verify_failures else "success"
                msg = f"Merged {len(applied)} change(s)" + (f", {len(verify_failures)} failed to verify" if verify_failures else "")
                _set_status(status, msg, log)
                activity_log.log("replication", f"{source.capitalize()} replication merged: {'; '.join(applied)}")
            else:
                step("All nodes already in sync — nothing to do")
                _set_status("error" if verify_failures else "success",
                             "All nodes already in sync" if not verify_failures else "Verification failures found", log)
                activity_log.log("replication", f"{source.capitalize()} replication — all nodes already in sync")
        except Exception as e:
            _set_status("error", str(e), list(log))
            activity_log.log("replication", f"{source.capitalize()} replication failed: {e}", level="error")


def start():
    threading.Thread(target=_sync_loop, daemon=True, name="replication-sync").start()
    threading.Thread(target=_drift_loop, daemon=True, name="replication-drift").start()
