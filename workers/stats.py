#!/usr/bin/env python3
"""Fleet-wide aggregated stats. Pi-hole's own dashboard only ever shows one
node's numbers — there's no built-in way to see the cluster as a whole. This
merges each node's query totals and top-domain/top-client lists into one
view.

Caveat: top_domains/top_clients are summed from each node's own top-N list,
not from an exhaustive per-domain count across the whole fleet (Pi-hole's
API has no cheap way to get that) — a domain that's #11 on every node but
never makes any node's own top-10 won't show up here even if its true
fleet-wide total would rank higher. Good enough for "what's dominating right
now," not a source of truth for long-tail analysis."""
import os
import threading

import requests

from workers import credentials, nodes

_sid_cache = {}
_sid_lock  = threading.Lock()


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


def _merge_domain_counts(per_node, key, top_count):
    domain_totals = {}
    for node in per_node.values():
        for d in node[key]:
            domain_totals[d["domain"]] = domain_totals.get(d["domain"], 0) + d["count"]
    top = sorted(domain_totals.items(), key=lambda kv: kv[1], reverse=True)[:top_count]
    return [{"domain": d, "count": c} for d, c in top]


def _merge_client_counts(per_node, key, top_count):
    client_totals = {}
    for node in per_node.values():
        for c in node[key]:
            ckey = c.get("ip") or c.get("name")
            if not ckey:
                continue
            entry = client_totals.setdefault(ckey, {"name": c.get("name", ""), "ip": c.get("ip", ""), "count": 0})
            entry["count"] += c.get("count", 0)
    return sorted(client_totals.values(), key=lambda c: c["count"], reverse=True)[:top_count]


def get_fleet_stats(top_count: int = 10) -> dict:
    ips = nodes.get_ips()
    per_node = {}
    for ip in ips:
        summary = _api_get(ip, "/stats/summary")
        domains = _api_get(ip, f"/stats/top_domains?count={top_count}")
        clients = _api_get(ip, f"/stats/top_clients?count={top_count}")
        denied_domains = _api_get(ip, f"/stats/top_domains?count={top_count}&blocked=true")
        denied_clients = _api_get(ip, f"/stats/top_clients?count={top_count}&blocked=true")
        reachable = summary is not None
        per_node[ip] = {
            "reachable": reachable,
            "summary": (summary or {}).get("queries", {}),
            "domains": (domains or {}).get("domains", []) if domains else [],
            "clients": (clients or {}).get("clients", []) if clients else [],
            "denied_domains": (denied_domains or {}).get("domains", []) if denied_domains else [],
            "denied_clients": (denied_clients or {}).get("clients", []) if denied_clients else [],
        }

    reachable_nodes = {ip: n for ip, n in per_node.items() if n["reachable"]}

    totals = {"total": 0, "blocked": 0, "forwarded": 0, "cached": 0}
    for node in reachable_nodes.values():
        q = node["summary"]
        for k in totals:
            totals[k] += q.get(k, 0) or 0
    totals["percent_blocked"] = round(totals["blocked"] / totals["total"] * 100, 2) if totals["total"] else 0.0

    return {
        "nodes": {ip: {"reachable": per_node[ip]["reachable"], "summary": per_node[ip]["summary"]} for ip in ips},
        "totals": totals,
        "top_domains": _merge_domain_counts(reachable_nodes, "domains", top_count),
        "top_clients": _merge_client_counts(reachable_nodes, "clients", top_count),
        "top_denied_domains": _merge_domain_counts(reachable_nodes, "denied_domains", top_count),
        "top_denied_clients": _merge_client_counts(reachable_nodes, "denied_clients", top_count),
    }
