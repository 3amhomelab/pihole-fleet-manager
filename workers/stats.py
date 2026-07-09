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

PIHOLE_IPS  = [ip.strip() for ip in os.environ.get("PIHOLE_IPS", "").split(",") if ip.strip()]
PIHOLE_PASS = os.environ.get("PIHOLE_ADMIN_PASSWORD", "")

_sid_cache = {}
_sid_lock  = threading.Lock()


def _auth(ip):
    try:
        r = requests.post(f"http://{ip}/api/auth", json={"password": PIHOLE_PASS}, timeout=8)
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


def get_fleet_stats(top_count: int = 10) -> dict:
    per_node = {}
    for ip in PIHOLE_IPS:
        summary = _api_get(ip, "/stats/summary")
        domains = _api_get(ip, f"/stats/top_domains?count={top_count}")
        clients = _api_get(ip, f"/stats/top_clients?count={top_count}")
        per_node[ip] = {
            "reachable": summary is not None,
            "summary": (summary or {}).get("queries", {}),
            "domains": (domains or {}).get("domains", []) if domains else [],
            "clients": (clients or {}).get("clients", []) if clients else [],
        }

    reachable = [ip for ip in PIHOLE_IPS if per_node[ip]["reachable"]]

    totals = {"total": 0, "blocked": 0, "forwarded": 0, "cached": 0}
    for ip in reachable:
        q = per_node[ip]["summary"]
        for k in totals:
            totals[k] += q.get(k, 0) or 0
    totals["percent_blocked"] = round(totals["blocked"] / totals["total"] * 100, 2) if totals["total"] else 0.0

    domain_totals = {}
    for ip in reachable:
        for d in per_node[ip]["domains"]:
            domain_totals[d["domain"]] = domain_totals.get(d["domain"], 0) + d["count"]
    top_domains = sorted(domain_totals.items(), key=lambda kv: kv[1], reverse=True)[:top_count]

    client_totals = {}
    for ip in reachable:
        for c in per_node[ip]["clients"]:
            key = c.get("ip") or c.get("name")
            if not key:
                continue
            entry = client_totals.setdefault(key, {"name": c.get("name", ""), "ip": c.get("ip", ""), "count": 0})
            entry["count"] += c.get("count", 0)
    top_clients = sorted(client_totals.values(), key=lambda c: c["count"], reverse=True)[:top_count]

    return {
        "nodes": {ip: {"reachable": per_node[ip]["reachable"], "summary": per_node[ip]["summary"]} for ip in PIHOLE_IPS},
        "totals": totals,
        "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
        "top_clients": top_clients,
    }
