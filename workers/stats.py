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
from workers import nodes, pihole_api


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
        summary = pihole_api.api_get(ip, "/stats/summary")
        domains = pihole_api.api_get(ip, f"/stats/top_domains?count={top_count}")
        clients = pihole_api.api_get(ip, f"/stats/top_clients?count={top_count}")
        denied_domains = pihole_api.api_get(ip, f"/stats/top_domains?count={top_count}&blocked=true")
        denied_clients = pihole_api.api_get(ip, f"/stats/top_clients?count={top_count}&blocked=true")
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
