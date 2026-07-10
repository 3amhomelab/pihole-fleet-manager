#!/usr/bin/env python3
"""Fleet-wide query log search: fans a domain/client search out to every
node's own /api/queries and merges the results, tagged with which node
answered. Pi-hole's own dashboard only ever shows one node's query log —
with a VIP in front of the cluster, "why was this domain blocked" requires
checking every node's dashboard by hand without this."""
import threading

from workers import nodes, pihole_api


def _query_one(ip: str, domain: str, client: str, limit: int) -> dict:
    params = {"length": limit}
    if domain:
        params["domain"] = domain if "*" in domain else f"*{domain}*"
    if client:
        params["client_ip"] = client
    resp = pihole_api.api_get(ip, "/queries", params)
    if resp is None:
        return {"ok": False, "queries": []}
    queries = resp.get("queries", [])
    for q in queries:
        q["node"] = ip
    return {"ok": True, "queries": queries}


def search(domain: str = "", client: str = "", limit_per_node: int = 100, total_limit: int = 300) -> dict:
    if not domain and not client:
        return {"queries": [], "node_status": {}}

    ips = nodes.get_ips()
    node_status = {}
    all_queries = []
    threads_results = {}

    def _run(ip):
        threads_results[ip] = _query_one(ip, domain, client, limit_per_node)

    threads = [threading.Thread(target=_run, args=(ip,)) for ip in ips]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    for ip in ips:
        result = threads_results.get(ip, {"ok": False, "queries": []})
        node_status[ip] = "ok" if result["ok"] else "unreachable"
        all_queries.extend(result["queries"])

    all_queries.sort(key=lambda q: q.get("time", 0), reverse=True)
    return {"queries": all_queries[:total_limit], "node_status": node_status}
