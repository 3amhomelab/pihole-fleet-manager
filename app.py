#!/usr/bin/env python3
"""Pihole Fleet Manager — manages the Pi-hole cluster: extra DHCP scopes (VLANs)
on top of Pi-hole's single built-in scope, config replication, software
auto-updates, and node health monitoring (ping/DNS/API checks, uptime, VIP
master detection, auto-heal escalation), all across every Pi-hole node."""
import os

from flask import Flask, jsonify, render_template, request

from workers import (
    activity_log, dhcp_failover, external_dhcp, gravity, lease_conflicts,
    monitor, pihole_push, primary_dhcp, recovery, replication, setup, stats,
    store, updater,
)

PORT        = int(os.environ.get("PORT", "8080"))
APP_VERSION = os.environ.get("APP_VERSION", "dev")

app = Flask(__name__)


@app.context_processor
def inject_globals():
    return {"app_version": APP_VERSION}


# --- Pages ---

@app.route("/")
def page_vlans():
    return render_template("vlans.html", active_page="vlans")


@app.route("/setup")
def page_setup():
    return render_template("setup.html", active_page="setup")


@app.route("/replication")
def page_replication():
    return render_template("replication.html", active_page="replication")


@app.route("/updater")
def page_updater():
    return render_template("updater.html", active_page="updater")


@app.route("/failover")
def page_failover():
    return render_template("failover.html", active_page="failover")


@app.route("/monitor")
def page_monitor():
    return render_template("monitor.html", active_page="monitor")


@app.route("/stats")
def page_stats():
    return render_template("stats.html", active_page="stats")


@app.route("/recovery")
def page_recovery():
    return render_template("recovery.html", active_page="recovery")


@app.route("/log")
def page_log():
    return render_template("log.html", active_page="log")


@app.route("/help")
def page_help():
    return render_template("help.html", active_page="help")


# --- VLAN API ---

@app.route("/api/vlans")
def api_list_vlans():
    pihole_config = primary_dhcp.get_config()
    store.ensure_primary_vlan(pihole_config)
    store.sync_primary_meta(pihole_config)

    vlans  = store.list_vlans()
    leases = primary_dhcp.get_leases()
    for v in vlans:
        static_hosts = primary_dhcp.get_reservations() if v.get("is_primary") else v["hosts"]
        v["hosts"] = store.merge_dynamic_hosts(v, static_hosts, leases)
    return jsonify({"vlans": vlans})


@app.route("/api/vlans", methods=["POST"])
def api_create_vlan():
    data = request.get_json(silent=True) or {}
    vlan, error = store.create_vlan(data)
    if error:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True, "vlan": vlan})


@app.route("/api/vlans/<vlan_id>", methods=["PATCH"])
def api_update_vlan(vlan_id):
    data = request.get_json(silent=True) or {}
    vlan, error = store.update_vlan(vlan_id, data)
    if error:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True, "vlan": vlan})


@app.route("/api/vlans/<vlan_id>", methods=["DELETE"])
def api_delete_vlan(vlan_id):
    ok, error = store.delete_vlan(vlan_id)
    if not ok:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True})


# --- Host API (scoped to a VLAN) ---
# The "primary" VLAN mirrors Pi-hole's own native scope, so its hosts are
# read/written straight against Pi-hole's API (primary_dhcp); every other
# VLAN's hosts live in the local store and get pushed out via dnsmasq.d.

@app.route("/api/vlans/<vlan_id>/hosts", methods=["POST"])
def api_add_host(vlan_id):
    data     = request.get_json(silent=True) or {}
    mac      = data.get("mac", "")
    ip       = data.get("ip", "")
    hostname = data.get("hostname", "")
    if not mac or not ip:
        return jsonify({"ok": False, "error": "mac and ip required"}), 400

    if vlan_id == "primary":
        ok, error = primary_dhcp.add_or_update_reservation(mac, ip, hostname)
        vlan = None
    else:
        vlan, error = store.add_or_update_host(vlan_id, mac, ip, hostname)
        ok = vlan is not None
    if not ok:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True, "vlan": vlan})


@app.route("/api/vlans/<vlan_id>/hosts/<ip>", methods=["DELETE"])
def api_delete_host(vlan_id, ip):
    if vlan_id == "primary":
        ok, error = primary_dhcp.delete_reservation(ip)
    else:
        ok, error = store.delete_host(vlan_id, ip)
    if not ok:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True})


@app.route("/api/vlans/<vlan_id>/hosts/<ip>", methods=["PATCH"])
def api_update_host(vlan_id, ip):
    """Change the MAC on an existing static reservation, keyed by its current
    ip. (IP edits go through POST /hosts instead — add_or_update is already
    keyed by mac, so it correctly replaces the old entry in place; a dynamic
    lease with no static reservation yet just gets a new one created.)"""
    data    = request.get_json(silent=True) or {}
    new_mac = data.get("mac", "")
    if not new_mac:
        return jsonify({"ok": False, "error": "mac required"}), 400

    if vlan_id == "primary":
        ok, error = primary_dhcp.update_reservation_mac(ip, new_mac)
        vlan = None
    else:
        vlan, error = store.update_host_mac(vlan_id, ip, new_mac)
        ok = vlan is not None
    if not ok:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True, "vlan": vlan})


# --- Push extra VLANs to Pi-hole nodes (dnsmasq.d) ---

@app.route("/api/push", methods=["POST"])
def api_push():
    pihole_push.trigger_push()
    return jsonify({"ok": True})


@app.route("/api/push/status")
def api_push_status():
    return jsonify(pihole_push.get_status())


@app.route("/api/push/preview")
def api_push_preview():
    return jsonify({"conf": pihole_push.render_conf(store.list_vlans())})


# --- Import VLANs that already exist on a node's dnsmasq.d config ---
# (e.g. pushed there by another/older instance pointed at the same nodes)

@app.route("/api/vlans/import/preview")
def api_vlans_import_preview():
    ip = request.args.get("ip") or (pihole_push.PIHOLE_IPS[0] if pihole_push.PIHOLE_IPS else None)
    if not ip:
        return jsonify({"ok": False, "error": "No Pi-hole IPs configured"}), 400
    content, error = pihole_push.fetch_remote_conf(ip)
    if error:
        return jsonify({"ok": False, "error": error}), 400
    existing_ids = {v["id"] for v in store.list_vlans()}
    parsed = pihole_push.parse_conf(content)
    for v in parsed:
        v["already_exists"] = v["id"] in existing_ids
    return jsonify({"ok": True, "ip": ip, "vlans": parsed})


@app.route("/api/vlans/import", methods=["POST"])
def api_vlans_import_apply():
    data = request.get_json(silent=True) or {}
    ip  = data.get("ip") or (pihole_push.PIHOLE_IPS[0] if pihole_push.PIHOLE_IPS else None)
    ids = data.get("ids") or []
    if not ip:
        return jsonify({"ok": False, "error": "No Pi-hole IPs configured"}), 400
    content, error = pihole_push.fetch_remote_conf(ip)
    if error:
        return jsonify({"ok": False, "error": error}), 400

    by_id = {v["id"]: v for v in pihole_push.parse_conf(content)}
    imported, errors = [], []
    for vlan_id in ids:
        vlan = by_id.get(vlan_id)
        if not vlan:
            errors.append(f"{vlan_id}: not found in {ip}'s config")
            continue
        result, err = store.import_vlan(vlan)
        (errors if err else imported).append(f"{vlan_id}: {err}" if err else result)
    return jsonify({"ok": not errors, "imported": imported, "errors": errors})


# --- Multi-master config + DHCP scope replication ---

@app.route("/api/replication/options")
def api_replication_options():
    return jsonify({"groups": replication.get_groups()})


@app.route("/api/replication/options", methods=["POST"])
def api_replication_set_options():
    data = request.get_json(silent=True) or {}
    replication.set_options(data)
    return jsonify({"ok": True, "groups": replication.get_groups()})


@app.route("/api/replication/sync", methods=["POST"])
def api_replication_sync():
    replication.trigger_sync()
    return jsonify({"ok": True})


@app.route("/api/replication/sync/status")
def api_replication_sync_status():
    return jsonify(replication.get_status())


@app.route("/api/replication/drift", methods=["POST"])
def api_replication_drift():
    replication.trigger_drift_check()
    return jsonify({"ok": True})


@app.route("/api/replication/drift/status")
def api_replication_drift_status():
    return jsonify(replication.get_drift_status())


@app.route("/api/replication/auto")
def api_replication_auto():
    return jsonify(replication.get_auto_config())


@app.route("/api/replication/auto", methods=["POST"])
def api_replication_set_auto():
    data = request.get_json(silent=True) or {}
    try:
        minutes = int(data.get("interval_minutes", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "interval_minutes must be a number"}), 400
    return jsonify(replication.set_auto_interval(minutes))


# --- Software auto-updater ---

@app.route("/api/updater")
def api_updater_state():
    return jsonify({"nodes": updater.get_state()})


@app.route("/api/updater/<path:ip>/upgrade", methods=["POST"])
def api_updater_upgrade(ip):
    ok, msg = updater.trigger_upgrade(ip)
    return jsonify({"ok": ok, "message": msg})


# --- Staggered gravity (blocklist) updates ---

@app.route("/api/gravity")
def api_gravity_state():
    return jsonify({"nodes": gravity.get_state()})


@app.route("/api/gravity/<path:ip>/update", methods=["POST"])
def api_gravity_update(ip):
    ok, msg = gravity.trigger_gravity(ip)
    return jsonify({"ok": ok, "message": msg})


# --- Fleet-wide aggregated stats ---

@app.route("/api/stats")
def api_stats():
    try:
        count = int(request.args.get("count", 10))
    except ValueError:
        count = 10
    return jsonify(stats.get_fleet_stats(top_count=count))


# --- Stale-lease / static-reservation conflict guard ---

@app.route("/api/lease-conflicts")
def api_lease_conflicts():
    return jsonify({"conflicts": lease_conflicts.check_conflicts()})


@app.route("/api/lease-conflicts/clear", methods=["POST"])
def api_lease_conflicts_clear():
    data = request.get_json(silent=True) or {}
    node = data.get("node", "")
    leased_ip = data.get("leased_ip", "")
    if not node or not leased_ip:
        return jsonify({"ok": False, "error": "node and leased_ip required"}), 400
    ok, error = lease_conflicts.clear_conflict(node, leased_ip)
    return jsonify({"ok": ok, "error": error})


# --- Node recovery (clone a healthy node onto a target) ---

@app.route("/api/recovery/status")
def api_recovery_status():
    return jsonify(recovery.get_status())


@app.route("/api/recovery/clone", methods=["POST"])
def api_recovery_clone():
    data = request.get_json(silent=True) or {}
    source = data.get("source", "")
    target = data.get("target", "")
    if not source or not target:
        return jsonify({"ok": False, "error": "source and target required"}), 400
    if source not in pihole_push.PIHOLE_IPS or target not in pihole_push.PIHOLE_IPS:
        return jsonify({"ok": False, "error": "source/target must be configured Pi-hole IPs"}), 400
    recovery.clone_node(source, target)
    return jsonify({"ok": True})


# --- External DHCP-source sync (UniFi, for DNS-only Pi-hole deployments) ---

@app.route("/api/external-dhcp")
def api_external_dhcp_state():
    return jsonify(external_dhcp.get_status())


@app.route("/api/external-dhcp/sync", methods=["POST"])
def api_external_dhcp_sync():
    ok, error = external_dhcp.sync_now()
    return jsonify({"ok": ok, "error": error})


# --- DHCP active/standby failover ---

@app.route("/api/failover")
def api_failover_state():
    return jsonify(dhcp_failover.get_state())


@app.route("/api/failover/enabled", methods=["POST"])
def api_failover_set_enabled():
    data = request.get_json(silent=True) or {}
    return jsonify(dhcp_failover.set_enabled(bool(data.get("enabled"))))


# --- Node health monitoring (ping/DNS/API checks, uptime, VIP master, auto-heal) ---

@app.route("/api/monitor")
def api_monitor_state():
    return jsonify(monitor.get_state())


@app.route("/api/monitor/interval", methods=["POST"])
def api_monitor_set_interval():
    data = request.get_json(silent=True) or {}
    try:
        seconds = int(data.get("seconds", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "seconds must be a number"}), 400
    monitor.set_interval(seconds)
    return jsonify({"ok": True})


@app.route("/api/monitor/<path:ip>/reboot", methods=["POST"])
def api_monitor_reboot(ip):
    if ip not in monitor.PIHOLE_IPS:
        return jsonify({"ok": False, "error": "Not a configured Pi-hole node"}), 400
    monitor.reboot(ip)
    return jsonify({"ok": True})


@app.route("/api/monitor/<path:ip>/diag", methods=["POST"])
def api_monitor_diag(ip):
    ok, msg = monitor.run_diagnostics(ip)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/monitor/failover", methods=["POST"])
def api_monitor_failover():
    ok, msg = monitor.trigger_failover()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/monitor/clear", methods=["POST"])
def api_monitor_clear():
    monitor.clear_history()
    return jsonify({"ok": True})


# --- Activity log ---

@app.route("/api/log")
def api_log():
    category = request.args.get("category", "")
    try:
        limit = int(request.args.get("limit", 200))
    except ValueError:
        limit = 200
    return jsonify({"events": activity_log.get_events(limit=limit, category=category)})


# --- SSH trust setup ---

@app.route("/api/setup/status")
def api_setup_status():
    return jsonify({
        "job":   setup.get_status(),
        "nodes": setup.get_node_status(),
        "key_exists": setup.key_exists(),
    })


@app.route("/api/setup/key")
def api_setup_key():
    """Durable read of the current key (unlike job.key_b64, which is only
    populated in memory right after a Setup run) — used by deploy.sh to pull
    the live key forward into the local .env on every deploy."""
    return jsonify({"key_b64": setup.get_key_b64()})


@app.route("/api/setup/run", methods=["POST"])
def api_setup_run():
    data = request.get_json(silent=True) or {}
    password   = data.get("password", "")
    regenerate = bool(data.get("regenerate", False))
    if not password:
        return jsonify({"ok": False, "error": "password required"}), 400
    setup.trigger_setup(password, regenerate)
    return jsonify({"ok": True})


if __name__ == "__main__":
    pihole_push.start()
    setup.start()
    replication.start()
    updater.start()
    dhcp_failover.start()
    gravity.start()
    external_dhcp.start()
    monitor.start()
    app.run(host="0.0.0.0", port=PORT)
