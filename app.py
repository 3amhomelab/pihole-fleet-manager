#!/usr/bin/env python3
"""Pihole Fleet Manager — manages the Pi-hole cluster: extra DHCP scopes (VLANs)
on top of Pi-hole's single built-in scope, config replication, software
auto-updates, and node health monitoring (ping/DNS/API checks, uptime, VIP
master detection, auto-heal escalation), all across every Pi-hole node."""
import os
import threading
from datetime import datetime

from flask import Flask, Response, jsonify, redirect, render_template, request, session

from workers import (
    activity_log, auth, backup, credentials, dhcp_failover, external_dhcp,
    gravity, lease_conflicts, maintenance, monitor, netbox_import, nodes,
    notify, pihole_push, primary_dhcp, query_log, recovery, replication,
    setup, stats, store, updater, wireless_migration, wizard,
)

PORT        = int(os.environ.get("PORT", "8080"))
APP_VERSION = os.environ.get("APP_VERSION", "dev")

app = Flask(__name__)
app.secret_key = auth.get_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").strip().lower() in ("1", "true", "yes"),
)

# Routes reachable with no session even when admin login is enabled: the
# login page/action itself, and /api/known-hosts, which other apps on the
# network (e.g. Network-Health) poll directly for Pi-hole DHCP awareness —
# gating it would silently break that cross-service integration.
_AUTH_EXEMPT = {"/login", "/api/known-hosts"}


@app.before_request
def _require_login():
    if request.path in _AUTH_EXEMPT or request.path.startswith("/static/"):
        return None
    if auth.is_active():
        if session.get("authenticated"):
            return None
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "Login required"}), 401
        return redirect("/login")
    # Enabled by default on a fresh install, but no password set yet — not
    # locking anyone out (see auth.is_active()), just steering every page
    # toward the wizard's Admin Login step until one is configured.
    if auth.is_enabled() and not auth.has_password() and request.path != "/wizard" \
            and not request.path.startswith("/api/"):
        return redirect("/wizard")
    return None


@app.context_processor
def inject_globals():
    return {"app_version": APP_VERSION}


# --- Admin login ---

@app.route("/login", methods=["GET", "POST"])
def page_login():
    if request.method == "GET":
        return render_template("login.html", error=None)
    password = request.form.get("password", "")
    if auth.check_password(password):
        session["authenticated"] = True
        session.permanent = True
        return redirect("/")
    return render_template("login.html", error="Incorrect password")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")


@app.route("/api/auth/status")
def api_auth_status():
    return jsonify({
        "enabled": auth.is_enabled(),
        "password_set": auth.has_password(),
        "authenticated": bool(session.get("authenticated")),
    })


@app.route("/api/auth/enable", methods=["POST"])
def api_auth_enable():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    ok, error = auth.enable(password)
    if not ok:
        return jsonify({"ok": False, "error": error}), 400
    session["authenticated"] = True
    session.permanent = True
    return jsonify({"ok": True})


@app.route("/api/auth/disable", methods=["POST"])
def api_auth_disable():
    auth.disable()
    return jsonify({"ok": True})


# --- Pages ---

@app.route("/wizard")
def page_wizard():
    return render_template("wizard.html", active_page="wizard")


@app.route("/")
def page_vlans():
    # No nodes configured at all is the unambiguous signal for "freshly
    # installed container" — once even one node is added this never fires
    # again, so it doesn't get in the way of someone who's deliberately
    # cleared their fleet down to zero nodes for some other reason.
    if not nodes.get_ips():
        return redirect("/wizard")
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
    ip = request.args.get("ip") or (nodes.get_ips()[0] if nodes.get_ips() else None)
    if not ip:
        return jsonify({"ok": False, "error": "No Pi-hole IPs configured"}), 400
    content, error = pihole_push.fetch_remote_conf(ip)
    if error:
        return jsonify({"ok": False, "error": error}), 400
    existing_ids = {v["id"] for v in store.list_vlans()}
    parsed = pihole_push.parse_conf(content)
    for v in parsed:
        v["already_exists"] = v["id"] in existing_ids

    # dnsmasq.d only ever holds the *extra* VLANs this app pushes — the node's
    # own standard Pi-hole scope (and its static DHCP reservations) lives in
    # Pi-hole's own config/API instead, so pull that in too for a full picture.
    primary = store.primary_vlan_from_config(primary_dhcp.get_config(ip))
    if primary:
        primary["hosts"] = primary_dhcp.get_reservations(ip)
        primary["already_exists"] = "primary" in existing_ids
        parsed.insert(0, primary)

    return jsonify({"ok": True, "ip": ip, "vlans": parsed})


@app.route("/api/netbox/preview")
def api_netbox_preview():
    if not netbox_import.configured():
        return jsonify({"ok": False, "error": "NETBOX_URL/NETBOX_TOKEN not configured"}), 400
    candidates, error = netbox_import.preview(store.list_vlans())
    if error:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True, "vlans": candidates})


@app.route("/api/netbox/import", methods=["POST"])
def api_netbox_import_apply():
    data = request.get_json(silent=True) or {}
    vlans = data.get("vlans") or []
    if not vlans:
        return jsonify({"ok": False, "error": "No VLANs selected"}), 400
    imported, errors = netbox_import.apply_import(vlans)
    return jsonify({"ok": not errors, "imported": imported, "errors": errors})


@app.route("/api/vlans/import", methods=["POST"])
def api_vlans_import_apply():
    data = request.get_json(silent=True) or {}
    ip  = data.get("ip") or (nodes.get_ips()[0] if nodes.get_ips() else None)
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


@app.route("/api/updater/halted")
def api_updater_halted():
    return jsonify(updater.get_halted())


@app.route("/api/updater/resume", methods=["POST"])
def api_updater_resume():
    updater.resume_rotation()
    return jsonify({"ok": True})


# --- Point-in-time backups + rollback ---

@app.route("/backup")
def page_backup():
    return render_template("backup.html", active_page="backup")


@app.route("/api/backup/settings")
def api_backup_settings():
    return jsonify(backup.get_settings())


@app.route("/api/backup/settings", methods=["POST"])
def api_backup_set_settings():
    data = request.get_json(silent=True) or {}
    try:
        keep = int(data.get("keep", 5))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "keep must be a number"}), 400
    return jsonify(backup.set_settings(keep, data.get("schedule", "off")))


@app.route("/api/backup/list")
def api_backup_list():
    return jsonify({"backups": backup.list_backups()})


@app.route("/api/backup/status")
def api_backup_status():
    return jsonify(backup.get_status())


@app.route("/api/backup/take", methods=["POST"])
def api_backup_take():
    threading.Thread(target=backup.take_backup, args=("manual",), daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/backup/<name>", methods=["DELETE"])
def api_backup_delete(name):
    ok, error = backup.delete_backup(name)
    return jsonify({"ok": ok, "error": error})


@app.route("/api/backup/<name>/rollback", methods=["POST"])
def api_backup_rollback(name):
    data = request.get_json(silent=True) or {}
    target_ip = data.get("target_ip") or None
    backup.rollback(name, target_ip)
    return jsonify({"ok": True})


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


@app.route("/api/query-log/search")
def api_query_log_search():
    domain = request.args.get("domain", "")
    client = request.args.get("client", "")
    return jsonify(query_log.search(domain, client))


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
    if source not in nodes.get_ips() or target not in nodes.get_ips():
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
    if ip not in nodes.get_ips():
        return jsonify({"ok": False, "error": "Not a configured Pi-hole node"}), 400
    monitor.reboot(ip)
    return jsonify({"ok": True})


@app.route("/api/monitor/<path:ip>/diag", methods=["POST"])
def api_monitor_diag(ip):
    ok, msg = monitor.run_diagnostics(ip)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/monitor/diagnostics")
def api_monitor_diagnostics_list():
    return jsonify({"reports": monitor.list_diagnostics()})


@app.route("/api/monitor/diagnostics/<path:name>")
def api_monitor_diagnostics_get(name):
    content = monitor.get_diagnostics_report(name)
    if content is None:
        return jsonify({"ok": False, "error": "Not found"}), 404
    return Response(content, mimetype="text/plain")


@app.route("/api/monitor/failover", methods=["POST"])
def api_monitor_failover():
    ok, msg = monitor.trigger_failover()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/monitor/clear", methods=["POST"])
def api_monitor_clear():
    monitor.clear_history()
    return jsonify({"ok": True})


# --- Per-node maintenance mode ---

@app.route("/api/maintenance")
def api_maintenance_state():
    return jsonify({"nodes": maintenance.get_state()})


@app.route("/api/maintenance/<path:ip>", methods=["POST"])
def api_maintenance_set(ip):
    data = request.get_json(silent=True) or {}
    try:
        minutes = int(data.get("minutes", 60))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "minutes must be a number"}), 400
    return jsonify(maintenance.set_maintenance(ip, minutes))


@app.route("/api/maintenance/<path:ip>", methods=["DELETE"])
def api_maintenance_clear(ip):
    maintenance.clear_maintenance(ip)
    return jsonify({"ok": True})


# --- Cross-service: DHCP config/leases + ip/mac->hostname lookup, for other
# apps (e.g. Network-Health) that need Pi-hole DHCP awareness without
# importing this app's internals directly ---

@app.route("/api/known-hosts")
def api_known_hosts():
    leases = primary_dhcp.get_leases()
    hosts_by_ip = {}
    for v in store.list_vlans():
        static_hosts = primary_dhcp.get_reservations() if v.get("is_primary") else v["hosts"]
        merged = store.merge_dynamic_hosts(v, static_hosts, leases)
        for h in merged:
            if h.get("ip"):
                hosts_by_ip[h["ip"]] = {"ip": h["ip"], "mac": h.get("mac", ""), "hostname": h.get("hostname", "")}
    return jsonify({
        "updated": datetime.utcnow().isoformat(),
        "pihole_ips": nodes.get_ips(),
        "vip": monitor.PIHOLE_VIP,
        "source": "fleet-manager",
        "config": primary_dhcp.get_config(),
        "leases": leases,
        "hosts": list(hosts_by_ip.values()),
    })


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

@app.route("/api/nodes")
def api_nodes_list():
    return jsonify({"ips": nodes.get_ips()})


@app.route("/api/nodes", methods=["POST"])
def api_nodes_add():
    data = request.get_json(silent=True) or {}
    ips, error = nodes.add_ip(data.get("ip", ""))
    if error:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True, "ips": ips})


@app.route("/api/nodes/<path:ip>", methods=["DELETE"])
def api_nodes_remove(ip):
    ips, error = nodes.remove_ip(ip)
    if error:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True, "ips": ips})


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


# --- Getting Started wizard ---

@app.route("/api/wizard/status")
def api_wizard_status():
    status = wizard.get_status()
    status["nodes"] = nodes.get_ips()
    status["ssh_key_exists"] = setup.key_exists()
    status["failover_enabled"] = dhcp_failover.is_enabled()
    status["auth_enabled"] = auth.is_enabled()
    status["auth_password_set"] = auth.has_password()
    return jsonify(status)


@app.route("/api/wizard/env", methods=["POST"])
def api_wizard_save_env():
    data = request.get_json(silent=True) or {}
    ok, error = wizard.save_env(data)
    if not ok:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True})


@app.route("/api/wizard/credentials", methods=["POST"])
def api_wizard_save_credentials():
    # Unlike api_wizard_save_env above, these two apply immediately — see
    # workers/credentials.py — so there's no restart-required banner for them.
    data = request.get_json(silent=True) or {}
    if "ssh_user" in data:
        credentials.set_ssh_user(data["ssh_user"])
    if data.get("admin_password"):
        credentials.set_admin_password(data["admin_password"])
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
    backup.start()
    wireless_migration.start()
    app.run(host="0.0.0.0", port=PORT)
