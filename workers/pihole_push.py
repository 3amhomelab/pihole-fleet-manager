#!/usr/bin/env python3
"""Renders VLAN scopes as a dnsmasq.d config snippet and pushes it to every
Pi-hole node over SSH, flipping misc.etc_dnsmasq_d via Pi-hole's own v6 API
so the snippet actually gets picked up, then reloading dnsmasq."""
import ipaddress
import os
import re
import subprocess
import threading
import time
from collections import deque
from datetime import datetime

from workers import activity_log, credentials, hostnames, nodes, pihole_api, primary_dhcp, store, validate

# --- Config ---
SSH_KEY      = os.environ.get("PIHOLE_SSH_KEY", "/root/.ssh/pihole_key")
CONF_NAME    = os.environ.get("DNSMASQ_CONF_NAME", "10-vlans.conf")
CONF_PATH    = f"/etc/dnsmasq.d/{CONF_NAME}"
MANAGED_TAG  = "# managed by Pihole Fleet Manager — do not edit by hand"
REBOOT_TIMEOUT_SECS = int(os.environ.get("PIHOLE_REBOOT_TIMEOUT_SECS", "180"))

_SSH_OPTS = ["-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=15", "-o", "BatchMode=yes"]

_status_lock = threading.Lock()
_status = {"status": "idle", "message": "", "timestamp": None, "log": []}
_event  = threading.Event()


def _enable_etc_dnsmasq_d(ip) -> bool:
    result = pihole_api.api_patch(ip, "/config", {"config": {"misc": {"etc_dnsmasq_d": True}}})
    return result is not None


def _vlan_hosts_with_dynamic(vlans: list, leases: list) -> dict:
    """{vlan_id: [static + dynamic hosts]} for every non-primary VLAN — used
    so group assignment (see _sync_vlan_groups) covers a device the moment it
    picks up a lease, not only once it gets a static reservation."""
    return {
        v["id"]: store.merge_dynamic_hosts(v, v["hosts"], leases)
        for v in vlans if not v.get("is_primary")
    }


def _sync_vlan_groups(ip: str, vlans: list, hosts_by_vlan: dict) -> list:
    """Assigns every host in a VLAN that has a `group_name` set to that Pi-hole
    group on this node, via /api/clients. Group names are resolved to this
    node's own (locally auto-assigned, so not necessarily the same numeric id
    on every node) group id — a VLAN whose group doesn't exist yet on this
    node is skipped with a warning rather than failing the whole push; groups
    themselves are reconciled fleet-wide separately, by replication.py."""
    managed = [v for v in vlans if not v.get("is_primary") and v.get("group_name")]
    if not managed:
        return []

    groups_resp = pihole_api.api_get(ip, "/groups")
    if groups_resp is None:
        return [f"{ip}: could not read groups to assign VLAN clients"]
    name_to_id = {g["name"]: g["id"] for g in groups_resp.get("groups", [])}

    warnings = []
    for v in managed:
        gid = name_to_id.get(v["group_name"])
        if gid is None:
            warnings.append(f"{ip}: group '{v['group_name']}' (VLAN '{v['name']}') doesn't exist on this node yet")
            continue
        for h in hosts_by_vlan.get(v["id"], []):
            mac = h.get("mac")
            if not mac:
                continue
            if pihole_api.api_post(ip, "/clients", {"client": mac, "groups": [gid]}) is None:
                warnings.append(f"{ip}: failed to assign {mac} to group '{v['group_name']}'")
    return warnings


def _sync_hostnames(ip, vlans) -> tuple:
    """Read this node's current dns.hosts, merge in the VLAN-derived entries,
    and push back only if something actually changed."""
    current = pihole_api.api_get(ip, "/config/dns/hosts")
    if current is None:
        return False, "could not read current dns.hosts"
    existing = current.get("config", {}).get("dns", {}).get("hosts", [])
    merged = hostnames.merge(existing, vlans)
    if sorted(merged) == sorted(existing):
        return True, None
    result = pihole_api.api_patch(ip, "/config", {"config": {"dns": {"hosts": merged}}})
    return result is not None, None if result is not None else "could not write dns.hosts"


# --- Render dnsmasq.d snippet from all defined VLANs ---

def render_conf(vlans: list) -> str:
    lines = [MANAGED_TAG, ""]
    for v in vlans:
        if v.get("is_primary"):
            continue  # Pi-hole already natively serves this scope — no snippet needed
        netmask = store.netmask_of(v)
        tag = v["id"]
        lines.append(f"# --- {v['name']} (subnet {v['subnet']}/{v['prefix']}) ---")
        lines.append(f"dhcp-range=set:{tag},{v['range_start']},{v['range_end']},{netmask},{v['lease_time']}")
        lines.append(f"dhcp-option=tag:{tag},3,{v['gateway']}")
        if v.get("cf_domain"):
            # Pi-hole's own Settings UI only supports one conditional-forwarding
            # domain/subnet — this lets every extra VLAN get its own, which the
            # GUI has no way to express.
            lines.append(f"server=/{v['cf_domain']}/{v['gateway']}")
            lines.append(f"rev-server={v['subnet']}/{v['prefix']},{v['gateway']}")
        sorted_hosts = sorted(v["hosts"], key=lambda h: ipaddress.ip_address(h["ip"]), reverse=True)
        for h in sorted_hosts:
            name_part = f",{h['hostname']}" if h.get("hostname") else ""
            lines.append(f"dhcp-host={h['mac']},{h['ip']}{name_part}")
        lines.append("")
    return "\n".join(lines)


# --- Import: read a node's already-deployed config back (the inverse of render_conf) ---
# Covers scopes that exist on a node but not in this instance's local store —
# e.g. pushed by an older/different instance pointed at the same nodes.

_BLOCK_RE  = re.compile(r"^#\s*---\s*(?P<name>.+?)\s*\(subnet\s+(?P<subnet>[\d.]+)/(?P<prefix>\d+)\)\s*---\s*$")
_RANGE_RE  = re.compile(r"^dhcp-range=set:(?P<tag>[^,]+),(?P<start>[^,]+),(?P<end>[^,]+),(?P<netmask>[^,]+),(?P<lease>[^,]+)$")
_OPTION_RE = re.compile(r"^dhcp-option=tag:(?P<tag>[^,]+),3,(?P<gateway>[^,]+)$")
_HOST_RE   = re.compile(r"^dhcp-host=(?P<mac>[0-9A-Fa-f:]+),(?P<ip>[\d.]+)(?:,(?P<hostname>.+))?$")
_SERVER_RE = re.compile(r"^server=/(?P<domain>[^/]+)/(?P<gateway>[\d.]+)$")


def fetch_remote_conf(ip: str) -> tuple:
    """Read-only — cats back whatever's currently at CONF_PATH on a node."""
    try:
        proc = subprocess.run(
            ["ssh", *_SSH_OPTS, f"{credentials.get_ssh_user()}@{ip}", f"cat {CONF_PATH} 2>/dev/null"],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            return None, proc.stderr.strip() or "ssh read failed"
        return proc.stdout, None
    except Exception as e:
        return None, str(e)


def parse_conf(content: str) -> list:
    """Reconstructs VLAN dicts from a rendered dnsmasq.d file. vlan_tag (the
    informational 802.1q number) isn't part of the rendered file, so it
    always comes back None — only the dnsmasq-relevant fields round-trip."""
    vlans, current = [], None
    for raw in (content or "").splitlines():
        line = raw.strip()
        m = _BLOCK_RE.match(line)
        if m:
            if current and current["id"]:
                vlans.append(current)
            current = {
                "id": None, "name": m.group("name"), "vlan_tag": None,
                "subnet": m.group("subnet"), "prefix": int(m.group("prefix")),
                "gateway": "", "range_start": "", "range_end": "", "lease_time": "",
                "cf_domain": "", "hosts": [],
            }
            continue
        if current is None:
            continue
        m = _RANGE_RE.match(line)
        if m:
            current.update(id=m.group("tag"), range_start=m.group("start"),
                            range_end=m.group("end"), lease_time=m.group("lease"))
            continue
        m = _OPTION_RE.match(line)
        if m:
            current["gateway"] = m.group("gateway")
            continue
        m = _SERVER_RE.match(line)
        if m:
            current["cf_domain"] = m.group("domain")
            continue
        m = _HOST_RE.match(line)
        if m:
            current["hosts"].append({"mac": m.group("mac").upper(), "ip": m.group("ip"),
                                      "hostname": m.group("hostname") or ""})
    if current and current["id"]:
        vlans.append(current)
    return vlans


# --- SSH push ---

def _ssh_write_file(ip: str, content: str) -> tuple:
    # `sudo tee` (rather than a plain redirect) so this works whether SSH_USER
    # is root or a non-root account with sudo access — sudo is a no-op for root.
    try:
        proc = subprocess.run(
            ["ssh", *_SSH_OPTS, f"{credentials.get_ssh_user()}@{ip}",
             f"sudo tee {CONF_PATH} > /dev/null && sudo chmod 644 {CONF_PATH}"],
            input=content, capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0:
            return False, proc.stderr.strip() or "ssh write failed"
        return True, None
    except Exception as e:
        return False, str(e)


def _ssh_reload_dns(ip: str) -> tuple:
    """Reloads DNS by rebooting the node outright (rather than a targeted
    service restart) — the reboot itself drops the SSH session before it can
    return cleanly, so that's expected, not a failure. Waits for the node to
    come back up before returning, since this push's later per-node steps
    (hostname sync, group assignment) need it reachable again."""
    user = credentials.get_ssh_user()
    try:
        subprocess.run(
            ["ssh", *_SSH_OPTS, f"{user}@{ip}", "sudo reboot"],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        return False, f"failed to trigger reboot: {e}"

    time.sleep(5)  # let it actually go down before polling, so an early poll doesn't just catch the pre-reboot host

    deadline = time.monotonic() + REBOOT_TIMEOUT_SECS
    while time.monotonic() < deadline:
        try:
            proc = subprocess.run(
                ["ssh", *_SSH_OPTS, "-o", "ConnectTimeout=5", f"{user}@{ip}", "true"],
                capture_output=True, text=True, timeout=8,
            )
            if proc.returncode == 0:
                return True, None
        except Exception:
            pass
        time.sleep(5)

    return False, f"node did not come back up within {REBOOT_TIMEOUT_SECS}s of reboot"


# --- Public: trigger + status (mirrors Network-Health's sync pattern) ---

def _set_status(status, message, log):
    with _status_lock:
        _status["status"], _status["message"] = status, message
        _status["timestamp"] = datetime.now().isoformat()
        _status["log"] = list(log)


def get_status() -> dict:
    with _status_lock:
        return dict(_status)


def trigger_push():
    _event.set()


def _push_loop():
    while True:
        _event.wait()
        _event.clear()

        ips = nodes.get_ips()
        if not ips:
            _set_status("error", "No PIHOLE_IPS configured", [])
            continue

        log = deque(maxlen=200)

        def step(msg):
            log.append(msg)
            _set_status("running", msg, log)

        try:
            vlans = store.list_vlans()

            step("Validating VLAN scopes before push")
            errors = validate.validate_vlans(vlans)
            if errors:
                _set_status("error", "Push blocked: " + "; ".join(errors), log)
                activity_log.log("push", f"VLAN config push blocked by validation: {'; '.join(errors)}", level="error")
                continue

            step(f"Rendering config for {len(vlans)} VLAN(s)")
            content = render_conf(vlans)

            leases = primary_dhcp.get_leases()
            hosts_by_vlan = _vlan_hosts_with_dynamic(vlans, leases)

            failed = []
            for ip in ips:
                step(f"Writing {CONF_PATH} to {ip}")
                ok, err = _ssh_write_file(ip, content)
                if not ok:
                    failed.append(f"{ip}: {err}")
                    continue

                step(f"Enabling misc.etc_dnsmasq_d on {ip}")
                if not _enable_etc_dnsmasq_d(ip):
                    failed.append(f"{ip}: could not set etc_dnsmasq_d via API")
                    continue

                step(f"Reloading dnsmasq on {ip}")
                ok, err = _ssh_reload_dns(ip)
                if not ok:
                    failed.append(f"{ip}: {err}")
                    continue

                step(f"Syncing hostname DNS records on {ip}")
                ok, err = _sync_hostnames(ip, vlans)
                if not ok:
                    failed.append(f"{ip}: {err}")
                    continue

                step(f"Syncing per-VLAN group assignments on {ip}")
                warnings = _sync_vlan_groups(ip, vlans, hosts_by_vlan)
                if warnings:
                    for w in warnings:
                        step(w)
                    activity_log.log("push", f"Group assignment warning(s) on {ip}: {'; '.join(warnings)}", level="warning")

            if failed:
                _set_status("error", "Push failed: " + "; ".join(failed), log)
                activity_log.log("push", f"VLAN config push failed: {'; '.join(failed)}", level="error")
            else:
                step("Push complete — all nodes updated")
                _set_status("success", f"Pushed to {', '.join(ips)}", log)
                activity_log.log("push", f"VLAN config pushed to {', '.join(ips)}")
        except Exception as e:
            _set_status("error", str(e), list(log))
            activity_log.log("push", f"VLAN config push error: {e}", level="error")


def start():
    threading.Thread(target=_push_loop, daemon=True, name="pihole-push").start()
