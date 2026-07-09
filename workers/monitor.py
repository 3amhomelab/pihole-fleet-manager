#!/usr/bin/env python3
"""Pi-hole node health monitoring: three-layer checks (ping -> DNS -> API),
uptime tracking, VIP master detection/history, and auto-heal escalation for
a node that stays down — an SSH reboot, then up to MONITOR_REBOOT_RETRIES
more SSH reboot attempts spaced by MONITOR_REBOOT_AFTER_MINUTES. A node
still down after all attempts is left down and flagged in the failure log —
no further automated action.
Ported from Network-Health's standalone DNS/DHCP monitor so fleet health
lives alongside the fleet-management features instead of a separate app."""
import json
import os
import subprocess
import threading
import time
from datetime import datetime

import requests

from workers import activity_log

# --- Config ---
PIHOLE_IPS        = [ip.strip() for ip in os.environ.get("PIHOLE_IPS", "").split(",") if ip.strip()]
# VIP: monitored for health but never auto-rebooted (it's a virtual IP, not a node)
PIHOLE_VIP        = os.environ.get("PIHOLE_VIP", "").strip()
PIHOLE_PASS       = os.environ.get("PIHOLE_ADMIN_PASSWORD", "")
SSH_USER          = os.environ.get("PIHOLE_SSH_USER", "root")
SSH_KEY           = os.environ.get("PIHOLE_SSH_KEY", "/data/ssh/pihole_key")
CHECK_INTERVAL    = int(os.environ.get("MONITOR_CHECK_INTERVAL", "60"))
MONITOR_DOMAINS   = [d.strip() for d in os.environ.get("MONITOR_DOMAINS", "google.com,cloudflare.com").split(",") if d.strip()]
DNS_RETRIES       = int(os.environ.get("MONITOR_DNS_RETRIES", "3"))
REBOOT_AFTER      = int(os.environ.get("MONITOR_REBOOT_AFTER", "3"))
REBOOT_AFTER_MINS = int(os.environ.get("MONITOR_REBOOT_AFTER_MINUTES", "10"))
REBOOT_RETRIES    = int(os.environ.get("MONITOR_REBOOT_RETRIES", "2"))
UPTIME_INTERVAL   = int(os.environ.get("MONITOR_UPTIME_INTERVAL", "300"))

STATE_FILE    = os.environ.get("MONITOR_STATE_FILE", "/data/monitor_state.json")
MAX_HISTORY   = 100
MAX_FAILURE_LOG  = 50
MAX_VIP_HISTORY  = 15

_SSH_OPTS = ["-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=15", "-o", "BatchMode=yes"]


# --- Shared state ---
_lock           = threading.Lock()
_node_state     = {}   # ip -> {checks: [...], last_rebooted, uptime_secs, last_boot_ts, blocking, stats}
_check_interval = CHECK_INTERVAL

_consec_fail    = {}
_fail_since     = {}
_reboot_attempts     = {}   # ip -> number of SSH reboots attempted this outage
_last_reboot_attempt = {}   # ip -> ts of the most recent attempt
_reboot_exhausted     = set()  # ip -> all retries used, left down (logged once)

_failure_log      = []
_failure_log_lock = threading.Lock()

_pihole_lock = threading.Lock()
_pihole_sid  = {}

_vip_master      = ""
_vip_master_lock = threading.Lock()
_vip_history     = []
_vip_hist_lock   = threading.Lock()


# --- Low-level helpers ---

def _now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _ssh_cmd(ip, cmd, timeout=30):
    return subprocess.run(["ssh", *_SSH_OPTS, f"{SSH_USER}@{ip}", cmd],
                           capture_output=True, text=True, timeout=timeout)


def _ssh(ip, cmd):
    try:
        _ssh_cmd(ip, cmd, timeout=30)
    except Exception as e:
        print(f"[monitor] SSH {ip} failed: {e}")


def _get_uptime(ip) -> dict:
    """Read /proc/uptime via SSH. Returns {uptime_secs, last_boot_ts} or {}."""
    try:
        r = _ssh_cmd(ip, "cat /proc/uptime", timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            secs = float(r.stdout.split()[0])
            return {"uptime_secs": int(secs), "last_boot_ts": int(time.time() - secs)}
    except Exception:
        pass
    return {}


def _node_label(ip: str) -> str:
    try:
        return f"pihole{PIHOLE_IPS.index(ip) + 1}"
    except ValueError:
        return ip


def _ping(ip) -> bool:
    try:
        r = subprocess.run(["ping", "-c", "3", "-W", "1", ip], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _dig(ip, domain) -> tuple:
    """DNS lookup for one domain. Returns (ok: bool, ms: int)."""
    start = time.monotonic()
    try:
        r = subprocess.run(
            ["dig", f"@{ip}", domain, "+time=3", "+tries=1", "+short"],
            capture_output=True, timeout=6,
        )
        ms = max(0, int((time.monotonic() - start) * 1000))
        return r.returncode == 0 and bool(r.stdout.strip()), ms
    except Exception:
        return False, 0


def _api_health(ip) -> bool:
    """Pi-hole v6 API check — GET /api/auth returns 401 when up but not authenticated."""
    try:
        r = requests.get(f"http://{ip}/api/auth", timeout=5)
        return r.status_code in (200, 401)
    except Exception:
        return False


def _check_node(ip) -> dict:
    """Three-layer health check: ping -> DNS (all MONITOR_DOMAINS, retried) -> Pi-hole API."""
    if not _ping(ip):
        return {"ok": False, "ms": 0, "reason": "ping_failed"}

    results = []
    dns_ok  = False
    for attempt in range(DNS_RETRIES):
        results = [_dig(ip, d) for d in MONITOR_DOMAINS]
        if any(ok for ok, _ in results):
            dns_ok = True
            break
        if attempt < DNS_RETRIES - 1:
            time.sleep(1)

    avg_ms = int(sum(ms for _, ms in results) / len(results)) if results else 0

    if not dns_ok:
        return {"ok": False, "ms": avg_ms, "reason": "dns_failed"}
    if not _api_health(ip):
        return {"ok": False, "ms": avg_ms, "reason": "api_failed"}
    return {"ok": True, "ms": avg_ms, "reason": "healthy"}


def _quorum_ok(failing_ip: str) -> bool:
    """True if at least 2 OTHER physical Pi-holes (not VIP) are healthy — guards
    against auto-rebooting/restarting a node when the cluster itself may be
    the thing that's actually unhealthy."""
    healthy = 0
    with _lock:
        for ip in PIHOLE_IPS:
            if ip == failing_ip or ip == PIHOLE_VIP:
                continue
            checks = _node_state.get(ip, {}).get("checks", [])
            if checks and checks[-1].get("ok"):
                healthy += 1
    return healthy >= 2


def _fetch_node_stats(ip) -> dict:
    """Blocking status + query stats from Pi-hole v6 API (authenticated)."""
    result = {}
    blocking = _api_get(ip, "/dns/blocking")
    if blocking is not None:
        result["blocking"] = blocking.get("blocking") == "enabled"
    summary = _api_get(ip, "/stats/summary")
    if summary is not None:
        q = summary.get("queries", {})
        result["stats"] = {
            "total":   q.get("total", 0),
            "blocked": q.get("blocked", 0),
            "percent": round(q.get("percent_blocked", 0.0), 1),
        }
    return result


# --- Persistence ---

def _load():
    last_master = ""
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
        with _lock:
            _node_state.update(data.get("piholes", {}))
        hist = data.get("vip_history", [])[-MAX_VIP_HISTORY:]
        with _vip_hist_lock:
            _vip_history.extend(hist)
        if hist:
            last_master = hist[-1].get("to", "")
        with _failure_log_lock:
            _failure_log.extend(data.get("failure_log", [])[-MAX_FAILURE_LOG:])
    except Exception:
        pass
    if last_master:
        global _vip_master
        with _vip_master_lock:
            _vip_master = last_master


def _save():
    with _lock:
        data = {
            "updated":        _now_iso(),
            "check_interval": _check_interval,
            "piholes":        dict(_node_state),
        }
    with _vip_hist_lock:
        data["vip_history"] = list(_vip_history)
    with _failure_log_lock:
        data["failure_log"] = list(_failure_log)
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        print(f"[monitor] save failed: {e}")


# --- Health monitor loop ---

def _monitor_loop():
    _load()
    _monitor_ips = PIHOLE_IPS + ([PIHOLE_VIP] if PIHOLE_VIP and PIHOLE_VIP not in PIHOLE_IPS else [])
    print(f"[monitor] Watching: {_monitor_ips}  domains={MONITOR_DOMAINS}")
    print(f"[monitor] VIP (monitor-only): {PIHOLE_VIP or 'none'}")
    print(f"[monitor] SSH reboot: after {REBOOT_AFTER} consecutive failures, up to {REBOOT_RETRIES} retries spaced {REBOOT_AFTER_MINS}m apart")

    while True:
        ts = int(time.time())

        for ip in _monitor_ips:
            result = _check_node(ip)
            ok, ms, reason = result["ok"], result["ms"], result["reason"]

            with _lock:
                if ip not in _node_state:
                    _node_state[ip] = {"checks": [], "last_rebooted": None}
                checks = _node_state[ip]["checks"]
                checks.append({"ts": ts, "ok": ok, "ms": ms, "reason": reason})
                if len(checks) > MAX_HISTORY:
                    _node_state[ip]["checks"] = checks[-MAX_HISTORY:]

            if ok:
                node_stats = _fetch_node_stats(ip)
                with _lock:
                    if "blocking" in node_stats:
                        _node_state[ip]["blocking"] = node_stats["blocking"]
                    if "stats" in node_stats:
                        _node_state[ip]["stats"] = node_stats["stats"]

            if ok:
                if ip in _fail_since:
                    print(f"[monitor] {ip} recovered")
                    activity_log.log("monitor", f"{_node_label(ip)} recovered")
                _fail_since.pop(ip, None)
                _reboot_attempts.pop(ip, None)
                _last_reboot_attempt.pop(ip, None)
                _reboot_exhausted.discard(ip)
                _consec_fail[ip] = 0
            else:
                _consec_fail[ip] = _consec_fail.get(ip, 0) + 1
                with _failure_log_lock:
                    _failure_log.append({"ts": ts, "ip": ip, "name": _node_label(ip), "reason": reason})
                    if len(_failure_log) > MAX_FAILURE_LOG:
                        _failure_log[:] = _failure_log[-MAX_FAILURE_LOG:]
                if ip not in _fail_since:
                    _fail_since[ip] = ts
                    print(f"[monitor] {ip} first failure — {reason}")
                    activity_log.log("monitor", f"{_node_label(ip)} is DOWN ({reason})", level="error")

                if ip == PIHOLE_VIP:
                    continue

                attempts = _reboot_attempts.get(ip, 0)
                last_attempt_ts = _last_reboot_attempt.get(ip, 0)

                # Reboot via SSH: first attempt after REBOOT_AFTER consecutive
                # failures, then up to REBOOT_RETRIES more attempts spaced by
                # REBOOT_AFTER_MINS if the node is still down. After that,
                # leave it down and flagged — no further automated action.
                should_attempt = (
                    (attempts == 0 and _consec_fail[ip] > REBOOT_AFTER) or
                    (0 < attempts <= REBOOT_RETRIES and (ts - last_attempt_ts) >= REBOOT_AFTER_MINS * 60)
                )

                if should_attempt:
                    if not _quorum_ok(ip):
                        print(f"[monitor] {ip} — skipping reboot: fewer than 2 other nodes are healthy")
                        activity_log.log("monitor", f"{_node_label(ip)} down but reboot skipped — quorum not met", level="error")
                    else:
                        attempts += 1
                        print(f"[monitor] {ip} — SSH reboot attempt {attempts}/{1 + REBOOT_RETRIES} (consec={_consec_fail[ip]})")
                        activity_log.log("monitor", f"Rebooting {_node_label(ip)} via SSH — attempt {attempts}/{1 + REBOOT_RETRIES}")
                        _ssh(ip, "sudo reboot")
                        with _lock:
                            _node_state[ip]["last_rebooted"] = _now_iso()
                        _reboot_attempts[ip] = attempts
                        _last_reboot_attempt[ip] = ts

                        def _refresh_uptime_after_reboot(target_ip):
                            time.sleep(90)
                            up = _get_uptime(target_ip)
                            if up:
                                with _lock:
                                    _node_state[target_ip]["uptime_secs"] = up["uptime_secs"]
                                    _node_state[target_ip]["last_boot_ts"] = up["last_boot_ts"]
                        threading.Thread(target=_refresh_uptime_after_reboot, args=(ip,), daemon=True).start()

                elif attempts > REBOOT_RETRIES and ip not in _reboot_exhausted:
                    print(f"[monitor] {ip} still down after {attempts} SSH reboot attempts — leaving down, flagged")
                    activity_log.log(
                        "monitor",
                        f"{_node_label(ip)} still down after {attempts} SSH reboot attempts — leaving down, flagged for manual intervention",
                        level="error",
                    )
                    _reboot_exhausted.add(ip)

        _save()
        with _lock:
            interval = _check_interval
        time.sleep(interval)


# --- Pi-hole v6 API (session auth, used for stats + VIP master probing) ---

def _auth(ip):
    try:
        r = requests.post(f"http://{ip}/api/auth", json={"password": PIHOLE_PASS}, timeout=8)
        r.raise_for_status()
        sid = r.json().get("session", {}).get("sid", "")
        with _pihole_lock:
            _pihole_sid[ip] = sid
        return sid
    except Exception as e:
        print(f"[monitor] auth to {ip} failed: {e}")
        return ""


def _api_get(ip, path):
    for attempt in range(2):
        with _pihole_lock:
            sid = _pihole_sid.get(ip, "")
        if not sid:
            sid = _auth(ip)
        if not sid:
            return None
        try:
            r = requests.get(f"http://{ip}/api{path}", headers={"sid": sid}, timeout=10)
            if r.status_code == 401 and attempt == 0:
                with _pihole_lock:
                    _pihole_sid.pop(ip, None)
                continue
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"[monitor] GET {path} from {ip} failed: {e}")
            return None
    return None


def _set_vip_master(ip: str, method: str) -> None:
    global _vip_master
    with _vip_master_lock:
        prev = _vip_master
        _vip_master = ip
    print(f"[monitor] VIP master={ip} ({method})")
    if prev != ip:
        entry = {"ts": _now_iso(), "from": prev or None, "to": ip}
        with _vip_hist_lock:
            _vip_history.append(entry)
            if len(_vip_history) > MAX_VIP_HISTORY:
                _vip_history[:] = _vip_history[-MAX_VIP_HISTORY:]
        activity_log.log("monitor", f"VIP master changed: {prev or '(none)'} -> {ip}")
        _save()


def _detect_vip_master():
    """Stage 1: SSH — which node has the VIP on its interface.
    Stage 2: Pi-hole API session test — FTL sessions are in-process memory, so
    a session token issued by the VIP only authenticates against the node
    that actually issued it."""
    if not PIHOLE_VIP or not PIHOLE_IPS:
        return

    for ip in PIHOLE_IPS:
        if ip == PIHOLE_VIP:
            continue
        try:
            r = _ssh_cmd(ip, f"ip addr show | grep {PIHOLE_VIP}", timeout=8)
            if r.returncode == 0 and PIHOLE_VIP in r.stdout:
                _set_vip_master(ip, "SSH/interface")
                return
        except Exception:
            pass

    if not PIHOLE_PASS:
        return
    try:
        r = requests.post(f"http://{PIHOLE_VIP}/api/auth", json={"password": PIHOLE_PASS}, timeout=8)
        r.raise_for_status()
        vip_sid = r.json().get("session", {}).get("sid", "")
        if not vip_sid:
            return
        for ip in PIHOLE_IPS:
            if ip == PIHOLE_VIP:
                continue
            try:
                probe = requests.get(f"http://{ip}/api/dns/blocking", headers={"sid": vip_sid}, timeout=5)
                if probe.status_code == 200:
                    _set_vip_master(ip, "API/session")
                    break
            except Exception:
                pass
        try:
            requests.delete(f"http://{PIHOLE_VIP}/api/auth", headers={"sid": vip_sid}, timeout=5)
        except Exception:
            pass
    except Exception as e:
        print(f"[monitor] VIP session detection failed: {e}")


def _failover_vip():
    """Trigger a keepalived failover by restarting keepalived on the current
    master — the backup node takes over within a few seconds."""
    with _vip_master_lock:
        master = _vip_master
    if not master:
        return False, "Current master not detected"
    try:
        result = subprocess.run(
            ["ssh", *_SSH_OPTS, f"{SSH_USER}@{master}", "sudo systemctl restart keepalived"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            def _redetect():
                for _ in range(10):
                    time.sleep(3)
                    _detect_vip_master()
                    with _vip_master_lock:
                        new = _vip_master
                    if new and new != master:
                        print(f"[monitor] VIP master changed to {new}")
                        return
                print("[monitor] VIP master re-detection timed out after failover")
            threading.Thread(target=_redetect, daemon=True).start()
            activity_log.log("monitor", f"Manual VIP failover triggered from {_node_label(master)}")
            return True, f"Keepalived restarted on {master} — backup will take over"
        return False, f"SSH failed on {master}: {result.stderr.strip()[:100]}"
    except Exception as e:
        return False, str(e)[:100]


# --- Uptime / VIP-detection loop ---

def _uptime_loop():
    while True:
        for ip in PIHOLE_IPS:
            if ip == PIHOLE_VIP:
                continue
            uptime = _get_uptime(ip)
            if uptime:
                with _lock:
                    if ip not in _node_state:
                        _node_state[ip] = {"checks": [], "last_rebooted": None}
                    _node_state[ip]["uptime_secs"] = uptime["uptime_secs"]
                    _node_state[ip]["last_boot_ts"] = uptime["last_boot_ts"]
        if PIHOLE_VIP:
            _detect_vip_master()
        time.sleep(UPTIME_INTERVAL)


# --- Public API ---

def start():
    threading.Thread(target=_monitor_loop, daemon=True, name="monitor-health").start()
    threading.Thread(target=_uptime_loop,  daemon=True, name="monitor-uptime").start()
    threading.Thread(target=_detect_vip_master, daemon=True, name="monitor-vip-detect").start()


def get_state():
    with _lock:
        piholes = {k: dict(v) for k, v in _node_state.items()}
        return {
            "updated":        _now_iso(),
            "check_interval": _check_interval,
            "piholes":        piholes,
            "vip":            PIHOLE_VIP,
            "vip_master":     get_vip_master(),
            "vip_history":    get_vip_history(),
            "failure_log":    get_failure_log(),
        }


def set_interval(seconds):
    global _check_interval
    with _lock:
        _check_interval = max(10, int(seconds))


def reboot(pihole_ip):
    if pihole_ip not in PIHOLE_IPS:
        print(f"[monitor] Refusing reboot — {pihole_ip} is not a configured Pi-hole node")
        return

    def _safe_reboot(ip):
        with _vip_master_lock:
            is_master = (_vip_master == ip)
        if is_master and PIHOLE_VIP:
            print(f"[monitor] {ip} is VIP master — failing over before reboot")
            _ssh_cmd(ip, "sudo systemctl restart keepalived", timeout=10)
            for _ in range(5):
                time.sleep(3)
                _detect_vip_master()
                with _vip_master_lock:
                    new_master = _vip_master
                if new_master and new_master != ip:
                    print(f"[monitor] VIP transferred to {new_master} — rebooting {ip}")
                    break
            else:
                print(f"[monitor] VIP transfer uncertain — rebooting {ip} anyway")
        activity_log.log("monitor", f"Manual reboot triggered for {_node_label(ip)}")
        _ssh(ip, "sudo reboot")

    threading.Thread(target=_safe_reboot, args=(pihole_ip,), daemon=True).start()


def get_vip_master() -> str:
    with _vip_master_lock:
        return _vip_master


def get_vip_history() -> list:
    with _vip_hist_lock:
        return list(_vip_history)


def get_failure_log() -> list:
    with _failure_log_lock:
        return list(_failure_log)


def trigger_failover() -> tuple:
    return _failover_vip()


DIAG_DIR      = os.environ.get("MONITOR_DIAG_DIR", "/data/diagnostics")
MAX_DIAG_REPORTS = 50


def run_diagnostics(ip: str) -> tuple:
    """Run collect-diag.sh on a node (expects the same keepalived diagnostics
    script used by the original Network-Health monitor), then pull the
    generated report back over SSH and save it into fleet-manager's own
    /data volume — the report otherwise only ever exists on that one node."""
    if ip == PIHOLE_VIP or ip not in PIHOLE_IPS:
        return False, "Invalid target"
    try:
        r = _ssh_cmd(ip, "sudo /etc/keepalived/collect-diag.sh manual", timeout=60)
        output = (r.stdout + r.stderr).strip()
        if r.returncode != 0:
            return False, output[-150:] or f"exit {r.returncode}"

        last_line = output.splitlines()[-1] if output else ""
        remote_path = last_line.removeprefix("Diagnostics written to ").strip()
        if not remote_path:
            return False, "Ran, but couldn't determine the remote report path"

        cat_r = _ssh_cmd(ip, f"sudo cat {remote_path}", timeout=15)
        if cat_r.returncode != 0:
            return False, f"Ran, but couldn't fetch the report: {cat_r.stderr.strip()[:100]}"

        os.makedirs(DIAG_DIR, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        local_name = f"{_node_label(ip)}-{ts}.log"
        tmp = os.path.join(DIAG_DIR, local_name + ".tmp")
        with open(tmp, "w") as f:
            f.write(cat_r.stdout)
        os.replace(tmp, os.path.join(DIAG_DIR, local_name))

        for old in sorted(os.listdir(DIAG_DIR))[:-MAX_DIAG_REPORTS]:
            try:
                os.remove(os.path.join(DIAG_DIR, old))
            except OSError:
                pass

        activity_log.log("monitor", f"Diagnostics saved for {_node_label(ip)}: {local_name}")
        return True, f"Saved as {local_name}"
    except subprocess.TimeoutExpired:
        return False, "Timed out"
    except Exception as e:
        return False, str(e)[:150]


def list_diagnostics() -> list:
    """Saved diagnostic reports, newest first."""
    try:
        reports = []
        for name in os.listdir(DIAG_DIR):
            path = os.path.join(DIAG_DIR, name)
            reports.append({
                "name": name,
                "size": os.path.getsize(path),
                "mtime": os.path.getmtime(path),
            })
        reports.sort(key=lambda r: r["mtime"], reverse=True)
        return reports
    except FileNotFoundError:
        return []


def get_diagnostics_report(name: str):
    """Read a saved report's content by filename. Strips any path components
    so this can't be used to read arbitrary files outside DIAG_DIR."""
    safe_name = os.path.basename(name)
    path = os.path.join(DIAG_DIR, safe_name)
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return f.read()


def clear_history():
    """Reset all health-check history, VIP master history, and failure log."""
    with _lock:
        for ip in _node_state:
            _node_state[ip]["checks"] = []
    with _vip_hist_lock:
        _vip_history.clear()
    with _failure_log_lock:
        _failure_log.clear()
    _save()
