#!/usr/bin/env python3
"""One-time (or repeatable) SSH trust bootstrap: generate or reuse a keypair,
distribute the public half to every configured Pi-hole node via password auth,
and verify key-based auth works — so Pihole Fleet Manager can push config
without any pre-existing key already sitting on the target host.

PIHOLE_SSH_USER need not be root: on nodes where root only allows pubkey
login (so there's no root password to distribute a key with in the first
place), point this at a non-root account that has passwordless sudo —
verification checks both SSH key auth and `sudo -n` for that account."""
import base64
import os
import subprocess
import threading
from datetime import datetime

from workers import activity_log, host_env, nodes

SSH_USER    = os.environ.get("PIHOLE_SSH_USER", "root")
KEY_PATH    = os.environ.get("PIHOLE_SSH_KEY", "/data/ssh/pihole_key")

_SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]

_status_lock = threading.Lock()
_status = {"status": "idle", "message": "", "timestamp": None, "log": [], "key_b64": None}
_event  = threading.Event()
_pending_args = {}


def key_exists() -> bool:
    return os.path.exists(KEY_PATH)


def get_key_b64() -> str | None:
    """Durable — reads the current key straight off disk, unlike the
    ephemeral job status's key_b64 (only populated in memory right after a
    run). Lets deploy.sh pull the live key forward into the local .env on
    every deploy, so it isn't only ever living in the /data volume."""
    if not key_exists():
        return None
    try:
        with open(KEY_PATH, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception:
        return None


def get_public_key() -> str | None:
    """Derive the public key from the private key file (works even without a .pub sidecar)."""
    if not key_exists():
        return None
    try:
        proc = subprocess.run(["ssh-keygen", "-y", "-f", KEY_PATH], capture_output=True, text=True, timeout=10)
        return proc.stdout.strip() if proc.returncode == 0 else None
    except Exception:
        return None


def test_key_auth(ip: str) -> bool:
    """Verifies key-based SSH login AND that sudo works without a password
    prompt — both must hold for a non-root SSH_USER to actually be usable
    for the privileged commands (writing dnsmasq.d, restartdns, pihole -up)."""
    if not key_exists():
        return False
    try:
        proc = subprocess.run(
            ["ssh", "-i", KEY_PATH, *_SSH_OPTS, "-o", "BatchMode=yes",
             f"{SSH_USER}@{ip}", "sudo -n true && echo ok"],
            capture_output=True, text=True, timeout=15,
        )
        return proc.returncode == 0 and "ok" in proc.stdout
    except Exception:
        return False


def get_node_status() -> list:
    return [{"ip": ip, "key_auth_ok": test_key_auth(ip)} for ip in nodes.get_ips()]


def _generate_keypair():
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    for path in (KEY_PATH, KEY_PATH + ".pub"):
        if os.path.exists(path):
            os.remove(path)
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", KEY_PATH, "-C", "pihole-fleet-manager"],
        capture_output=True, text=True, timeout=15, check=True,
    )
    os.chmod(KEY_PATH, 0o600)


def _write_key_to_host_env(key_b64: str) -> None:
    """Best-effort: if this stack's own .env is bind-mounted in (see
    docker-compose.yml's ./.env:/config/host.env), update PIHOLE_SSH_KEY_B64
    there directly right when Setup succeeds — instant, and works for any
    stack this compose file happens to be running as, not just one deploy.sh
    knows about. Silently no-ops if the mount isn't present."""
    host_env.write_vars({"PIHOLE_SSH_KEY_B64": key_b64})


def _distribute_key(ip: str, password: str, pubkey: str) -> tuple:
    remote_cmd = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "
        "KEY=$(cat) && grep -qF \"$KEY\" ~/.ssh/authorized_keys || echo \"$KEY\" >> ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys"
    )
    try:
        proc = subprocess.run(
            ["sshpass", "-p", password, "ssh", *_SSH_OPTS,
             "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
             f"{SSH_USER}@{ip}", remote_cmd],
            input=pubkey, capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0:
            return False, proc.stderr.strip() or "ssh (password auth) failed"
        return True, None
    except Exception as e:
        return False, str(e)


# --- Public: trigger + status (mirrors the push-status pattern) ---

def _set_status(status, message, log, key_b64=None):
    with _status_lock:
        _status["status"], _status["message"] = status, message
        _status["timestamp"] = datetime.now().isoformat()
        _status["log"] = list(log)
        if key_b64 is not None:
            _status["key_b64"] = key_b64


def get_status() -> dict:
    with _status_lock:
        return dict(_status)


def trigger_setup(password: str, regenerate: bool):
    _pending_args["password"] = password
    _pending_args["regenerate"] = regenerate
    _event.set()


def _setup_loop():
    while True:
        _event.wait()
        _event.clear()
        password  = _pending_args.get("password", "")
        regenerate = _pending_args.get("regenerate", False)

        ips = nodes.get_ips()
        if not ips:
            _set_status("error", "No PIHOLE_IPS configured", [])
            continue
        if not password:
            _set_status("error", "Password required", [])
            continue

        log = []

        def step(msg):
            log.append(msg)
            _set_status("running", msg, log)

        try:
            if regenerate or not key_exists():
                step("Generating new ed25519 keypair" if regenerate else "No key found — generating one")
                _generate_keypair()

            pubkey = get_public_key()
            if not pubkey:
                _set_status("error", "Could not read generated public key", log)
                continue

            failed = []
            for ip in ips:
                step(f"Distributing public key to {ip}")
                ok, err = _distribute_key(ip, password, pubkey)
                if not ok:
                    failed.append(f"{ip}: {err}")
                    continue
                step(f"Verifying key-based auth to {ip}")
                if not test_key_auth(ip):
                    failed.append(f"{ip}: key distributed but auth still failing")

            if failed:
                _set_status("error", "Setup failed: " + "; ".join(failed), log)
                activity_log.log("setup", f"SSH trust setup failed: {'; '.join(failed)}", level="error")
            else:
                step("All nodes trust the key — setup complete")
                with open(KEY_PATH, "rb") as f:
                    key_b64 = base64.b64encode(f.read()).decode()
                _write_key_to_host_env(key_b64)
                _set_status("success", f"Key trusted by {', '.join(ips)}", log, key_b64=key_b64)
                activity_log.log("setup", f"SSH trust established with {', '.join(ips)}")
        except subprocess.CalledProcessError as e:
            _set_status("error", f"ssh-keygen failed: {e}", log)
            activity_log.log("setup", f"SSH trust setup error: {e}", level="error")
        except Exception as e:
            _set_status("error", str(e), log)
            activity_log.log("setup", f"SSH trust setup error: {e}", level="error")


def start():
    threading.Thread(target=_setup_loop, daemon=True, name="pihole-setup").start()
