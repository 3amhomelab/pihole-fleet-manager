#!/usr/bin/env python3
"""Getting Started wizard: one guided page covering the whole first-run
setup, instead of hand-editing a long .env before the app is usable.

Reuses each feature's own worker for anything that's already dynamic
(node list, SSH trust, DHCP failover enable, admin login — all take effect
immediately, no restart). Everything else in this app is still a plain
env var read once at process start (PIHOLE_VIP, EXTERNAL_DHCP_SOURCE +
UniFi creds, NOTIFY_WEBHOOK_URL, NETBOX_*) — this module's job is just
writing those back to the stack's .env in one place, behind an explicit
allowlist, so the wizard can't be used to inject an arbitrary env var."""
import os

from workers import host_env

# Every key here is read once from the environment at process start
# elsewhere in this app — writing a new value takes effect only after the
# container is restarted (see the wizard page's "restart required" banner).
ENV_KEYS = {
    "PIHOLE_ADMIN_PASSWORD", "PIHOLE_SSH_USER",
    "PIHOLE_VIP",
    "EXTERNAL_DHCP_SOURCE", "UNIFI_HOST", "UNIFI_USER", "UNIFI_PASSWORD", "UNIFI_SITE",
    "NOTIFY_WEBHOOK_URL",
    "NETBOX_URL", "NETBOX_TOKEN", "NETBOX_VERIFY_SSL",
}


def get_status() -> dict:
    """Current values straight from this process's environment — reflects
    what's actually active right now, not any not-yet-applied wizard edit
    from earlier in the same session (that's tracked client-side until a
    restart picks it up)."""
    return {
        "pihole_ssh_user": os.environ.get("PIHOLE_SSH_USER", "root"),
        "pihole_admin_password_set": bool(os.environ.get("PIHOLE_ADMIN_PASSWORD")),
        "pihole_vip": os.environ.get("PIHOLE_VIP", ""),
        "external_dhcp_source": os.environ.get("EXTERNAL_DHCP_SOURCE", ""),
        "unifi_host": os.environ.get("UNIFI_HOST", ""),
        "unifi_user": os.environ.get("UNIFI_USER", ""),
        "unifi_password_set": bool(os.environ.get("UNIFI_PASSWORD")),
        "unifi_site": os.environ.get("UNIFI_SITE", "default"),
        "notify_webhook_set": bool(os.environ.get("NOTIFY_WEBHOOK_URL")),
        "netbox_url": os.environ.get("NETBOX_URL", ""),
        "netbox_token_set": bool(os.environ.get("NETBOX_TOKEN")),
        "netbox_verify_ssl": os.environ.get("NETBOX_VERIFY_SSL", "false"),
    }


def save_env(updates: dict) -> tuple:
    bad = [k for k in updates if k not in ENV_KEYS]
    if bad:
        return False, f"Not allowed: {', '.join(bad)}"
    if not updates:
        return False, "No values given"
    host_env.write_vars(updates)
    return True, None
