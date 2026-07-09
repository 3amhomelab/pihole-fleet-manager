#!/usr/bin/env python3
"""Generic outbound webhook for events nobody is watching the activity log
for in real time — a node left down after reboot retries are exhausted, a
gravity update flagged as a probable partial failure, an upgrade that failed
after all retries, drift findings, a failover. Deliberately just one env var
(NOTIFY_WEBHOOK_URL) POSTing a small JSON payload rather than baking in a
specific provider's API — the receiving side can be Home Assistant's REST
API, ntfy, a Telegram bridge, n8n, or anything else that takes a webhook.
Inert (does nothing) unless the URL is set."""
import os
import threading

import requests

WEBHOOK_URL = os.environ.get("NOTIFY_WEBHOOK_URL", "").strip()
TIMEOUT     = 10


def enabled() -> bool:
    return bool(WEBHOOK_URL)


def _post(payload: dict) -> None:
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=TIMEOUT)
    except Exception as e:
        print(f"[notify] webhook delivery failed: {e}")


def send(event: str, message: str, severity: str = "warning") -> None:
    """severity: info | warning | error. Fire-and-forget in a background
    thread so a slow/unreachable webhook endpoint never blocks the caller
    (monitor loops, replication runs, etc. all call this inline)."""
    if not enabled():
        return
    payload = {
        "event": event,
        "message": message,
        "severity": severity,
        "source": "pihole-fleet-manager",
    }
    threading.Thread(target=_post, args=(payload,), daemon=True).start()
