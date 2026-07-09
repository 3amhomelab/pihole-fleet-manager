#!/usr/bin/env python3
"""Shared write-back to the stack's bind-mounted host .env
(./.env:/config/host.env in docker-compose.yml). Several features persist a
value here so it survives a container recreate, not just the /data volume —
the SSH key (setup.py), the admin password (auth.py), the node list
(nodes.py), and now the Getting Started wizard's env-var-only settings.

Writes in place (open/writelines) rather than the usual write-tmp-then-
rename pattern — a single-file bind mount's target inode can't be replaced
via rename() from inside the container (EBUSY), only written to directly."""
import os

HOST_ENV_FILE = os.environ.get("HOST_ENV_FILE", "/config/host.env")


def write_vars(updates: dict) -> None:
    """Updates/appends KEY=value lines for every key in `updates`, in one
    pass. Silently no-ops if the bind mount isn't present (e.g. running
    without docker-compose)."""
    if not os.path.exists(HOST_ENV_FILE) or not updates:
        return
    try:
        with open(HOST_ENV_FILE) as f:
            lines = f.readlines()
        remaining = dict(updates)
        for i, line in enumerate(lines):
            if "=" not in line:
                continue
            key = line.split("=", 1)[0]
            if key in remaining:
                lines[i] = f"{key}={remaining.pop(key)}\n"
        if remaining:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            for key, val in remaining.items():
                lines.append(f"{key}={val}\n")
        with open(HOST_ENV_FILE, "w") as f:
            f.writelines(lines)
    except Exception as e:
        print(f"[host_env] Could not write {list(updates.keys())} back to host .env: {e}")
