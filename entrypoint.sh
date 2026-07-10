#!/bin/sh
# --- SSH key bootstrap ---
# Priority: an existing key already at PIHOLE_SSH_KEY wins (whether bind-mounted
# in, or persisted on the /data volume from a previous Setup-tab run) — never
# clobber it. Only decode PIHOLE_SSH_KEY_B64 if no key is there yet, so a fresh
# container can bootstrap from either an env var or the Setup tab.
KEY_PATH="${PIHOLE_SSH_KEY:-/data/ssh/pihole_key}"
if [ ! -f "$KEY_PATH" ] && [ -n "$PIHOLE_SSH_KEY_B64" ]; then
    mkdir -p "$(dirname "$KEY_PATH")"
    echo "$PIHOLE_SSH_KEY_B64" | base64 -d > "$KEY_PATH"
    chmod 600 "$KEY_PATH"
fi

exec "$@"
