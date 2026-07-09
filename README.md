# Pi-hole Fleet Manager

A Flask app for managing a multi-node Pi-hole v6 cluster: extra DHCP scopes
(VLANs) layered on top of Pi-hole's single built-in scope, config
replication across nodes, scheduled software updates, and activity logging.

## Features

- **VLAN DHCP scopes** — Pi-hole natively serves one DHCP scope; this adds
  any number of additional scopes (subnet, range, gateway, lease time,
  static host reservations), rendered as a `dnsmasq.d` config snippet and
  pushed to every node over SSH.
- **Multi-master replication** — compares Pi-hole settings and DHCP scope
  (including static reservations) across all nodes and propagates whichever
  node changed most recently, using a local change-detection ledger since
  Pi-hole's API doesn't expose per-field modification times.
- **Auto-updater** — daily round-robin `pihole -up` across nodes (one per
  day) plus on-demand manual upgrade, with retries and history.
- **Per-VLAN conditional forwarding** — Pi-hole's own Settings UI only
  supports one conditional-forwarding subnet/domain; each extra VLAN can
  define its own, rendered as `server=`/`rev-server=` lines in the same
  pushed dnsmasq.d snippet.
- **Pre-flight validation** — a fleet-wide DHCP scope push is blocked if the
  VLAN set has an overlap or a host/range outside its subnet, rather than
  fanning a bad config out to every node. Replication runs also check each
  node's default group/blocklist health and surface warnings (catches the
  "empty default group silently disables blocking" footgun).
- **Sync verification & drift check** — every replication push is read back
  from the node it was just applied to, to confirm it actually landed
  instead of trusting the API's response; a separate read-only "drift
  check" compares all nodes on demand without changing anything.
- **DHCP failover enforcement** — DHCP is broadcast-based, so the existing
  keepalived VIP (DNS-only) does nothing to stop every node's embedded DHCP
  server from answering independently. This polls for which node currently
  holds the VIP and keeps DHCP active only there, continuously re-asserting
  so a manually re-enabled node gets corrected automatically.
- **Per-VLAN group assignment** — a VLAN can name a Pi-hole group; every push
  assigns that VLAN's clients (static reservations and current dynamic
  leases alike) to it via `/api/clients`, so blocklist policy can differ per
  VLAN without manually assigning every device.
- **Fleet-wide hostname resolution** — each Pi-hole node only knows the
  hostnames of clients *it personally* leased, so a DNS query landing on a
  different node (or a different VLAN) can fail to resolve a device's DHCP
  hostname. Every push publishes each VLAN's static-host hostnames as local
  DNS (`dns.hosts`) records on every node, merged in without touching any
  unrelated/manually-added entries.
- **Groups & client reconciliation** *(off by default — opt in on the
  Replication page)* — extends replication to also reconcile Pi-hole's group
  definitions and per-client group membership across nodes. Matched by name
  (groups) and client identifier (clients) rather than raw id, since group
  ids are assigned locally per node and the same group can end up with a
  different id on each one.
- **Fleet-wide aggregated stats** — Pi-hole's own dashboard only ever shows
  one node; this merges query totals and top-domain/top-client lists across
  the whole fleet into one view.
- **Staggered gravity updates** — a blocklist URL that's briefly unreachable
  can be silently skipped with no reliable success signal from Pi-hole. One
  node updates gravity per day (offset from the software updater's own
  schedule), and each update's blocklist domain count is compared against
  its own prior count — a large drop is flagged as a probable partial-update
  failure.
- **Node recovery** — clones a healthy node's settings, DHCP reservations,
  groups/client assignments, and VLAN scopes onto a target node, then
  triggers gravity there. For rebuilding a wiped/reprovisioned node — far
  more complete than restoring from a Teleporter backup, which is
  config-only and not a real gravity/query-database backup.
- **Stale-lease conflict guard** — a client with a static reservation can
  still be served its old dynamic lease until the lease database is
  manually cleared; this checks every node's active leases against every
  static reservation (primary scope and all VLANs) and can clear a
  confirmed stale lease directly.
- **External DHCP-source sync** *(opt-in, UniFi only, unverified against
  real hardware)* — for setups where Pi-hole is DNS-only and DHCP is served
  by UniFi/pfSense/OPNsense instead, so clients don't show up as "Unknown."
  Pulls client name/MAC/IP from a UniFi OS controller and publishes it as
  local DNS records, same mechanism as the VLAN hostname sync above.
- **SSH trust bootstrap** — generates an ed25519 keypair and distributes it
  to every node via one-time password auth, so subsequent operations need
  no stored password.
- **Activity log** — unified history of pushes, replication runs, upgrades,
  and failovers.
- **Node health monitoring** — three-layer health check per node (ping → DNS
  → Pi-hole API) with a response-time sparkline, uptime tracking, and a
  failure log. A node that stays down gets an SSH reboot, then up to two
  more retries spaced several minutes apart (gated on cluster quorum so
  this never fires while the cluster itself may be unhealthy) — if all
  retries are exhausted it's left down and flagged for manual intervention
  rather than escalated to a hypervisor-level restart.
- **VIP master detection & manual failover** — tracks which physical node
  currently holds the keepalived VIP (SSH interface check, falling back to
  a Pi-hole session-token probe), keeps a history of master changes, and
  offers a one-click manual failover (restarts keepalived on the current
  master so the backup takes over). Inert and hidden from the UI entirely
  if `PIHOLE_VIP` isn't set.
- **On-demand diagnostics** — runs a per-node diagnostic script (system
  resources, `pihole-FTL`/keepalived service status and journals, DNS
  resolution tests, DHCP config/leases, rate-limiting events) over SSH and
  pulls the report back into fleet-manager's own `/data` volume — browsable
  from the Health page instead of only existing on the node itself.

## Configuration

The app is configured entirely through environment variables — there's no
config file to edit.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | HTTP port the Flask app listens on |
| `PIHOLE_IPS` | *(required)* | Comma-separated list of Pi-hole node IPs |
| `PIHOLE_ADMIN_PASSWORD` | *(required)* | Pi-hole v6 admin password (used for API auth on every node) |
| `PIHOLE_SSH_USER` | `root` | SSH user for pushing config to nodes — see [account requirements](#the-pihole_ssh_user-account) below, doesn't have to be root |
| `PIHOLE_SSH_KEY` | `/data/ssh/pihole_key` | Path to the SSH private key used for node access |
| `PIHOLE_SSH_KEY_B64` | *(optional)* | Base64-encoded private key, decoded to `PIHOLE_SSH_KEY` on first boot if no key exists yet |
| `DNSMASQ_CONF_NAME` | `10-vlans.conf` | Filename written under `/etc/dnsmasq.d/` on each node |
| `PIHOLE_UPDATER_HOUR` | `3` | UTC hour the daily auto-update round-robin fires |
| `UPGRADE_RETRIES` | `3` | Retry attempts per node per upgrade run |
| `UPDATER_VERSION_POLL_SECS` | `3600` | How often the updater polls for new Pi-hole releases |
| `PIHOLE_VIP` | *(optional)* | The keepalived VIP already in front of the cluster for DNS. DHCP is broadcast-based and ignores the VIP entirely, so without this set, every node's embedded DHCP server answers every request independently — set this to enable the Failover tab, which keeps DHCP active only on whichever node currently holds the VIP |
| `DHCP_FAILOVER_CHECK_INTERVAL_SECS` | `15` | How often (seconds) the failover worker re-checks the VIP master and re-asserts DHCP state |
| `GRAVITY_UPDATE_HOUR` | `4` | UTC hour the daily staggered gravity-update round-robin fires (offset from `PIHOLE_UPDATER_HOUR` on purpose) |
| `GRAVITY_DROP_THRESHOLD_PERCENT` | `10` | Blocklist domain-count drop (%) after an update that's flagged as a probable partial-update failure |
| `EXTERNAL_DHCP_SOURCE` | *(optional)* | Set to `unifi` to enable pulling client names from a UniFi OS controller for DNS-only Pi-hole setups; blank disables this entirely |
| `EXTERNAL_DHCP_POLL_SECS` | `300` | How often (seconds) the external DHCP-source sync re-polls and re-syncs |
| `UNIFI_HOST` / `UNIFI_USER` / `UNIFI_PASSWORD` | *(optional)* | UniFi OS controller credentials — all required together if `EXTERNAL_DHCP_SOURCE=unifi` |
| `UNIFI_SITE` | `default` | UniFi site name |
| `MONITOR_CHECK_INTERVAL` | `60` | Seconds between health checks (also adjustable live from the Health page) |
| `MONITOR_DOMAINS` | `google.com,cloudflare.com` | Domains queried for the DNS-layer health check — passes if any one resolves |
| `MONITOR_DNS_RETRIES` | `3` | DNS check retries before marking a node's DNS as failed |
| `MONITOR_REBOOT_AFTER` | `3` | Consecutive failures before the first SSH reboot is attempted |
| `MONITOR_REBOOT_RETRIES` | `2` | Extra SSH reboot attempts if still down, spaced by `MONITOR_REBOOT_AFTER_MINUTES`; exhausted retries leave the node down and flagged, no further automated action |
| `MONITOR_REBOOT_AFTER_MINUTES` | `10` | Minutes between SSH reboot retries |
| `MONITOR_UPTIME_INTERVAL` | `300` | Seconds between uptime refresh + VIP master re-detection |
| `TZ` | `UTC` | Container timezone |

Node health monitoring needs `ping` and `dig` inside the container plus the
`NET_RAW` capability for ICMP — both are already included in the published
image and `docker-compose.yml`; if you're building your own image or
running with `docker run` directly, make sure to add `--cap-add=NET_RAW`.

Data (VLAN definitions, replication ledger, updater state, activity log,
the SSH key, saved diagnostics reports) persists under `/data`, which
should be mounted as a volume.

## The `PIHOLE_SSH_USER` account

Every privileged remote command (writing `/etc/dnsmasq.d/`, `pihole
restartdns`, `pihole -up`, `reboot`) is run with `sudo`, so `PIHOLE_SSH_USER`
just needs SSH access plus sudo rights — it does **not** have to be root.
This matters because some hosts lock root down to key-only login (no root
password at all), which leaves nothing for the Setup tab's one-time
password-based key distribution to authenticate with. A non-root account
sidesteps that.

Requirements for the account, on every Pi-hole node:

1. **A password, for the one-time SSH key distribution** (the Setup tab
   only uses it once, to install its key — day-to-day operation is
   key-based):
   ```bash
   echo '<user>:<password>' | chpasswd
   ```
2. **Passwordless sudo** — required because the app runs sudo over a
   non-interactive SSH session with no terminal to type a password into:
   ```bash
   echo '<user> ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/<user>
   ```
3. **`sshd` must allow password auth for this account** (it usually does by
   default — `PasswordAuthentication yes` — even on hosts where
   `PermitRootLogin` is restricted to keys).

After that, point `PIHOLE_SSH_USER` at the account and run Setup as usual.
The Setup tab's node-status check verifies both SSH key auth and
`sudo -n` (non-interactive sudo) for each node, so a missing NOPASSWD
entry shows up immediately as a failed check rather than a mysterious
failure during a later push or upgrade.

**Key persistence:** a key generated via the Setup tab is written to the
`/data` volume, which survives ordinary container restarts/redeploys on its
own. For protection against losing that volume entirely (stack recreate,
host migration, etc.), `docker-compose.yml` bind-mounts the stack's own
`.env` file into the container (`./.env:/config/host.env`), and the Setup
tab writes the freshly generated key's `PIHOLE_SSH_KEY_B64` there directly,
immediately, the moment setup succeeds — no redeploy needed, and it works
for whatever stack the compose file is running as. `deploy.sh` also pulls
the currently-live key forward into local `.env` via `GET /api/setup/key`
on every deploy, as a fallback for the one stack it manages.

## Running

Pull the pre-built image from Docker Hub and run it, mounting a volume at
`/data` and supplying the environment variables above:

```bash
docker run -d \
  -p 8080:8080 \
  -v pihole_fleet_manager_data:/data \
  -e PIHOLE_IPS=<node-ip-1>,<node-ip-2>,<node-ip-3> \
  -e PIHOLE_ADMIN_PASSWORD=<password> \
  3amhomelab/pihole-fleet-manager:latest
```

Or use the included `docker-compose.yml` / `docker-compose.env` (copy the
latter to `.env` and fill in your values) with `docker compose up -d`.

On first run, use the **Setup** tab (or `POST /api/setup/run`) to bootstrap
SSH trust to each node with a one-time password — no key needs to be
pre-installed on the targets.

## Security

This app has **no built-in authentication** — every page and `/api/...`
endpoint (including DHCP/DNS config pushes to your Pi-hole nodes) is open
to anyone who can reach the container. It's designed to run on a trusted
internal network, not to be exposed to the internet. If you need remote
access, put it behind a reverse proxy or VPN that handles auth rather than
exposing the container's port directly.

## Development

```bash
pip install -r requirements.txt
PIHOLE_IPS=<node-ip> PIHOLE_ADMIN_PASSWORD=<password> python app.py
```

## Layout

```
app.py              Flask routes (pages + JSON API)
workers/
  store.py           VLAN + host reservation persistence
  primary_dhcp.py     Reads/writes Pi-hole's own native DHCP scope
  pihole_push.py       Renders + pushes dnsmasq.d config over SSH
  replication.py       Multi-master settings/scope sync
  updater.py           Scheduled + manual Pi-hole upgrades
  setup.py             SSH trust bootstrap
  activity_log.py      Unified event log
templates/           Jinja2 templates (one per tab)
```
