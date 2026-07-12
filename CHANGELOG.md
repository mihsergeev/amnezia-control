# Changelog

All notable changes to Amnezia Control are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

## [0.31.0] — 2026-07-12

### Infrastructure
- **Default PostgreSQL bumped to 18** (from 17). Note for existing installs:
  PostgreSQL 18's Docker image stores data in a **version subdirectory**, so the
  volume mount moved from `/var/lib/postgresql/data` to `/var/lib/postgresql`, and
  a major-version data directory is **not** read in place. Upgrade by dumping from
  17 (`pg_dump`) and restoring into a fresh 18 (or keep pinning
  `postgres:17-alpine`). Minor 17.x → 18.x is a major upgrade — take a backup first.

### Added (security)
- **Exporting a server's "full access" link now requires re-entering your panel
  password** (step-up auth). That link embeds a root-equivalent SSH key, so it
  shouldn't be one click away from a hijacked session. Wrong-password attempts are
  rate-limited and a denial is written to the audit log.
- **The password-change endpoint is now rate-limited** — repeated wrong
  current-password attempts are throttled (shared lockout with the step-up), so a
  stolen session can't brute-force the password to escalate.

## [0.30.1] — 2026-07-12

### Fixed (UX)
- **Focus stays inside an open dialog.** Tab (and Shift+Tab) now cycle within the
  modal instead of falling through to the page behind it; focus moves into the
  dialog when it opens and returns to where it was when it closes.
- **Mobile layout.** Wide client tables now scroll horizontally *inside their
  card* instead of stretching the whole page sideways (the root cause was a
  flex child that wouldn't shrink). The header also adapts on narrow screens —
  logo only, the nav drops to its own row — and the clients dialog is responsive.

## [0.30.0] — 2026-07-12

### Fixed (UX)
- **Copy-to-clipboard now works over plain HTTP.** The panel is often opened at
  `http://IP:8080`, where the browser Clipboard API is unavailable, so "Copy"
  buttons silently did nothing. Added an `execCommand` fallback, so copying a
  config, the setup script and the full-access link works everywhere.
- **Backup download no longer fails silently** — an error is now shown, and a
  transient error while downloading a saved backup no longer logs you out (only a
  real 401 does).
- **Modals close on Escape and on clicking outside** — across the whole panel
  (clients, deploy log, backups, alerts, 2FA, password, import, per-client stats,
  and the add/edit/delete/full-access/script dialogs). Nested dialogs close
  top-first.

## [0.29.3] — 2026-07-12

### Fixed
- **English translations for the strings added this session.** Pause/resume, "take
  under management", XRay reissue and the related audit-log entries were showing in
  Russian when the UI language was English. Added all missing keys to the EN
  dictionary (verified: 0 untranslated `t()` strings and audit labels remain).

## [0.29.2] — 2026-07-12

### Fixed
- **Client action buttons no longer overflow the table.** After the Pause button
  (and the traffic column) were added, the row of buttons became too wide and got
  cut off behind a horizontal scrollbar. Each row now shows one primary button
  plus a compact **"⋯" menu** with the rest (reissue, traffic, pause, revoke). The
  menu uses fixed positioning so it isn't clipped by the scrolling client list,
  and the clients dialog is now a bit wider and responsive (also fixes it
  overflowing on narrow screens).

## [0.29.1] — 2026-07-12

### Fixed (security / data hygiene)
- **Deleting a server now removes *all* of its panel-side data.** It previously
  left behind `OvpnConfig` — which stores the client's `vpn://` link **including a
  private key** — plus the client-name cache, node traffic history and
  paused-client records. The cleanup now iterates every table with a `server_id`,
  so a leaked secret can't linger after a server is removed, and any table added
  in the future is covered automatically.

## [0.29.0] — 2026-07-12

### Added
- **Pause / resume now covers OpenVPN too** — the feature is complete across all
  three protocols. OpenVPN is certificate-based, so instead of removing the client
  it uses `client-config-dir`: pausing drops a `disable` file for the client's
  certificate (the cert is **not** revoked), resuming removes it. New OpenVPN
  deploys enable `client-config-dir`; existing servers get it automatically on the
  first pause. Verified on a test node: openvpn starts and stays up with the
  config, and the disable file is written correctly.

## [0.28.0] — 2026-07-12

### Added
- **Pause / resume a client without revoking** (AmneziaWG and XRay). "Pause" takes
  the client off the server so they can't connect, but remembers their
  credentials; "Resume" puts them back with the **same key and IP** (AmneziaWG) or
  the same UUID (XRay) — the client's existing config just works again, no
  reissue. Paused clients stay in the list with a ⏸ badge. Useful to freeze a
  client for a while (non-payment, travel) without losing their config.
  (OpenVPN pause is next — it's certificate-based and needs a different mechanism.)

## [0.27.0] — 2026-07-12

### Added (protocol parity)
- **XRay now has per-client traffic and a per-client traffic graph**, like
  AmneziaWG and OpenVPN. The deploy config now enables XRay's `StatsService`
  (a local-only API inbound + per-user policy), each client gets a stable stats
  key, and the panel reads usage via `xray api statsquery`. Existing XRay servers
  turn this on automatically the next time you **"Update core"** or issue/revoke a
  client (the config self-heals). New deploys have it from the start. Verified on
  a test node: xray starts with the stats config and the API returns live
  counters.

## [0.26.0] — 2026-07-12

### Added (protocol parity)
- **Per-client notes now work for XRay and OpenVPN too** (previously AmneziaWG
  only) — the same inline ✎ editor, and the note is carried over on reissue. The
  notes table is now shared across protocols.
- **The OpenVPN client list shows online status and per-client traffic** (↓ / ↑),
  read live from `openvpn-status.log` — just like AmneziaWG's handshake/traffic
  columns. (The collector's status-log parsing was extracted into a shared,
  now-tested helper.)

## [0.25.0] — 2026-07-12

### Added (protocol parity)
- **OpenVPN/Cloak can now be rebuilt from the UI** ("Переустановить") — previously
  it could only be *deployed* (never rebuilt/updated once installed). The rebuild
  preserves the PKI, the container's real port and every client (verified
  end-to-end: the CA is byte-identical after a rebuild).
- **XRay clients can be reissued** — rotate the UUID while keeping the same name and
  expiry, like AmneziaWG and OpenVPN already could.
- **AmneziaWG "Reissue" now works for panel-created clients too**, not only for
  clients created outside the panel — so you can rotate any client's key from the
  UI without deleting and recreating it.

## [0.24.0] — 2026-07-12

### Added (alerting coverage)
- **Deploy/update/adopt failure now alerts you** even if you closed the log window
  — a background watcher waits for the result and pings your Telegram/webhook on
  `DEPLOY_ERROR`.
- **Auto-backup failure (and recovery) now alerts.** A silently failing backup was
  the worst kind — you'd find out only when you needed the backup.
- **A client that expired but couldn't be revoked** (node unreachable) now alerts
  once a day, instead of silently keeping access.
- **"Client expires in ~N days" heads-up** before the auto-revoke, so you can renew
  in time (`VPNPANEL_EXPIRY_WARN_DAYS`, default 3; 0 disables).

### Changed
- **Server-down alerts are debounced** — a node must miss several collection cycles
  in a row before it's reported down (`VPNPANEL_SERVER_DOWN_MISSES`, default 2), so
  a single transient blip no longer pages you. Recovery still alerts immediately.

## [0.23.0] — 2026-07-12

### Fixed (resilience)
- **One hung node no longer freezes monitoring/auto-revoke for all of them.** The
  metrics collector and the expiry auto-revoke now wrap the whole per-node work in
  a hard timeout — previously only the TCP handshake was bounded, so a stalled
  `docker exec`/`wg show` on a single node blocked the entire cycle.
- **Server cards show live online/offline** without a manual "Check". The collector
  now updates each server's status every cycle (the protocol tabs / last check
  details are preserved), so a node that goes down turns red on its own.
- **A failed image build no longer takes the VPN down.** `docker build … | tail`
  masked the build's exit code, so a broken build proceeded to remove and re-run
  the container anyway. All three deploys (AmneziaWG/XRay/OpenVPN) now check the
  build result and abort *before* touching the running container.

### Added / Changed (ops)
- **`/api/health` now checks the database** (returns 503 if it can't reach it), and
  the backend has a Docker healthcheck so a dead DB actually restarts the backend
  instead of the panel reporting healthy. The frontend now waits for the backend to
  be healthy before starting.
- **Docker log rotation** (`max-size`/`max-file`) on all services, so the panel
  can't fill its own disk with unbounded container logs.

## [0.22.0] — 2026-07-10

### Fixed (data-safety)
- **OpenVPN (re)deploy could wipe every client.** The deploy checked only the
  *host* for `ca.crt`; a server built by the Amnezia app keeps its PKI inside the
  container, so a redeploy regenerated a new CA and invalidated every client
  certificate — the same class as the AmneziaWG incidents, unfixed for OpenVPN.
  Deploy now reads the PKI/config out of the *live* container onto the host
  first, keeps the container's real published port, and removes any parallel
  openvpn/cloak container instead of leaving a second one.
- **Backup silently dropped 7 of 13 tables** — including client expiry dates
  (`client_limits`), the alert Telegram token/webhook (`app_settings`), the audit
  log, and the client-name cache. A restore looked successful while silently
  losing all expiry (paid clients became permanent) and disabling alerting. The
  backup now contains every table, and restore resets PostgreSQL id-sequences so
  the first post-restore create no longer fails with a duplicate-key error.
- **Snapshot rollback no longer reports false success.** `restore_snapshot`
  printed `RESTORE_OK` unconditionally; a truncated/corrupt snapshot (or ENOSPC
  mid-extract) "restored" with an error yet the API said success. It now checks
  the `tar` exit code, and a snapshot of the current state is taken *before* a
  rollback so the rollback itself can be undone.

## [0.21.2] — 2026-07-10

### Fixed
- **Legacy `wg0`-layout AmneziaWG servers are recognized and adoptable.** Some
  servers the Amnezia app deployed keep their config in `wg0.conf` on interface
  `wg0` (not the panel's `awg0.conf`/`awg0`) — they are still genuine AmneziaWG
  (obfuscation params present), but the panel mislabeled them "not AmneziaWG" and
  refused to manage them. Compatibility is now judged by the presence of the
  AmneziaWG obfuscation params (`Jc`/`H1`…), not the file name: such a server can
  now be taken under management (the panel normalizes `wg0.conf → awg0.conf`,
  preserving the obfuscation, port and every client), while a genuine plain
  WireGuard server (no obfuscation) is still correctly refused.

## [0.21.1] — 2026-07-10

### Fixed
- **Adopt now refuses containers that aren't panel-compatible AmneziaWG.** A
  server built by the Amnezia app as *plain WireGuard* keeps its config in
  `wg0.conf` (not `awg0.conf`); adopting it would have regenerated a blank
  AmneziaWG config and lost every client. "Take under management" is now only
  offered/allowed when the container really is AmneziaWG (`awg0.conf` present).
  The adopt also falls back to the live container's published port if the config
  has no readable `ListenPort`.

## [0.21.0] — 2026-07-10

### Added
- **Take a client-built AmneziaWG under panel management** ("Взять под
  управление"). If a server's AmneziaWG container was built by the AmneziaVPN
  app (not the panel), the client list now offers a one-click adopt: the panel
  reads the current config out of the *live* container, keeps its listen port
  and keys, and replaces it with its own container — so existing clients keep
  working (same keys, same port) and version/update/rebuild become available. A
  config snapshot is taken first, so it can be rolled back.

### Fixed
- **"Rebuild" is no longer hidden when the panel can't read the base-image
  digest.** On some panel-built servers the base image isn't tagged, so the
  panel couldn't tell its version and hid the rebuild button (showing "built
  outside the panel"). Rebuild is offered again — it's safe: the config is
  preserved out of the live container regardless of where it lives, and the
  container's real listen port is kept (not reset to the default).

## [0.20.1] — 2026-07-10

### Fixed
- **Login screen no longer shows the logo twice** — the small header logo is
  hidden on the login page, leaving just the large one in the login card.

## [0.20.0] — 2026-07-10

### Added
- **Config snapshots & rollback now cover XRay and OpenVPN too** (not just
  AmneziaWG). Before every rebuild each protocol's config is snapshotted on the
  node (now a tar of the whole config, so OpenVPN's PKI is included), and a
  **Roll back** menu appears in each client list. XRay's "Update core" also
  preserves the config out of the live container, like AmneziaWG.

## [0.19.0] — 2026-07-10

### Added
- **Config snapshots & one-click rollback for AmneziaWG.** Before every rebuild
  the panel now snapshots the current config (peers + keys) on the node. If a
  rebuild goes wrong, use **Roll back** in the client list to restore any recent
  snapshot — clients and keys come back. Snapshots rotate (last 10 kept).

## [0.18.5] — 2026-07-10

### Fixed
- **AmneziaWG "Rebuild" could wipe clients even for a panel-built image.** The
  config-preserve check looked for `awg0.conf` on the host bind-mount; if the
  running container kept its config internally, the check thought there was no
  config, regenerated a blank one (new keys) and dropped all peers. Rebuild now
  first **reads the current config out of the running container** and writes it
  to the host, so it is preserved regardless of where it lived. The rebuild
  button also asks for confirmation.

## [0.18.4] — 2026-07-10

### Changed
- **Tidier header.** The row of icon buttons (alerts, 2FA, change-password, the
  wide Backup dropdown, Sign out) is consolidated into a single **⚙ menu** with
  grouped items; only the version, theme and language toggles stay inline. Less
  clutter, especially on narrower screens. Refreshed the README hero screenshot.

## [0.18.3] — 2026-07-10

### Fixed
- **"Top clients" stats showed raw public keys** instead of names for clients
  that weren't issued through the panel (bulk-imported or created on the node).
  The collector now caches each client's name from the node's `clientsTable`, so
  the traffic stats show the same names as the client list. (Names appear after
  the next metrics-collection cycle.)

## [0.18.2] — 2026-07-10

### Fixed
- **AmneziaWG "Rebuild" on an externally-built image no longer spins up a
  parallel empty container.** The panel deploys AmneziaWG as `amnezia-awg2`; on a
  server whose original container is `amnezia-awg` (built outside the panel),
  "Rebuild" created a *second*, empty container on a different port and the panel
  then displayed that one — looking like all clients had vanished (they were
  safe on the original). The rebuild button is now hidden for images not built by
  the panel, and the deploy/update endpoints refuse (409) when a non-panel
  AmneziaWG container is present.

## [0.18.1] — 2026-07-10

### Fixed
- **Deploy/rebuild showed the wrong protocol's log.** On a server running more
  than one protocol (e.g. AmneziaWG + XRay), clicking "Rebuild" on one tab could
  display the other protocol's leftover deploy log — all protocols shared a single
  `/tmp/acontrol/deploy.log`. Each protocol now uses its own directory under
  `$HOME/.acontrol/<protocol>/` (also owned by the SSH user, avoiding a silent
  no-op when the shared `/tmp` path was owned by a different user).

## [0.18.0] — 2026-07-09

### Security (detection & recovery follow-up to 0.17.0)

- **Security-event alerts** — brute-force lockout, a node's **host key changing**
  (possible MITM), and admin password change are now sent to your configured
  Telegram/webhook alerts.
- **Auth events in the audit log** — successful/failed logins, lockouts, host-key
  changes, and password changes are recorded (forensics after an incident).
- **Break-glass recovery** — `ACONTROL_ADMIN_PASSWORD_RESET=1` resets the admin
  password and disables 2FA on next start, for when both are lost.
- **Panel SSH key hardened on nodes** — new-node setup installs the key with
  `restrict` (command-execution only, no tunneling/pivoting) and
  `from="<panel_ip>"` (bound to the panel's IP), shrinking the blast radius if the
  key ever leaks. Existing nodes: re-run the setup script or add the options by
  hand.
- **CI & supply-chain** — GitHub Actions run the test suite plus `pip-audit`,
  `npm audit`, and a Trivy image scan; Dependabot watches pip/npm/Docker/Actions.
  Added a `SECURITY.md` disclosure policy.

## [0.17.0] — 2026-07-09

### Security

A full security audit and hardening pass. No exploited vulnerability in a
correctly-configured deployment was found, but several defense-in-depth gaps and
one latent bug were fixed:

- **Restore RCE fixed** — a crafted backup archive with an absolute-path member
  could write files outside the data directory (arbitrary file write → RCE). The
  restore endpoint now rejects absolute paths and verifies every member stays
  inside the data dir, and caps the upload size.
- **SSH host-key pinning (TOFU)** — the panel used to disable host-key
  verification entirely. It now records each node's host key on first connect and
  verifies it thereafter, so a man-in-the-middle between panel and node is
  detected. If you rebuild a node, remove its line from `data/ssh/known_hosts`.
- **Refuses to start on default/weak secrets** — an empty/default `JWT_SECRET`
  (`< 32` chars) or a default admin password now aborts startup instead of
  running with a forgeable token. `.env.example` no longer ships working
  placeholders.
- **Change the admin password in the UI** (🔑) — changing it invalidates all
  existing sessions (JWT token-version). The password is no longer re-synced from
  `.env` on every restart.
- **Login brute-force protection** — per-IP throttling with a temporary lockout;
  timing-equalised login (no username enumeration); TOTP codes can't be replayed.
- **Security headers** — CSP, `X-Frame-Options: DENY` (anti-clickjacking),
  `nosniff`, `Referrer-Policy`, HSTS; `server_tokens off`; API docs disabled in
  production.
- **Hardening** — node-supplied interface/IP names are validated before use in
  shell commands; the panel SSH key is written atomically as `0600`; backups dir
  is `0700`; `ssh_user` restricted to a safe charset; import decompression is
  size-capped; containers get `no-new-privileges`.

## [0.16.0] — 2026-07-09

### Added
- **Deploy OpenVPN-over-Cloak to a clean server** — the "More" menu on an online
  server without OpenVPN now has "Deploy OpenVPN / Cloak". It builds an
  Alpine image (openvpn + [Cloak](https://github.com/cbeuw/Cloak) + shadowsocks),
  generates the easy-rsa PKI, Cloak keys and shadowsocks config, and starts the
  container with a live log — same build-on-target, config-preserving model as the
  AmneziaWG and XRay deploys. Previously OpenVPN/Cloak servers could only be
  managed (issue/revoke) if the container already existed; now the panel can stand
  one up from scratch.

## [0.15.3] — 2026-07-09

### Fixed
- Fresh **XRay deploy now installs the latest xray-core** (fetched from GitHub)
  instead of a pinned older version — no need to click "Update core" right after.
  Falls back to a bundled version if GitHub is unreachable.

## [0.15.2] — 2026-07-09

### Fixed
- After deploying a protocol (e.g. XRay) the server is now **re-checked
  automatically**, so the new protocol shows up immediately — previously you had
  to click "Check" by hand for the badge and clients tab to appear.

## [0.15.1] — 2026-07-09

### Changed
- Clearer "add server" flow: the setup method is now an explicit choice between
  **auto-setup by SSH password** and **run a script yourself**. The script path
  creates the SSH user, installs the key and opens the firewall on its own — no
  need to prepare the user by hand first.

## [0.15.0] — 2026-07-08

### Added
- **Server groups (folders)** — organize servers into collapsible groups by
  company, location, or anything else. Ungrouped servers stay at the bottom;
  the collapsed/expanded state is remembered.

### Changed
- The base `compose.yml` is now **standalone**: it publishes the panel on a host
  port (`ACONTROL_BIND`, default `127.0.0.1:8080`), so a fresh clone runs without
  any extra proxy. The caddy-docker-proxy setup moved to an optional
  `compose.caddy.yml` override.
- Renamed the compose files to `compose.yml` / `compose.caddy.yml` (modern Docker
  Compose naming — auto-discovered without `-f`).
- caddy override: publishes no host port, the network name is configurable via
  `ACONTROL_CADDY_NETWORK`, and an empty `ACONTROL_ALLOW_IPS` now means "allow
  from any IP".
- Cleaner transparent logo (smooth edges, no dark fringe).

### Removed
- The redundant HTTP basic auth in front of the panel — the single login is the
  panel's own JWT + optional 2FA, with network access gated by the reverse proxy.

## [0.14.0] — 2026-07-07

Initial public release.

### Added
- Manage **AmneziaWG**, **OpenVPN-over-Cloak** and **XRay/REALITY** servers over
  plain SSH (no agent on the nodes).
- Issue / revoke / reissue client configs — animated QR in the AmneziaVPN format
  plus a plain `.conf`; per-client **expiry** with auto-revoke; per-client traffic
  history; **top clients** by traffic.
- **Deploy** AmneziaWG / XRay to a clean server (build-on-target, config-preserving);
  one-click core update with a live log.
- **Node resource monitoring** (CPU, RAM, disk, uptime); **server-down** and
  **low-disk alerts** to Telegram and/or a webhook.
- **Two-factor auth** (TOTP), an action **audit log**, DB **backup & restore** plus
  scheduled auto-backups.
- Dark / light theme and English / Russian UI.

[0.31.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.31.0
[0.30.1]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.30.1
[0.30.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.30.0
[0.29.3]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.29.3
[0.29.2]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.29.2
[0.29.1]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.29.1
[0.29.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.29.0
[0.28.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.28.0
[0.27.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.27.0
[0.26.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.26.0
[0.25.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.25.0
[0.24.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.24.0
[0.23.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.23.0
[0.22.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.22.0
[0.21.2]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.21.2
[0.21.1]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.21.1
[0.21.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.21.0
[0.20.1]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.20.1
[0.20.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.20.0
[0.19.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.19.0
[0.18.5]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.18.5
[0.18.4]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.18.4
[0.18.3]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.18.3
[0.18.2]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.18.2
[0.18.1]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.18.1
[0.18.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.18.0
[0.17.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.17.0
[0.16.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.16.0
[0.15.3]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.3
[0.15.2]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.2
[0.15.1]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.1
[0.15.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.0
[0.14.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.14.0
