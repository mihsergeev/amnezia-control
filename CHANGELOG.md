# Changelog

All notable changes to Amnezia Control are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

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

[0.18.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.18.0
[0.17.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.17.0
[0.16.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.16.0
[0.15.3]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.3
[0.15.2]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.2
[0.15.1]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.1
[0.15.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.0
[0.14.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.14.0
