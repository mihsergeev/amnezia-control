# Changelog

All notable changes to Amnezia Control are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

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

[0.15.1]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.1
[0.15.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.15.0
[0.14.0]: https://github.com/mihsergeev/amnezia-control/releases/tag/v0.14.0
