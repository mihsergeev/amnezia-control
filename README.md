<p align="center">
  <img src="docs/logo.png" alt="Amnezia Control" width="380" />
</p>

<p align="center">
  <b>Self-hosted web panel to manage a fleet of VPN servers</b> — deploy nodes, issue and revoke client configs, watch traffic and server health, all from one place. A replacement for managing servers by hand through the AmneziaVPN desktop client.
</p>

<p align="center"><b>English</b> · <a href="README.ru.md">Русский</a></p>

<p align="center">
  <img src="https://img.shields.io/badge/License-AGPL%20v3-blue" alt="License: AGPL v3" />
  <img src="https://img.shields.io/badge/backend-FastAPI-009688" alt="FastAPI" />
  <img src="https://img.shields.io/badge/frontend-React%20%2B%20Vite-61DAFB" alt="React + Vite" />
  <img src="https://img.shields.io/badge/deploy-Docker-2496ED" alt="Docker" />
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome" />
</p>

![Overview dashboard](docs/screenshots/dashboard.png)

Nodes are managed over plain SSH (no agent installed on them). Three protocols are supported side by side: **AmneziaWG**, **OpenVPN over Cloak**, and **XRay / REALITY**. Clients are issued in the AmneziaVPN `vpn://` format (with a scannable animated QR) and, for WireGuard, as a plain `.conf`.

---

## Features

**Servers & nodes**
- Add servers with one-command onboarding (auto-setup over SSH password, or a copy-paste root script)
- Import already-deployed servers from an AmneziaVPN "full access" `vpn://` link or a bulk host list
- Deploy AmneziaWG / XRay to a clean server (build-on-target from the official base image, config-preserving)
- Update the server core in one click; live deploy log
- Per-node resource monitoring: CPU load, RAM, disk, uptime — right on the card

**Clients**
- Issue / revoke / reissue configs per protocol, with search, sorting and notes
- Animated QR in the exact AmneziaVPN format the app scans, plus plain `.conf` for WireGuard
- **Expiry**: set a lifetime per client (7 / 30 / 90 days or a custom date) — a background task auto-revokes on the node when it lapses
- **Per-client traffic history** (AmneziaWG & OpenVPN) with a speed chart and cumulative totals
- **Top clients by traffic** across all servers on the dashboard

**Monitoring & alerts**
- Overview dashboard: aggregate traffic and online-clients charts (24 h), per-server breakdown
- **Server-down alerts** and **low-disk alerts** to Telegram and/or a webhook, configured from the UI

**Operations & security**
- **Two-factor auth (TOTP)** for panel login
- Action **audit log** (who issued / revoked / deployed / deleted, and when)
- DB **backup & restore** (download an archive, or restore from one) + scheduled auto-backups with rotation
- **Dark / light theme** and **English / Russian** UI
- Edge TLS + IP allow-list via `caddy-docker-proxy` labels (or bring your own reverse proxy)

---

## Screenshots

| Servers (dark) | Servers (light) |
|---|---|
| ![Servers](docs/screenshots/servers-dark.png) | ![Servers light](docs/screenshots/servers-light.png) |

| Clients | Server-down alerts | Two-factor auth |
|---|---|---|
| ![Clients](docs/screenshots/clients.png) | ![Alerts](docs/screenshots/alerts.png) | ![2FA](docs/screenshots/two-factor.png) |

| Deploy a protocol | Action log | Import servers |
|---|---|---|
| ![Deploy](docs/screenshots/deploy.png) | ![Action log](docs/screenshots/audit.png) | ![Import](docs/screenshots/import.png) |

**Issuing a client config** — an animated QR in the exact format the AmneziaVPN app scans, plus a plain `.conf` for the AmneziaWG / WireGuard apps:

| AmneziaWG `.conf` | AmneziaVPN app (`vpn://`) |
|---|---|
| ![Config .conf](docs/screenshots/issue-conf.png) | ![Config vpn://](docs/screenshots/issue-vpn.png) |

---

## Architecture

- **Backend** — Python 3.12, FastAPI, SQLAlchemy (async) + Alembic, node management over SSH via `asyncssh`
- **Database** — PostgreSQL 17 (SQLite in tests)
- **Frontend** — React + Vite + TypeScript, hand-rolled SVG charts, no UI framework
- **Delivery** — Docker Compose on a single host; the panel builds protocol images *on the target node* from the official `amneziavpn/*` base images, so only a tiny script travels over SSH

The panel holds its own SSH keypair and connects to each node as an unprivileged `acontrol` user (docker access via group or `sudo`). Client private keys for WireGuard/OpenVPN are generated **on the panel** — only the public key / CSR ever reaches a node.

---

## Requirements

- A Linux host for the panel with **Docker** and **Docker Compose** (v2)
- A reverse proxy for HTTPS (nginx / Caddy / Traefik) — an optional caddy-docker-proxy override is included
- VPN **nodes**: Linux with Docker; reachable over SSH from the panel

---

## Quick start

```bash
git clone <your-repo-url> acontrol && cd acontrol
cp .env.example .env
# edit .env — set ADMIN_PASSWORD, DB_PASSWORD, JWT_SECRET, PANEL_IP
docker compose up -d --build
```

This is **standalone**: the panel is published on the host at `ACONTROL_BIND` (default `127.0.0.1:8080`). Open it at http://127.0.0.1:8080, or set `ACONTROL_BIND=0.0.0.0:8080` to expose it on all interfaces. Generate the JWT secret with `openssl rand -hex 32`.

### HTTPS / reverse proxy

The panel serves plain HTTP — **put a reverse proxy with TLS in front** (nginx, Caddy, Traefik, …) pointing at `ACONTROL_BIND`. It's a login-protected control panel, so don't expose it over plain HTTP on the internet.

**Optional — caddy-docker-proxy.** If you already run [caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy) (external Docker network `caddy`), an override adds automatic TLS + an IP allow-list:

```bash
# set ACONTROL_DOMAIN and ACONTROL_ALLOW_IPS in .env, then:
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

(or put `COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml` in `.env`). See [`docker-compose.caddy.yml`](docker-compose.caddy.yml).

---

## Adding a VPN node

Each node needs an `acontrol` user with docker access. Create it once (as root on the node):

```bash
useradd -m -s /bin/bash acontrol
echo 'acontrol ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/acontrol && chmod 440 /etc/sudoers.d/acontrol
usermod -aG docker acontrol   # if a docker group exists
```

Then add the server in the panel — two ways:

1. **Auto-setup by SSH password** — the panel connects once with a password, installs its key and opens the SSH port **for the panel IP only**. The password is not stored. Requires `PasswordAuthentication yes` on the node.
2. **Manual script** — the panel shows a root script you run on the node (useful when a firewall blocks inbound SSH from the panel, since the script opens access for the panel IP itself).

You can also **import** existing AmneziaVPN servers via their "full access" `vpn://` link, or add many at once from a `host:port user password` list.

> Firewall: the panel only opens the **SSH port for its own IP** (via ufw / firewalld / `hosts.allow`). The **VPN port** is opened to the world by the deploy step (Docker publish + ufw / firewalld), because clients need it — nothing else is exposed.

---

## Configuration

Set in `.env` (see [`.env.example`](.env.example)):

| Variable | Default | Meaning |
|---|---|---|
| `ACONTROL_ADMIN_USER` / `ACONTROL_ADMIN_PASSWORD` | `admin` / — | Panel login |
| `ACONTROL_DB_PASSWORD` | — | PostgreSQL password (internal) |
| `ACONTROL_JWT_SECRET` | — | JWT signing secret (32+ random bytes) |
| `ACONTROL_PANEL_IP` | — | Public IP of the panel (written into node firewall rules) |
| `ACONTROL_DEFAULT_SSH_USER` | `acontrol` | Prefilled SSH user for new servers |
| `ACONTROL_STATS_INTERVAL` | `300` | Metrics/monitoring interval, seconds (0 = off) |
| `ACONTROL_EXPIRY_INTERVAL` | `300` | Expired-client auto-revoke scan, seconds (0 = off) |
| `ACONTROL_DISK_ALERT_PERCENT` | `90` | Low-disk alert threshold, % (0 = off) |
| `ACONTROL_BACKUP_INTERVAL_HOURS` | `24` | Auto-backup interval (0 = off) |
| `ACONTROL_BACKUP_KEEP` | `14` | Auto-backups to keep |

Telegram / webhook alert channels are configured **from the UI** (🔔 button) and stored in the DB.

---

## Security notes

- Enable **2FA** (🔒 in the header) once you have set an admin password.
- Keep the edge **IP allow-list** tight (Caddy labels) — the panel is a high-value target.
- The **"Full access" export** produces a `vpn://` link containing a private SSH key that manages the node — treat it like a secret. It uses a dedicated key, regenerating invalidates the old one.
- DB backups (`db.json`) contain secrets (password hash, client private keys) — store them safely.

---

## Backups

- **Backup → Download** grabs a `tar.gz` with a JSON dump of all tables plus the panel's SSH key.
- **Backup → Restore from file** replaces the current state from such an archive.
- Scheduled auto-backups are written to `./data/backups` with rotation; browse and download them from **Backup → Auto-backups**.

---

## Updating

The panel is a normal git checkout — pull and rebuild:

```bash
cd acontrol
git pull
docker compose up -d --build
```

Database migrations run automatically on backend startup. If you use the caddy override, keep `COMPOSE_FILE` in `.env` (or add `-f docker-compose.yml -f docker-compose.caddy.yml`). Grab a DB backup first (**Backup → Download**) as a restore point.

## Development

```bash
# backend
cd backend
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m uvicorn app.main:app --reload   # http://localhost:8000/api/docs
.venv/bin/python -m pytest

# frontend (proxies /api to :8000)
cd frontend
npm install
npm run dev                                          # http://localhost:5173
```

DB migrations (Alembic) run automatically on backend startup.

---

## Contributing

Issues and pull requests are welcome.

1. Fork, create a branch.
2. Backend: `cd backend && pytest` must pass; keep it typed and minimal.
3. Frontend: `cd frontend && npm run build` must pass (`tsc` + `vite`).
4. Keep the UI bilingual — add both the Russian source string and its English translation in `frontend/src/i18n.tsx`.

For larger changes, open an issue first to discuss the direction.

## License

**GNU AGPL-3.0** — see [`LICENSE`](LICENSE). You may self-host and modify it freely; if you run a modified version as a network service, you must make your source available to its users (AGPL §13).
