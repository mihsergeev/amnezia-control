# Changelog

All notable changes to Amnezia Control are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

## [0.44.1] — 2026-07-16

### Fixed
- **No more false "alert channel is broken" pages from a single transient.** The
  heartbeat's channel self-test (`getMe`) now retries once, and the channel is
  only marked down after `CHANNEL_FAIL_STRIKES` (3) consecutive failures — a brief
  network/DNS blip or the restart during a deploy no longer trips it, while a real
  outage (revoked token, Telegram blocked) still persists past the streak and
  alerts. An invalid-token response (401/404) fails fast without waiting out the
  retry. The host watchdog (`ops/panel-watchdog.sh`) gained the same defense: it
  pages only after 2 consecutive problem detections (streak debounce, state file
  stays backward-compatible), and `HB`/`MAX_AGE`/`STRIKES` are now env-tunable.

### Added
- **Watchdog alerts name the specific panel with a link.** The heartbeat now
  records the panel's public URL (`panel=…`, from the new `panel_url` setting /
  `VPNPANEL_PANEL_URL`, derived from `ACONTROL_DOMAIN` by default), and the
  watchdog puts it in the alert — so when several panels report to one Telegram
  chat, it's immediately clear which one is alerting.

## [0.44.0] — 2026-07-16

### Changed
- **New AmneziaWG deployments now pin the base image to a known-good digest**
  instead of pulling `amneziavpn/amneziawg-go:latest` blindly. A broken upstream
  `:latest` can no longer break fresh installs. Upgrading the base image is now an
  explicit action — the "Update" button (`mode="update"`) deliberately pulls
  `:latest`. The exact base digest a node was built on is recorded on the node
  (`/opt/acontrol/base-digest`) and used for version detection, so it stays
  accurate regardless of how the image was pulled.

### Added
- **Post-deploy readback check.** A deploy now verifies the `awg0` interface
  actually came up and is listening before reporting success; if `awg-quick up`
  silently failed (e.g. an upstream image changed behavior), the deploy reports an
  error instead of marking a broken node "ready".
- **Golden-master format contract tests.** The AmneziaVPN app's `vpn://` format
  (full-access and client link) is now pinned in a fixture derived from real app
  exports, with tests asserting the panel's output matches it key-for-key. If the
  undocumented format drifts — on our side or upstream — the tests point at exactly
  which key set diverged, instead of configs silently failing in the field.

### Fixed
- **Redeploy never overwrites a config it doesn't recognize.** The "recreate a
  clientless legacy config as 2.0" path now fires only for a genuinely-recognized
  AmneziaWG 1.0 config (single-value `H1`, no `I1`). An unfamiliar future format
  (e.g. a hypothetical AWG 3.0) is preserved and logged rather than rewritten,
  guarding against upstream-format-driven config loss.

## [0.43.5] — 2026-07-15

### Fixed
- **Client configs ("For the AmneziaVPN app" / `.conf`) for a 2.0 server now
  connect instead of hanging on "Connecting…".** The panel collapsed the server's
  `H1`–`H4` header **ranges** into a single value inside each range for the client
  config. But AmneziaWG 2.0 varies the message-type header per packet within the
  range: the server sends its handshake response with a random header in its `H2`
  range, and a client pinned to one exact value rejects it — so the handshake
  never completes. The client now mirrors the server's `H1`–`H4` ranges verbatim
  (identical ranges on both ends), exactly like the AmneziaVPN app's own client
  config. Re-issue client configs after upgrading.

## [0.43.4] — 2026-07-15

### Fixed
- **Full access to a panel-deployed AmneziaWG 2.0 finally connects from the
  AmneziaVPN app as "AmneziaWG (version 2)".** This was the real root cause behind
  the whole "shows as Legacy over full access" saga: the panel's full-access
  `vpn://` link carried only the bare container marker
  (`{"container": "amnezia-awg2"}`) with **no embedded protocol config**, so the
  app never saw `protocol_version = "2"` and fell back to treating the server as
  legacy — regardless of how correct the on-server config was. The panel now reads
  the node's `awg0.conf` over SSH and embeds the full `awg` object into the link
  (H1–H4 ranges, `I1`–`I5`, `Jc`/`S…`, port, `subnet_address`,
  `transport_proto`, `protocol_version = "2"`), exactly matching the AmneziaVPN
  app's own full-access export — verified key-for-key against a link the app
  itself produced. Re-export full access after upgrading.

## [0.43.3] — 2026-07-15

### Fixed
- **Full access to a panel-deployed AmneziaWG now connects from the AmneziaVPN
  app as "AmneziaWG (version 2)".** The panel wrote the magic headers `H1`–`H4`
  as single values (the AmneziaWG 1.x format), so the app read a panel server
  over full access as legacy and its client's obfuscation didn't match the server
  (peer added, no handshake). The panel now generates the 2.0 config exactly like
  the AmneziaVPN app: `H1`–`H4` as ascending non-overlapping **ranges**
  (`low-high` — the 2.0 marker), the default CPS `I1` with `I2`–`I5` empty, and
  `Jmin`/`Jmax`/`S4` in the app's ranges. Client configs pick a single header
  value inside each server range. Verified byte-for-byte against an
  app-deployed 2.0 server. Redeploy a server to move it to this format.

## [0.43.2] — 2026-07-15

### Fixed
- **Full access to a 2.0 server now connects from the AmneziaVPN app.** The panel
  wrote the AmneziaWG `I1`–`I5` (CPS) parameters as active lines in the server
  config, but the AmneziaVPN app keeps them **commented** (`# I1 = …`) and reads
  them from there when it builds a client over full access. So the app's client
  came up without CPS while the server had it applied, and the 2.0 handshake never
  completed (the peer was added, but no handshake). The panel now writes `I1`–`I5`
  commented — exactly matching Amnezia's own server layout (awg-quick doesn't apply
  them to the server anyway) — and reads them back from the commented lines for
  client configs. Redeploy an existing server to move it to this format.

## [0.43.1] — 2026-07-15

### Fixed
- **Full-access link mislabeled the new AmneziaWG as Legacy.** The export
  collapsed the modern `amnezia-awg2` container into the legacy `amnezia-awg`
  type (a `startswith` ordering bug), so the AmneziaVPN app showed the server as
  "AmneziaWG Legacy" and failed to connect with ErrorCode 202 ("missing Docker
  container" — it looked for a non-existent `amnezia-awg`). The link now emits
  `amnezia-awg2` for the new protocol, and keeps both types when a server runs
  legacy + new side by side.

## [0.43.0] — 2026-07-15

### Fixed
- **The panel now notices when a protocol's container is removed outside the
  panel.** The background collector (every few minutes, over the SSH connection it
  already opens) refreshes the live container list per server, so a protocol
  deleted via the AmneziaVPN desktop app — or by hand — disappears from the panel
  automatically, without a manual **Check**. The list is only updated when Docker
  actually answered; a transient SSH failure or a Docker restart never hides a
  protocol tab.
- **Redeploying a client-less legacy AmneziaWG server now upgrades it to 2.0.**
  When a reused config is legacy (no `I1` parameter) and the server has no peers,
  redeploy regenerates it as AmneziaWG 2.0 — so **Full access** and issued client
  configs come up as **AmneziaWG**, not **AmneziaWG Legacy**. Servers that already
  have clients are left untouched (changing obfuscation would break their
  handshake — redeploy such a server deliberately to move it to 2.0).

## [0.42.0] — 2026-07-14

### Fixed
- **AmneziaWG deploys now generate the AmneziaWG 2.0 obfuscation set.** New
  deploys add `S3`/`S4` and the `I1`–`I5` CPS junk-packet parameters, so the
  AmneziaVPN app recognizes issued clients as **AmneziaWG** instead of
  **AmneziaWG Legacy**. Previously only the 1.0/legacy params (`Jc`/`Jmin`/`Jmax`
  /`S1`/`S2`/`H1`–`H4`) were generated. CPS tags (`<b>`/`<r>`/`<rd>`/`<rc>`/`<t>`)
  were validated end-to-end against `amneziawg-go 0.0.20250522`.
  Existing servers keep their current config — **redeploy** one (fresh keys, so
  re-issue its clients) to move it to 2.0.

## [0.41.2] — 2026-07-14

### Changed (UI — Servers)
- **Unreachable servers stand out.** A server that failed its last check now has
  a red-tinted card and a **Check** button right on it (online servers keep Check
  in the "More" menu), so you can spot a down node and re-probe it at a glance.

## [0.41.1] — 2026-07-14

### Changed (UI — Servers)
- **Clearer group headers.** Folder headers are now a bolder, brighter title with
  a divider line under them and more space between groups, so groups no longer
  blend into the stream of cards.

## [0.41.0] — 2026-07-14

### Added (UI — Servers)
- **Drag-and-drop ordering.** Grab the ⠿ handle on a server card to reorder it
  within its group or move it into another group, and drag a group header to
  reorder whole groups — so your most-used servers and groups sit at the top.
  The order is persisted (new `position` column) and restored on reload; group
  order follows the servers' positions. New servers land at the end.

## [0.40.3] — 2026-07-14

### Fixed
- After a protocol deploy succeeds, the panel re-checks the node right away.
  Previously the server card kept its pre-deploy snapshot (docker unavailable,
  no protocol badge) until a manual "Check" or the next collection cycle, so a
  just-deployed node looked like the deploy had failed even though the container
  was already up.

## [0.40.2] — 2026-07-14

### Added
- **Prebuilt Docker images on GHCR.** Every release publishes multi-arch
  (amd64/arm64) backend and frontend images, so you can install with
  `docker compose pull` instead of building locally. Pin a version via
  `ACONTROL_VERSION` in `.env`.

### Fixed
- The default range tab on the Overview reads "24 h" instead of "1 d" (the
  preset boundary was `< 24`, so 24 hours fell into the days branch).

## [0.40.1] — 2026-07-13

### Added (UI — Overview)
- **Sortable tables.** Click a column header to sort the servers table (name /
  status / clients / traffic) and the "Top clients by traffic" table (client /
  server / protocol / traffic / total); click again to flip the direction.

### Changed
- The "total traffic" tile is now labelled "since node start" with a tooltip:
  it sums every node's counters since it last started (reset on container
  restart), not a fixed period — it equals the sum of the "Traffic" column in
  the table below.

## [0.40.0] — 2026-07-13

### Added (UI — Overview charts)
- **Time-range picker.** Preset buttons 3h / 6h / 12h / 24h / 7d / 30d / 90d
  instead of a hard-wired "last 24h". The title and interval label are dynamic.
- **Drag-to-zoom, Grafana-style.** Select a span on either chart and both zoom
  to that window; the "✕ zoom" button resets.

### Changed
- The backend `/api/stats/history` accepts an arbitrary window
  (`from_ms`/`to_ms`) and picks a "nice" bucket step sized to the range
  (5 min … 12 h), so even 90 days fits in a few hundred points instead of tens
  of thousands.
- Traffic-sample retention raised from 30 to 90 days (matches the max chart
  range; that's ~1 row per server per interval — negligible).

## [0.39.4] — 2026-07-12

### Fixed (UI — charts)
- **Chart text is no longer stretched.** The charts used `preserveAspectRatio=
  "none"` on a narrow (640-unit) viewBox, so the whole SVG — including the axis
  labels — was squashed horizontally to fill the width, which looked cheap. Charts
  now measure their real pixel width (ResizeObserver) and draw in true pixel
  coordinates, so labels and the line are crisp. Added a dot at the latest value.

## [0.39.3] — 2026-07-12

### Changed (UI — Overview page)
- **Charts got a gradient fill** (colour fading to transparent under the line)
  instead of the old flat translucent area — they look far less dull.
- **The "total traffic" stat tile** value was much smaller than the other two
  tiles (mono 1.15rem vs 1.9rem), which read as misaligned; bumped it to 1.5rem
  bold so the three tiles balance.

## [0.39.2] — 2026-07-12

### Changed (UI)
- **Server metrics redesigned.** Uptime now sits on the left (bigger, with a clock
  icon), and CPU / RAM / Disk moved to the right as boxed chips with icons and
  labels (like the info chips in the clients dialog) — far more readable than the
  old flat inline line. Warn/critical still tints the value and chip border.

## [0.39.1] — 2026-07-12

### Changed (UI)
- **Server cards, round 2:** bigger server name and country flag, and the note
  moved below the address line (was above it) for a cleaner top-to-bottom read.

## [0.39.0] — 2026-07-12

### Added (UI)
- **Country flag per server.** The panel geolocates each server's IP (once, via
  ipwho.is, cached in a new `country` column) and shows the country flag next to
  the address, so it's obvious where a VPN exits. Flags render even on Windows
  (which drops flag emojis) via a bundled ~78 KB Twemoji flags web font.
- **Bigger, less cramped server cards** — larger name and address, more padding.

## [0.38.4] — 2026-07-12

### Changed (UI)
- **The clients dialog header is less dull.** The flat "iface · endpoint · subnet"
  muted line is now a row of labelled info chips, and the version/adopt line sits
  in its own subtle boxed strip — the area between the tabs and the client list
  reads as structured info instead of grey text.

## [0.38.3] — 2026-07-12

### Changed (UI)
- **Client/data tables are easier to read.** Rows were blending into the flat dark
  background; added zebra striping, a hover highlight, more row padding, and a
  slightly stronger header divider so rows are cleanly separated at a glance.

## [0.38.2] — 2026-07-12

### Changed (UX)
- **Wider content on large screens.** The main column max-width went from 1080px
  to 1440px, so the panel uses more of a big/4K display instead of a narrow strip
  (still capped so lines stay readable).

## [0.38.1] — 2026-07-12

### Changed (UX)
- **The client config dialog opens on the "For the AmneziaVPN app" (vpn://) tab by
  default**, with the AmneziaWG `.conf` tab second — the app link is what's needed
  most often, so it's no longer a second click away.

## [0.38.0] — 2026-07-12

### Added (self-monitoring — dead-man's-switch)
- **The panel can no longer die silently.** A watchman can't watch itself, so the
  panel now writes a heartbeat every minute to `data/heartbeat` (timestamp +
  alert-channel health + the Telegram/webhook creds), and a tiny host-side cron
  (`ops/panel-watchdog.sh`, runs outside Docker) reads it and **independently**
  alerts you if:
  - the heartbeat goes stale (>10 min) — the container/DB is dead or hung, or
  - `alerts_ok=0` — the panel's own alert channel self-test failed (Telegram
    unreachable / bad token), so normal alerts wouldn't get through either.
  The watchdog sends via the creds from the heartbeat (so it works even when the
  panel and DB are down) and only alerts on state changes — no noise. The panel
  self-tests the alert channel with a Telegram `getMe` through the configured API
  base each cycle. Install steps are documented at the top of the watchdog script.

## [0.37.0] — 2026-07-12

### Changed (backup — lighter + self-tested)
- **Backups no longer carry traffic history by default, so they're tiny.** The
  `client_traffic_samples`/`traffic_samples` tables were ~99% of the archive
  (hundreds of MB) and are non-critical (they regenerate). A backup is now a few
  KB — practical to download from the ⚙ menu as your off-site copy. Set
  `ACONTROL_BACKUP_INCLUDE_TRAFFIC=1` to include the history. Restore only touches
  tables present in the archive, so restoring a light backup never wipes traffic.
- **Every auto-backup is self-tested right after it's written** (re-read from
  disk): the archive must open, `db.json`/manifest must parse, row counts must
  match the manifest, and the admin user + panel SSH key must be present. If the
  self-test fails, you get an alert — a backup you can't restore no longer passes
  silently.

## [0.36.1] — 2026-07-12

### Fixed (UX)
- **Modals no longer close when you click just outside them.** Clicking the
  backdrop used to dismiss the dialog, which fired accidentally on a near-miss
  click and was easy to trigger by mistake (even mid-drag). Dialogs now close only
  via their Close/Cancel button or Escape. Applies to every modal (clients,
  alerts, import, deploy, backups, 2FA, password, full-access, delete-confirm,
  setup-script, config view, client stats).

## [0.36.0] — 2026-07-12

### Added (alerts)
- **The Telegram Bot API address is now configurable** in the alert settings
  (defaults to `https://api.telegram.org`). Point it at a mirror/reverse proxy
  (e.g. `https://api-tg.example.com`) when Telegram is blocked in the server's
  region, so alerts still get through. Empty = the default.

## [0.35.2] — 2026-07-12

### Added (UI)
- **Server cards now show a green "AmneziaWG Legacy" badge** when a legacy
  AmneziaWG runs alongside the new one (both `amnezia-awg` and `amnezia-awg2`
  containers present), so the second protocol is visible at a glance. The same
  detection drives the "AmneziaWG Legacy" tab in the clients dialog.

## [0.35.1] — 2026-07-12

### Changed (UI)
- **Server cards are less cluttered.** The SSH connection line
  (`SSH user@host:port`) is gone from the card — it's rarely needed and still
  lives in the server's Edit form. The **Check** button moved into the "More" (⋯)
  menu, since checks are run only occasionally.

## [0.35.0] — 2026-07-12

### Added (two AmneziaWG protocols per server — UI)
- **The clients dialog now shows a separate "AmneziaWG Legacy" tab** whenever a
  legacy AmneziaWG (wg0) runs alongside the new one. Selecting it lists the legacy
  clients and supports issue / reissue / revoke / pause / resume / config download
  against `/awg-legacy`. The legacy tab intentionally has **no** version/update/
  adopt controls — the panel never rebuilds the legacy engine.
- Completes the two-protocol feature started in 0.34.0.

## [0.34.0] — 2026-07-12

### Added (two AmneziaWG protocols per server — backend)
- **A server can now run both AmneziaWG "new" (awg0) and "Legacy" (wg0) side by
  side, managed as separate protocols.** The panel detects the two by their
  runtime config (awg0.conf vs wg0.conf), not by container name (Amnezia and the
  panel both use `amnezia-awg2`). The AWG state now reports a `legacy_container`
  when a legacy AmneziaWG runs alongside the new one.
- **New read-only-ish `/awg-legacy` API** for the legacy protocol: list clients,
  issue / reissue / revoke / pause / resume, download configs — but **no rebuild
  or version control** (the panel never touches the legacy container's engine, per
  design). Legacy client metadata is stored under `protocol="awglegacy"`.
- Validated on a live server (tw-kz) with 29 legacy + 7 new clients.
- UI (a second "AmneziaWG Legacy" tab) lands next.

## [0.33.0] — 2026-07-12

### Added (data-safety — pre-op backup)
- **Every container-level operation now snapshots first, so it can be rolled back.**
  New `snapshot_all` takes a config snapshot of *every* protocol container on the
  node before deploy / rebuild / adopt / config-restore — for AmneziaWG that means
  **both** `amnezia-awg` (legacy) and `amnezia-awg2` are backed up, not just one.
  Snapshots land in "config backups" and are restorable from the UI. Snapshot
  timestamps are now collision-proof (a burst of snapshots in the same second no
  longer overwrites each other). XRay deploy also snapshots first now (it didn't).

## [0.32.0] — 2026-07-12

### Fixed (data-safety — AmneziaWG adopt)
- **Adopting a server that runs two AmneziaWG protocols no longer destroys one of
  them.** Amnezia names its newer AWG container `amnezia-awg2` — the same name the
  panel uses for its own container — so the panel mistook an active foreign
  `amnezia-awg2` for its own: it snapshotted only the *other* container and then
  `docker rm -f`'d the whole `amnezia-awg*` family, wiping the un-snapshotted one
  (a server with both AmneziaWG **Legacy** and **awg2** lost awg2). Now:
  - The panel's own container is identified by **image** (`acontrol-awg`), not by
    name, so a foreign `amnezia-awg2` is correctly seen as foreign.
  - On adopt, **every** foreign AWG container is snapshotted to "config backups"
    *before* anything is touched — nothing is removed without a recovery point.
  - If a server has **two** AWG containers, adopt now **refuses** (409) with both
    configs safely snapshotted, instead of silently taking one and killing the
    other. (Managing two AWG protocols on one server is a follow-up.)
  - The deploy script removes only the container on the **target port** and the
    panel's own container — an AWG sibling on a *different* port (a second
    protocol) is left running instead of being force-removed.

## [0.31.2] — 2026-07-12

### Fixed
- **Import dialog now has a clear "done" state.** After importing servers the form
  (and the "Import" button) collapse to just the result list plus a primary
  **Done** button (and a "Import more" reset), so it's obvious the import finished
  and the dialog can be closed — previously the "Import" button lingered and the
  end state was ambiguous.

## [0.31.1] — 2026-07-12

### Fixed
- **Client IP behind the reverse proxy.** The panel runs behind caddy → nginx, so
  the backend saw the proxy's internal Docker address (172.20.0.x) instead of the
  real user. That wrong address was written to the audit log ("logged in from
  172.20.0.4"), used as the security-alert IP, and — worst — used as the
  **rate-limit key**, so every client shared one bucket. The real client is now
  taken from `X-Forwarded-For` (first public address from the right, internal
  proxies skipped, so a spoofed header can't win).
- **Backups no longer swallow the Postgres rollback directory.** The archive
  excluded `postgres`/`pgdata`/`backups`, but a post-upgrade rollback dir like
  `postgres.v17` slipped through, bloating a download by hundreds of MB of raw
  cluster files. Exclusion now matches any `postgres*`/`pgdata*` directory (and
  restore skips them symmetrically).

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
- **OpenVPN/Cloak can now be rebuilt from the UI** ("Reinstall") — previously
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
- **Take a client-built AmneziaWG under panel management** ("Take under
  management"). If a server's AmneziaWG container was built by the AmneziaVPN
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
