# Install panel updates from the web interface

The Updates screen can install the latest stable Amnezia Control release after an administrator confirms with a password and a current authenticator code. An administrator must first enable the host updater. The panel can continue to check for releases without it.

The updater supports the official prebuilt images on Linux with Docker Engine, Docker Compose v2.24 or later, Docker Buildx installed system-wide, systemd, Python 3.11 or later, and GitHub CLI 2.106 or later at /usr/bin/gh. It uses public release data and attestations without a GitHub token. The service manages one stock PostgreSQL Compose project per host. It supports the default configuration, compose.caddy.yml with caddy-docker-proxy, and compose.tls.yml with the supplied Caddyfile.

The project must be in a root-owned directory with root-owned parents and no group or world write permission. The official Compose files must match the installed release, and .env must be root-owned with mode 0600. The data directory must use ordinary bind mounts from that directory and share a filesystem with the project. Use manual updates for customized Compose files, source builds, Docker user namespace remapping, named data volumes, Compose changes in a new release, or a new database migration. Install the updater after bringing the panel to a version that already includes the Updates installation screen.

## Enable the service

Run these commands as root on the panel host. Start in the project directory and use the updater files from the source of the same release as the running panel. Use the existing Compose project name from docker compose ls. The snippets assume the default Compose configuration.

+ Place the two Python modules in /lib65/scripts/acontrol-updater and the systemd unit in /etc/systemd/system.

    ~~~sh
    install -d -m 0755 /lib65/scripts/acontrol-updater
    install -m 0644 ops/acontrol_updater.py ops/acontrol_update_verify.py /lib65/scripts/acontrol-updater/
    install -m 0644 ops/acontrol-updater.service /etc/systemd/system/acontrol-updater.service
    ~~~

+ Create /etc/acontrol-updater.conf, owned by root with mode 0600, and set the directory and project name. Set ACONTROL_PROXY to caddy for compose.caddy.yml or tls for compose.tls.yml.

    ~~~dotenv
    ACONTROL_PROJECT_DIR=/opt/amnezia-control
    ACONTROL_PROJECT_NAME=amnezia-control
    ACONTROL_PROXY=none
    ~~~

+ Create the image override once. Keep the existing file when re-enabling the updater, because it pins the images from the last successful installation.

    ~~~sh
    if [ ! -e compose.updater.images.yml ]; then
        (umask 077; printf 'services: {}\n' > compose.updater.images.yml)
    fi
    systemctl daemon-reload
    systemctl enable --now acontrol-updater.service
    ~~~

+ Set ACONTROL_VERSION in .env to the exact installed release if the project does not already use digest pins. Append the updater files to your Compose file list in .env. Preserve any official proxy file already in the list. For the default configuration use COMPOSE_FILE=compose.yml:compose.updater.yml:compose.updater.images.yml. Keep the existing project name or set COMPOSE_PROJECT_NAME to that name. Make sure both images for the installed version are available locally, then recreate the frontend and backend on that version to attach the socket.

    ~~~sh
    docker compose up -d --no-deps --no-build --pull never --wait backend
    docker compose up -d --no-deps --no-build --pull never --wait frontend
    ~~~

Open Settings → Updates. Use an HTTPS panel address and enable two-factor authentication in your account before installing a release.

## During an update

The host independently verifies the provenance of both images against the official published tag and downloads them by digest. All supported runtime files and the database migration head must match. Verification and download run before the update takes the panel offline.

The updater stops the panel stack, saves its configuration, and makes a cold copy of its data, including PostgreSQL. It starts the database and new backend on that copy and checks the database, backend version, and frontend through a private preview with background jobs disabled. The previous datastore stays available for restoring the old release. During this maintenance period, the web interface is temporarily unavailable. Connected VPN nodes are separate from the panel stack.

If the private preview fails, the updater restores the original datastore and previous images. Once normal startup enables background jobs and incoming traffic, rollback keeps the active database on the compatible schema and restores the previous images. This preserves writes from background jobs and incoming requests. The host journal allows a restarted updater to resume rollback. The dialog reads the saved result after the panel comes back.

## Backups and recovery

The hidden .acontrol-update-store directory contains a root-only journal and per-attempt copies. Keep enough free storage for a second copy of the panel data and new images. Keep rollback copies and their images until stability is confirmed. Include the independent backup location in your usual encrypted backup routine, and remove obsolete attempts while the worker is stopped after verifying another restore point. Retain the attempt referenced by state.json when recovery is required.

Use journalctl -u acontrol-updater.service and the service status to diagnose failures. On “Recovery required”, stop the unit, address the underlying error, then run the same Python command as the unit with --recover and restart the unit after successful recovery. The backup and saved configuration remain available for manual recovery if Docker cannot start the previous stack.

Stop the updater before manually changing the Compose project, images or database. For a manual upgrade, reset compose.updater.images.yml to services: {}, set the intended ACONTROL_VERSION in .env, and recreate the stack using the official files for that version. Verify which images are running before enabling the updater again.
