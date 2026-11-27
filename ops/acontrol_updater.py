#!/usr/bin/env python3
"""Local, opt-in service that replaces this panel's signed Docker images."""

import argparse
import fcntl
import json
import logging
import os
import re
import shutil
import socket
import socketserver
import stat
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

from acontrol_update_verify import download_source_file, verify_release

LOG = logging.getLogger("acontrol-updater")
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,7})\.(?:0|[1-9][0-9]{0,7})\.(?:0|[1-9][0-9]{0,7})")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
REVISION = re.compile(r"[a-zA-Z0-9_]{1,64}")
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}")
STORE = ".acontrol-update-store"
OVERLAY = "compose.updater.yml"
PINS = "compose.updater.images.yml"
SOCKET = Path("/run/acontrol-updater/control.sock")
PANEL_UID = 10001
PROXIES = {"none": (), "caddy": ("compose.caddy.yml",), "tls": ("compose.tls.yml", "deploy/Caddyfile")}
ACTIVE = {"queued", "verifying", "backing_up", "installing", "checking", "rolling_back"}
PUBLIC = ("phase", "version", "error")


class Refused(Exception):
    pass


def stable(value):
    return isinstance(value, str) and VERSION.fullmatch(value) is not None


def trusted(path, *, directory=False, private=False):
    """A root-operated Compose input must not be replaceable by other users."""
    path = path.absolute()
    for item in [path, *path.parents]:
        info = item.lstat()
        expected = stat.S_ISDIR if item != path or directory else stat.S_ISREG
        if info.st_uid != 0 or info.st_mode & 0o022 or not expected(info.st_mode):
            raise Refused("incompatible")
    if private and path.stat().st_mode & 0o077:
        raise Refused("incompatible")
    return path


def sync_dir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_file(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
        tmp = Path(file.name)
        try:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
            os.replace(tmp, path)
            sync_dir(path.parent)
        finally:
            tmp.unlink(missing_ok=True)


def move(source, destination):
    os.rename(source, destination)
    sync_dir(source.parent)
    if source.parent != destination.parent:
        sync_dir(destination.parent)


def run(command, *, timeout=90):
    # Compose reads the explicitly configured .env, never the caller's env.
    completed = subprocess.run(
        command, check=False, timeout=timeout, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "HOME": "/root", "LC_ALL": "C"},
    )
    if completed.returncode:
        LOG.warning("%s %s exited %s", Path(command[0]).name, command[1], completed.returncode)
        raise RuntimeError("command failed")
    return completed.stdout


class Panel:
    def __init__(self, directory, name, proxy):
        if not PROJECT.fullmatch(name):
            raise Refused("incompatible")
        self.root = trusted(directory, directory=True)
        self.name = name
        self.source_files = ("compose.yml", *PROXIES[proxy])
        self.compose_files = [item for item in self.source_files if item.endswith(".yml")]
        self.data_services = ("db", "caddy") if proxy == "tls" else ("db",)
        self.services = (*self.data_services, "backend", "frontend")
        self.data = self.root / "data"
        self.store = self.root / STORE
        self.store.mkdir(mode=0o700, exist_ok=True)
        trusted(self.store, directory=True, private=True)

    def check_inputs(self):
        for filename in (".env", *self.source_files, OVERLAY, PINS):
            trusted(self.root / filename, private=filename == ".env")

    def docker(self, *args, timeout=90):
        return run(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args], timeout=timeout)

    def compose(self, *args, timeout=90):
        files = [flag for item in (*self.compose_files, OVERLAY, PINS) for flag in ("-f", str(self.root / item))]
        return self.docker(
            "compose", "--project-directory", str(self.root), "--project-name", self.name,
            "--env-file", str(self.root / ".env"), *files, *args, timeout=timeout,
        )

    def pins(self, images, *, preview=False):
        config = {"services": {name: {"image": ref} for name, ref in images.items()}}
        if preview:
            # The migration head is already equal. Probe the HTTP application
            # without lifespan jobs that can change remote VPN nodes.
            config["services"]["backend"]["command"] = [
                "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--lifespan", "off",
            ]
        write_file(self.root / PINS, json.dumps(config).encode("ascii") + b"\n")

    def inspect(self, service):
        container_id = self.compose("ps", "-q", service).decode("ascii").strip()
        if not re.fullmatch(r"[a-f0-9]{12,64}", container_id):
            raise Refused("incompatible")
        return json.loads(self.docker("inspect", container_id))[0]

    def version(self):
        command = (
            "import json, urllib.request\n"
            "from app.config import Settings\n"
            "with urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4) as response:\n"
            "    assert json.load(response)['db'] == 'ok'\n"
            "print(Settings().version)\n"
        )
        version = self.compose("exec", "-T", "backend", "python", "-c", command, timeout=12).decode("ascii").strip()
        if not stable(version):
            raise Refused("incompatible")
        return version

    def revision(self):
        revision = self.compose(
            "exec", "-T", "db", "psql", "-XAt", "-v", "ON_ERROR_STOP=1",
            "-U", "acontrol", "-d", "acontrol", "-c", "SELECT version_num FROM alembic_version", timeout=15,
        ).decode("ascii").strip()
        if not REVISION.fullmatch(revision):
            raise Refused("incompatible")
        return revision

    def configured_images(self):
        services = json.loads(self.compose("config", "--format", "json"))["services"]
        if set(services) != set(self.services):
            raise Refused("incompatible")
        if str(services["backend"]["environment"]["VPNPANEL_ADMIN_PASSWORD_RESET"]) != "0":
            raise Refused("incompatible")
        return {name: services[name]["image"] for name in self.services}

    def local_image_ids(self, configuration):
        return {
            service: self.docker("image", "inspect", "--format", "{{.Id}}", image).decode("ascii").strip()
            for service, image in configuration.items()
        }

    def check_active_images(self, configuration):
        expected = dict(line.split() for line in self.compose("config", "--hash", "*").decode("ascii").splitlines())
        active = self.docker(
            "ps", "--filter", f"label=com.docker.compose.project={self.name}",
            "--format", '{{.Label "com.docker.compose.service"}}',
        ).decode("ascii").splitlines()
        if set(expected) != set(configuration) or sorted(active) != sorted(configuration):
            raise Refused("incompatible")
        image_ids = self.local_image_ids(configuration)
        for service, image_id in image_ids.items():
            actual = self.inspect(service)
            labels = actual["Config"]["Labels"]
            if (not IMAGE_ID.fullmatch(image_id) or actual["Image"] != image_id
                    or labels.get("com.docker.compose.config-hash") != expected[service]):
                raise Refused("incompatible")
        return image_ids

    def validate(self, previous, target, candidate):
        self.check_inputs()
        for filename in self.source_files:
            local = (self.root / filename).read_bytes()
            if (local != download_source_file(f"v{previous}", filename)
                    or local != download_source_file(candidate, filename)):
                raise Refused("incompatible")
        # The current data must be a plain directory on the store filesystem.
        info = self.data.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_dev != self.store.stat().st_dev:
            raise Refused("incompatible")
        mount_paths = Path("/proc/self/mountinfo").read_text().splitlines()
        for line in mount_paths:
            mount = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), line.split()[4])
            if Path(mount).is_relative_to(self.data):
                raise Refused("incompatible")
        images = self.configured_images()
        for service in ("backend", "frontend"):
            prefix = f"ghcr.io/mihsergeev/amnezia-control-{service}"
            if images[service] != f"{prefix}:{previous}" and not re.fullmatch(
                re.escape(prefix) + r"@sha256:[a-f0-9]{64}", images[service],
            ):
                raise Refused("incompatible")
        image_ids = self.check_active_images(images)
        for service, dest, source in (
            ("backend", "/data", self.data), ("db", "/var/lib/postgresql", self.data / "postgres"),
        ):
            actual = self.inspect(service)["Mounts"]
            matching = [m for m in actual if m["Destination"] == dest]
            if len(matching) != 1 or matching[0]["Type"] != "bind" or matching[0]["Source"] != str(source):
                raise Refused("incompatible")
        self.check_data_paths()
        if tuple(map(int, target.split("."))) <= tuple(map(int, previous.split("."))):
            raise Refused("incompatible")
        return images, image_ids

    def check_data_paths(self):
        subdirectories = ("postgres",)
        if "caddy" in self.services:
            subdirectories += ("caddy", "caddy/data", "caddy/config")
        for path in (self.data, *(self.data / name for name in subdirectories)):
            if not stat.S_ISDIR(path.lstat().st_mode):
                raise Refused("incompatible")

    def candidate_revision(self, image, target):
        command = (
            "from alembic.config import Config\n"
            "from alembic.script import ScriptDirectory\n"
            "from app.config import Settings\n"
            "import json\n"
            "print(json.dumps([Settings().version, ScriptDirectory.from_config(Config('alembic.ini')).get_heads()]))"
        )
        version, heads = json.loads(self.docker(
            "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", str(PANEL_UID),
            "--entrypoint", "python", image, "-c", command,
        ))
        if version != target or len(heads) != 1 or not REVISION.fullmatch(heads[0]):
            raise Refused("incompatible")
        return heads[0]

    def stop(self):
        self.compose("stop", "--timeout", "30", *reversed(self.services), timeout=180)

    def start(self, *services):
        self.compose("up", "-d", "--no-deps", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "150",
                     *services, timeout=180)

    def start_data_services(self):
        # Use the nested data mounts before running a container that can write
        # to their parent directory. Start and restart each service explicitly.
        self.check_data_paths()
        self.start(*self.data_services)

    def check_space(self):
        self.check_data_paths()
        needed = int(run(["/usr/bin/du", "-sbx", str(self.data)], timeout=60).split()[0])
        if shutil.disk_usage(self.store).free < needed + (128 << 20):
            raise Refused("backup_failed")

    def copy_data(self, destination):
        self.check_space()
        run(["/usr/bin/cp", "-ax", "--reflink=auto", str(self.data), str(destination)], timeout=1800)
        run(["/usr/bin/sync", "-f", str(destination)], timeout=120)
        sync_dir(destination.parent)

    def check_frontend(self, shadow=None):
        for _ in range(10):
            try:
                result = self.frontend_get("/api/health", shadow)
                if json.loads(result).get("db") == "ok" and self.frontend_get("/", shadow):
                    return
            except (ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired):
                pass
            time.sleep(1)
        raise Refused("health_failed")

    def frontend_get(self, path, shadow):
        args = ("wget", "-qO-", f"http://127.0.0.1{path}")
        if shadow:
            return self.docker("exec", shadow, *args, timeout=8)
        return self.compose("exec", "-T", "frontend", *args, timeout=8)

    def shadow_name(self, job):
        return f"{self.name}-update-check-{job}"

    def remove_shadow(self, job):
        name = self.shadow_name(job)
        containers = self.docker("ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{.Names}}")
        if containers.decode("ascii").splitlines() == [name]:
            self.docker("rm", "-f", name)

    def check_candidate_frontend(self, job, image):
        name = self.shadow_name(job)
        self.docker(
            "run", "-d", "--pull", "never", "--name", name,
            "--network", f"{self.name}_internal", "--security-opt", "no-new-privileges", image,
        )
        try:
            self.check_frontend(shadow=name)
        finally:
            self.remove_shadow(job)


class Updater:
    def __init__(self, panel):
        self.panel = panel
        self.state_path = panel.store / "state.json"
        self.state = {"phase": "idle", "version": None, "error": None}
        if self.state_path.exists():
            self.state = json.loads(trusted(self.state_path, private=True).read_bytes())
        self.lock = threading.RLock()

    def journal(self, **fields):
        with self.lock:
            new = {**self.state, **fields}
            write_file(self.state_path, json.dumps(new).encode("ascii") + b"\n")
            self.state = new

    def status(self):
        with self.lock:
            return {field: self.state[field] for field in PUBLIC}

    def install(self, version):
        with self.lock:
            state = self.status()
            if state["phase"] in ACTIVE:
                return {**state, "accepted": False, "error": "busy"}
            if state["phase"] == "recovery_required":
                return {**state, "accepted": False, "error": "recovery_failed"}
            if not stable(version):
                return {**state, "accepted": False, "error": "incompatible"}
            # A repeated request for the already installed job is harmless.
            if state["phase"] == "succeeded" and state["version"] == version:
                return {**state, "accepted": False, "error": "incompatible"}
            job = uuid.uuid4().hex
            self.journal(phase="queued", version=version, error=None, job=job, previous=None,
                         promoted=False, stopped=False)
            queued = self.status()
            threading.Thread(target=self.update, args=(job, version), daemon=True).start()
            return {**queued, "accepted": True}

    def update(self, job, target):
        panel = self.panel
        attempt = panel.store / job
        failure = "verification_failed"
        try:
            self.journal(phase="verifying")
            panel.check_inputs()
            previous = panel.version()
            if tuple(map(int, target.split("."))) <= tuple(map(int, previous.split("."))):
                raise Refused("incompatible")
            candidate_images, source = verify_release(target)
            failure = "incompatible"
            old_images, old_ids = panel.validate(previous, target, source)
            revision = panel.revision()
            for image in candidate_images.values():
                panel.docker("pull", image, timeout=900)
            if panel.candidate_revision(candidate_images["backend"], target) != revision:
                raise Refused("incompatible")

            failure = "backup_failed"
            panel.check_space()
            attempt.mkdir(mode=0o700)
            for item in (".env", *panel.source_files, OVERLAY, PINS):
                destination = attempt / "config" / item
                destination.parent.mkdir(parents=True, exist_ok=True)
                write_file(destination, (panel.root / item).read_bytes())
            sync_dir(attempt / "config")
            sync_dir(attempt)
            self.journal(phase="backing_up", previous=previous, images=old_images, image_ids=old_ids, stopped=True)
            panel.stop()
            panel.copy_data(attempt / "data.next")
            # Keep the original datastore untouched as the rollback copy. The
            # clone only becomes live after a DB boot and a schema check.
            move(panel.data, attempt / "data.previous")
            move(attempt / "data.next", panel.data)

            failure = "install_failed"
            self.journal(phase="installing")
            panel.pins(candidate_images, preview=True)
            panel.start_data_services()
            if panel.revision() != revision:
                raise Refused("health_failed")
            panel.start("backend")
            failure = "health_failed"
            self.journal(phase="checking")
            if panel.version() != target or panel.revision() != revision:
                raise Refused("health_failed")
            panel.check_candidate_frontend(job, candidate_images["frontend"])
            # Normal startup enables jobs that can write to VPN nodes. Preserve
            # the active datastore from here, including writes from those jobs
            # and from requests served by the new frontend.
            self.journal(promoted=True)
            panel.pins(candidate_images)
            panel.start("backend")
            if panel.version() != target or panel.revision() != revision:
                raise Refused("health_failed")
            panel.start("frontend")
            panel.check_frontend()
            panel.check_active_images(panel.configured_images())
            self.journal(phase="succeeded", error=None, stopped=False)
        except Exception as error:
            code = str(error) if isinstance(error, Refused) else failure
            LOG.warning("Update %s %s (%s)", target, code, type(error).__name__)
            self.restore(code)

    def restore(self, error):
        if not self.state.get("stopped"):
            self.journal(phase="failed", error=error)
            return
        panel = self.panel
        job = self.state["job"]
        if not re.fullmatch(r"[a-f0-9]{32}", job):
            raise Refused("unusable_state")
        attempt = panel.store / job
        try:
            self.journal(phase="rolling_back", error=error)
            panel.check_inputs()
            if panel.local_image_ids(self.state["images"]) != self.state["image_ids"]:
                raise Refused("recovery_failed")
            panel.remove_shadow(job)
            panel.stop()
            original = attempt / "data.previous"
            if original.exists() and not self.state["promoted"]:
                if panel.data.exists():
                    move(panel.data, attempt / "data.failed")
                move(original, panel.data)
            pins = (attempt / "config" / PINS).read_bytes()
            write_file(panel.root / PINS, pins)
            panel.start_data_services()
            panel.start("backend")
            panel.start("frontend")
            if panel.version() != self.state["previous"]:
                raise Refused("recovery_failed")
            panel.check_frontend()
            if panel.check_active_images(self.state["images"]) != self.state["image_ids"]:
                raise Refused("recovery_failed")
            self.journal(phase="rolled_back", stopped=False)
        except Exception as exc:
            LOG.error("Rollback needs operator recovery (%s)", type(exc).__name__)
            self.journal(phase="recovery_required", error="recovery_failed")


class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        credentials = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", credentials)
        if uid not in (0, PANEL_UID):
            return
        try:
            line = self.rfile.readline(4097)
            if len(line) > 4096 or not line.endswith(b"\n"):
                return
            request = json.loads(line.decode("ascii"))
            updater = self.server.updater
            if request == {"action": "status"}:
                result = updater.status()
            elif isinstance(request, dict) and set(request) == {"action", "version"} and request["action"] == "install":
                result = updater.install(request["version"])
            else:
                return
            self.wfile.write(json.dumps(result).encode("ascii") + b"\n")
        except (OSError, ValueError, RecursionError):
            return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-dir", required=True, type=Path)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--proxy", choices=PROXIES, default="none")
    parser.add_argument("--recover", action="store_true", help="Retry rollback and exit")
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO)
    panel = Panel(args.project_dir, args.project_name, args.proxy)
    trusted(SOCKET.parent, directory=True)
    with (panel.store / "worker.lock").open("a") as lock, (SOCKET.parent / "worker.lock").open("a") as runtime_lock:
        fcntl.flock(runtime_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        updater = Updater(panel)
        if args.recover:
            if updater.state["phase"] in ACTIVE | {"recovery_required"}:
                updater.restore(updater.state.get("error") or "interrupted")
            return int(updater.state["phase"] == "recovery_required")
        if updater.state["phase"] in ACTIVE:
            updater.restore(updater.state.get("error") or "interrupted")
        os.chown(SOCKET.parent, 0, PANEL_UID)
        os.chmod(SOCKET.parent, 0o750)
        SOCKET.unlink(missing_ok=True)
        try:
            with socketserver.UnixStreamServer(str(SOCKET), RequestHandler) as serving:
                serving.updater = updater
                os.chown(SOCKET, 0, PANEL_UID)
                os.chmod(SOCKET, 0o660)
                serving.serve_forever()
        finally:
            SOCKET.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
