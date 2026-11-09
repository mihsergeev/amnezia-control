import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import ValidationError

from app import xray, xray_reality as reality
from app.api import xray as xray_api


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


@pytest.fixture
def server():
    return {
        "inbounds": [
            {
                "port": 443,
                "protocol": "vless",
                "settings": {"clients": [{"id": "test-client", "flow": xray.FLOW}]},
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "serverNames": ["old.example", "extra.example"],
                        "dest": "old.example:443",
                        "privateKey": encode(X25519PrivateKey.generate().private_bytes_raw()),
                        "shortIds": ["1234", "", "ef"],
                    },
                },
            },
            {"protocol": "dokodemo-door", "port": 10085},
        ],
        "outbounds": [{"protocol": "freedom"}],
    }


class Connection:
    def __init__(self, server, *, fail_site=None, marker="UPDATED"):
        self.raw = json.dumps(server)
        self.id = "0" * 64
        self.fail_site = fail_site
        self.marker = marker
        self.checks = []
        self.applied = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def run(self, command, *, input=None, check=False):
        if ".HostConfig.PortBindings" in command:
            return SimpleNamespace(exit_status=0, stdout=f'{self.id}|{{"443/tcp":[{{"HostPort":"8443"}}]}}')
        if "cat /opt/amnezia/xray/server.json" in command and input is None:
            return SimpleNamespace(exit_status=0, stdout=self.raw)
        if "openssl s_client" in command and input is None:
            self.checks.append(command)
            return SimpleNamespace(
                exit_status=int(self.fail_site is not None and self.fail_site in command),
                stdout="sensitive stderr is never forwarded",
            )
        assert "xray run -test" in command and "trap cleanup EXIT" in command
        assert "mv -f" in command and "$DOCKER cp -a" in command
        assert "\0" not in command
        self.applied.append(input)
        if self.marker in {"UPDATED", "REVERT_FAILED"}:
            self.raw = input
        return SimpleNamespace(exit_status=int(self.marker != "UPDATED"), stdout=self.marker)


def request(state, *, index=0, site="new.example", dest="new.example:8444"):
    return reality.RealityUpdate(revision=state.revision, inbound_index=index, site=site, dest=dest)


def prepare(monkeypatch):
    monkeypatch.setattr(reality.deploy, "ensure_idle", AsyncMock())
    snapshot = AsyncMock(return_value="20260101-010203")
    monkeypatch.setattr(reality.deploy, "snapshot_config", snapshot)
    return snapshot


async def test_reality_read_reports_live_fields_without_private_key(server):
    settings = server["inbounds"][0]["streamSettings"]["realitySettings"]
    key = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(settings["privateKey"] + "="))
    state = await reality.read(Connection(server), xray.CONTAINER_NAME)
    item, = state.inbounds
    assert item.server_names == ["old.example", "extra.example"]
    assert item.short_ids == ["1234", "", "ef"]
    assert item.public_key == encode(key.public_key().public_bytes_raw())
    assert item.destination == "old.example:443"
    assert item.destination_port == 443
    assert item.destination_field == "dest"
    assert item.port == 443 and item.published_ports == [8443]
    assert settings["privateKey"] not in state.model_dump_json()
    assert "test-client" not in state.model_dump_json()


@pytest.mark.parametrize("alias", ["target", "dest", "both"])
async def test_reality_changes_only_selected_inbound_and_preserves_old_names(server, monkeypatch, alias):
    second = copy.deepcopy(server["inbounds"][0])
    second["port"] = 5443
    second["tag"] = "secondary"
    second_settings = second["streamSettings"]["realitySettings"]
    if alias != "dest":
        second_settings["target"] = second_settings["dest"]
    if alias == "target":
        del second_settings["dest"]
    server["inbounds"].append(second)
    snapshot = prepare(monkeypatch)
    conn = Connection(server)
    state = await reality.read(conn, xray.CONTAINER_NAME)
    assert [item.index for item in state.inbounds] == [0, 2]
    updated, changed = await reality.update(conn, xray.CONTAINER_NAME, request(state, index=2), "vpn.example")
    assert changed and updated.revision != state.revision
    assert updated.inbounds[1].server_names == ["new.example", "old.example", "extra.example"]
    assert updated.inbounds[1].public_key == state.inbounds[1].public_key
    assert updated.inbounds[1].short_ids == state.inbounds[1].short_ids
    for name in updated.inbounds[1].server_names:
        assert any(f"-servername {name}" in check for check in conn.checks)
    result = json.loads(conn.raw)
    assert result["inbounds"][:2] == server["inbounds"][:2]
    for key in ("target", "dest"):
        if key in second_settings:
            second_settings[key] = "new.example:8444"
    second_settings["serverNames"].insert(0, "new.example")
    assert result == server
    snapshot.assert_awaited_once_with(conn, "xray", container=xray.CONTAINER_NAME)


async def test_reality_does_not_write_if_new_target_cannot_serve_old_sni(server, monkeypatch):
    snapshot = prepare(monkeypatch)
    conn = Connection(server, fail_site="old.example")
    state = await reality.read(conn, xray.CONTAINER_NAME)
    with pytest.raises(reality.RealityValidation, match="old.example") as exc:
        await reality.update(conn, xray.CONTAINER_NAME, request(state), "vpn.example")
    assert "sensitive" not in str(exc.value)
    snapshot.assert_not_awaited()
    assert not conn.applied


@pytest.mark.parametrize("marker", ["VALIDATION_FAILED", "REVERTED", "REVERT_FAILED"])
async def test_reality_keeps_config_on_rejection_or_rollback(server, monkeypatch, marker):
    prepare(monkeypatch)
    conn = Connection(server, marker=marker)
    state = await reality.read(conn, xray.CONTAINER_NAME)
    with pytest.raises(xray.XrayError) as exc:
        await reality.update(conn, xray.CONTAINER_NAME, request(state), "vpn.example")
    assert "sensitive" not in str(exc.value)
    assert ("восстановлена" in str(exc.value)) == (marker == "REVERTED")
    assert (json.loads(conn.raw) == server) == (marker != "REVERT_FAILED")


@pytest.mark.parametrize("disk,marker,restarts", [
    ("old", "WRITE_FAILED", 0), ("new", "REVERTED", 1), ("foreign", "REVERT_FAILED", 0),
    ("stopped", "REVERTED", 1), ("restore_ack_restart_failed", "REVERT_FAILED", 1),
])
def test_lost_install_reply_recovers_only_our_write(tmp_path, monkeypatch, disk, marker, restarts):
    config = tmp_path / "server.json"
    config.write_bytes(b"old")
    monkeypatch.setattr(xray, "SERVER_JSON", config.name)
    monkeypatch.setattr(xray, "_DOCKER", "DOCKER=docker; ")
    monkeypatch.setattr(reality, "_tls_check", lambda *_: "true")
    fake_docker = tmp_path / "docker"
    fake_docker.write_text("""#!/bin/sh
ACTION=$1
shift
case "$ACTION" in
cp)
    [ "$1" = -a ] && shift
    if [ "$1" = - ]; then
        tar -xf - -C "${2#node:}"
    elif [ "$2" = - ]; then
        tar -cf - "${1#node:}"
    else
        exit 1
    fi
    ;;
inspect)
    if [ "$TEST_DISK" = stopped ]; then echo false; else echo true; fi
    ;;
exec)
    if [ "$1" = -i ]; then
        printf new > "$STAGED"
        cp "$CONFIG" "$STAGED.previous"
        exit
    fi
    shift
    case "$*" in
        *'mv -f'*'.previous '*)
            [ "$TEST_DISK" = stopped ] && exit 1
            "$@"
            if [ "$TEST_DISK" = restore_ack_restart_failed ]; then exit 124; fi
            ;;
        *'mv -f'*)
            case "$TEST_DISK" in
                new|stopped|restore_ack_restart_failed) mv "$STAGED" "$CONFIG" ;;
                foreign) printf foreign > "$CONFIG" ;;
            esac
            exit 124
            ;;
        *'/proc/'*) exit 0 ;;
        *) "$@" ;;
    esac
    ;;
restart)
    echo restart >> "$RESTARTS"
    if [ "$TEST_DISK" = restore_ack_restart_failed ]; then exit 1; fi
    ;;
esac
""", encoding="utf-8", newline="\n")
    fake_docker.chmod(0o700)
    staged = f"{config.name}.acontrol-reality.test.json"
    monkeypatch.setattr(reality.uuid, "uuid4", lambda: SimpleNamespace(hex="test"))
    command = reality._apply_script(
        "node", hashlib.sha256(b"old").hexdigest(), hashlib.sha256(b"new").hexdigest(),
        "127.0.0.1:443", ["new.example"], "old.example",
    )
    script = tmp_path / "apply.sh"
    script.write_text('export PATH="$PWD:$PATH" TMPDIR="$PWD"\n' + command.replace("exec 2>/dev/null\n", ""),
                      encoding="utf-8", newline="\n")
    restart_log = tmp_path / "restarts"
    result = subprocess.run(
        [shutil.which("bash") or "bash", script.name], cwd=tmp_path,
        stdin=subprocess.DEVNULL, capture_output=True, timeout=20,
        env={**os.environ, "CONFIG": config.name, "STAGED": staged, "TEST_DISK": disk,
             "RESTARTS": restart_log.name},
    )
    assert result.returncode != 0 and result.stdout.splitlines()[-1] == marker.encode(), result.stderr
    assert config.read_bytes() == (b"foreign" if disk == "foreign" else b"old")
    assert (restart_log.read_text().count("restart") if restart_log.exists() else 0) == restarts
    assert bool(list(tmp_path.glob("*/original.tar"))) == (marker == "REVERT_FAILED")


async def test_reality_stale_update_and_noop_do_not_restart(server, monkeypatch):
    snapshot = prepare(monkeypatch)
    conn = Connection(server)
    state = await reality.read(conn, xray.CONTAINER_NAME)
    result = await reality.update(
        conn, xray.CONTAINER_NAME, request(state, site="old.example", dest="old.example"), "vpn.example",
    )
    assert result == (state, False)
    conn.raw += "\n"
    with pytest.raises(reality.RealityConflict):
        await reality.update(conn, xray.CONTAINER_NAME, request(state), "vpn.example")
    snapshot.assert_not_awaited()
    assert not conn.applied and not conn.checks


async def test_reality_rejects_a_destination_on_its_own_published_port(server, monkeypatch):
    snapshot = prepare(monkeypatch)
    conn = Connection(server)
    state = await reality.read(conn, xray.CONTAINER_NAME)
    with pytest.raises(reality.RealityValidation, match="самого входа"):
        await reality.update(
            conn, xray.CONTAINER_NAME, request(state, dest="vpn.example:8443"), "vpn.example",
        )
    snapshot.assert_not_awaited()
    assert not conn.applied and not conn.checks


@pytest.mark.parametrize("custom", [
    {"serverNames": ["*.example"]},
    {"target": "conflict.example:443"},
    {"dest": "/tmp/custom.sock"},
    {"xver": 1},
])
async def test_custom_reality_configs_are_visible_and_read_only(server, monkeypatch, custom):
    snapshot = prepare(monkeypatch)
    server["inbounds"][0]["streamSettings"]["realitySettings"].update(custom)
    conn = Connection(server)
    state = await reality.read(conn, xray.CONTAINER_NAME)
    assert not state.inbounds[0].editable
    with pytest.raises(reality.RealityConflict):
        await reality.update(conn, xray.CONTAINER_NAME, request(state), "vpn.example")
    snapshot.assert_not_awaited()


@pytest.mark.parametrize("site,dest", [
    ("*.example.org", "example.org:443"),
    ("example.org", "example.org:10085"),
    ("example.org", "https://example.org"),
    (" ", "example.org"),
    ("example.org", " "),
])
def test_reality_update_validation(site, dest):
    with pytest.raises(ValidationError):
        reality.RealityUpdate(revision="0" * 64, inbound_index=0, site=site, dest=dest)


async def test_reality_api_requires_panel_auth_and_only_returns_public_fields(
    client, auth_headers, server, monkeypatch,
):
    conn = Connection(server)
    monkeypatch.setattr(xray_api, "_connect", lambda _: conn)
    monkeypatch.setattr(xray, "detect_container", AsyncMock(return_value=xray.CONTAINER_NAME))
    prepare(monkeypatch)
    created = await client.post("/api/servers", json={
        "name": "test", "host": "203.0.113.10", "ssh_port": 22, "ssh_user": "test",
    }, headers=auth_headers)
    path = f"/api/servers/{created.json()['id']}/xray/reality"
    assert (await client.get(path)).status_code == 401
    state = await client.get(path, headers=auth_headers)
    assert state.status_code == 200
    body = request(reality.RealityState.model_validate(state.json())).model_dump()
    assert (await client.put(path, json=body)).status_code == 401
    updated = await client.put(path, json=body, headers=auth_headers)
    assert updated.status_code == 200
    private = server["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
    assert private not in state.text and private not in updated.text
    assert updated.json()["inbounds"][0]["server_names"] == ["new.example", "old.example", "extra.example"]
    assert (await client.put(path, json=body, headers=auth_headers)).status_code == 409
