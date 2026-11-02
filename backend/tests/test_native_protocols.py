import base64
import json
import subprocess
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select

from app import awg, collector, deploy, expiry, native_deploy, native_vpn, native_snapshots, openvpn, protoremove, sshops, torrent
from app.api import native_vpn as api
from app.models import AwgConfig, NativeVpnConfig, PausedClient, Server


@pytest.mark.parametrize("protocol,transport", [("wireguard", "udp"), ("openvpn-native", "udp"), ("openvpn-native", "tcp")])
def test_native_deployment_is_valid_shell_and_uses_separate_owned_resources(protocol, transport):
    script = native_deploy.build_script(protocol, native_deploy.SPECS[protocol].port,
                                        transport, "1.1.1.1, 1.0.0.1")
    # Bytes preserve LF on Windows; text-mode stdin would translate it to CRLF.
    result = subprocess.run(["bash", "-n"], input=script.encode(), capture_output=True)
    assert result.returncode == 0, "Native deployment shell must be valid"
    assert "--restart unless-stopped" in script
    assert "OLD_RENAMED=no" in script and "NEW_ATTEMPT=no" in script
    assert "org.amnezia.control.native" in script
    assert "amnezia-awg2" not in script and "amnezia-openvpn-cloak" not in script


def test_native_runtime_uses_interface_independent_nat_and_standard_engines():
    assert "wireguard-go" in native_deploy.WG_DOCKERFILE
    assert "amneziawg" not in native_deploy.WG_DOCKERFILE
    assert "! -o wg0" in native_deploy.WG_START and "! -o tun0" in native_deploy.OVPN_START
    assert "-o eth0" not in native_deploy.WG_START + native_deploy.OVPN_START
    assert "cloak" not in native_deploy.OVPN_DOCKERFILE.lower()
    assert native_deploy.OVPN_START.index("chmod 770 /run/openvpn") < native_deploy.OVPN_START.index("chown nobody /run/openvpn")
    for direction in ("-i wg0", "-o wg0"):
        assert f"FORWARD {direction} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" in native_deploy.WG_START


async def test_native_wireguard_export_matches_server_mtu_without_proprietary_fields(monkeypatch):
    async def state(*args): return object()
    async def create(*args, **kwargs):
        return SimpleNamespace(public_key="fixture"), "[Interface]\nAddress = 192.0.2.2/32\n[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\n"
    monkeypatch.setattr(native_vpn, "wg_state", state)
    monkeypatch.setattr(awg, "create_client", create)
    _, text = await native_vpn.issue(object(), "wireguard", "client", "203.0.113.10", "1.1.1.1")
    assert "MTU = 1380" in text and text.count("[Interface]") == 1
    assert "Jc" not in text and "S1" not in text


async def test_management_disconnect_waits_for_kill_ack_without_early_quit(monkeypatch):
    commands = []
    async def run(conn, command, **kwargs):
        commands.append(command)
        return "SUCCESS: common name fixture killed"
    monkeypatch.setattr(native_vpn, "run", run)
    await native_vpn.disconnect(object(), "fixture")
    assert "socat -t 3" in commands[0] and "quit" not in commands[0]
    script = native_deploy.build_script("openvpn-native", 1194, "udp", "1.1.1.1")
    assert "quit" not in next(line for line in script.splitlines() if line.startswith("for n in"))


def test_native_ovpn_is_an_ordinary_inline_profile():
    text = native_vpn.ovpn_profile("203.0.113.10", 1194, "udp", "1.1.1.1", {
        "ca": "test-ca", "cert": "test-cert", "key": "test-key", "tls-auth": "test-ta"})
    assert "remote 203.0.113.10 1194" in text and "proto udp" in text
    assert "localhost" not in text and "127.0.0.1" not in text and "vpn://" not in text
    assert all(f"<{key}>" in text for key in ("ca", "cert", "key", "tls-auth"))
    assert "remote-cert-tls server" in text
    assert "redirect-gateway ipv6" in text and "block-ipv6" in text
    assert "ifconfig-ipv6 " in text
    with pytest.raises(native_vpn.NativeError):
        native_vpn.ovpn_profile("example.invalid\nscript-security 2", 1194, "udp", "", {})


def test_native_openvpn_server_blocks_ipv6_with_documented_tun_routes():
    text = native_deploy.ovpn_server_config(1194, "udp", "1.1.1.1")
    assert 'push "ifconfig-ipv6 ' in text
    assert 'push "redirect-gateway ipv6"' in text
    assert "\nblock-ipv6\n" in text


async def test_detection_never_treats_docker_failure_as_protocol_absence():
    class Connection:
        async def run(self, *args, **kwargs):
            return SimpleNamespace(exit_status=1, stdout="", stderr="daemon unavailable")
    with pytest.raises(native_vpn.NativeError) as error:
        await native_vpn.detect(Connection(), "wireguard")
    assert not isinstance(error.value, native_vpn.NativeNotDeployed)


async def test_detection_requires_exact_native_label_and_running_state():
    class Connection:
        def __init__(self, label, running=True): self.label, self.running = label, running
        async def run(self, *args, **kwargs):
            return SimpleNamespace(exit_status=0, stdout=json.dumps([{
                "Config": {"Labels": {native_deploy.LABEL: self.label}},
                "State": {"Running": self.running}}]), stderr="")
    for connection in (Connection("awg"), Connection("wireguard", False)):
        with pytest.raises(native_vpn.NativeError):
            await native_vpn.detect(connection, "wireguard")
    assert await native_vpn.detect(Connection("wireguard"), "wireguard") == "acontrol-wireguard"


async def test_image_with_container_name_does_not_count_as_installed_container():
    class Connection:
        async def run(self, command, **kwargs):
            if "container inspect" in command:
                return SimpleNamespace(exit_status=1, stdout="", stderr="No such container")
            if " ps -a " in command:
                return SimpleNamespace(exit_status=0, stdout="unrelated\n", stderr="")
            pytest.fail("Container inspection must not adopt a same-named image")
    with pytest.raises(native_vpn.NativeNotDeployed):
        await native_vpn.detect(Connection(), "wireguard")


def test_installer_inspection_failure_is_fail_closed_before_directory_writes():
    script = native_deploy.build_script("wireguard", 51820, "udp", "1.1.1.1")
    function = next(line for line in script.splitlines() if line.startswith("container_present(){"))
    prefix = "fail(){ echo SAFE_FAILURE; exit 73; }; sudo(){ \"$@\"; }; "
    daemon = prefix + "docker(){ echo 'Cannot connect to daemon' >&2; return 1; }; " + function
    result = subprocess.run(["bash"], input=(daemon + '; if container_present test; then echo PRESENT; else echo ABSENT; fi').encode(), capture_output=True)
    assert result.returncode == 73 and b"ABSENT" not in result.stdout
    absent = prefix + "docker(){ echo 'Error: No such container: test' >&2; return 1; }; " + function
    result = subprocess.run(["bash"], input=(absent + '; if container_present test; then exit 74; fi').encode(), capture_output=True)
    assert result.returncode == 0
    assert 'docker inspect ' not in script
    assert script.index('unsafe native path') < script.index('sudo mkdir -p "$D"')


async def test_retry_reads_owned_listener_metadata_without_regenerating_keys():
    commands = []
    class Connection:
        async def run(self, command, **kwargs):
            commands.append(command)
            if "container inspect" in command:
                return SimpleNamespace(exit_status=1, stdout="", stderr="")
            if " ps -a " in command:
                return SimpleNamespace(exit_status=0, stdout="", stderr="")
            assert command.startswith("sudo -n python3 - ")
            assert "is_symlink" in kwargs["input"]
            return SimpleNamespace(exit_status=0, stdout=json.dumps({
                "protocol": "wireguard", "port": 51821, "transport": "udp"}), stderr="")
    assert await native_vpn.installed_metadata(Connection(), "wireguard") == {"port": 51821, "transport": "udp"}
    assert all("genkey" not in command for command in commands)


async def test_retry_listener_is_preserved_and_incompatible_port_is_rejected(
    client, auth_headers, session_factory, monkeypatch,
):
    sid = await server(session_factory)
    stub_connection(monkeypatch)
    scripts = []
    async def prerequisites(*args): pass
    async def metadata(*args): return {"port": 51821, "transport": "udp"}
    async def detect(*args): raise native_vpn.NativeNotDeployed("not created yet")
    async def owner(*args, **kwargs): return None
    async def launch(conn, script, **kwargs): scripts.append(script)
    monkeypatch.setattr(native_vpn, "deployment_prerequisites", prerequisites)
    monkeypatch.setattr(native_vpn, "installed_metadata", metadata)
    monkeypatch.setattr(native_vpn, "detect", detect)
    monkeypatch.setattr(deploy, "port_owner", owner)
    monkeypatch.setattr(deploy, "launch", launch)
    monkeypatch.setattr(api.deploywatch, "spawn", lambda *args: None)
    response = await client.post(f"/api/servers/{sid}/wireguard/deploy", headers=auth_headers, json={"port": 51820})
    assert response.status_code == 409 and not scripts
    response = await client.post(f"/api/servers/{sid}/wireguard/deploy", headers=auth_headers, json={})
    assert response.status_code == 202
    assert "-p 51821:51821/udp" in scripts[0]


async def test_missing_docker_is_an_immediate_readable_api_conflict(
    client, auth_headers, session_factory, monkeypatch,
):
    sid = await server(session_factory)
    stub_connection(monkeypatch)
    async def prerequisites(*args): raise native_vpn.NativeNotDeployed("Для установки нужен Docker")
    async def launch(*args, **kwargs): pytest.fail("must not launch background installer")
    monkeypatch.setattr(native_vpn, "deployment_prerequisites", prerequisites)
    monkeypatch.setattr(deploy, "launch", launch)
    response = await client.post(f"/api/servers/{sid}/wireguard/deploy", headers=auth_headers, json={})
    assert response.status_code == 409 and "Docker" in response.json()["detail"]


async def test_unavailable_native_container_never_becomes_successful_expiry(monkeypatch):
    async def idle(*args, **kwargs): pass
    async def detect(*args, **kwargs): raise native_vpn.NativeError("temporarily stopped")
    monkeypatch.setattr(deploy, "ensure_idle", idle)
    monkeypatch.setattr(native_vpn, "detect", detect)
    with pytest.raises(native_vpn.NativeError):
        await expiry._revoker(object(), SimpleNamespace(host="203.0.113.10"), "wireguard")


def test_check_parser_keeps_native_protocols_separate_from_amnezia():
    result = sshops._parse_check_output(
        "HOST=test\nacontrol-wireguard\nacontrol-openvpn-native\namnezia-openvpn-cloak\n"
        "PROTO=acontrol-wireguard|wireguard\nPROTO=acontrol-openvpn-native|openvpn-native\n"
        "PROTO=amnezia-openvpn-cloak|openvpn\n")
    assert result.protocols["acontrol-wireguard"] == "wireguard"
    assert result.protocols["acontrol-openvpn-native"] == "openvpn-native"
    assert result.protocols["amnezia-openvpn-cloak"] == "openvpn"


async def server(session_factory):
    async with session_factory() as session:
        value = Server(name="native-test", host="203.0.113.10")
        session.add(value)
        await session.commit()
        return value.id


def stub_connection(monkeypatch):
    @asynccontextmanager
    async def connection(*args): yield object()
    async def idle(*args, **kwargs): pass
    monkeypatch.setattr(api, "connection", connection)
    monkeypatch.setattr(deploy, "ensure_idle", idle)


@pytest.mark.parametrize("protocol", native_vpn.PROTOCOLS)
async def test_native_endpoints_require_jwt(client, protocol):
    assert (await client.get(f"/api/servers/1/{protocol}")).status_code == 401
    assert (await client.post(f"/api/servers/1/{protocol}/clients", json={"name": "client"})).status_code == 401


async def test_native_wireguard_config_does_not_overwrite_awg_with_same_public_key(
    client, auth_headers, session_factory, monkeypatch,
):
    sid = await server(session_factory)
    public_key = base64.b64encode(bytes(range(32))).decode()
    async with session_factory() as session:
        session.add(AwgConfig(server_id=sid, protocol="awg", public_key=public_key,
                              name="legacy", config="legacy-config"))
        await session.commit()
    stub_connection(monkeypatch)
    async def issue(*args, **kwargs):
        return {"name": "native", "public_key": public_key, "address": "192.0.2.2/32"}, "native-config"
    monkeypatch.setattr(native_vpn, "issue", issue)
    response = await client.post(f"/api/servers/{sid}/wireguard/clients", headers=auth_headers,
                                 json={"name": "native"})
    assert response.status_code == 201
    assert response.json()["format"] == "wireguard" and response.json()["filename"] == "native.conf"
    assert "config_amnezia" not in response.json()
    downloaded = await client.post(f"/api/servers/{sid}/wireguard/config", headers=auth_headers,
                                   json={"public_key": public_key})
    assert downloaded.status_code == 200 and downloaded.json()["config"] == "native-config"
    async with session_factory() as session:
        assert (await session.scalar(select(AwgConfig))).config == "legacy-config"
        assert (await session.scalar(select(NativeVpnConfig))).protocol == "wireguard"


async def test_native_openvpn_returns_ovpn_and_pause_resume_keeps_profile(
    client, auth_headers, session_factory, monkeypatch,
):
    sid = await server(session_factory)
    stub_connection(monkeypatch)
    async def issue(*args, **kwargs):
        return {"client_id": "client_one", "name": "native", "creation_date": ""}, "ovpn-config"
    async def state(*args):
        return {"clients": [{"client_id": "client_one", "name": "native"}]}
    calls = []
    async def pause(*args): calls.append("pause"); return {}
    async def resume(*args): calls.append("resume")
    monkeypatch.setattr(native_vpn, "issue", issue)
    monkeypatch.setattr(native_vpn, "state", state)
    monkeypatch.setattr(native_vpn, "pause", pause)
    monkeypatch.setattr(native_vpn, "resume", resume)
    response = await client.post(f"/api/servers/{sid}/openvpn-native/clients", headers=auth_headers,
                                 json={"name": "native"})
    assert response.status_code == 201 and response.json()["filename"] == "native.ovpn"
    for action in ("pause", "resume"):
        response = await client.post(f"/api/servers/{sid}/openvpn-native/{action}",
                                     headers=auth_headers, json={"client_id": "client_one"})
        assert response.status_code == 204
    assert calls == ["pause", "resume"]
    async with session_factory() as session:
        assert await session.scalar(select(PausedClient)) is None
        assert (await session.scalar(select(NativeVpnConfig))).config == "ovpn-config"


async def test_native_expiry_cleans_only_requested_protocol(session_factory):
    async with session_factory() as session:
        session.add_all([NativeVpnConfig(server_id=1, protocol=protocol,
            client_id="client", name="native", config="fixture") for protocol in native_vpn.PROTOCOLS])
        await session.commit()
        await expiry.cleanup_client_db(session, 1, "wireguard", "client")
        await session.commit()
        values = list(await session.scalars(select(NativeVpnConfig)))
        assert [value.protocol for value in values] == ["openvpn-native"]


async def test_native_pki_restore_is_explicitly_unavailable_without_node_writes(client, auth_headers, session_factory, monkeypatch):
    sid = await server(session_factory)
    @asynccontextmanager
    async def connection(*args): pytest.fail("must not write node"); yield
    monkeypatch.setattr(api, "connection", connection)
    response = await client.post(f"/api/servers/{sid}/openvpn-native/config-restore", headers=auth_headers,
                                 json={"id": "20261102-120000"})
    assert response.status_code == 409


def test_native_protocols_have_distinct_snapshot_and_removal_tags():
    for protocol in native_vpn.PROTOCOLS:
        assert protocol in protoremove.PROTOCOLS
        assert deploy._SNAP_SPECS[protocol]["container"] == native_deploy.SPECS[protocol].container


async def test_native_node_snapshot_is_private_before_writing_archive():
    class Connection:
        async def run(self, command, **kwargs):
            assert command.startswith("umask 077;")
            assert command.index('chmod 700 "$R"') < command.index('> "$F"')
            assert 'chmod 700 "$R" || exit 1' in command
            return SimpleNamespace(stdout="SNAP 20261102-150000", exit_status=0)
    assert await deploy.snapshot_config(Connection(), "wireguard") == "20261102-150000"


def test_legacy_openvpn_deployment_never_adopts_native_pki():
    script = openvpn.build_deploy_script(443, "example.invalid", "203.0.113.10")
    source = next(line for line in script.splitlines() if line.startswith("SRC=$("))
    mock = "sudo(){ printf '%s\\n' acontrol-openvpn-native amnezia-openvpn-cloak; }; "
    result = subprocess.run(["bash"], input=(mock + source + '; printf "%s" "$SRC"').encode(), capture_output=True)
    assert result.returncode == 0 and result.stdout == b"amnezia-openvpn-cloak"


async def test_native_collector_and_torrent_keep_protocol_identity(monkeypatch):
    async def state(conn, protocol, host):
        if protocol == "wireguard":
            return {"container": "acontrol-wireguard", "clients": [{"public_key": "fixture-key", "name": "client",
                "address": "192.0.2.2/32", "rx_bytes": 100, "tx_bytes": 200}]}
        return {"container": "acontrol-openvpn-native", "clients": [{"client_id": "fixture-cn", "name": "other",
            "rx_bytes": 300, "tx_bytes": 400, "connected": True}]}
    async def raw(*args): return ""
    async def conts(*args): return {"new": None, "legacy": None}
    async def names(*args): return []
    async def legacy(*args): raise openvpn.OpenVpnError("not installed")
    monkeypatch.setattr(native_vpn, "state", state)
    monkeypatch.setattr(openvpn, "read_status_text", raw)
    monkeypatch.setattr(awg, "detect_awg_containers", conts)
    monkeypatch.setattr(deploy, "awg3_containers", names)
    monkeypatch.setattr(openvpn, "detect_container", legacy)
    totals, rows = await collector._native_part(object(), "203.0.113.10")
    assert totals["rx"] == 400 and totals["tx"] == 600 and totals["total"] == 2 and totals["online"] == 1
    assert {row["protocol"] for row in rows} == {"wireguard", "openvpn-native"}
    networks = await torrent.node_nets(object(), "203.0.113.10")
    assert networks[0]["ips"]["192.0.2.2"] == ("fixture-key", "client")
    assert {row["protocol"] for row in networks} == {"wireguard", "openvpn-native"}


async def test_native_private_profiles_and_snapshot_manifests_survive_server_transfer(
    client, auth_headers, session_factory,
):
    sid = await server(session_factory)
    async with session_factory() as session:
        node = await session.get(Server, sid)
        session.add(NativeVpnConfig(server_id=sid, protocol="wireguard", client_id="fixture-key",
                                   name="client", config="private-fixture-profile"))
        await session.commit()
        await native_snapshots.save(session, node, "wireguard", "20261102-120000", {"port": 51820, "transport": "udp"})
    response = await client.get(f"/api/servers/{sid}/export", headers={**auth_headers, "X-Confirm-Password": "testpass"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["tables"]["native_vpn_configs"][0]["config"] == "private-fixture-profile"
    assert len(payload["native_snapshots"]) == 1
    assert (await client.delete(f"/api/servers/{sid}", headers=auth_headers)).status_code == 200
    response = await client.post("/api/servers/import-file", headers=auth_headers, json=payload)
    assert response.status_code == 200
    new_sid = response.json()["server_id"]
    async with session_factory() as session:
        node = await session.get(Server, new_sid)
        manifest = await native_snapshots.load(session, node, "wireguard", "20261102-120000")
        assert manifest["rows"]["profiles"][0]["config"] == "private-fixture-profile"


async def test_full_backup_restore_retains_native_private_profiles_and_snapshot_metadata(
    client, auth_headers, session_factory,
):
    sid = await server(session_factory)
    async with session_factory() as session:
        node = await session.get(Server, sid)
        session.add(NativeVpnConfig(server_id=sid, protocol="openvpn-native", client_id="fixture-cn",
                                   name="native", config="inline-private-fixture"))
        await session.commit()
        await native_snapshots.save(session, node, "openvpn-native", "20261102-130000", {"port": 1194, "transport": "udp"})
    archive = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
    assert archive.status_code == 200
    async with session_factory() as session:
        await session.execute(delete(NativeVpnConfig))
        await native_snapshots.delete_server(session, sid)
        await session.commit()
    restored = await client.post("/api/backup/restore", content=archive.content,
                                headers={**auth_headers, "X-Confirm-Password": "testpass"})
    assert restored.status_code == 200 and restored.json()["restored"]["native_vpn_configs"] == 1
    async with session_factory() as session:
        assert (await session.scalar(select(NativeVpnConfig))).config == "inline-private-fixture"
        node = await session.get(Server, sid)
        manifest = await native_snapshots.load(session, node, "openvpn-native", "20261102-130000")
        assert manifest["rows"]["profiles"][0]["config"] == "inline-private-fixture"
