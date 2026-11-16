"""Country metadata must never silently stand in for applied gateway rules."""

import copy
import json
import shlex
import socket
import subprocess
import sys
from contextlib import asynccontextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import cascade, cascade_routes, geo, sshops
from app.models import Cascade, Server


@pytest.mark.parametrize("value", ["RU", "fi", "", "XK"])
async def test_server_override_is_explicit_and_does_not_change_ssh(client, auth_headers, value):
    response = await client.post("/api/servers", headers=auth_headers, json={
        "name": "entry", "host": "192.0.2.10", "country_override": value,
    })
    assert response.status_code == 201, response.text
    server = response.json()
    assert server["country_override"] == value.upper()
    assert server["country"] == value.upper()
    changed = await client.patch(f"/api/servers/{server['id']}", headers=auth_headers,
                                 json={"country_override": "de"})
    assert changed.status_code == 200, changed.text
    assert changed.json()["host"] == "192.0.2.10"
    assert changed.json()["country"] == changed.json()["country_override"] == "DE"
    cleared = await client.patch(f"/api/servers/{server['id']}", headers=auth_headers,
                                 json={"country_override": ""})
    assert cleared.json()["country"] == cleared.json()["country_override"] == ""


@pytest.mark.parametrize("value", ["ZZ", "R1", " RU", None, "RUS"])
async def test_invalid_override_is_rejected(client, auth_headers, value):
    response = await client.post("/api/servers", headers=auth_headers,
                                 json={"name": "entry", "host": "192.0.2.10", "country_override": value})
    assert response.status_code == 422


async def test_unchanged_auto_field_preserves_detected_country(client, auth_headers, session_factory):
    async with session_factory() as session:
        server = Server(name="entry", host="192.0.2.10", country="FI", country_override="")
        session.add(server)
        await session.commit()
        sid = server.id
    response = await client.patch(f"/api/servers/{sid}", headers=auth_headers,
                                  json={"name": "new label", "country_override": ""})
    assert response.status_code == 200
    assert response.json()["country"] == "FI"


async def test_private_management_country_comes_from_host_not_client_exit(client, auth_headers, monkeypatch):
    # TEST-NET management is deliberately non-global, like an RFC1918 target.
    created = await client.post("/api/servers", headers=auth_headers,
                                json={"name": "entry", "host": "192.0.2.10"})
    sid = created.json()["id"]
    lookups = []

    async def check(*_args):
        return sshops.CheckResult(ok=True, amnezia_containers=["amnezia-awg"])

    @asynccontextmanager
    async def connect(*_args):
        yield object()

    async def lookup(host):
        lookups.append(host)
        return "FI" if host == "198.51.100.10" else ""

    async def host_probe(_conn):
        return "198.51.100.10"

    async def client_probe(_conn):
        return "203.0.113.20"

    async def ip_info(_ip):
        return "DE", "fixture"

    monkeypatch.setattr(sshops, "check_server", check)
    monkeypatch.setattr(sshops, "connect", connect)
    monkeypatch.setattr(sshops, "probe_host_egress", host_probe)
    monkeypatch.setattr(sshops, "probe_egress", client_probe)
    monkeypatch.setattr(geo, "country_code", lookup)
    monkeypatch.setattr(geo, "ip_info", ip_info)
    response = await client.post(f"/api/servers/{sid}/check", headers=auth_headers)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["host"] == "192.0.2.10"
    assert result["country"] == "FI"
    assert result["egress_country"] == "DE"
    assert lookups == ["192.0.2.10", "198.51.100.10"]
    await client.patch(f"/api/servers/{sid}", headers=auth_headers, json={"country_override": "RU"})
    lookups.clear()
    response = await client.post(f"/api/servers/{sid}/check", headers=auth_headers)
    assert response.json()["country"] == response.json()["country_override"] == "RU"
    assert lookups == []


@pytest.mark.parametrize("value", ["192.0.2.10", "203.0.113.20", "localhost", "198.51.100.1\nEGRESS=bad", "bad"])
async def test_host_probe_rejects_non_global_and_injected_output(value):
    class Connection:
        async def run(self, command, **kwargs):
            assert command == sshops.HOST_EGRESS_COMMAND
            assert kwargs == {"check": False, "timeout": 15}
            return SimpleNamespace(stdout=f"EGRESS={value}")

    assert await sshops.probe_host_egress(Connection()) == ""
    assert "--noproxy '*'" in sshops.HOST_EGRESS_COMMAND
    assert "--max-filesize 64" in sshops.HOST_EGRESS_COMMAND
    assert "-L" not in sshops.HOST_EGRESS_COMMAND


async def test_failed_host_geography_does_not_suppress_client_egress(client, auth_headers, monkeypatch):
    @asynccontextmanager
    async def connect(*_args):
        yield object()

    async def check(*_args):
        return sshops.CheckResult(ok=True, amnezia_containers=["amnezia-awg"])

    async def host_probe(_conn):
        raise RuntimeError("Host discovery unavailable")

    async def client_probe(_conn):
        return "203.0.113.20"

    async def country(_host):
        return ""

    async def info(_ip):
        return "FI", "fixture"

    monkeypatch.setattr(sshops, "connect", connect)
    monkeypatch.setattr(sshops, "check_server", check)
    monkeypatch.setattr(sshops, "probe_host_egress", host_probe)
    monkeypatch.setattr(sshops, "probe_egress", client_probe)
    monkeypatch.setattr(geo, "country_code", country)
    monkeypatch.setattr(geo, "ip_info", info)
    created = await client.post("/api/servers", headers=auth_headers,
                                json={"name": "entry", "host": "192.0.2.10"})
    response = await client.post(f"/api/servers/{created.json()['id']}/check", headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json()["egress_ip"] == "203.0.113.20"
    assert response.json()["egress_country"] == "FI"
    assert response.json()["egress_at"] is not None


def test_country_state_uses_actual_rules_not_metadata():
    config = json.loads(cascade.entry_gateway_config("gre", "203.0.113.20", {}, country="RU"))
    rules = config["routing"]["rules"]
    assert cascade_routes.routing_state(rules, "FI", []) == {"state": "pending", "applied_country": "RU"}
    assert cascade_routes.routing_state(rules, "RU", []) == {"state": "synced", "applied_country": "RU"}
    assert cascade_routes.routing_state(rules + [{"domain": ["domain:example.com"], "outboundTag": "exit"}], "RU", []) == {
        "state": "unknown", "applied_country": None,
    }


@pytest.mark.parametrize("failure", [None, "owner", "stopped", "newer_file", "extra_config", "pending", "different_command"])
def test_read_state_only_accepts_a_confirmed_running_config(tmp_path, monkeypatch, capsys, failure):
    path = tmp_path / "config.json"
    rules = [{"ip": ["geoip:private"], "outboundTag": "block"}, *cascade_routes.xray_rules([]), *cascade.local_rules("RU")]
    path.write_text(json.dumps({"routing": {"rules": rules}, "private_transport": "must-never-be-exported"}), encoding="utf-8")
    if failure == "extra_config":
        (tmp_path / "other.json").write_text("{}", encoding="utf-8")
    if failure == "pending":
        (tmp_path / ".routes-pending").write_text("pending", encoding="utf-8")

    def docker(*_args, **_kwargs):
        return SimpleNamespace(stdout=json.dumps([{
            "Config": {"Labels": {"org.amnezia.control.owner": "wrong" if failure == "owner" else "owner"},
                       "Entrypoint": ["/usr/local/bin/xray"],
                       "Cmd": ["run", "-config", "/other.json"] if failure == "different_command" else ["run", "-confdir", "/usr/local/etc/xray/"]},
            "State": {"Running": failure != "stopped", "StartedAt": "2100-01-01T00:00:00Z"},
            "Mounts": [{"Source": str(tmp_path), "Destination": "/usr/local/etc/xray"}],
        }]))

    lstat = Path.lstat

    def config_stat(self, *args, **kwargs):
        meta = lstat(self, *args, **kwargs)
        if self == path:
            return SimpleNamespace(st_mode=meta.st_mode, st_size=meta.st_size, st_uid=0,
                                   st_mtime=5_000_000_000 if failure == "newer_file" else 1)
        return meta

    monkeypatch.setattr(Path, "lstat", config_stat)
    monkeypatch.setattr(subprocess, "run", docker)
    monkeypatch.setattr(sys, "argv", ["-c", json.dumps([str(tmp_path), "gateway", "owner"])])
    if failure:
        with pytest.raises(SystemExit) as error:
            exec(cascade_routes._READ, {})
        assert error.value.code == 73
        assert capsys.readouterr().out == ""
    else:
        exec(cascade_routes._READ, {})
        output = capsys.readouterr().out
        assert json.loads(output) == rules
        assert "must-never" not in output


@pytest.mark.parametrize("transport", ["gre", "awg", "vless"])
def test_country_update_preserves_entire_transport_config_and_custom_rules(tmp_path, monkeypatch, transport):
    params = {"port": 443, "uuid": "fixture-id", "sni": "example.com", "public_key": "fixture-public", "short_id": "fixture"}
    original = json.loads(cascade.entry_gateway_config(transport, "203.0.113.20", params, country="RU"))
    original["customRootSetting"] = {"preserve": [1, 2, 3]}
    custom = {"domain": ["domain:custom.example"], "outboundTag": "exit"}
    original["routing"]["rules"].insert(3, custom)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(original), encoding="utf-8")
    script = cascade_routes.update_script(str(tmp_path), "gateway", 1080, "owner", [], "FI")
    words = shlex.split(script)
    monkeypatch.setattr(sys, "argv", ["-c", words[-1]])
    calls = []

    def docker(args, **kwargs):
        calls.append(args)
        if args[1] == "inspect":
            return SimpleNamespace(stdout=json.dumps([{
                "Id": "a" * 64, "Config": {"Labels": {"org.amnezia.control.owner": "owner"}},
                "State": {"Running": True}, "Mounts": [{"Source": str(tmp_path), "Destination": "/usr/local/etc/xray"}],
            }]))
        return SimpleNamespace(stdout="")

    lstat = Path.lstat

    def config_stat(self, *args, **kwargs):
        meta = lstat(self, *args, **kwargs)
        return SimpleNamespace(st_mode=meta.st_mode, st_size=meta.st_size, st_uid=0) if self == path else meta

    monkeypatch.setattr(subprocess, "run", docker)
    monkeypatch.setattr(Path, "lstat", config_stat)
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: nullcontext())
    exec(cascade_routes._UPDATE, {})
    updated = json.loads(path.read_text(encoding="utf-8"))
    expected = copy.deepcopy(original)
    expected["routing"]["rules"] = [original["routing"]["rules"][0], *cascade_routes.xray_rules([]), custom, *cascade_routes.country_rules("FI")]
    assert updated == expected  # Deep equality includes all keys and transport credentials.
    assert not any(args[1] in {"create", "rm", "run"} for args in calls)
    assert [args for args in calls if args[1] == "restart"] == [["docker", "restart", "gateway"]]


async def test_routes_apply_and_live_state_preserve_params_and_fail_closed(client, auth_headers, session_factory, monkeypatch):
    from app.api import cascades as api

    params = {"entry_ip": "192.0.2.10", "exit_ip": "203.0.113.20", "entry_country": "RU",
              "entry_country_override": "", "runtime_owner": "a" * 32, "runtime_layout": 2,
              "entry_port": 12345, "exit_port": 23456, "keys": {"keep": "fixture"}}
    async with session_factory() as session:
        entry = Server(name="entry", host="192.0.2.10", country="FI")
        exit_ = Server(name="exit", host="203.0.113.20")
        session.add_all([entry, exit_])
        await session.flush()
        row = Cascade(entry_server_id=entry.id, exit_server_id=exit_.id, transport="gre", status="ready",
                      params=json.dumps(params), result=json.dumps({"health": {"ok": True}, "ru": "192.0.2.10"}))
        session.add(row)
        await session.commit()
        cid = row.id

    live = json.loads(cascade.entry_gateway_config("gre", "203.0.113.20", params, country="RU"))["routing"]["rules"]
    status = 0

    class Connection:
        async def run(self, command, **_kwargs):
            nonlocal live
            if ".routes-test-" in command:
                live = [live[0], *cascade_routes.xray_rules([]), *cascade_routes.country_rules("FI")]
                return SimpleNamespace(exit_status=status, stdout="")
            return SimpleNamespace(exit_status=status, stdout=json.dumps(live))

    @asynccontextmanager
    async def locked(_server):
        yield Connection()

    monkeypatch.setattr(api, "_locked", locked)
    path = f"/api/cascades/{cid}/routes"
    before = await client.get(path + "/state", headers=auth_headers)
    assert before.json() == {"state": "pending", "applied_country": "RU", "desired_country": "FI"}
    saved = await client.put(path, headers=auth_headers, json={"routes": [], "entry_country": ""})
    assert saved.status_code == 200, saved.text
    assert saved.json()["entry_country"] == "FI"
    after = await client.get(path + "/state", headers=auth_headers)
    assert after.json() == {"state": "synced", "applied_country": "FI", "desired_country": "FI"}
    async with session_factory() as session:
        row = await session.get(Cascade, cid)
        assert json.loads(row.params) == params | {"entry_country": "FI", "routes": []}
        assert "health" not in json.loads(row.result)
    status = 73
    unknown = await client.get(path + "/state", headers=auth_headers)
    assert unknown.json()["state"] == "unknown"
    failed = await client.put(path, headers=auth_headers, json={"routes": [], "entry_country": "DE"})
    assert failed.status_code == 502
    async with session_factory() as session:
        assert json.loads((await session.get(Cascade, cid)).params)["entry_country"] == "FI"
