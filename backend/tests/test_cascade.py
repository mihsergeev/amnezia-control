import json
import shutil
import socket
import subprocess
import sys

import httpx
import pytest

from app import cascade
from app.models import Cascade, Server

VLESS = {
    "entry_ip": "203.0.113.10", "exit_ip": "198.51.100.20", "port": 443,
    "uuid": "11111111-2222-3333-4444-555555555555", "private_key": "priv",
    "public_key": "pub", "short_id": "0123456789abcdef", "sni": "www.example.com",
}


def _bash_ok(script: str) -> None:
    r = subprocess.run(
        [shutil.which("bash"), "-n"], input=script, capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
@pytest.mark.parametrize("transport", ["vless", "gre"])
def test_scripts_are_valid_shell(transport) -> None:
    _bash_ok(cascade.build_exit_script(transport, "203.0.113.10", 3, VLESS))
    _bash_ok(cascade.build_entry_script(transport, "198.51.100.20", 3, VLESS))
    _bash_ok(cascade.build_remove_entry() + cascade.ufw_cleanup("198.51.100.20", None))
    _bash_ok(cascade.build_remove_exit() + cascade.ufw_cleanup("203.0.113.10", 443))
    _bash_ok(cascade.build_check_command())
    for text in (cascade._GRE_TUN_SH, cascade._TPROXY_SH, cascade._GEO_SH):
        _bash_ok(cascade._fill(text))


def test_entry_turns_clients_over_only_after_check() -> None:
    script = cascade.build_entry_script("gre", "198.51.100.20", 3, VLESS)
    # клиенты уходят в шлюз только после того, как через него открылся интернет
    assert script.index('[ -n "$EG" ] || fail') < script.index("enable --now acontrol-cascade-tproxy")
    assert script.rstrip().endswith('echo "DEPLOY_DONE"')


def test_gre_defaults_per_role() -> None:
    exit_script = cascade.build_exit_script("gre", "203.0.113.10", 3, {})
    assert "ROLE=exit" in exit_script and "NET=10.99.4.0/30" in exit_script
    assert "INNER=10.99.4.2/30" in exit_script and "REMOTE=203.0.113.10" in exit_script
    entry_script = cascade.build_entry_script("gre", "198.51.100.20", 3, {})
    assert "ROLE=entry" in entry_script and "MARK=0x200" in entry_script
    assert "INNER=10.99.4.1/30" in entry_script


def test_gateway_default_route_is_exit() -> None:
    gre = json.loads(cascade.entry_gateway_config("gre", "198.51.100.20", {}))
    assert gre["outbounds"][0]["tag"] == "exit"
    assert gre["outbounds"][0]["streamSettings"]["sockopt"]["mark"] == cascade.GRE_MARK
    vless = json.loads(cascade.entry_gateway_config("vless", "198.51.100.20", VLESS))
    out = vless["outbounds"][0]
    assert out["tag"] == "exit" and out["protocol"] == "vless"
    assert out["settings"]["vnext"][0] == {
        "address": "198.51.100.20", "port": 443,
        "users": [{"id": VLESS["uuid"], "encryption": "none", "flow": "xtls-rprx-vision-udp443"}],
    }
    rules = vless["routing"]["rules"]
    assert {"ip": ["geoip:ru"], "outboundTag": "direct"} in rules


def test_exit_vless_config_matches_entry_keys() -> None:
    cfg = json.loads(cascade.exit_vless_config(VLESS))
    inbound = cfg["inbounds"][0]
    assert inbound["port"] == 443
    assert inbound["settings"]["clients"][0]["id"] == VLESS["uuid"]
    assert inbound["streamSettings"]["realitySettings"]["privateKey"] == "priv"


def test_new_vless_params_are_fresh() -> None:
    a, b = cascade.new_vless_params(), cascade.new_vless_params()
    assert a["uuid"] != b["uuid"] and a["private_key"] != b["private_key"]
    assert len(a["short_id"]) == 16


def test_probe_verdict() -> None:
    frozen = cascade.probe_verdict({"bytes": 36200, "secs": 6.0, "connected": True}, {})
    assert frozen["ok"] is False and frozen["mbps"] == 0
    full = cascade.probe_verdict({"bytes": 20 * 2**20, "secs": 0.5, "connected": True}, {})
    assert full["ok"] is True and full["mbps"] == 336
    refused = cascade.probe_verdict({"connected": False}, {"error": "timed out"})
    assert refused["ok"] is False and refused["error"] == "timed out"
    assert cascade.recommend(full, frozen) == "vless"
    assert cascade.recommend(frozen, full) == "gre"
    assert cascade.recommend(frozen, frozen) == ""


def test_probe_helpers_move_bytes_locally() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    recv = subprocess.Popen(
        [sys.executable, "-c", cascade._RECV_PY, "127.0.0.1", str(port), "10"],
        stdout=subprocess.PIPE, text=True,
    )
    send = subprocess.run(
        [sys.executable, "-c", cascade._SEND_PY, "127.0.0.1", str(port), str(4 * 2**20), "10"],
        capture_output=True, text=True, timeout=30,
    )
    out, _ = recv.communicate(timeout=30)
    verdict = cascade.probe_verdict(cascade._json_line(out), cascade._json_line(send.stdout))
    assert verdict["ok"] is True and verdict["bytes"] >= 4 * 2**20


def test_check_result_ignores_garbage() -> None:
    kv = cascade.parse_kv("CASCADE_EGRESS=198.51.100.20\nCASCADE_RU=<html>\nCASCADE_GW=yes\n")
    assert kv["gw"] == "yes"
    assert cascade.check_result(kv) == {"egress": "198.51.100.20", "ru": ""}


async def _servers(session_factory, n=3, ok=True) -> list[int]:
    async with session_factory() as session:
        rows = [
            Server(name=f"vpn-{i}", host=f"203.0.113.{10 + i}", last_check_ok=ok)
            for i in range(n)
        ]
        session.add_all(rows)
        await session.commit()
        return [r.id for r in rows]


async def test_pair_validation(client: httpx.AsyncClient, auth_headers, session_factory) -> None:
    a, b, c = await _servers(session_factory)
    r = await client.post("/api/cascades/probe", json={"entry_id": a, "exit_id": a},
                          headers=auth_headers)
    assert r.status_code == 400
    async with session_factory() as session:
        session.add(Cascade(entry_server_id=a, exit_server_id=b, transport="gre", status="ready"))
        await session.commit()
    r = await client.post("/api/cascades", json={"entry_id": c, "exit_id": b, "transport": "gre"},
                          headers=auth_headers)
    assert r.status_code == 409
    down = (await _servers(session_factory, 1, ok=False))[0]
    r = await client.post("/api/cascades/probe", json={"entry_id": c, "exit_id": down},
                          headers=auth_headers)
    assert r.status_code == 409 and "не на связи" in r.json()["detail"]


async def test_interrupted_install_becomes_error(
    client: httpx.AsyncClient, auth_headers, session_factory
) -> None:
    a, b, _c = await _servers(session_factory)
    async with session_factory() as session:
        session.add(Cascade(entry_server_id=a, exit_server_id=b, transport="vless"))
        await session.commit()
    r = await client.get("/api/cascades", headers=auth_headers)
    assert r.status_code == 200
    row = r.json()[0]
    assert row["status"] == "error" and "перезапуском" in row["error"]


async def test_delete_dismantles_entry_first(
    client: httpx.AsyncClient, auth_headers, session_factory, monkeypatch
) -> None:
    a, b, _c = await _servers(session_factory)
    async with session_factory() as session:
        cas = Cascade(entry_server_id=a, exit_server_id=b, transport="gre", status="ready",
                      params=json.dumps({"entry_ip": "203.0.113.10", "exit_ip": "203.0.113.11"}))
        session.add(cas)
        entry = await session.get(Server, a)
        entry.egress_ip = "203.0.113.11"
        await session.commit()
        cid = cas.id
    calls: list[tuple[str, str]] = []

    async def fake(server, script):
        calls.append((server.name, script))
        return "" if server.id == a else "«vpn-1»: нет связи"

    from app.api import cascades as api

    monkeypatch.setattr(api, "_dismantle", fake)
    r = await client.delete(f"/api/cascades/{cid}", headers=auth_headers)
    assert r.status_code == 502
    assert [c[0] for c in calls] == ["vpn-0", "vpn-1"]
    assert "acontrol-cascade-tproxy" in calls[0][1]
    r = await client.delete(f"/api/cascades/{cid}?force=true", headers=auth_headers)
    assert r.status_code == 204
    assert (await client.get("/api/cascades", headers=auth_headers)).json() == []
    async with session_factory() as session:
        assert (await session.get(Server, a)).egress_ip == ""


async def test_server_delete_drops_cascade(
    client: httpx.AsyncClient, auth_headers, session_factory
) -> None:
    a, b, _c = await _servers(session_factory)
    async with session_factory() as session:
        session.add(Cascade(entry_server_id=a, exit_server_id=b, transport="gre", status="ready"))
        await session.commit()
    r = await client.delete(f"/api/servers/{b}", headers=auth_headers)
    assert r.status_code == 200
    assert (await client.get("/api/cascades", headers=auth_headers)).json() == []
