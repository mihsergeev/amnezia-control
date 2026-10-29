import json
import os
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
    vless = json.loads(cascade.entry_gateway_config("vless", "198.51.100.20", VLESS, country="RU"))
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
    assert cascade.check_result(kv) == {"egress": "198.51.100.20", "ru": "", "client": "", "direct": ""}


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


def test_pick_source() -> None:
    # адрес на интерфейсе публичный - его и видит выход
    assert cascade.pick_source("203.0.113.10", "198.51.100.20", "") == "203.0.113.10"
    # вход за NAT, выход в интернете - внешний адрес
    assert cascade.pick_source("10.0.0.5", "8.8.8.8", "203.0.113.10") == "203.0.113.10"
    # оба во внутренней сети - внутренний адрес, а не адрес роутера
    assert cascade.pick_source("192.168.1.21", "192.168.1.22", "8.8.4.4") == "192.168.1.21"


def test_egress_due_accepts_naive_sqlite_dates() -> None:
    from datetime import datetime, timedelta, timezone

    from app import server_ops

    now = datetime.now(timezone.utc)
    s = Server(name="vpn-a", host="203.0.113.10")
    s.egress_at = (now - timedelta(minutes=5)).replace(tzinfo=None)
    assert server_ops.egress_due(s, now) is False
    s.egress_at = (now - timedelta(hours=2)).replace(tzinfo=None)
    assert server_ops.egress_due(s, now) is True


def test_bootstrap_gateway_needs_no_geo_files() -> None:
    for transport in ("gre", "vless"):
        boot = cascade.entry_gateway_config(transport, "198.51.100.20", VLESS, bootstrap=True)
        assert "geoip:" not in boot and "geosite:" not in boot
        assert json.loads(boot)["outbounds"][0]["tag"] == "exit"


def test_entry_fetches_geo_through_bootstrap_gateway() -> None:
    script = cascade.build_entry_script("vless", "198.51.100.20", 3, VLESS)
    boot = script.index(f"-v {cascade.DIR}/boot:")
    geo = script.index(f"sudo {cascade.DIR}/geo-update.sh")
    full = script.index(f"-v {cascade.DIR}/config:")
    assert boot < geo < full
    assert "--socks5-hostname $via" in cascade._GEO_SH
    assert f"127.0.0.1:{cascade.SOCKS_PORT}" in cascade._fill(cascade._GEO_SH)


def _geo_run(tmp_path, gateway_up: bool) -> str:
    import hashlib

    base = (tmp_path / "cas").as_posix()
    src, bin_ = tmp_path / "src", tmp_path / "bin"
    for d in (src, bin_, tmp_path / "cas" / "config"):
        d.mkdir(parents=True, exist_ok=True)
    for name in ("geoip.dat", "geosite.dat"):
        data = name.encode() * 100
        (src / name).write_bytes(data)
        (src / f"{name}.sha256sum").write_bytes(f"{hashlib.sha256(data).hexdigest()}  {name}\n".encode())
    log = (tmp_path / "log").as_posix()
    # подставные curl и docker: пишут вызовы в лог, curl отдает файлы из src
    (bin_ / "curl").write_text(
        "#!/bin/sh\n"
        f'echo "curl $*" >> {log}\n'
        'out=""; prev=""; for a in "$@"; do [ "$prev" = -o ] && out=$a; prev=$a; done\n'
        f'cp "{src.as_posix()}/$(basename "$a")" "$out"\n',
        newline="\n",
    )
    (bin_ / "docker").write_text(
        "#!/bin/sh\n"
        f'echo "docker $*" >> {log}\n'
        f'[ "$1" = ps ] && {"echo " + cascade.GATEWAY if gateway_up else "true"}\n'
        "exit 0\n",
        newline="\n",
    )
    for f in bin_.iterdir():
        f.chmod(0o755)
    script = cascade._fill(cascade._GEO_SH.replace("@DIR@", base))
    env = {**os.environ, "PATH": str(bin_) + os.pathsep + os.environ["PATH"]}
    r = subprocess.run(
        [shutil.which("bash"), "-c", script], capture_output=True, text=True, timeout=60, env=env,
    )
    assert r.returncode == 0, r.stderr
    text = open(log).read()
    open(log, "w").close()
    return text


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
def test_geo_update_goes_through_gateway_and_skips_unchanged(tmp_path) -> None:
    first = _geo_run(tmp_path, gateway_up=True)
    proxy = f"--socks5-hostname 127.0.0.1:{cascade.SOCKS_PORT}"
    downloads = [line for line in first.splitlines() if line.startswith("curl")]
    assert len(downloads) == 4 and all(proxy in line for line in downloads)
    assert (tmp_path / "cas" / "geo" / "geosite.dat").exists()
    assert f"docker restart {cascade.GATEWAY}" in first
    # базы не менялись: качаются только контрольные суммы, шлюз не трогаем
    second = _geo_run(tmp_path, gateway_up=True)
    assert "geosite.dat " not in second and "geosite.dat.sha256sum" in second
    assert "restart" not in second
    # без шлюза напрямую
    (tmp_path / "cas" / "geo" / "geoip.dat").write_bytes(b"old")
    third = _geo_run(tmp_path, gateway_up=False)
    assert "socks5" not in third
    assert any(line.endswith("/geoip.dat") and "socks5" not in line for line in third.splitlines())


def test_local_rules_follow_entry_country() -> None:
    def rules(cc):
        return json.loads(cascade.entry_gateway_config("gre", "198.51.100.20", {}, country=cc))["routing"]["rules"]

    kz = rules("KZ")
    assert {"ip": ["geoip:kz"], "outboundTag": "direct"} in kz
    assert {"domain": ["domain:kz", "domain:xn--80ao21a"], "outboundTag": "direct"} in kz
    # списка доменов Казахстана в geosite нет: ссылка на него уронила бы шлюз
    assert "geosite:" not in json.dumps(kz) and "ru-blocked" not in json.dumps(kz)
    assert {"domain": ["domain:de"], "outboundTag": "direct"} in rules("de")
    assert "geosite:category-ir" in json.dumps(rules("IR"))
    ru = json.dumps(rules("RU"))
    assert "geosite:ru-blocked" in ru and "geoip:ru" in ru and "domain:xn--p1ai" in ru
    # страна неизвестна: только блок частных адресов, остальное на выход
    assert rules("") == [{"ip": ["geoip:private"], "outboundTag": "block"}]


def test_local_ip_check_only_where_known() -> None:
    assert "ip.nic.ru" in cascade.build_check_command("RU")
    kz = cascade.build_check_command("KZ")
    assert "ip.nic.ru" not in kz and 'RU=""' in kz and "CASCADE_RU=$RU" in kz
    script = cascade.build_entry_script("gre", "198.51.100.20", 3, VLESS, "KZ")
    assert "ip.nic.ru" not in script


def test_tproxy_catches_amnezia_dns_net() -> None:
    tp = cascade._fill(cascade._TPROXY_SH)
    # контейнеры приложения Amnezia выходят через amnezia-dns-net, а не docker0
    assert "amnezia-dns-net" in tp and "for IF in $(bridges)" in tp
    # переходы снимаются все, в том числе на мосты, которых уже нет
    assert "iptables -t mangle -S PREROUTING | sed -n" in tp


def test_lost_gre_rule_drops_instead_of_leaking() -> None:
    tp = cascade._fill(cascade._TPROXY_SH)
    gre = cascade._GRE_TUN_SH
    # сам GRE не режем: внешний пакет туннеля может унаследовать метку
    assert 'rule filter OUTPUT -m mark --mark "$MARK" ! -o "$IF" ! -p gre -j DROP' in gre
    assert 'unrule filter OUTPUT -m mark --mark "$MARK" ! -o "$IF" ! -p gre -j DROP' in gre
    for text in (tp, gre):
        assert "heal) heal ;;" in text


def test_heal_service_installed_and_removed() -> None:
    script = cascade.build_entry_script("vless", "198.51.100.20", 3, VLESS)
    assert "/etc/systemd/system/acontrol-cascade-heal.service" in script
    assert "systemctl restart acontrol-cascade-heal.service" in script
    unit = cascade._fill(cascade._HEAL_UNIT)
    assert f"{cascade.DIR}/cascade-tproxy.sh heal" in unit and f"{cascade.DIR}/gre-tun.sh heal" in unit
    assert "acontrol-cascade-heal.service" in cascade.build_remove_entry()


def test_check_looks_from_inside_the_vpn_container() -> None:
    cmd = cascade.build_check_command()
    assert 'nsenter -t "$P" -n curl' in cmd and 'echo "CASCADE_CLIENT=$CL"' in cmd
    assert "CASCADE_DIRECT=" in cmd
    assert "fwmark 0x100 lookup 241" in cmd and "fwmark 0x200 lookup 242" in cmd


def test_health_catches_a_leak() -> None:
    base = ("CASCADE_GW=yes\nCASCADE_TPROXY=active\nCASCADE_TUN=UNKNOWN\nCASCADE_RULE=yes\n"
            "CASCADE_GRERULE=yes\nCASCADE_EGRESS=198.51.100.20\n")

    def health(text, transport="vless"):
        kv = cascade.parse_kv(text)
        return cascade.health(transport, kv, cascade.check_result(kv))

    assert health(base + "CASCADE_CLIENT=198.51.100.20\n") == (True, "")
    # из контейнера спросить нечем - не судим
    assert health(base + "CASCADE_CLIENT=\n") == (True, "")
    assert health(base + "CASCADE_CLIENT=203.0.113.10\n") == (
        False, "клиенты выходят в интернет мимо выхода")
    # адрес входа известен: обход - только если клиенты выходят именно с него
    assert health(base + "CASCADE_DIRECT=203.0.113.10\nCASCADE_CLIENT=203.0.113.10\n") == (
        False, "клиенты выходят в интернет мимо выхода")
    assert health(base + "CASCADE_DIRECT=203.0.113.10\nCASCADE_CLIENT=198.51.100.99\n") == (True, "")
    no_rule = base.replace("CASCADE_RULE=yes", "CASCADE_RULE=no")
    assert health(no_rule)[1] == "пропало правило маршрутизации в шлюз"
    no_gre_rule = base.replace("CASCADE_GRERULE=yes", "CASCADE_GRERULE=no")
    assert health(no_gre_rule, "gre")[1] == "пропало правило маршрутизации в шлюз"
    assert health(no_gre_rule, "vless") == (True, "")


class _Conn:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.ran: list[str] = []

    async def run(self, cmd, check=False, timeout=None):
        self.ran.append(cmd)
        out = self.outputs.pop(0) if "CASCADE_GW" in cmd else "DEPLOY_DONE\n"
        return type("R", (), {"stdout": out})()


@pytest.mark.parametrize("rev, upgraded", [("0", True), ("1", True), (cascade.SCRIPTS_REV, False), ("", False)])
async def test_check_upgrades_old_entry_scripts(rev, upgraded) -> None:
    first = "CASCADE_GW=yes\n" + (f"CASCADE_REV={rev}\n" if rev else "")
    conn = _Conn([first, f"CASCADE_GW=yes\nCASCADE_REV={cascade.SCRIPTS_REV}\n"])
    out = await cascade.run_check(conn)
    assert any("acontrol-cascade-heal.service" in c and "CASCADE_GW" not in c for c in conn.ran) is upgraded
    assert len(conn.ran) == (3 if upgraded else 1)
    if upgraded:
        assert cascade.parse_kv(out)["rev"] == cascade.SCRIPTS_REV


@pytest.mark.skipif(shutil.which("bash") is None, reason="нужен bash")
def test_upgrade_script_is_valid_shell() -> None:
    script = cascade.build_entry_upgrade()
    _bash_ok(script)
    assert f"# rev {cascade.SCRIPTS_REV}" in cascade._fill(cascade._TPROXY_SH)
    # GRE-скрипт только там, где каскад на GRE
    assert f"if [ -f {cascade.GRE_DEFAULTS} ]; then" in script
