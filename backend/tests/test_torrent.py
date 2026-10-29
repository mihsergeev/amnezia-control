"""Блокировка торрентов: правила в контейнерах, разбор попаданий, запись,
алерт и автопауза (app/torrent.py)."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import alerts, config, pausestore, settings_store, torrent
from app.db import Base, create_engine_and_factory
from app.models import AuditLog, Server, TorrentHit


@pytest.fixture(autouse=True)
def _clean_state():
    torrent._cleared.clear()
    torrent._status.clear()
    yield
    torrent._cleared.clear()
    torrent._status.clear()


RECENT = (
    "src=10.8.1.2 ttl: 64 last_seen: 4295001000 oldest_pkt: 3 "
    "4295000100, 4295000500, 4295001000\n"
    "src=10.8.1.5 ttl: 64 last_seen: 4295000900 oldest_pkt: 1 4295000900\n"
)


def test_parse_recent_counts_stamps():
    assert torrent.parse_recent(RECENT) == {"10.8.1.2": 3, "10.8.1.5": 1}
    assert torrent.parse_recent("") == {}
    # строка с настоящего ядра (5.15): номер старой метки и 5 меток пакетов
    real = ("src=10.99.0.2 ttl: 64 last_seen: 30909413119 oldest_pkt: 5 30909413118, "
            "30909413118, 30909413118, 30909413119, 30909413119")
    assert torrent.parse_recent(real) == {"10.99.0.2": 5}
    assert torrent.parse_recent("мусор\n") == {}


def test_parse_output_marker():
    assert torrent.parse_output("ACTORRENT ok=1\n" + RECENT) == (
        True, {"10.8.1.2": 3, "10.8.1.5": 1},
    )
    assert torrent.parse_output("ACTORRENT ok=0\n")[0] is False
    # скрипт оборвался до маркера - состояние неизвестно
    assert torrent.parse_output("")[0] is None


def test_parse_ovpn_routes():
    text = (
        "OpenVPN CLIENT LIST\n"
        "Updated,2026-10-29 10:00:00\n"
        "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n"
        "cid-1,198.51.100.4:5000,100,200,2026-10-29 09:00:00\n"
        "ROUTING TABLE\n"
        "Virtual Address,Common Name,Real Address,Last Ref\n"
        "10.8.0.6,cid-1,198.51.100.4:5000,2026-10-29 10:00:00\n"
        "10.8.0.10C,cid-2,198.51.100.9:5000,2026-10-29 10:00:00\n"
        "GLOBAL STATS\n"
        "Max bcast/mcast queue length,0\n"
        "END\n"
    )
    assert torrent.parse_ovpn_routes(text) == {"10.8.0.6": "cid-1", "10.8.0.10": "cid-2"}


@dataclass
class _Client:
    public_key: str
    name: str
    address: str


def test_awg_ipmap():
    m = torrent.awg_ipmap([
        _Client("pk1", "alice", "10.8.1.2/32"),
        _Client("pk2", "bob", "10.8.1.3/32, fd00::3/128"),
        _Client("pk3", "", ""),
    ])
    assert m["10.8.1.2"] == ("pk1", "alice")
    assert m["10.8.1.3"] == ("pk2", "bob")
    assert "fd00::3" in m and "" not in m


def test_enable_script_rules():
    s = torrent.enable_script()
    # каждая сигнатура - отдельное правило с recent и DROP
    assert s.count("-m recent --name actorrent --rsource --set -j DROP") == len(torrent.SIGNATURES)
    for sig in torrent.SIGNATURES:
        assert sig in s
    # набор сверяется по числу правил, переход ставится первым в FORWARD
    assert f'!= "{len(torrent.SIGNATURES)}"' in s
    assert "iptables -C FORWARD ! -i eth0 -j ACTORRENT" in s
    assert "iptables -I FORWARD 1 ! -i eth0 -j ACTORRENT" in s
    # накопленные адреса забираются и очищаются
    assert "echo / > $f" in s
    d = torrent.disable_script()
    assert "iptables -D FORWARD ! -i eth0 -j ACTORRENT" in d and "iptables -X ACTORRENT" in d


class _Result:
    def __init__(self, stdout):
        self.stdout = stdout


class _Conn:
    def __init__(self, out):
        self.out = out
        self.cmds: list[str] = []

    async def run(self, cmd, check=False):
        self.cmds.append(cmd)
        return _Result(self.out(cmd) if callable(self.out) else self.out)


def _server(**kw) -> Server:
    base = dict(id=1, name="vpn-a", host="203.0.113.10", ssh_port=22, ssh_user="root",
                torrent_block=True, torrent_autopause=False)
    base.update(kw)
    return Server(**base)


NETS = [{"container": "amnezia-awg2", "protocol": "awg",
         "ips": {"10.8.1.2": ("pk1", "alice")}}]


async def test_sample_maps_hits_to_clients():
    conn = _Conn("ACTORRENT ok=1\n" + RECENT)
    hits = await torrent.sample(conn, _server(), NETS)
    # 10.8.1.5 - не клиент панели (или уже отозван), пропускаем
    assert hits == [{"protocol": "awg", "client_id": "pk1", "name": "alice", "hits": 3}]
    assert "amnezia-awg2" in conn.cmds[0]
    assert torrent.status(1)["ok"] is True


async def test_sample_reports_failed_rules():
    conn = _Conn("ACTORRENT ok=0\n")
    assert await torrent.sample(conn, _server(), NETS) == []
    st = torrent.status(1)
    assert st["ok"] is False and "amnezia-awg2" in st["error"]


async def test_sample_disabled_cleans_once():
    conn = _Conn("ACTORRENT off\n")
    srv = _server(torrent_block=False)
    assert await torrent.sample(conn, srv, NETS) == []
    assert len(conn.cmds) == 1 and "iptables -X ACTORRENT" in conn.cmds[0]
    # правила сняты - в следующие циклы на ноду не ходим
    await torrent.sample(conn, srv, NETS)
    assert len(conn.cmds) == 1


async def test_sample_disabled_retries_until_clean():
    conn = _Conn("")
    srv = _server(torrent_block=False)
    await torrent.sample(conn, srv, NETS)
    await torrent.sample(conn, srv, NETS)
    assert len(conn.cmds) == 2


@pytest.fixture
async def factory(tmp_path, monkeypatch):
    monkeypatch.setenv("VPNPANEL_DATA_DIR", (tmp_path / "data").as_posix())
    config.get_settings.cache_clear()
    engine, session_factory = create_engine_and_factory(
        f"sqlite+aiosqlite:///{(tmp_path / 't.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield session_factory
    await engine.dispose()
    config.get_settings.cache_clear()


@pytest.fixture
def sent(monkeypatch):
    cards: list = []

    async def _cfg(session, settings):
        return {"webhook": "http://hook.example.com"}

    async def _send(cfg, settings, card):
        cards.append(card)

    monkeypatch.setattr(settings_store, "get_alert_config", _cfg)
    monkeypatch.setattr(alerts, "send_card", _send)
    return cards


def _hit(n, cid="pk1"):
    return {"server_id": 1, "torrent": [
        {"protocol": "awg", "client_id": cid, "name": "alice", "hits": n}]}


async def test_record_alerts_once_per_day(factory, sent):
    settings = config.get_settings()
    srv = _server()
    await torrent.record(factory, settings, [_hit(5)], {1: srv})
    await torrent.record(factory, settings, [_hit(4)], {1: srv})
    async with factory() as session:
        row = await session.scalar(select(TorrentHit))
    assert row.hits == 9
    assert len(sent) == 1
    text, _html = sent[0].render(lang="en")
    assert "downloading torrents" in text and "alice" in text and "vpn-a" in text


async def test_record_below_threshold_no_alert(factory, sent):
    await torrent.record(factory, config.get_settings(), [_hit(1)], {1: _server()})
    assert sent == []
    async with factory() as session:
        row = await session.scalar(select(TorrentHit))
    assert row.hits == 1 and row.alerted_at is None


async def test_record_realerts_after_a_day(factory, sent):
    settings = config.get_settings()
    srv = _server()
    await torrent.record(factory, settings, [_hit(5)], {1: srv})
    async with factory() as session:
        obj = await session.scalar(select(TorrentHit))
        obj.alerted_at = datetime.now(timezone.utc) - timedelta(hours=25)
        await session.commit()
    await torrent.record(factory, settings, [_hit(5)], {1: srv})
    assert len(sent) == 2


async def test_autopause(factory, sent, monkeypatch):
    calls = []

    async def _pause(server, settings, protocol, client_id):
        calls.append((protocol, client_id))
        return {"ip": "10.8.1.2"}

    monkeypatch.setattr(torrent, "_pause", _pause)
    srv = _server(torrent_autopause=True)
    await torrent.record(factory, config.get_settings(), [_hit(5)], {1: srv})
    assert calls == [("awg", "pk1")]
    async with factory() as session:
        paused = await pausestore.list_paused(session, 1, "awg")
        actions = [a.action for a in await session.scalars(select(AuditLog))]
    assert paused["pk1"]["data"] == {"ip": "10.8.1.2"}
    assert "awg_torrent_pause" in actions
    assert "paused" in sent[0].render(lang="en")[0]


async def test_autopause_failure_still_alerts(factory, sent, monkeypatch):
    async def _pause(server, settings, protocol, client_id):
        raise RuntimeError("контейнер протокола не запущен")

    monkeypatch.setattr(torrent, "_pause", _pause)
    await torrent.record(factory, config.get_settings(), [_hit(5)],
                         {1: _server(torrent_autopause=True)})
    async with factory() as session:
        assert await pausestore.list_paused(session, 1, "awg") == {}
    assert "Could not pause" in sent[0].render(lang="en")[0]


async def test_patch_and_get_torrent(client, auth_headers, monkeypatch):
    applied = []
    monkeypatch.setattr(torrent, "spawn_apply", lambda server, settings: applied.append(server.id))
    r = await client.post("/api/servers", headers=auth_headers, json={
        "name": "vpn-a", "host": "203.0.113.10", "ssh_port": 22, "ssh_user": "root"})
    sid = r.json()["id"]
    assert r.json()["torrent_block"] is False

    r = await client.patch(f"/api/servers/{sid}", headers=auth_headers,
                           json={"torrent_block": True, "torrent_autopause": True})
    assert r.status_code == 200
    assert r.json()["torrent_block"] is True and r.json()["torrent_autopause"] is True
    assert applied == [sid]
    # та же настройка повторно - на ноду не ходим
    await client.patch(f"/api/servers/{sid}", headers=auth_headers, json={"torrent_block": True})
    # только автопауза - правила на ноде не меняются
    await client.patch(f"/api/servers/{sid}", headers=auth_headers, json={"torrent_autopause": False})
    assert applied == [sid]

    now = datetime.now(timezone.utc)
    async with client.session_factory() as session:
        session.add(TorrentHit(server_id=sid, protocol="awg", client_id="pk1", name="alice",
                               hits=7, first_seen=now, last_seen=now))
        await session.commit()
    r = await client.get(f"/api/servers/{sid}/torrent", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is None
    assert body["clients"][0]["client_id"] == "pk1" and body["clients"][0]["hits"] == 7
