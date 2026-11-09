import asyncio
import json

import asyncssh
import pytest

from app import xray


STATS_CONFIG = {"api": {"listen": "127.0.0.1:10085", "services": ["StatsService"]}}


def test_ensure_stats_config_idempotent_and_backfills_email():
    server = {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "port": 443, "protocol": "vless",
                "settings": {"clients": [
                    {"id": "UID-A", "flow": "x"},
                    {"id": "UID-B", "flow": "x"},
                ]},
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
    }
    assert xray.ensure_stats_config(server) is True
    # второй проход ничего не меняет (идемпотентность)
    assert xray.ensure_stats_config(server) is False

    assert server["stats"] == {}
    assert server["api"]["services"] == ["StatsService"]
    assert server["policy"]["levels"]["0"]["statsUserUplink"] is True
    # api-inbound добавлен ровно один раз, порт локальный
    api_inbounds = [i for i in server["inbounds"] if i.get("tag") == "api"]
    assert len(api_inbounds) == 1
    assert api_inbounds[0]["listen"] == "127.0.0.1"
    assert api_inbounds[0]["port"] == xray.STATS_API_PORT
    # routing-правило для api есть
    assert server["routing"]["rules"][0]["inboundTag"] == ["api"]
    # email = UUID у всех клиентов (ключ статистики)
    emails = {c["id"]: c["email"] for c in server["inbounds"][0]["settings"]["clients"]}
    assert emails == {"UID-A": "UID-A", "UID-B": "UID-B"}


def test_deploy_script_server_json_valid_with_stats():
    """Свежий server.json должен быть валидным JSON и содержать stats/api/routing."""
    import re

    s = xray.build_deploy_script(443, "www.googletagmanager.com", "v26.3.27")
    m = re.search(r'server\.json" >/dev/null <<EOF[^\n]*\n(.*?)\nEOF', s, re.S)
    block = m.group(1)
    for k, v in {
        "$INBOUND_PORT": "443", "$XRAY_SITE_NAME": '"ex.com"', "$XRAY_DEST": '"ex.com:443"',
        "$UUID": "11111111-1111-1111-1111-111111111111",
        "$PRIV": "P", "$SID": "ab",
    }.items():
        block = block.replace(k, v)
    cfg = json.loads(block)
    assert cfg["api"]["tag"] == "api"
    assert cfg["inbounds"][0]["settings"]["clients"][0]["email"]
    assert any(i.get("tag") == "api" for i in cfg["inbounds"])
    assert cfg["routing"]["rules"][0]["outboundTag"] == "api"


def test_enable_stats_preserves_custom_policy_api_and_client_email():
    client = {"id": "UID-A", "email": "operator-label", "level": 7}
    server = {
        "api": {"tag": "management", "services": ["HandlerService"]},
        "policy": {
            "levels": {"0": {"connIdle": 90}, "7": {"handshake": 6}},
            "system": {"statsOutboundUplink": True},
        },
        "inbounds": [
            {"protocol": "vless", "settings": {"clients": [client]}},
            {"protocol": "vless", "settings": {"clients": [client.copy()]}},
        ],
    }
    assert xray.ensure_stats_config(server) is True
    assert xray.ensure_stats_config(server) is False
    assert server["api"] == {"tag": "management", "services": ["HandlerService", "StatsService"]}
    assert server["policy"]["levels"]["0"]["connIdle"] == 90
    assert server["policy"]["levels"]["7"]["handshake"] == 6
    assert server["policy"]["levels"]["7"]["statsUserDownlink"] is True
    assert server["policy"]["system"]["statsOutboundUplink"] is True
    assert server["routing"]["rules"][0]["outboundTag"] == "management"
    assert server["inbounds"][0]["settings"]["clients"][0]["email"] == "operator-label"
    assert server["inbounds"][1]["settings"]["clients"] == [client]


def test_client_stats_ignore_duplicate_keys():
    clients = [
        xray.XrayClient("id-a", "A", "", "shared"),
        xray.XrayClient("id-b", "B", "", "shared"),
        xray.XrayClient("id-c", "C", "", "distinct"),
    ]
    counters = {"shared": {"up": 10, "down": 20}, "distinct": {"up": 3, "down": 4}}
    assert xray.client_stats_by_id(clients, counters) == {"id-c": counters["distinct"]}


def test_enabling_stats_preserves_independent_vless_clients():
    primary = {"id": "UID-A", "flow": "xtls-rprx-vision"}
    secondary = {"id": "UID-B", "email": "fallback-user", "level": 7}
    server = {"inbounds": [
        {"protocol": "vless", "settings": {"clients": [primary]}},
        {"protocol": "vless", "settings": {"clients": [secondary.copy()]}},
    ]}

    assert xray.ensure_stats_config(server) is True
    assert xray.ensure_stats_config(server) is False
    assert primary == {"id": "UID-A", "flow": "xtls-rprx-vision", "email": "UID-A"}
    assert server["inbounds"][1]["settings"]["clients"] == [secondary]
    assert server["policy"]["levels"]["7"]["statsUserDownlink"] is True


@pytest.mark.parametrize("native", [True, False])
async def test_stats_use_existing_api_address_without_adding_an_inbound(native):
    server = {"api": {"tag": "management", "services": ["HandlerService"]}, "inbounds": []}
    if native:
        server["api"]["listen"] = "127.0.0.1:10085"
        address = "127.0.0.1:10085"
    else:
        server["inbounds"].append({
            "tag": "admin-in", "protocol": "dokodemo-door", "listen": "::1", "port": 10855,
        })
        server["routing"] = {"rules": [
            {"type": "field", "inboundTag": ["admin-in"], "outboundTag": "management"},
        ]}
        address = "[::1]:10855"
    inbounds = server["inbounds"].copy()
    routing = server.get("routing")

    assert xray.ensure_stats_config(server) is True
    assert xray.ensure_stats_config(server) is False
    assert server["inbounds"] == inbounds
    assert server.get("routing") == routing
    assert server["api"]["services"] == ["HandlerService", "StatsService"]

    class Conn:
        async def run(self, command, *, check):
            assert "--server=" in command and address in command
            return type("Result", (), {"exit_status": 0, "stdout": "{}"})

    assert await xray.read_client_stats(Conn(), "amnezia-xray", server) == {}


def test_stats_listener_does_not_take_existing_vless_ports():
    server = {"inbounds": [{"tag": "api", "protocol": "vless", "port": "443,10084-10086"}]}
    assert xray.ensure_stats_config(server) is True
    assert xray._stats_api_address(server) == "127.0.0.1:10087"
    assert xray.ensure_stats_config(server) is False
    assert server["inbounds"][0]["port"] == "443,10084-10086"


async def test_default_profile_traffic_is_not_attributed_to_an_imported_client(monkeypatch):
    async def read_all(_conn, _container):
        return {"inbounds": [{"settings": {"clients": [
            {"id": "default", "email": "shared"},
            {"id": "imported", "email": "shared"},
        ]}}]}, "default", []

    monkeypatch.setattr(xray, "_read_all", read_all)
    clients = await xray.read_clients(None, "amnezia-xray")
    assert [client.client_id for client in clients] == ["imported"]
    assert xray.client_stats_by_id(clients, {"shared": {"up": 1, "down": 1}}) == {}


async def test_read_client_stats_parses_statsquery():
    class C:
        def __init__(self, out, code=0):
            self.out, self.code = out, code

        async def run(self, cmd, check=False):  # noqa: A002
            return type("R", (), {
                "exit_status": self.code, "stdout": self.out, "stderr": "",
            })()

    payload = json.dumps({"stat": [
        {"name": "user>>>UID-A>>>traffic>>>uplink", "value": "100"},
        {"name": "user>>>UID-A>>>traffic>>>downlink", "value": "2500"},
        {"name": "user>>>UID-B>>>traffic>>>downlink", "value": "7"},
        {"name": "inbound>>>api>>>traffic>>>downlink", "value": "9"},  # не user
    ]})
    stats = await xray.read_client_stats(C(payload), "amnezia-xray", STATS_CONFIG)
    assert stats["UID-A"] == {"up": 100, "down": 2500}
    assert stats["UID-B"] == {"up": 0, "down": 7}
    assert "api" not in stats  # inbound-статистика не попадает в клиентов

    assert await xray.read_client_stats(C("{}"), "amnezia-xray", STATS_CONFIG) == {}
    assert await xray.read_client_stats(C("", code=1), "amnezia-xray", STATS_CONFIG) is None
    for invalid in ("not json", "[]", '{"stat":{}}', '{"stat":[42]}'):
        assert await xray.read_client_stats(C(invalid), "amnezia-xray", STATS_CONFIG) is None


async def test_optional_statsquery_survives_ssh_channel_failure_and_timeout(monkeypatch):
    class Refused:
        async def run(self, cmd, check=False):
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_RESOURCE_SHORTAGE, "test channel limit")

    class Slow:
        async def run(self, cmd, check=False):
            await asyncio.sleep(1)

    assert await xray.read_client_stats(Refused(), "amnezia-xray", STATS_CONFIG) is None
    monkeypatch.setattr(xray, "STATS_QUERY_TIMEOUT", 0.01)
    assert await xray.read_client_stats(Slow(), "amnezia-xray", STATS_CONFIG) is None
