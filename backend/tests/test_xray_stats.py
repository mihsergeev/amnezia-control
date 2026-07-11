import json

from app import xray


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
    m = re.search(r'server\.json" >/dev/null <<EOF\n(.*?)\nEOF', s, re.S)
    block = m.group(1)
    for k, v in {
        "$XRAY_SERVER_PORT": "443", "$XRAY_SITE_NAME": "ex.com",
        "$UUID": "11111111-1111-1111-1111-111111111111",
        "$PRIV": "P", "$SID": "ab",
    }.items():
        block = block.replace(k, v)
    cfg = json.loads(block)
    assert cfg["api"]["tag"] == "api"
    assert cfg["inbounds"][0]["settings"]["clients"][0]["email"]
    assert any(i.get("tag") == "api" for i in cfg["inbounds"])
    assert cfg["routing"]["rules"][0]["outboundTag"] == "api"


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
    stats = await xray.read_client_stats(C(payload), "amnezia-xray")
    assert stats["UID-A"] == {"up": 100, "down": 2500}
    assert stats["UID-B"] == {"up": 0, "down": 7}
    assert "api" not in stats  # inbound-статистика не попадает в клиентов

    # статистика не включена / мусор → пусто, без исключений
    assert await xray.read_client_stats(C("", code=1), "amnezia-xray") == {}
    assert await xray.read_client_stats(C("not json"), "amnezia-xray") == {}
