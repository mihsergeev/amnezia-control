"""Golden-master контракт формата приложения AmneziaVPN.

Панель генерит vpn://-ссылки (full-access и клиентскую) байт-совместимо с
приложением. Эталонные наборы ключей зафиксированы в fixtures/amnezia_app_format.json
из РЕАЛЬНЫХ экспортов приложения. Эти тесты падают, если:
  * наш генератор дрейфует (регрессия на нашей стороне), ИЛИ
  * структура формата приложения меняется (апстрим-дрейф) и мы это заметили,
    пере-декодировав свежий экспорт и обновив fixture.
Так недокументированный формат не «уедет» тихо — тест укажет разъехавшийся набор.
"""

import base64
import json
import zlib
from pathlib import Path

from app import awg
from app.deploy import generate_server_config
from app.fullaccess import build_full_access_link

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "amnezia_app_format.json").read_text("utf-8")
)


def _decode(link: str) -> dict:
    raw = link[len("vpn://"):]
    raw += "=" * (-len(raw) % 4)
    return json.loads(zlib.decompress(base64.urlsafe_b64decode(raw)[4:]))


def _server_conf() -> str:
    return generate_server_config(47180)["conf"]


def test_full_access_matches_app_contract() -> None:
    spec = FIXTURE["full_access"]
    awg2 = awg.build_fullaccess_awg_object(_server_conf())
    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=2221,
        private_key="KEY\n", description="srv", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-awg2"], awg2_config=awg2,
    )
    top = _decode(link)
    assert sorted(top) == sorted(spec["top_keys"]), "top-ключи full-access разъехались"
    assert top["defaultContainer"] == FIXTURE["default_container"]
    entry = next(c for c in top["containers"] if c["container"] == "amnezia-awg2")
    assert sorted(entry) == sorted(spec["container_entry_keys"])
    assert sorted(entry["awg"]) == sorted(spec["awg_keys"]), "awg-ключи разъехались"
    for k, v in spec["awg_invariants"].items():
        assert entry["awg"][k] == v


def test_client_link_matches_app_contract() -> None:
    spec = FIXTURE["client_link"]
    interface, _ = awg.parse_conf(_server_conf())
    params = {k: interface[k] for k in awg.AWG_PARAM_KEYS if k in interface}
    priv, _pub = awg.generate_keypair()
    conf = awg.build_client_config(
        client_private=priv, address="10.8.1.2",
        server_public="NSzHmLC7cq08Y7FK1EeAzPu51yZeOZiuoLIPYeeH3yk=",
        preshared="7jE5uKQj63MXTY7KX6oL90Oe5sCYvUCe/uab9fY3kao=",
        endpoint="203.0.113.10:47180", params=params, dns="1.1.1.1, 1.0.0.1",
    )
    link = awg.build_amnezia_link(conf, "203.0.113.10", "srv", "1.1.1.1", "1.0.0.1")
    top = _decode(link)
    assert sorted(top) == sorted(spec["top_keys"]), "top-ключи клиентской ссылки разъехались"
    assert top["defaultContainer"] == FIXTURE["default_container"]
    entry = next(c for c in top["containers"] if c["container"] == "amnezia-awg2")
    assert sorted(entry) == sorted(spec["container_entry_keys"])
    assert sorted(entry["awg"]) == sorted(spec["awg_keys"]), "awg-ключи клиента разъехались"
    for k, v in spec["awg_invariants"].items():
        assert entry["awg"][k] == v
    last_config = json.loads(entry["awg"]["last_config"])
    assert sorted(last_config) == sorted(spec["last_config_keys"]), "last_config разъехался"
