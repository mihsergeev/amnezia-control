"""full-access vpn:// link: правильная классификация контейнеров.

Регресс на баг, из-за которого новый AmneziaWG 2.0 (amnezia-awg2) кодировался
как legacy amnezia-awg → приложение метило «AmneziaWG Legacy» и падало с
ErrorCode 202 («отсутствует Docker-контейнер»)."""

import base64
import json
import struct
import zlib

from app.awg import build_fullaccess_awg_object
from app.fullaccess import _canonical, build_full_access_link

# серверный awg0.conf в формате панели/приложения: H1-H4 диапазонами (маркер 2.0),
# I1 закомментирован (CPS раздаётся клиентам, но awg-quick его не применяет)
_SERVER_CONF = """[Interface]
Address = 10.8.1.1/24
ListenPort = 45728
PrivateKey = privkeybase64==
Jc = 6
Jmin = 10
Jmax = 50
S1 = 116
S2 = 15
S3 = 23
S4 = 9
H1 = 362244257-2055058689
H2 = 2117589042-2121064189
H3 = 2131202284-2144532456
H4 = 2147357173-2147462980
# I1 = <r 2><b 0x858000010001>

[Peer]
PublicKey = clientpubkey==
AllowedIPs = 10.8.1.2/32
"""


def _decode(link: str) -> dict:
    raw = link[len("vpn://"):]
    raw += "=" * (-len(raw) % 4)
    blob = base64.urlsafe_b64decode(raw)
    return json.loads(zlib.decompress(blob[4:]))


def test_canonical_new_awg_not_collapsed_to_legacy() -> None:
    # новый AmneziaWG 2.0 — отдельный тип, НЕ схлопывается в legacy
    assert _canonical("amnezia-awg2") == "amnezia-awg2"
    # реальный legacy остаётся legacy
    assert _canonical("amnezia-awg") == "amnezia-awg"
    assert _canonical("amnezia-openvpn-cloak") == "amnezia-openvpn-cloak"
    assert _canonical("amnezia-xray") == "amnezia-xray"


def test_link_encodes_awg2_container() -> None:
    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=22,
        private_key="KEY", description="srv", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-awg2"],
    )
    top = _decode(link)
    assert top["defaultContainer"] == "amnezia-awg2"
    assert {"container": "amnezia-awg2"} in top["containers"]
    assert {"container": "amnezia-awg"} not in top["containers"]


def test_link_keeps_both_awg_when_present() -> None:
    # сервер с двумя AWG (legacy + new) — оба типа в ссылке
    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=22,
        private_key="KEY", description="srv", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-awg", "amnezia-awg2", "amnezia-xray"],
    )
    types = {c["container"] for c in _decode(link)["containers"]}
    assert types == {"amnezia-awg", "amnezia-awg2", "amnezia-xray"}


def test_awg_object_matches_app_format() -> None:
    # awg-объект для full-access строится из серверного конфига и повторяет
    # формат экспорта приложения (protocol_version="2", H диапазонами, I2-I5="")
    obj = build_fullaccess_awg_object(_SERVER_CONF)
    assert obj["protocol_version"] == "2"
    assert obj["transport_proto"] == "udp"
    assert obj["port"] == "45728"
    assert obj["subnet_address"] == "10.8.1.0"
    assert obj["H1"] == "362244257-2055058689"  # диапазон — маркер 2.0
    assert "-" in obj["H4"]
    assert obj["Jc"] == "6" and obj["S3"] == "23" and obj["S4"] == "9"
    assert obj["I1"].startswith("<r 2>")  # CPS из закомментированной строки
    assert obj["I2"] == "" == obj["I5"]  # пустые CPS явно присутствуют
    # last_config в full-access НЕ вкладывается (в отличие от клиентской ссылки)
    assert "last_config" not in obj


def test_link_embeds_awg2_protocol_config() -> None:
    # ключевой регресс: full-access должен нести вложенный awg-объект, иначе
    # приложение не видит версию 2 и метит сервер legacy (не подключается)
    awg2 = build_fullaccess_awg_object(_SERVER_CONF)
    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=2221,
        private_key="KEY\n", description="de-hz", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-awg2"], awg2_config=awg2,
    )
    top = _decode(link)
    entry = next(c for c in top["containers"] if c["container"] == "amnezia-awg2")
    assert entry["awg"]["protocol_version"] == "2"
    assert entry["awg"]["port"] == "45728"
    assert entry["awg"]["subnet_address"] == "10.8.1.0"
    assert top["defaultContainer"] == "amnezia-awg2"
    assert set(top) >= {"hostName", "userName", "password", "port", "dns1", "dns2"}


def test_link_without_awg2_config_stays_bare() -> None:
    # если конфиг не передан (нода без awg2) — контейнер без вложенного объекта
    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=22,
        private_key="KEY", description="srv", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-openvpn-cloak"],
    )
    entry = _decode(link)["containers"][0]
    assert entry == {"container": "amnezia-openvpn-cloak"}
