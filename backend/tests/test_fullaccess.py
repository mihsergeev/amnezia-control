"""full-access vpn:// link: правильная классификация контейнеров.

Регресс на баг, из-за которого новый AmneziaWG 2.0 (amnezia-awg2) кодировался
как legacy amnezia-awg → приложение метило «AmneziaWG Legacy» и падало с
ErrorCode 202 («отсутствует Docker-контейнер»)."""

import base64
import json
import struct
import zlib

from app.fullaccess import _canonical, build_full_access_link


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
