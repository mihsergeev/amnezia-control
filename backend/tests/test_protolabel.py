"""Подпись протокола клиента с версией - как плашки на карточке сервера.

Раскладки взяты с настоящих нод. Ключ протокола версию не несет: у Amnezia
контейнер amnezia-awg2 бывает и 1.0, а в amnezia-awg3 живет и старая 3.0.
Раньше в топе клиентов Legacy и 3.x выходили с пустой плашкой, а поиск
подписывал любую 3.x как 3.0.
"""

import json
from types import SimpleNamespace

from app.protolabel import protocol_label


def _srv(containers: list[str], kinds: dict[str, str]) -> SimpleNamespace:
    return SimpleNamespace(last_check_info=json.dumps(
        {"amnezia_containers": containers, "protocols": kinds}))


# vpn-corp: старая 3.0, 2.0 и Legacy на одной ноде
CORP = _srv(["amnezia-awg3", "amnezia-awg2", "amnezia-awg"],
            {"amnezia-awg3": "awg3", "amnezia-awg2": "awg2", "amnezia-awg": "awg1"})
# vpn-x-developer: 3.1 рядом с 2.0 и xray
DEV = _srv(["amnezia-awg3", "amnezia-xray", "amnezia-awg2"],
           {"amnezia-awg3": "awg31", "amnezia-xray": "xray", "amnezia-awg2": "awg2"})
# vpn-g: контейнер назван amnezia-awg2, а внутри AmneziaWG 1.0
MISNAMED = _srv(["amnezia-awg2", "amnezia-xray"], {"amnezia-awg2": "awg1", "amnezia-xray": "xray"})


def test_three_versions_on_one_node() -> None:
    assert protocol_label(CORP, "awg") == "AmneziaWG 2.0"
    assert protocol_label(CORP, "awg3") == "AmneziaWG 3.0"  # правда 3.0, а не 3.1
    assert protocol_label(CORP, "awglegacy") == "AmneziaWG Legacy"


def test_31_next_to_20() -> None:
    assert protocol_label(DEV, "awg3") == "AmneziaWG 3.1"
    assert protocol_label(DEV, "awg") == "AmneziaWG 2.0"
    assert protocol_label(DEV, "xray") == "XRay/REALITY"


def test_version_comes_from_config_not_container_name() -> None:
    assert protocol_label(MISNAMED, "awg") == "AmneziaWG 1.0"


def test_upgraded_in_place_to_31() -> None:
    srv = _srv(["amnezia-awg2"], {"amnezia-awg2": "awg31"})
    assert protocol_label(srv, "awg") == "AmneziaWG 3.1"


def test_lone_legacy_container_labelled_by_version() -> None:
    # старый контейнер один на ноде: сборщик пишет его клиентов как awglegacy,
    # а карточка сервера подписывает его версией - подпись должна совпасть
    srv = _srv(["amnezia-awg"], {"amnezia-awg": "awg1"})
    assert protocol_label(srv, "awglegacy") == "AmneziaWG 1.0"


def test_without_check_info_falls_back_sanely() -> None:
    # нода еще не проверялась: подпись без версии, но не пустая
    blank = SimpleNamespace(last_check_info="")
    assert protocol_label(blank, "awg") == "AmneziaWG"
    assert protocol_label(blank, "awg3") == "AmneziaWG 3.1"
    assert protocol_label(blank, "awglegacy") == "AmneziaWG Legacy"
    assert protocol_label(None, "openvpn") == "OpenVPN/Cloak"
    assert protocol_label(SimpleNamespace(last_check_info="{broken"), "awg") == "AmneziaWG"


def test_unknown_protocol_is_never_blank() -> None:
    assert protocol_label(CORP, "wireguard") == "wireguard"
