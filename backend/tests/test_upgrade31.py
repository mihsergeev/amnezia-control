"""Обновление AmneziaWG 2.0 → 3.1 ВНУТРИ контейнера amnezia-awg2.

Приложение AmneziaVPN знает ровно три имени контейнеров (amnezia-awg,
amnezia-awg2, amnezia-openvpn-cloak), а версию протокола берёт из поля
protocol_version, а не из имени. Поэтому отдельный панельный amnezia-awg3
приложение не видит вовсе, и «полный доступ» показывал 2.0 даже там, где рядом
крутилась третья версия. Единственный способ отдать приложению 3.1 — обновить
протокол на месте, в том же amnezia-awg2.

Тесты закрывают то, что нельзя проверить только на живой ноде: конфиг после
обновления обязан сохранить идентичность сервера (ключ, порт, подсеть) и всех
пиров, добавить ключи третьей версии в рабочих для движка границах и не
оставить следов 2.0-раскладки.
"""

import base64
import json
import re
import struct
import zlib

import pytest

from app import deploy
from app.api.awg import link_version_from_conf
from app.awg import build_fullaccess_awg_object

# конфиг 2.0 ровно в том виде, в каком его пишет панель: H диапазонами,
# I1 закомментирован, два живых пира
CONF_20 = """[Interface]
Address = 10.8.1.1/24
ListenPort = 47180
PrivateKey = cGFuZWxwcml2YXRla2V5YmFzZTY0MDAwMDAwMDAwMDA=
Jc = 4
Jmin = 8
Jmax = 80
S1 = 116
S2 = 61
S3 = 23
S4 = 9
H1 = 362244257-2055058689
H2 = 2117589042-2121064189
H3 = 2131202284-2144532456
H4 = 2147357173-2147462980
# I1 = <r 2><b 0x858000010001>

[Peer]
PublicKey = Y2xpZW50b25lcHVibGlja2V5MDAwMDAwMDAwMDAwMDA=
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = Y2xpZW50dHdvcHVibGlja2V5MDAwMDAwMDAwMDAwMDA=
AllowedIPs = 10.8.1.3/32
"""


def _iface(conf: str) -> str:
    return conf.split("[Peer]", 1)[0]


def _val(conf: str, key: str) -> str | None:
    m = re.search(rf"^{key} = (.+)$", _iface(conf), re.M)
    return m.group(1) if m else None


@pytest.fixture
def upgraded() -> str:
    return deploy.upgrade_conf_to_31(CONF_20, deploy.generate_awg3_params())


def test_upgrade_keeps_server_identity(upgraded: str) -> None:
    # ключ, порт и подсеть — это и есть «тот же сервер». Смена любого из них
    # означала бы не обновление, а новый сервер: приложение бы не подключилось,
    # а откат снимком перестал бы быть эквивалентным.
    assert _val(upgraded, "PrivateKey") == _val(CONF_20, "PrivateKey")
    assert _val(upgraded, "ListenPort") == "47180"
    assert _val(upgraded, "Address") == "10.8.1.1/24"


def test_upgrade_keeps_all_peers(upgraded: str) -> None:
    # пиры переносятся дословно: обновление меняет обфускацию, а не список
    # выданных клиентов (перевыпуск конфигов — отдельное действие оператора)
    assert upgraded.count("[Peer]") == 2
    for pk in ("Y2xpZW50b25lcHVibGlja2V5MDAwMDAwMDAwMDAwMDA=",
               "Y2xpZW50dHdvcHVibGlja2V5MDAwMDAwMDAwMDAwMDA="):
        assert pk in upgraded
    assert "10.8.1.2/32" in upgraded and "10.8.1.3/32" in upgraded


def test_upgrade_adds_all_31_keys(upgraded: str) -> None:
    for key in deploy.AWG3_PARAM_KEYS if hasattr(deploy, "AWG3_PARAM_KEYS") else (
        "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime",
        "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
        "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
    ):
        assert _val(upgraded, key), f"в конфиге нет ключа {key}"
    assert _val(upgraded, "RandomTrailers") in ("on", "off")
    assert _val(upgraded, "DisableCookies") in ("on", "off")
    # 32 байта base64 — движок отвергает ключ другой длины
    hpk = _val(upgraded, "HeaderProtectionKey")
    assert len(base64.b64decode(hpk)) == 32


def test_upgrade_respects_engine_junk_minimum(upgraded: str) -> None:
    # с HeaderProtectionKey движок требует КАЖДЫЙ S >= HeaderCipherNonceSize
    # (12). Исходный конфиг 2.0 держал S4 = 9 — если бы обновление тащило старые
    # S как есть, awg-quick падал бы при старте интерфейса.
    for key in ("S1", "S2", "S3", "S4"):
        assert int(_val(upgraded, key)) >= deploy._AWG3_MIN_JUNK, key


def test_upgrade_writes_ranges_not_single_values(upgraded: str) -> None:
    # тайминги/паддинг третьей версии задаются диапазонами — так их пишет и
    # приложение; одиночное значение движок не примет
    for key in ("ContentPaddingAddition", "RekeyAfterTime", "RejectAfterTime"):
        assert "-" in _val(upgraded, key), key


def test_upgrade_is_idempotent() -> None:
    # повторный прогон не должен дублировать ключи (иначе awg-quick упадёт на
    # неоднозначном конфиге)
    once = deploy.upgrade_conf_to_31(CONF_20, deploy.generate_awg3_params())
    twice = deploy.upgrade_conf_to_31(once, deploy.generate_awg3_params())
    for key in ("HeaderProtectionKey", "RandomTrailers", "DisableCookies"):
        assert len(re.findall(rf"^{key} = ", _iface(twice), re.M)) == 1, key


def test_link_version_follows_config() -> None:
    # версия в ссылке берётся из конфига, а не из имени контейнера
    assert link_version_from_conf(CONF_20) == "2"
    up = deploy.upgrade_conf_to_31(CONF_20, deploy.generate_awg3_params())
    assert link_version_from_conf(up) == "3.1"
    # нода, развёрнутая до появления 3.1: ключи 3.0 есть, 3.1 — нет. Такую
    # помечаем «3» — приложение не знает эту константу и предложит обновиться
    v30 = "\n".join(
        ln for ln in up.splitlines()
        if not ln.startswith(("RandomTrailers", "DisableCookies"))
    )
    assert link_version_from_conf(v30) == "3"


def test_fullaccess_object_reports_31_after_upgrade() -> None:
    # главный симптом бага: «полный доступ» показывал версию 2 на обновлённой
    # ноде. Объект для приложения обязан следовать за конфигом.
    assert build_fullaccess_awg_object(CONF_20)["protocol_version"] == "2"
    up = deploy.upgrade_conf_to_31(CONF_20, deploy.generate_awg3_params())
    obj = build_fullaccess_awg_object(up)
    assert obj["protocol_version"] == deploy.AWG3_PROTOCOL_VERSION
    assert obj["port"] == "47180"  # порт остаётся прежним
    assert obj["RandomTrailers"] in ("on", "off")
    assert obj["HeaderProtectionKey"]


def test_upgrade_script_nats_the_real_subnet() -> None:
    # правила NAT берутся из Address конфига, а не из константы панели: под
    # обновление попадают и ноды, взятые под управление у Amnezia/прошлого
    # админа, где подсеть своя. Промах = туннель поднялся, а интернета нет.
    conf = CONF_20.replace("Address = 10.8.1.1/24", "Address = 10.77.3.1/24")
    script = deploy.build_script_upgrade31(conf)
    assert "10.77.3.0/24" in script
    assert "10.8.1.0/24" not in script
    # адрес хоста (.1) в правило попасть не должен — только сеть
    assert "-s 10.77.3.1/24" not in script


def test_upgrade_script_is_valid_bash_and_targets_awg2() -> None:
    script = deploy.build_script_upgrade31(CONF_20)
    # обновляем именно контейнер приложения, а не панельный amnezia-awg3
    assert deploy.CONTAINER in script
    assert deploy.CONTAINER_V3 not in script
    # порт снимается с живого контейнера, а не подставляется по умолчанию
    assert "docker port" in script
    assert "DEPLOY_DONE" in script and "DEPLOY_ERROR" in script


@pytest.mark.parametrize("conf", [CONF_20])
def test_upgraded_conf_survives_link_roundtrip(conf: str) -> None:
    # клиентская ссылка на обновлённой ноде должна распаковываться и нести 3.1
    from app import awg as awgmod

    up = deploy.upgrade_conf_to_31(conf, deploy.generate_awg3_params())
    iface, _peers = awgmod.parse_conf(up)
    client = awgmod.build_client_config(
        client_private=base64.b64encode(bytes(range(32))).decode(),
        address="10.8.1.9",
        server_public=base64.b64encode(bytes(range(32, 64))).decode(),
        preshared=base64.b64encode(bytes(32)).decode(),
        endpoint="203.0.113.10:47180",
        params={k: iface[k] for k in awgmod.AWG_PARAM_KEYS if k in iface},
        dns="1.1.1.1",
    )
    link = awgmod.build_amnezia_link(
        client, "203.0.113.10", "srv", "1.1.1.1", "1.0.0.1",
        protocol_version=deploy.AWG3_PROTOCOL_VERSION,
    )
    raw = link[len("vpn://"):]
    raw += "=" * (-len(raw) % 4)
    blob = base64.urlsafe_b64decode(raw)
    assert struct.unpack(">I", blob[:4])[0] > 0
    data = json.loads(zlib.decompress(blob[4:]))
    inner = data["containers"][0]["awg"]
    assert inner["protocol_version"] == "3.1"
    assert inner["RandomTrailers"] in ("on", "off")
