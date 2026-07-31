"""AmneziaWG 3.0: генерация параметров, серверный конфиг, скрипт развёртывания.

Все инварианты сверены с исходниками апстрима (amneziawg-go v3.0.2,
amneziawg-tools v3.0.20260730) и проверены на живой ноде.
"""

import base64
import re

from app import awg, deploy


def test_awg3_junk_sizes_allow_header_protection() -> None:
    """КЛЮЧЕВОЙ инвариант 3.0: при заданном HeaderProtectionKey движок требует,
    чтобы КАЖДЫЙ из S1–S4 был >= 12 (HeaderCipherNonceSize) — иначе setconf
    падает с «Invalid argument». Ловили это на живой ноде: S4=6 роняло деплой.
    (Текст ошибки движка врёт: порог 12, а не 8, и индексы в нём с нуля.)"""
    for _ in range(200):
        p = deploy.generate_awg3_params()
        for key in ("S1", "S2", "S3", "S4"):
            assert int(p[key]) >= 12, f"{key}={p[key]} < 12 — защита заголовков не включится"


def test_awg3_header_protection_key_is_32_bytes() -> None:
    # ключ защиты заголовков — 32 байта (HeaderCipherKeySize), как PSK
    p = deploy.generate_awg3_params()
    assert len(base64.b64decode(p["HeaderProtectionKey"])) == 32


def test_awg3_ranges_are_valid() -> None:
    """Новые параметры 3.0 — диапазоны «low-high» с low < high; тайминги должны
    сохранять инвариант протокола RejectAfterTime > RekeyAfterTime."""
    for _ in range(100):
        p = deploy.generate_awg3_params()
        bounds = {}
        for key in ("ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
                    "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"):
            m = re.fullmatch(r"(\d+)-(\d+)", str(p[key]))
            assert m, f"{key}={p[key]} не диапазон low-high"
            lo, hi = int(m.group(1)), int(m.group(2))
            assert lo < hi, f"{key}: low не меньше high"
            bounds[key] = (lo, hi)
        # отбраковка ключа протокола: истечение должно наступать позже перевыпуска
        assert bounds["RejectAfterTime"][0] > bounds["RekeyAfterTime"][1]


def test_awg3_server_config_shape() -> None:
    conf = deploy.generate_server_config_v3(47300)["conf"]
    # своя подсеть — чтобы 3.0 и 2.0 не конфликтовали на одной ноде
    assert f"Address = {deploy.SUBNET_V3}" in conf
    assert deploy.SUBNET_V3 != deploy.SUBNET
    # активные ключи третьей версии
    for key in ("HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime",
                "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
                "MaxHandshakeAttempts"):
        assert re.search(rf"^{key} = ", conf, re.M), f"{key} нет среди активных"
    # I1–I5, как и в 2.0, закомментированы (awg-quick их к серверу не применяет)
    assert "# I1 = " in conf and not re.search(r"^I1 = ", conf, re.M)
    # H1–H4 остались диапазонами (в 3.0 это по-прежнему u32-диапазоны)
    assert re.search(r"^H1 = \d+-\d+$", conf, re.M)


def test_awg3_script_builds_from_source_not_stale_image() -> None:
    """Официальный образ amneziavpn/amneziawg-go даже с тегом 3.0.2 содержит
    старые бинари (tools v1.0.20210914, движок без ключей 3.0) — проверено на
    ноде. Поэтому 3.0 обязан собираться из исходников по закреплённым тегам."""
    cfg = deploy.generate_server_config_v3(47300)
    script = deploy.build_script_v3("deploy", 47300, cfg)
    assert deploy.AWG3_GO_TAG in script and deploy.AWG3_TOOLS_TAG in script
    # Dockerfile уезжает на ноду base64-блобом — проверяем его содержимое
    blobs = re.findall(r"echo ([A-Za-z0-9+/=]{40,}) \| base64 -d", script)
    decoded = [base64.b64decode(b).decode() for b in blobs]
    dockerfile = next(d for d in decoded if d.startswith("FROM "))
    assert "amnezia-vpn/amneziawg-go" in dockerfile
    assert "amnezia-vpn/amneziawg-tools" in dockerfile
    assert deploy.AWG3_GO_TAG in dockerfile and deploy.AWG3_TOOLS_TAG in dockerfile
    # базовый образ Amnezia (со старыми бинарями) для 3.0 НЕ используется
    assert "amneziavpn/amneziawg-go" not in dockerfile
    assert "amneziavpn/amneziawg-go" not in script


def test_awg3_script_readback_uses_awg_binary() -> None:
    """В собранном из исходников образе бинарь называется `awg`; `wg` там нет.
    Регресс: readback с `wg show` ложно объявлял успешный деплой провалившимся."""
    cfg = deploy.generate_server_config_v3(47300)
    script = deploy.build_script_v3("deploy", 47300, cfg)
    assert "awg show awg0" in script
    assert "wg show awg0" not in script.replace("awg show awg0", "")
    assert 'grep -qE "listening port"' in script  # сам readback на месте


def test_awg3_image_provides_wg_aliases() -> None:
    """Панель управляет клиентами командами `wg show/set`. В образе из исходников
    бинарь называется `awg`, поэтому нужны алиасы — иначе выдача/отзыв клиентов
    3.0 падают с 502 (ловили на живой ноде)."""
    cfg = deploy.generate_server_config_v3(47300)
    script = deploy.build_script_v3("deploy", 47300, cfg)
    blobs = re.findall(r"echo ([A-Za-z0-9+/=]{40,}) \| base64 -d", script)
    dockerfile = next(
        d for d in (base64.b64decode(b).decode() for b in blobs) if d.startswith("FROM ")
    )
    assert "ln -sf /usr/bin/awg /usr/bin/wg" in dockerfile
    assert "ln -sf /usr/bin/awg-quick /usr/bin/wg-quick" in dockerfile


def test_awg3_script_isolates_from_other_protocols() -> None:
    """3.0 не должен задевать контейнеры 2.0/legacy на той же ноде."""
    cfg = deploy.generate_server_config_v3(47300)
    script = deploy.build_script_v3("deploy", 47300, cfg)
    assert deploy.CONTAINER_V3 in script
    assert deploy.HOST_DIR_V3 in script
    # снос — только своего контейнера и того, кто занял наш порт
    assert 'name=^${CONT}$' in script
    assert deploy.CONTAINER not in script  # amnezia-awg2 не упоминается


def test_panel_awg3_container_not_treated_as_foreign() -> None:
    """Регресс: контейнер 3.0 собран образом acontrol-awg3 — если не считать его
    своим, он блокировал бы deploy/update AmneziaWG 2.0 на той же ноде (409)."""
    out = (
        f"amnezia-awg2\t{deploy.IMAGE}:latest\n"
        f"amnezia-awg3\t{deploy.IMAGE_V3}:latest\n"
        "amnezia-awg\tamneziavpn/amnezia-wg:latest\n"
    )
    assert deploy._parse_foreign_awg(out) == ["amnezia-awg"]


async def test_awg2_detection_excludes_awg3_container() -> None:
    """Регресс (поймано на ноде с обеими версиями): у контейнера 3.0 тоже
    awg0.conf, поэтому детектор 2.0 принимал его за «новый» контейнер и операции
    2.0 уходили на сервер 3.0. Команды детекта обязаны исключать awg3."""

    seen: list[str] = []

    class FakeResult:
        stdout = ""
        stderr = ""
        exit_status = 0

    class FakeConn:
        async def run(self, cmd, **kw):
            seen.append(cmd)
            return FakeResult()

    conts = await awg.detect_awg_containers(FakeConn())
    assert conts == {"new": None, "legacy": None}
    assert "grep -iv awg3" in seen[0], "детект 2.0 не исключает контейнер 3.0"


def test_client_config_mirrors_v3_params() -> None:
    """Клиент обязан повторять параметры 3.0 за сервером (ключ защиты заголовков
    — общий секрет, диапазоны — общие рамки)."""
    conf = deploy.generate_server_config_v3(47300)["conf"]
    interface, _ = awg.parse_conf(conf)
    params = {k: interface[k] for k in awg.AWG_PARAM_KEYS if k in interface}
    client = awg.build_client_config(
        client_private="k", address="10.8.3.2", server_public="s", preshared="p",
        endpoint="203.0.113.10:47300", params=params, dns="1.1.1.1",
    )
    for key in awg.AWG3_PARAM_KEYS:
        assert f"{key} = {interface[key]}" in client, f"{key} не перенесён клиенту"


def test_v3_link_carries_v3_fields_and_version() -> None:
    """vpn://-ссылка 3.0 должна нести поля третьей версии и protocol_version=3."""
    import json
    import zlib

    conf = deploy.generate_server_config_v3(47300)["conf"]
    interface, _ = awg.parse_conf(conf)
    params = {k: interface[k] for k in awg.AWG_PARAM_KEYS if k in interface}
    priv, _pub = awg.generate_keypair()
    client = awg.build_client_config(
        client_private=priv, address="10.8.3.2",
        server_public="NSzHmLC7cq08Y7FK1EeAzPu51yZeOZiuoLIPYeeH3yk=",
        preshared="7jE5uKQj63MXTY7KX6oL90Oe5sCYvUCe/uab9fY3kao=",
        endpoint="203.0.113.10:47300", params=params, dns="1.1.1.1, 1.0.0.1",
    )
    link = awg.build_amnezia_link(
        client, "203.0.113.10", "srv", "1.1.1.1", "1.0.0.1", protocol_version="3"
    )
    raw = link[len("vpn://"):]
    raw += "=" * (-len(raw) % 4)
    top = json.loads(zlib.decompress(base64.urlsafe_b64decode(raw)[4:]))
    obj = top["containers"][0]["awg"]
    assert obj["protocol_version"] == "3"
    for key in awg.AWG3_PARAM_KEYS:
        assert obj[key] == interface[key]


def test_v2_link_unchanged_by_v3_support() -> None:
    """Ссылка 2.0 не должна измениться от добавления 3.0: тот же набор ключей
    и protocol_version=2 (иначе поедет совместимость с приложением)."""
    import json
    import zlib

    conf = deploy.generate_server_config(47180)["conf"]
    interface, _ = awg.parse_conf(conf)
    params = {k: interface[k] for k in awg.AWG_PARAM_KEYS if k in interface}
    priv, _pub = awg.generate_keypair()
    client = awg.build_client_config(
        client_private=priv, address="10.8.1.2",
        server_public="NSzHmLC7cq08Y7FK1EeAzPu51yZeOZiuoLIPYeeH3yk=",
        preshared="7jE5uKQj63MXTY7KX6oL90Oe5sCYvUCe/uab9fY3kao=",
        endpoint="203.0.113.10:47180", params=params, dns="1.1.1.1, 1.0.0.1",
    )
    link = awg.build_amnezia_link(client, "203.0.113.10", "srv", "1.1.1.1", "1.0.0.1")
    raw = link[len("vpn://"):]
    raw += "=" * (-len(raw) % 4)
    obj = json.loads(zlib.decompress(base64.urlsafe_b64decode(raw)[4:]))
    entry = obj["containers"][0]["awg"]
    assert entry["protocol_version"] == "2"
    for key in awg.AWG3_PARAM_KEYS:
        assert key not in entry  # полей 3.0 в ссылке 2.0 быть не должно
