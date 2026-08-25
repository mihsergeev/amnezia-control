"""Разворачивание и обновление AmneziaWG на ноде (build-on-target).

Стратегия: собираем образ прямо на сервере из официального базового образа
Amnezia `amneziavpn/amneziawg-go:latest` (Docker Hub) + наш start.sh. По SSH
уходит только маленький скрипт; тяжёлый базовый образ сервер тянет сам.

Версии сравниваются по digest базового образа: локальный (на ноде) против
текущего `:latest` на Docker Hub.
"""

import base64
import random
import re
import secrets

import asyncssh
import httpx

from app import awg

BASE_REPO = "amneziavpn/amneziawg-go"
# Известный рабочий digest базового образа. НОВЫЕ развёртывания (deploy/adopt)
# пинятся на него — чтобы внезапно сломанный `:latest` на Docker Hub не поломал
# установку на свежих нодах. Обновление образа — ЯВНОЕ действие (mode="update",
# кнопка «Обновить» в UI), оно намеренно тянет `:latest`. Порядок обновления пина:
# дождаться нового latest → проверить его canary/тестом → вписать сюда новый digest.
PINNED_BASE_DIGEST = (
    "sha256:acef5ae84808a9568448e9d8c7a96f640a5ccc590b0f8dfbc2df9f9dc0e848c9"
)  # latest на 2026-06-17
BASE_IMAGE_LATEST = f"{BASE_REPO}:latest"
BASE_IMAGE_PINNED = f"{BASE_REPO}@{PINNED_BASE_DIGEST}"
# файл-маркер на ноде: точный digest базового образа, на котором собран текущий
# контейнер (пишется деплоем). Детект версий читает его — не зависит от того,
# каким рефом (пин/тег) тянули, и переживает уход `:latest` вперёд.
BASE_DIGEST_MARKER = "/opt/acontrol/base-digest"
IMAGE = "acontrol-awg"
CONTAINER = "amnezia-awg2"
SUBNET = "10.8.1.0/24"

# --- AmneziaWG 3.0 ----------------------------------------------------------
# Третья версия протокола — ОТДЕЛЬНЫЙ протокол рядом с 2.0 и legacy: свой
# контейнер, порт, подсеть и каталог конфига, поэтому обе версии спокойно живут
# на одной ноде и клиенты одной не задеваются операциями над другой.
# ВАЖНО про образ: официальный amneziavpn/amneziawg-go даже с тегом 3.0.2
# (latest на 28.07.2026) содержит СТАРЫЕ бинари — amneziawg-tools v1.0.20210914 и
# go-движок без UAPI-ключей третьей версии. Проверено на ноде: `awg setconf`
# отвечает «Line unrecognized: HeaderProtectionKey». Поэтому 3.0 собираем ИЗ
# ИСХОДНИКОВ по закреплённым тегам — это единственный способ получить рабочий
# AmneziaWG 3.0 сегодня и заодно независимость от сроков обновления их образа.
AWG3_GO_TAG = "v3.1.20260814"  # amneziawg-go (движок)
AWG3_TOOLS_TAG = "v3.1.20260812"  # amneziawg-tools (awg / awg-quick)
# Версия протокола в vpn://-ссылке. У приложения это СТРОКА «3.1»
# (protocolConstants.h: awgV3[] = "3.1"), а не «3»: наши прежние ссылки с "3"
# приложение не распознавало и рисовало сервер без номера версии. Более того,
# любой awg-контейнер с protocol_version != "3.1" оно метит устаревшим
# (serversUiController.cpp) и показывает баннер «обновите протокол».
AWG3_PROTOCOL_VERSION = "3.1"
AWG3_VERSION_MARKER = "/opt/acontrol/awg3-version"
IMAGE_V3 = "acontrol-awg3"
CONTAINER_V3 = "amnezia-awg3"
SUBNET_V3 = "10.8.3.0/24"  # НЕ пересекается с 2.0 (10.8.1.0/24) на той же ноде
# конфиг 3.0 живёт в отдельном каталоге хоста, а внутрь контейнера монтируется на
# штатный путь — иначе два контейнера делили бы один awg0.conf и затирали друг друга
HOST_DIR_V3 = "/opt/amnezia/awg3"
# образы, которые собирает САМА панель (для отличия своих контейнеров от чужих)
_PANEL_AWG_IMAGES = {IMAGE, IMAGE_V3}
# Каталог рабочих файлов деплоя — в $HOME текущего ssh-пользователя (всегда наш,
# без коллизий владельца в общем /tmp) и СВОЙ у каждого протокола (tag), чтобы
# лог одного деплоя не подменял другой на сервере с несколькими протоколами.
WORK_ROOT = "$HOME/.acontrol"
HUB_TAGS_URL = "https://hub.docker.com/v2/repositories/amneziavpn/amneziawg-go/tags?page_size=50"

def _start_sh(subnet: str = SUBNET) -> str:
    """Точка входа контейнера. Параметр — подсеть клиентов: у 3.0 она своя, а
    для 2.0 подставляется прежняя, поэтому её скрипт остаётся байт-в-байт тем же."""
    return f"""#!/bin/sh
# Amnezia Control: точка входа контейнера AmneziaWG
awg-quick down /opt/amnezia/awg/awg0.conf >/dev/null 2>&1
awg-quick up /opt/amnezia/awg/awg0.conf 2>/dev/null || true
iptables -t nat -C POSTROUTING -s {subnet} -o eth0 -j MASQUERADE 2>/dev/null \\
  || iptables -t nat -A POSTROUTING -s {subnet} -o eth0 -j MASQUERADE
iptables -C FORWARD -i awg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -j ACCEPT
iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \\
  || iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
exec tail -f /dev/null
"""


START_SH = _start_sh()

def _dockerfile(base_ref: str) -> str:
    """Dockerfile надстройки над базовым образом. base_ref — пин (repo@sha256:…)
    для обычного деплоя или repo:latest для явного обновления."""
    return (
        f"FROM {base_ref}\n"
        "RUN apk add --no-cache bash iptables iproute2 2>/dev/null \\\n"
        "  || (apt-get update && apt-get install -y --no-install-recommends bash iptables iproute2) \\\n"
        "  || true\n"
        "COPY start.sh /opt/amnezia/start.sh\n"
        "RUN chmod +x /opt/amnezia/start.sh\n"
        'ENTRYPOINT ["/opt/amnezia/start.sh"]\n'
    )

# идемпотентный подъём интерфейса + NAT внутри контейнера
def _dockerfile_v3() -> str:
    """Образ AmneziaWG 3.0: движок и тулзы собираются из исходников по
    закреплённым тегам (готового образа с бинарями 3.0 в природе пока нет).
    Многостадийная сборка — в финальном образе только бинари, без тулчейнов."""
    return (
        f"FROM golang:1.25-alpine AS go-build\n"
        "RUN apk add --no-cache git make\n"
        f"RUN git clone --depth 1 --branch {AWG3_GO_TAG} "
        "https://github.com/amnezia-vpn/amneziawg-go /src && make -C /src\n"
        "\n"
        "FROM alpine:3.22 AS tools-build\n"
        "RUN apk add --no-cache git make build-base linux-headers bash\n"
        f"RUN git clone --depth 1 --branch {AWG3_TOOLS_TAG} "
        "https://github.com/amnezia-vpn/amneziawg-tools /src && "
        "make -C /src/src install DESTDIR=/out PREFIX=/usr WITH_WGQUICK=yes\n"
        "\n"
        "FROM alpine:3.22\n"
        "RUN apk add --no-cache bash iptables iproute2 openresolv\n"
        "COPY --from=go-build /src/amneziawg-go /usr/bin/amneziawg-go\n"
        "COPY --from=tools-build /out/usr/bin/awg /usr/bin/awg\n"
        "COPY --from=tools-build /out/usr/bin/awg-quick /usr/bin/awg-quick\n"
        # amneziawg-tools — форк wireguard-tools, и панель читает состояние нод
        # командами `wg show/set`. В базовом образе Amnezia `wg` есть, в собранном
        # из исходников — нет, поэтому даём алиасы: иначе все клиентские операции
        # 3.0 падали бы с 502 (проверено на ноде).
        "RUN ln -sf /usr/bin/awg /usr/bin/wg "
        "&& ln -sf /usr/bin/awg-quick /usr/bin/wg-quick\n"
        "COPY start.sh /opt/amnezia/start.sh\n"
        "RUN chmod +x /opt/amnezia/start.sh\n"
        'ENTRYPOINT ["/opt/amnezia/start.sh"]\n'
    )


def _bringup(subnet: str = SUBNET) -> str:
    """Идемпотентный подъём интерфейса + NAT внутри контейнера (подсеть — своя
    у каждой версии протокола)."""
    return (
        "awg-quick down /opt/amnezia/awg/awg0.conf >/dev/null 2>&1; "
        "awg-quick up /opt/amnezia/awg/awg0.conf; "
        f"iptables -t nat -C POSTROUTING -s {subnet} -o eth0 -j MASQUERADE 2>/dev/null "
        f"|| iptables -t nat -A POSTROUTING -s {subnet} -o eth0 -j MASQUERADE; "
        "iptables -C FORWARD -i awg0 -j ACCEPT 2>/dev/null "
        "|| iptables -A FORWARD -i awg0 -j ACCEPT; "
        "iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null "
        "|| iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"
    )


_BRINGUP = _bringup()


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# I1 по умолчанию как у самого приложения Amnezia (CPS-пакет, мимикрирующий под
# DNS-ответ icloud.com); I2–I5 приложение оставляет ПУСТЫМИ. Берём тот же дефолт —
# так конфиг байт-в-байт совместим с деплоем приложения (full-access видит 2.0).
_DEFAULT_SPECIAL_JUNK_1 = (
    "<r 2><b 0x858000010001000000000669636c6f756403636f6d"
    "0000010001c00c000100010000105a00044d583737>"
)


def generate_awg_params() -> dict[str, object]:
    """Параметры обфускации AmneziaWG 2.0 — точно как генерит приложение Amnezia:
    H1–H4 в формате ДИАПАЗОНОВ «low-high» (это и есть признак 2.0; одиночные
    значения приложение считает 1.0/Legacy), I1 = дефолтный CPS, I2–I5 пустые."""
    jc = random.randint(4, 6)  # у приложения bounded(4, 7)
    jmin = 10  # у приложения фиксировано
    jmax = 50
    while True:
        s1 = random.randint(15, 150)
        s2 = random.randint(15, 150)
        if s1 != s2 and s1 + 56 != s2 and s2 + 56 != s1:
            break
    s3 = random.randint(0, 64)
    s4 = random.randint(0, 20)  # у приложения bounded(0, 20)
    # H1–H4: восходящие непересекающиеся диапазоны (каждый следующий стартует от
    # верхней границы предыдущего) — как AwgInstaller::generateAwgParameters для 2.0
    headers: list[str] = []
    lo = 5
    hi_max = 2**31 - 1
    for _ in range(4):
        first = random.randint(lo, hi_max - 1)
        second = random.randint(first, hi_max)
        lo = second
        headers.append(f"{first}-{second}")
    return {
        "Jc": jc, "Jmin": jmin, "Jmax": jmax,
        "S1": s1, "S2": s2, "S3": s3, "S4": s4,
        "H1": headers[0], "H2": headers[1], "H3": headers[2], "H4": headers[3],
        "I1": _DEFAULT_SPECIAL_JUNK_1, "I2": "", "I3": "", "I4": "", "I5": "",
    }


# Активные параметры (применяются awg-quick к серверному интерфейсу) и порядок.
# I1–I5 (CPS) в СЕРВЕРНОМ конфиге хранятся ЗАКОММЕНТИРОВАННЫМИ (как у Amnezia):
# awg-quick их не применяет (это клиентский джанк, сервер входящий CPS игнорит),
# они нужны лишь чтобы раздавать клиентам — и чтобы приложение AmneziaVPN по
# full-access прочитало их из «# I1 = …» (иначе клиент выходит без CPS и
# рукопожатие с 2.0-сервером не сходится).
_AWG_ACTIVE_ORDER = [
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
]
_AWG_CPS_KEYS = ["I1", "I2", "I3", "I4", "I5"]


def generate_server_config(port: int) -> dict[str, str]:
    priv, pub = awg.generate_keypair()
    psk = base64.b64encode(secrets.token_bytes(32)).decode()
    p = generate_awg_params()
    conf = (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {SUBNET}\n"
        f"ListenPort = {port}\n"
        + "".join(f"{k} = {p[k]}\n" for k in _AWG_ACTIVE_ORDER)
        + "".join(f"# {k} = {p[k]}\n" for k in _AWG_CPS_KEYS)
    )
    return {"priv": priv, "pub": pub, "psk": psk, "conf": conf}


# --- параметры AmneziaWG 3.0 ------------------------------------------------
# Что 3.0 добавляет к 2.0 (сверено с исходниками amneziawg-tools v3.0.20260730 и
# amneziawg-go v3.0.2, ключи .conf — src/config.c):
#   HeaderProtectionKey    — 32-байтный ключ (как PSK): защита заголовков пакетов
#   ContentPaddingAddition — добавочный паддинг содержимого, ДИАПАЗОН uint16
#   Rekey/Reject/Keepalive/MaxHandshakeAttempts — тайминги протокола, тоже
#   диапазоны uint16: значение выбирается в пределах диапазона, что размывает
#   характерный временной «отпечаток» WireGuard.
# H1–H4 в 3.0 остались диапазонами uint32, как в 2.0 (u32_range_from_string).
_AWG3_TIMING_DEFAULTS = {
    # Диапазоны вокруг штатных таймингов WireGuard: рандомизация ломает
    # тайминг-фингерпринт, но остаётся в проверенных пределах. Инвариант
    # RejectAfterTime > RekeyAfterTime соблюдён с запасом (180-200 > 120-140).
    "RekeyAfterTime": (120, 140),      # WG: 120
    "RekeyTimeout": (5, 7),            # WG: 5
    "RejectAfterTime": (180, 200),     # WG: 180
    "KeepaliveTimeout": (10, 12),      # WG: 10
    "MaxHandshakeAttempts": (18, 20),  # WG: 18
}



# Минимальный размер джанка при включённой защите заголовков. Движок 3.0
# требует, чтобы КАЖДЫЙ из S1–S4 был >= HeaderCipherNonceSize (12): под nonce
# шифра заголовка нужно место. Иначе setconf падает с «Invalid argument».
# ОСТОРОЖНО с текстом ошибки движка: «S3 must be more then 8 to use
# headerProtection» врёт дважды — порог на самом деле 12, а индекс в сообщении
# нумеруется с нуля, поэтому «S3» означает S4 (проверено на живой ноде).
_AWG3_MIN_JUNK = 12


def generate_awg3_params() -> dict[str, object]:
    """Параметры AmneziaWG 3.1 = параметры 2.0 + ключи третьей версии.

    3.1 к 3.0 добавила ровно два булевых ключа (RandomTrailers, DisableCookies)
    и ничего не убрала — сверено дифом amneziawg-tools v3.0→v3.1. Значения у
    приложения строковые «on»/«off» (awgBoolOn/awgBoolOff), оба по умолчанию
    включены (defaultRandomTrailers / defaultDisableCookies).
    """
    p = dict(generate_awg_params())
    # S3/S4 у 2.0 могут быть меньше 12 (0-64 и 0-20) — для 3.0 поднимаем порог,
    # иначе защита заголовков не включится. S1/S2 и так генерятся от 15.
    p["S3"] = random.randint(_AWG3_MIN_JUNK, 64)
    p["S4"] = random.randint(_AWG3_MIN_JUNK, 20)
    # ключ защиты заголовков — общий секрет сервера и клиента (как PSK), 32 байта
    p["HeaderProtectionKey"] = base64.b64encode(secrets.token_bytes(32)).decode()
    # добавочный паддинг держим скромным: конверт не должен упереться в MTU
    lo = random.randint(0, 8)
    p["ContentPaddingAddition"] = f"{lo}-{lo + random.randint(4, 16)}"
    for key, (low, high) in _AWG3_TIMING_DEFAULTS.items():
        start = random.randint(low, high - 1)
        p[key] = f"{start}-{random.randint(start + 1, high)}"
    # ключи 3.1: включены, как и у приложения (оба дефолта — «on»)
    p["RandomTrailers"] = "on"
    p["DisableCookies"] = "on"
    return p


_AWG3_ACTIVE_ORDER = _AWG_ACTIVE_ORDER + [
    "HeaderProtectionKey", "ContentPaddingAddition",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts",
    # порядок как в template.conf приложения: новые ключи 3.1 идут последними
    "RandomTrailers", "DisableCookies",
]


def generate_server_config_v3(port: int) -> dict[str, str]:
    """Серверный awg0.conf для AmneziaWG 3.0. I1–I5, как и в 2.0, пишем
    ЗАКОММЕНТИРОВАННЫМИ: awg-quick их к серверу не применяет (это клиентский
    джанк), но они нужны, чтобы раздать их клиентам."""
    priv, pub = awg.generate_keypair()
    psk = base64.b64encode(secrets.token_bytes(32)).decode()
    p = generate_awg3_params()
    conf = (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {SUBNET_V3}\n"
        f"ListenPort = {port}\n"
        + "".join(f"{k} = {p[k]}\n" for k in _AWG3_ACTIVE_ORDER)
        + "".join(f"# {k} = {p[k]}\n" for k in _AWG_CPS_KEYS)
    )
    return {"priv": priv, "pub": pub, "psk": psk, "conf": conf}


def build_script(
    mode: str, port: int, cfg: dict[str, str], base_ref: str | None = None
) -> str:
    """mode: 'deploy' | 'adopt' | 'update'. base_ref — конкретный образ для
    режима update (см. ниже); по умолчанию берётся ветка 2.x, а НЕ `:latest`.

    deploy/adopt пинятся на PINNED_BASE_DIGEST (известный рабочий образ) — так
    сломанный `:latest` не ломает новые установки. update ТЯНЕТ `:latest`
    намеренно (явное обновление образа кнопкой). Точный digest собранного образа
    пишется в BASE_DIGEST_MARKER на ноде для детекта версий.

    Явный `docker pull` обязателен: без него buildkit не оставляет базовый
    образ тегированным, и версию (digest) потом не прочитать.
    """
    # ВАЖНО: `:latest` с 31.07.2026 указывает на 3.0.x — а это ДРУГОЙ протокол,
    # живущий у нас в своём контейнере. Обновление AmneziaWG 2.0 обязано
    # оставаться в своей ветке, иначе кнопка «Обновить» пересобрала бы рабочий
    # 2.0 на образе третьей версии. Конкретный образ ветки передаёт вызывающий
    # (он знает теги с Docker Hub); без него безопасный дефолт — известный пин.
    if mode == "update":
        base_ref = base_ref or BASE_IMAGE_PINNED
    else:
        base_ref = BASE_IMAGE_PINNED
    parts = [
        "#!/bin/bash",
        "set -e",
        "trap 'echo DEPLOY_ERROR' ERR",
        f"D=/opt/amnezia/awg; BUILD=/opt/acontrol/build; IMG={IMAGE}; CONT={CONTAINER}; PORT={port}",
        'log(){ echo "[$(date +%H:%M:%S)] $*"; }',
        "",
        'log "[1/6] docker"',
        "command -v docker >/dev/null || { curl -fsSL https://get.docker.com | sudo sh >/dev/null; }",
        "",
        'log "[2/6] tun + ip_forward + фаервол"',
        "sudo modprobe tun || true",
        "echo tun | sudo tee /etc/modules-load.d/tun.conf >/dev/null",
        'echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-acontrol.conf >/dev/null',
        "sudo sysctl -p /etc/sysctl.d/99-acontrol.conf >/dev/null",
        # VPN-порт наружу: Docker публикует, но ufw (особенно ufw-docker) / firewalld
        # по умолчанию блокируют — открываем best-effort (клиентам порт нужен снаружи)
        'if command -v ufw >/dev/null 2>&1; then sudo ufw allow $PORT/udp >/dev/null 2>&1 || true; '
        'sudo ufw route allow proto udp from any to any port $PORT >/dev/null 2>&1 || true; fi',
        'if command -v firewall-cmd >/dev/null 2>&1; then '
        'sudo firewall-cmd --permanent --add-port=$PORT/udp >/dev/null 2>&1 && '
        'sudo firewall-cmd --reload >/dev/null 2>&1 || true; fi',
        "",
        'log "[3/6] Dockerfile + start.sh"',
        'sudo mkdir -p "$BUILD" "$D" /opt/acontrol',
        f'echo {_b64(_dockerfile(base_ref))} | base64 -d | sudo tee "$BUILD/Dockerfile" >/dev/null',
        f'echo {_b64(START_SH)} | base64 -d | sudo tee "$BUILD/start.sh" >/dev/null',
        "",
        f'log "[4/6] базовый образ {base_ref} + сборка"',
        f'sudo docker pull {base_ref} 2>&1 | tail -1',
        # `| tail` маскирует код возврата build → без проверки PIPESTATUS битая
        # сборка прошла бы дальше к rm+run (снос рабочего контейнера ради
        # несобравшегося образа). Прерываемся ДО удаления контейнера.
        'sudo docker build -t $IMG "$BUILD" 2>&1 | tail -3; '
        '[ ${PIPESTATUS[0]} -eq 0 ] || { echo DEPLOY_ERROR; exit 1; }',
        # запоминаем точный digest базового образа, на котором собрались, — детект
        # версий читает этот маркер (не зависит от того, пином или тегом тянули).
        f'sudo docker inspect --format "{{{{index .RepoDigests 0}}}}" {base_ref} 2>/dev/null '
        f'| sed "s/.*@//" | sudo tee {BASE_DIGEST_MARKER} >/dev/null || true',
        "",
        'log "[5/6] конфиг + контейнер"',
        # КРИТИЧНО: перед пересборкой вытаскиваем текущий конфиг из ЖИВОГО
        # контейнера на хост-маунт. Конфиг мог лежать ВНУТРИ контейнера (не на
        # хосте) — тогда guard ниже решил бы, что конфига нет, сгенерил пустой и
        # затёр клиентов (инцидент de-hz 10.07). Читаем через docker exec, что
        # покрывает оба случая (внутри контейнера / на маунте). base64 —
        # побайтовое сохранение (важен завершающий \n у clientsTable).
        # Источник конфига: клиентский amnezia-awg (взятие под управление) в
        # приоритете, иначе панельный amnezia-awg2 (обычная пересборка). Читаем
        # из ЖИВОГО контейнера — конфиг мог лежать ВНУТРИ него, не на хост-маунте.
        'SRC=$(sudo docker ps --format "{{.Names}}" | grep -ix "amnezia-awg" || true)',
        '[ -z "$SRC" ] && SRC=$(sudo docker ps --format "{{.Names}}" | grep -ix "amnezia-awg2" || true)',
        'if [ -n "$SRC" ]; then',
        '  for f in awg0.conf clientsTable wireguard_server_private_key.key '
        'wireguard_server_public_key.key wireguard_psk.key; do',
        '    B=$(sudo docker exec "$SRC" cat "/opt/amnezia/awg/$f" 2>/dev/null '
        '| base64 -w0 2>/dev/null || true);',
        '    [ -n "$B" ] && echo "$B" | base64 -d | sudo tee "$D/$f" >/dev/null || true;',
        '  done',
        # Старые сборки Amnezia держат конфиг в wg0.conf (интерфейс wg0), а не
        # awg0.conf — это тот же AmneziaWG. Нормализуем имя в awg0.conf (панель
        # поднимает awg0). Содержимое и обфускация сохраняются побайтово.
        '  if ! sudo test -s "$D/awg0.conf"; then',
        '    B=$(sudo docker exec "$SRC" cat "/opt/amnezia/awg/wg0.conf" 2>/dev/null '
        '| base64 -w0 2>/dev/null || true);',
        '    [ -n "$B" ] && echo "$B" | base64 -d | sudo tee "$D/awg0.conf" >/dev/null '
        '&& log "wg0.conf нормализован в awg0.conf" || true;',
        '  fi',
        '  log "конфиг перечитан из контейнера $SRC"',
        'fi',
        # Пересоздаём как 2.0 ТОЛЬКО распознанный legacy AmneziaWG 1.0 без клиентов
        # (иначе приложение метит его «Legacy» и им нельзя нормально пользоваться).
        # Признак 1.0: нет I1 (ни активного, ни `# I1`) И H1 — ОДИНОЧНОЕ число (у 2.0
        # H1 — диапазон «low-high»). Если пиры есть — НЕ трогаем (смена обфускации
        # разорвёт хендшейк). Если формат НЕ распознан (нет I1, но H1 не одиночный —
        # напр. будущий AWG 3.0) — НИЧЕГО не переписываем: сохраняем и логируем,
        # чтобы неизвестный апстрим-формат не был затёрт нашим (защита от потери).
        'if sudo test -f "$D/awg0.conf" && ! sudo grep -qE "^#? *I1" "$D/awg0.conf"; then',
        '  if sudo grep -qE "^H1 *= *[0-9]+ *$" "$D/awg0.conf"; then',
        '    PEERS=$(sudo grep -c "^\\[Peer\\]" "$D/awg0.conf" 2>/dev/null || echo 0)',
        '    if [ "$PEERS" = "0" ]; then',
        '      sudo rm -f "$D/awg0.conf"',
        '      log "legacy 1.0 без клиентов — пересоздаю как AmneziaWG 2.0"',
        '    else',
        '      log "legacy 1.0 с клиентами — сохранён, не трогаю"',
        '    fi',
        '  else',
        '    log "конфиг без I1 и не legacy 1.0 — формат не распознан, НЕ переписываю"',
        '  fi',
        'fi',
        'if [ ! -f "$D/awg0.conf" ]; then',
        f'  echo {_b64(cfg["conf"])} | base64 -d | sudo tee "$D/awg0.conf" >/dev/null',
        f'  echo {_b64(cfg["pub"])} | base64 -d | sudo tee "$D/wireguard_server_public_key.key" >/dev/null',
        f'  echo {_b64(cfg["priv"])} | base64 -d | sudo tee "$D/wireguard_server_private_key.key" >/dev/null',
        f'  echo {_b64(cfg["psk"])} | base64 -d | sudo tee "$D/wireguard_psk.key" >/dev/null',
        '  printf "[]\\n" | sudo tee "$D/clientsTable" >/dev/null',
        '  log "конфиг создан (новый сервер)"',
        "else",
        '  log "конфиг уже есть — сохранён, клиенты не тронуты"',
        "fi",
        # порт берём из самого конфига: у взятого под управление сервера порт
        # клиента может отличаться от переданного — сохраняем его, иначе клиенты
        # перестанут подключаться (endpoint у них зашит на старый порт). Если в
        # конфиге порта нет — берём опубликованный порт живого контейнера.
        'DPORT=$(sudo grep -iE "^ *ListenPort" "$D/awg0.conf" 2>/dev/null '
        '| head -1 | tr -dc "0-9" || true)',
        'if [ -z "$DPORT" ] && [ -n "$SRC" ]; then DPORT=$(sudo docker inspect "$SRC" '
        '--format "{{range \\$p,\\$c := .NetworkSettings.Ports}}{{\\$p}} {{end}}" '
        '2>/dev/null | grep -o "[0-9]*" | head -1 || true); fi',
        '[ -n "$DPORT" ] && PORT=$DPORT',
        'if command -v ufw >/dev/null 2>&1; then sudo ufw allow $PORT/udp >/dev/null 2>&1 || true; '
        'sudo ufw route allow proto udp from any to any port $PORT >/dev/null 2>&1 || true; fi',
        'log "порт контейнера: $PORT"',
        # Сносим ТОЛЬКО контейнер на целевом порту (его и заменяем) и свой прежний
        # ($CONT). AWG-контейнеры на ДРУГИХ портах (второй протокол, напр. legacy
        # рядом с awg2) НЕ трогаем — их снос убил бы клиентов (инцидент ru-be 12.07).
        # Порт-совпадение сохраняет и фикс инцидента uz (клиентский контейнер на том
        # же порту, что разворачивает панель, всё так же удаляется).
        'RM="$(sudo docker ps -aq --filter "name=^${CONT}$" 2>/dev/null; '
        'sudo docker ps -aq --filter "publish=$PORT" 2>/dev/null)"; '
        'RM=$(printf "%s\\n" "$RM" | sort -u | grep . || true); '
        '[ -n "$RM" ] && sudo docker rm -f $RM >/dev/null 2>&1 || true',
        "sudo docker run -d --name $CONT --restart always --privileged \\",
        "  --cap-add NET_ADMIN --cap-add SYS_MODULE \\",
        "  --sysctl net.ipv4.conf.all.src_valid_mark=1 \\",
        '  -v "$D":/opt/amnezia/awg -p $PORT:$PORT/udp $IMG >/dev/null',
        "sleep 5",
        "",
        'log "[6/6] подъём awg0 + NAT + systemd"',
        f'sudo docker exec $CONT sh -c {_shell_quote(_BRINGUP)}',
        f'echo {_b64(_systemd_unit())} | base64 -d | sudo tee /etc/systemd/system/awg-up.service >/dev/null',
        "sudo systemctl daemon-reload && sudo systemctl enable awg-up.service >/dev/null 2>&1",
        # READBACK-проверка: убеждаемся, что интерфейс РЕАЛЬНО поднялся и слушает,
        # а не молча провалился (awg-quick up мог упасть — напр. новый базовый образ
        # сменил поведение). Раньше здесь стоял `|| true` и DEPLOY_DONE печатался
        # всегда — битая нода помечалась «готова». Теперь при неуспехе — DEPLOY_ERROR.
        'AWGSHOW=$(sudo docker exec $CONT wg show awg0 2>/dev/null || true)',
        'if ! printf "%s" "$AWGSHOW" | grep -qE "listening port"; then '
        'echo "READBACK: интерфейс awg0 не поднялся (awg-quick up не сработал)"; '
        'echo DEPLOY_ERROR; exit 1; fi',
        'printf "%s" "$AWGSHOW" | grep -E "interface|listening" || true',
        'log "readback: awg0 поднят и слушает — ok"',
        "echo DEPLOY_DONE",
    ]
    return "\n".join(parts) + "\n"


def build_script_v3(mode: str, port: int, cfg: dict[str, str]) -> str:
    """Развёртывание AmneziaWG 3.0 (mode: 'deploy' | 'update').

    Скрипт СВОЙ, а не общий с 2.0, намеренно: у 2.0 он оброс историей — апгрейд
    legacy-конфига, «усыновление» чужого контейнера, спасение конфига из живого
    контейнера. Для 3.0 всё это лишнее (развёрнутых кем-то ещё amnezia-awg3 в
    природе нет), а общий скрипт пришлось бы ветвить и рисковать боевым 2.0.

    Как и у 2.0: deploy пинится на известный рабочий образ, update тянет :latest.
    Существующий конфиг НЕ перезаписывается — клиенты переживают пересборку.
    """
    bringup = _bringup(SUBNET_V3)
    parts = [
        "#!/bin/bash",
        "set -e",
        "trap 'echo DEPLOY_ERROR' ERR",
        f"D={HOST_DIR_V3}; BUILD=/opt/acontrol/build-awg3; IMG={IMAGE_V3}; "
        f"CONT={CONTAINER_V3}; PORT={port}",
        'log(){ echo "[$(date +%H:%M:%S)] $*"; }',
        "",
        'log "[1/6] docker"',
        "command -v docker >/dev/null || { curl -fsSL https://get.docker.com | sudo sh >/dev/null; }",
        "",
        'log "[2/6] tun + ip_forward + фаервол"',
        "sudo modprobe tun || true",
        "echo tun | sudo tee /etc/modules-load.d/tun.conf >/dev/null",
        'echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-acontrol.conf >/dev/null',
        "sudo sysctl -p /etc/sysctl.d/99-acontrol.conf >/dev/null",
        'if command -v ufw >/dev/null 2>&1; then sudo ufw allow $PORT/udp >/dev/null 2>&1 || true; '
        'sudo ufw route allow proto udp from any to any port $PORT >/dev/null 2>&1 || true; fi',
        'if command -v firewall-cmd >/dev/null 2>&1; then '
        'sudo firewall-cmd --permanent --add-port=$PORT/udp >/dev/null 2>&1 && '
        'sudo firewall-cmd --reload >/dev/null 2>&1 || true; fi',
        "",
        'log "[3/6] Dockerfile + start.sh"',
        'sudo mkdir -p "$BUILD" "$D" /opt/acontrol',
        f'echo {_b64(_dockerfile_v3())} | base64 -d | sudo tee "$BUILD/Dockerfile" >/dev/null',
        f'echo {_b64(_start_sh(SUBNET_V3))} | base64 -d | sudo tee "$BUILD/start.sh" >/dev/null',
        "",
        f'log "[4/6] сборка из исходников: go {AWG3_GO_TAG} + tools {AWG3_TOOLS_TAG}"',
        'log "(первая сборка тянет тулчейны и компилирует — это несколько минут)"',
        # без --pull: тулчейн-образы кешируются, повторная сборка быстрая
        'sudo docker build -t $IMG "$BUILD" 2>&1 | tail -5; '
        '[ ${PIPESTATUS[0]} -eq 0 ] || { echo DEPLOY_ERROR; exit 1; }',
        f'printf "go={AWG3_GO_TAG}\\ntools={AWG3_TOOLS_TAG}\\n" '
        f'| sudo tee {AWG3_VERSION_MARKER} >/dev/null || true',
        "",
        'log "[5/6] конфиг + контейнер"',
        # конфиг 3.0 живёт в своём каталоге, поэтому спасать его из контейнера
        # (как у 2.0) не требуется — он и так на хост-маунте и переживает пересборку
        'if [ ! -f "$D/awg0.conf" ]; then',
        f'  echo {_b64(cfg["conf"])} | base64 -d | sudo tee "$D/awg0.conf" >/dev/null',
        f'  echo {_b64(cfg["pub"])} | base64 -d | sudo tee "$D/wireguard_server_public_key.key" >/dev/null',
        f'  echo {_b64(cfg["priv"])} | base64 -d | sudo tee "$D/wireguard_server_private_key.key" >/dev/null',
        f'  echo {_b64(cfg["psk"])} | base64 -d | sudo tee "$D/wireguard_psk.key" >/dev/null',
        '  printf "[]\\n" | sudo tee "$D/clientsTable" >/dev/null',
        '  log "конфиг создан (новый сервер AmneziaWG 3.0)"',
        "else",
        '  log "конфиг уже есть — сохранён, клиенты не тронуты"',
        "fi",
        # порт берём из конфига: при пересборке он должен остаться прежним, иначе
        # у выданных клиентов протухнет endpoint
        'DPORT=$(sudo grep -iE "^ *ListenPort" "$D/awg0.conf" 2>/dev/null '
        '| head -1 | tr -dc "0-9" || true)',
        '[ -n "$DPORT" ] && PORT=$DPORT',
        'if command -v ufw >/dev/null 2>&1; then sudo ufw allow $PORT/udp >/dev/null 2>&1 || true; '
        'sudo ufw route allow proto udp from any to any port $PORT >/dev/null 2>&1 || true; fi',
        'log "порт контейнера: $PORT"',
        # сносим ТОЛЬКО свой контейнер 3.0 и то, что занимает наш порт: контейнеры
        # других протоколов (2.0/legacy) на этой ноде не трогаем
        'RM="$(sudo docker ps -aq --filter "name=^${CONT}$" 2>/dev/null; '
        'sudo docker ps -aq --filter "publish=$PORT" 2>/dev/null)"; '
        'RM=$(printf "%s\\n" "$RM" | sort -u | grep . || true); '
        '[ -n "$RM" ] && sudo docker rm -f $RM >/dev/null 2>&1 || true',
        "sudo docker run -d --name $CONT --restart always --privileged \\",
        "  --cap-add NET_ADMIN --cap-add SYS_MODULE \\",
        "  --sysctl net.ipv4.conf.all.src_valid_mark=1 \\",
        '  -v "$D":/opt/amnezia/awg -p $PORT:$PORT/udp $IMG >/dev/null',
        "sleep 5",
        "",
        'log "[6/6] подъём awg0 + NAT + systemd"',
        f'sudo docker exec $CONT sh -c {_shell_quote(bringup)}',
        f'echo {_b64(_systemd_unit_v3())} | base64 -d | sudo tee '
        "/etc/systemd/system/awg3-up.service >/dev/null",
        "sudo systemctl daemon-reload && sudo systemctl enable awg3-up.service >/dev/null 2>&1",
        # readback: убеждаемся, что интерфейс реально поднялся (иначе битую ноду
        # пометили бы «готова» — та же защита, что у 2.0)
        # В образе 3.0 (собран из исходников amneziawg-tools) бинарь называется
        # `awg`; `wg` из базового образа Amnezia тут отсутствует, поэтому читаем
        # состояние именно им, иначе readback ложно сочтёт ноду битой.
        'AWGSHOW=$(sudo docker exec $CONT awg show awg0 2>/dev/null || true)',
        'if ! printf "%s" "$AWGSHOW" | grep -qE "listening port"; then '
        'echo "READBACK: интерфейс awg0 не поднялся (awg-quick up не сработал)"; '
        'echo DEPLOY_ERROR; exit 1; fi',
        'printf "%s" "$AWGSHOW" | grep -E "interface|listening" || true',
        'log "readback: awg0 (3.1) поднят и слушает — ok"',
        "echo DEPLOY_DONE",
    ]
    return "\n".join(parts) + "\n"


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _systemd_unit() -> str:
    return (
        "[Unit]\n"
        "Description=Bring up AmneziaWG interface + NAT inside container\n"
        "After=docker.service\nRequires=docker.service\n\n"
        "[Service]\nType=oneshot\nExecStartPre=/bin/sleep 8\n"
        f"ExecStart=/usr/bin/docker exec {CONTAINER} sh -c '{_BRINGUP}'\n"
        "RemainAfterExit=yes\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def _systemd_unit_v3() -> str:
    """Юнит подъёма 3.0 — отдельный от awg-up.service, чтобы версии протокола
    не мешали друг другу при перезагрузке ноды."""
    return (
        "[Unit]\n"
        "Description=Bring up AmneziaWG 3.0 interface + NAT inside container\n"
        "After=docker.service\nRequires=docker.service\n\n"
        "[Service]\nType=oneshot\nExecStartPre=/bin/sleep 8\n"
        f"ExecStart=/usr/bin/docker exec {CONTAINER_V3} sh -c '{_bringup(SUBNET_V3)}'\n"
        "RemainAfterExit=yes\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def _paths(tag: str) -> tuple[str, str, str]:
    d = f"{WORK_ROOT}/{tag}"
    return d, f"{d}/run.sh", f"{d}/deploy.log"


# --- снимки конфигов протоколов для отката пересборки -----------------------
# $HOME/.acontrol/snapshots/<tag>/<ts>.tar.gz — tar конфига из ЖИВОГО контейнера.
SNAP_ROOT = f"{WORK_ROOT}/snapshots"
_SNAP_ID_RE = re.compile(r"^\d{8}-\d{6}$")

# спецификация снимка на протокол: контейнер, пути внутри контейнера для tar,
# clientsTable для подсчёта клиентов, команда применения восстановленного конфига
_SNAP_SPECS: dict[str, dict] = {
    "awg": {
        "container": CONTAINER,  # amnezia-awg2
        "paths": "/opt/amnezia/awg",
        "table": "/opt/amnezia/awg/clientsTable",
        "reload": (
            "sudo docker exec %C sh -c "
            "'[ -s /opt/amnezia/awg/awg0.conf ] || cp /opt/amnezia/awg/wg0.conf "
            "/opt/amnezia/awg/awg0.conf 2>/dev/null; "
            "awg-quick down /opt/amnezia/awg/awg0.conf >/dev/null 2>&1; "
            "awg-quick up /opt/amnezia/awg/awg0.conf'"
        ),
    },
    "awg3": {
        "container": CONTAINER_V3,  # amnezia-awg3
        # внутри контейнера путь штатный — свой каталог 3.0 монтируется именно сюда
        "paths": "/opt/amnezia/awg",
        "table": "/opt/amnezia/awg/clientsTable",
        "reload": (
            "sudo docker exec %C sh -c "
            "'awg-quick down /opt/amnezia/awg/awg0.conf >/dev/null 2>&1; "
            "awg-quick up /opt/amnezia/awg/awg0.conf'"
        ),
    },
    "xray": {
        "container": "amnezia-xray",
        "paths": "/opt/amnezia/xray",
        "table": "/opt/amnezia/xray/clientsTable",
        "reload": "sudo docker restart %C",
    },
    "openvpn": {
        "container": "amnezia-openvpn-cloak",
        "paths": "/opt/amnezia/openvpn /opt/amnezia/cloak /opt/amnezia/shadowsocks",
        "table": "/opt/amnezia/openvpn/clientsTable",
        "reload": "sudo docker restart %C",
    },
}


async def snapshot_config(
    conn: asyncssh.SSHClientConnection,
    tag: str,
    keep: int = 10,
    container: str | None = None,
) -> str | None:
    """Снимок конфига протокола (tar из ЖИВОГО контейнера) в
    $HOME/.acontrol/snapshots/<tag>/<ts>.tar.gz. Возвращает id снимка или None.

    container переопределяет контейнер из спецификации — нужно, чтобы снять
    снимок клиентского amnezia-awg перед взятием его под управление панелью."""
    spec = _SNAP_SPECS[tag]
    cont = container or spec["container"]
    cmd = (
        f'C={cont}; R={SNAP_ROOT}/{tag}; '
        f'sudo docker ps --format "{{{{.Names}}}}" | grep -qx "$C" || {{ echo NO_CONT; exit 0; }}; '
        # TS уникален посекундно; при снимке нескольких контейнеров подряд
        # (пре-оп бэкап) ждём смены секунды, иначе второй снимок затёр бы первый.
        f'mkdir -p "$R"; TS=$(date +%Y%m%d-%H%M%S); '
        f'while [ -e "$R/$TS.tar.gz" ]; do sleep 1; TS=$(date +%Y%m%d-%H%M%S); done; '
        f'F="$R/$TS.tar.gz"; '
        f'if sudo docker exec "$C" tar -czf - {spec["paths"]} 2>/dev/null > "$F" && [ -s "$F" ]; then '
        f'n=$(sudo docker exec "$C" grep -c "clientId" "{spec["table"]}" 2>/dev/null || echo 0); '
        f'echo "$n" > "$R/$TS.n"; echo "SNAP $TS"; else rm -f "$F"; fi; '
        f'ls -1t "$R"/*.tar.gz 2>/dev/null | tail -n +{keep + 1} | while read f; do rm -f "$f" "${{f%.tar.gz}}.n"; done'
    )
    out = await conn.run(cmd, check=False)
    for line in (out.stdout or "").splitlines():
        if line.startswith("SNAP "):
            return line.split()[1]
    return None


async def list_snapshots(conn: asyncssh.SSHClientConnection, tag: str) -> list[dict]:
    """Список снимков конфига: [{id, clients}], новые первыми."""
    cmd = (
        f'R={SNAP_ROOT}/{tag}; ls -1t "$R"/*.tar.gz 2>/dev/null | while read f; do '
        'ts=$(basename "$f" .tar.gz); n=$(cat "${f%.tar.gz}.n" 2>/dev/null || echo 0); '
        'echo "$ts|$n"; done'
    )
    out = await conn.run(cmd, check=False)
    res: list[dict] = []
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        ts, n = line.rsplit("|", 1)
        if _SNAP_ID_RE.match(ts):
            res.append({"id": ts, "clients": int(n) if n.strip().isdigit() else 0})
    return res


async def restore_snapshot(
    conn: asyncssh.SSHClientConnection, tag: str, snap_id: str
) -> bool:
    """Восстанавливает конфиг из снимка (распаковка tar В живой контейнер + reload)."""
    if not _SNAP_ID_RE.match(snap_id or ""):
        raise ValueError("некорректный id снимка")
    spec = _SNAP_SPECS[tag]
    reload_cmd = spec["reload"].replace("%C", spec["container"])
    # РАСПАКОВКА проверяется по коду возврата tar — раньше RESTORE_OK печатался
    # безусловно, и битый/оборванный (ENOSPC) снимок «восстанавливался» с ошибкой,
    # а API рапортовал успех. Теперь reload и RESTORE_OK — только если tar прошёл.
    cmd = (
        f'C={spec["container"]}; F={SNAP_ROOT}/{tag}/{snap_id}.tar.gz; '
        f'[ -f "$F" ] || {{ echo NO_SNAP; exit 0; }}; '
        f'if cat "$F" | sudo docker exec -i "$C" tar -xzf - -C /; then '
        f'{reload_cmd} >/dev/null 2>&1; echo RESTORE_OK; '
        f'else echo RESTORE_FAIL; fi'
    )
    out = await conn.run(cmd, check=False)
    return "RESTORE_OK" in (out.stdout or "")


async def launch(
    conn: asyncssh.SSHClientConnection, script: str, *, tag: str = "awg"
) -> None:
    """Кладёт скрипт в $HOME/.acontrol/<tag> (свой каталог протокола) и запускает
    детачед. Отдельный каталог на протокол не даёт логам деплоя перемешиваться."""
    d, run, log = _paths(tag)
    await conn.run(f'mkdir -p "{d}"', check=False)
    await conn.run(
        f'cat > "{run}" && rm -f "{log}"',
        input=script, check=False,
    )
    await conn.run(
        f'nohup setsid bash "{run}" > "{log}" 2>&1 </dev/null & disown',
        check=False,
    )


def _parse_foreign_awg(stdout: str) -> list[str]:
    """Из вывода `docker ps --format {{.Names}}\\t{{.Image}}` — имена ЧУЖИХ (не
    панельных) AWG-контейнеров. Свой определяем по ОБРАЗУ ({IMAGE}), а НЕ по имени:
    у Amnezia активный «новый» протокол называется amnezia-awg2 — как и панельный
    CONTAINER. Определение по имени принимало чужой awg2 за свой, поэтому его конфиг
    не снимался в снимок, а deploy сносил его без страховки (инцидент ru-be 12.07:
    снесли и legacy, и awg2, сохранив конфиг только одного)."""
    foreign: list[str] = []
    for line in stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, image = parts[0].strip(), parts[1].strip()
        if not name:
            continue
        # свои контейнеры — образы панели (acontrol-awg для 2.0, acontrol-awg3
        # для 3.0) с любым тегом; всё прочее чужое. ВАЖНО: 3.0 обязан быть в
        # этом списке — иначе панельный amnezia-awg3 считался бы чужим и
        # блокировал бы deploy/update AmneziaWG 2.0 на той же ноде (409).
        if image.split(":", 1)[0] not in _PANEL_AWG_IMAGES:
            foreign.append(name)
    return foreign


async def foreign_awg_containers(
    conn: asyncssh.SSHClientConnection,
) -> list[str]:
    """Имена ВСЕХ AWG-контейнеров на ноде, собранных НЕ панелью (образ != {IMAGE}).

    На таком сервере пересборка панелью создала бы ПАРАЛЛЕЛЬНЫЙ пустой контейнер
    (конфиг оригинала живёт внутри его контейнера, панель его не переносит), а
    клиенты остались бы на старом — поэтому deploy/update надо запрещать, а при
    adopt — снять снимок КАЖДОГО из них до замены."""
    cmd = (
        'D=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '
        '$D ps --format "{{.Names}}\t{{.Image}}" | grep -iE "amnezia-awg|acontrol-awg" || true'
    )
    result = await conn.run(cmd, check=False)
    return _parse_foreign_awg(result.stdout or "")


async def foreign_awg_container(conn: asyncssh.SSHClientConnection) -> str | None:
    """Первый чужой AWG-контейнер, если есть (одиночный случай)."""
    names = await foreign_awg_containers(conn)
    return names[0] if names else None


async def container_on_port(
    conn: asyncssh.SSHClientConnection, port: int, exclude: str = ""
) -> str | None:
    """Имя контейнера, который уже публикует этот порт (кроме `exclude`).

    Нужна ПЕРЕД развёртыванием нового протокола: скрипт деплоя сносит контейнер,
    занимающий целевой порт (так заменяется свой же при пересборке). Если порт
    по ошибке указан чужой — снесётся рабочий контейнер другого протокола со
    всеми клиентами. Поэтому такой случай ловим заранее и операцию не начинаем.
    """
    # ВАЖНО: `--filter publish=NNN` без протокола НЕ находит контейнеры с
    # UDP-публикацией (проверено на ноде: awg2 на 47180/udp так не виден), а у
    # AmneziaWG порт как раз UDP. Поэтому спрашиваем оба протокола явно.
    p = int(port)
    cmd = (
        'D=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '
        f'$D ps --filter "publish={p}/udp" --filter "publish={p}/tcp" '
        '--format "{{.Names}}"'
    )
    result = await conn.run(cmd, check=False)
    for line in (result.stdout or "").splitlines():
        name = line.strip()
        if name and name != exclude:
            return name
    return None


async def awg3_containers(conn: asyncssh.SSHClientConnection) -> list[str]:
    """Контейнеры AmneziaWG 3.0 на ноде (по образу панели, а не по имени —
    имя мог бы занять кто угодно)."""
    cmd = (
        'D=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '
        '$D ps --format "{{.Names}}\t{{.Image}}" | grep -iE "awg3" || true'
    )
    result = await conn.run(cmd, check=False)
    names: list[str] = []
    for line in (result.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, image = parts[0].strip(), parts[1].strip()
        if name and image.split(":", 1)[0] == IMAGE_V3:
            names.append(name)
    return names


async def all_awg_containers(conn: asyncssh.SSHClientConnection) -> list[str]:
    """Имена ВСЕХ awg-контейнеров на ноде — и панельных, и чужих. Для пре-оп
    бэкапа (снимок каждого перед операцией)."""
    cmd = (
        'D=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '
        '$D ps --format "{{.Names}}\t{{.Image}}" | grep -iE "amnezia-awg|acontrol-awg" || true'
    )
    result = await conn.run(cmd, check=False)
    names: list[str] = []
    for line in (result.stdout or "").splitlines():
        name = line.split("\t")[0].strip()
        if name:
            names.append(name)
    return names


async def snapshot_all(conn: asyncssh.SSHClientConnection, tag: str) -> int:
    """Пре-оп бэкап: снимок КАЖДОГО контейнера протокола ДО мутирующей операции —
    чтобы её можно было откатить (config-restore/ручная пересборка). Для awg
    снимает и legacy (amnezia-awg), и awg2, и панельный контейнер; для остальных —
    контейнер из спецификации. Возвращает число сделанных снимков."""
    # Снимки строго разведены по тегам: restore_snapshot распаковывает архив в
    # контейнер СВОЕГО тега, поэтому конфиг 2.0, попавший в снимки 3.0, при
    # откате уехал бы в чужой контейнер и сломал его. Отсюда фильтры ниже.
    if tag == "awg":
        conts = [c for c in await all_awg_containers(conn) if "awg3" not in c.lower()]
    elif tag == "awg3":
        conts = await awg3_containers(conn)
    else:
        spec = _SNAP_SPECS.get(tag)
        conts = [spec["container"]] if spec else []
    made = 0
    for cont in conts:
        if await snapshot_config(conn, tag, container=cont):
            made += 1
    return made


_CONT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


async def awg_adoptable(
    conn: asyncssh.SSHClientConnection, container: str
) -> bool:
    """Можно ли безопасно взять контейнер под управление панелью.

    Переносим только настоящий AmneziaWG — его конфиг (awg0.conf ИЛИ старый
    wg0.conf) содержит параметры обфускации (Jc/H1...). Обычный WireGuard их не
    имеет: перенос в AmneziaWG-контейнер сломал бы клиентов (у них нет обфускации).
    Поэтому признак совместимости — наличие Jc/H1 в конфиге, а не имя файла."""
    if not container or not _CONT_NAME_RE.match(container):
        return False
    cmd = (
        'D=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '
        "$D exec " + container + " sh -c '"
        "for f in awg0.conf wg0.conf; do "
        'grep -qiE "^(Jc|H1) *=" "/opt/amnezia/awg/$f" 2>/dev/null '
        "&& { echo YES; exit 0; }; done; echo NO' 2>/dev/null || echo NO"
    )
    result = await conn.run(cmd, check=False)
    return "YES" in (result.stdout or "")


async def detect_openvpn_container(
    conn: asyncssh.SSHClientConnection,
) -> str | None:
    """Имя запущенного openvpn/cloak-контейнера (панельного amnezia-openvpn-cloak
    или родного Amnezia с иным именем), если есть — чтобы снять с него снимок
    перед перезаписью PKI."""
    cmd = (
        'D=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '
        '$D ps --format "{{.Names}}" | grep -iE "openvpn|cloak" | head -1 || true'
    )
    result = await conn.run(cmd, check=False)
    name = (result.stdout or "").strip()
    return name or None


async def read_status(
    conn: asyncssh.SSHClientConnection, *, tag: str = "awg"
) -> dict:
    _d, _run, log = _paths(tag)
    result = await conn.run(f'cat "{log}" 2>/dev/null', check=False)
    log = result.stdout if isinstance(result.stdout, str) else ""
    if "DEPLOY_DONE" in log:
        state = "done"
    elif "DEPLOY_ERROR" in log:
        state = "error"
    elif log.strip():
        state = "running"
    else:
        state = "unknown"
    tail = "\n".join(log.strip().splitlines()[-15:])
    return {"state": state, "log": tail}


async def node_base_digest(conn: asyncssh.SSHClientConnection) -> str | None:
    # 1) маркер, записанный деплоем — точный digest собранного образа (не зависит
    # от того, пином или тегом тянули; переживает уход :latest вперёд).
    marker = await conn.run(
        f"cat {BASE_DIGEST_MARKER} 2>/dev/null || sudo -n cat {BASE_DIGEST_MARKER} 2>/dev/null",
        check=False,
    )
    mout = (marker.stdout or "").strip()
    if mout.startswith("sha256:"):
        return mout
    # 2) фолбэк для нод, развёрнутых до появления маркера: inspect пина, затем тега.
    for ref in (BASE_IMAGE_PINNED, BASE_IMAGE_LATEST):
        cmd = (
            f"docker inspect --format '{{{{index .RepoDigests 0}}}}' {ref} 2>/dev/null "
            f"|| sudo docker inspect --format '{{{{index .RepoDigests 0}}}}' {ref} 2>/dev/null"
        )
        result = await conn.run(cmd, check=False)
        out = (result.stdout or "").strip()
        if "@sha256:" in out:
            return out.split("@", 1)[1]
    return None


async def node_awg_go_version(conn: asyncssh.SSHClientConnection) -> str | None:
    """Версия бинаря amneziawg-go из работающего контейнера (напр. 0.0.20250522)."""
    cmd = (
        'D=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '
        'C=$($D ps --format "{{.Names}}" | grep -m1 amnezia-awg); '
        '[ -n "$C" ] && $D exec "$C" amneziawg-go --version 2>/dev/null'
    )
    result = await conn.run(cmd, check=False)
    out = (result.stdout or "").strip()
    # "amneziawg-go 0.0.20250522 - https://amnezia.org" → 0.0.20250522
    match = re.search(r"\d+\.\d+[\d.]*", out)
    return match.group(0) if match else None


def _is_version_tag(name: str) -> bool:
    return bool(re.match(r"^\d+\.\d+", name))


async def hub_info() -> dict:
    """Тянет теги с Docker Hub, строит digest→версия и находит latest."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(HUB_TAGS_URL)
        resp.raise_for_status()
        data = resp.json()
    latest_digest = ""
    latest_updated = ""
    digest_to_version: dict[str, str] = {}
    # Новейший тег ВЕТКИ 2.x (major < 3). С 31.07.2026 `:latest` указывает на
    # 3.0.x, а у нас 3.0 — ОТДЕЛЬНЫЙ протокол со своим контейнером. Сравнивать
    # 2.0-ноду с `:latest` значит предлагать «обновиться» на чужую ветку: кнопка
    # пересобрала бы рабочий 2.0 на образе 3.0. Поэтому для 2.0 держим свою линию.
    # Берём самый свежий ПО ДАТЕ, а не по номеру: тег 2.0.0 старше 0.2.19.
    line_latest: tuple[str, str, str] | None = None
    for tag in data.get("results", []):
        name = tag.get("name", "")
        digest = tag.get("digest", "")
        if name == "latest":
            latest_digest = digest
            latest_updated = tag.get("last_updated", "")
        elif digest and _is_version_tag(name):
            digest_to_version.setdefault(digest, name)
            if not name.startswith("3."):
                upd = tag.get("last_updated", "")
                if line_latest is None or upd > line_latest[0]:
                    line_latest = (upd, name, digest)
    return {
        "latest_digest": latest_digest,
        "latest_version": digest_to_version.get(latest_digest),
        "latest_updated": latest_updated,
        "digest_to_version": digest_to_version,
        # ветка 2.x — с ней сравнивается версия протокола AmneziaWG 2.0
        "line_latest_digest": line_latest[2] if line_latest else "",
        "line_latest_version": line_latest[1] if line_latest else None,
        "line_latest_updated": line_latest[0] if line_latest else "",
    }
