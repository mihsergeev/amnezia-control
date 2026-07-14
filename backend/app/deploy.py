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

BASE_IMAGE = "amneziavpn/amneziawg-go:latest"
BASE_REPO = "amneziavpn/amneziawg-go"
IMAGE = "acontrol-awg"
CONTAINER = "amnezia-awg2"
SUBNET = "10.8.1.0/24"
# Каталог рабочих файлов деплоя — в $HOME текущего ssh-пользователя (всегда наш,
# без коллизий владельца в общем /tmp) и СВОЙ у каждого протокола (tag), чтобы
# лог одного деплоя не подменял другой на сервере с несколькими протоколами.
WORK_ROOT = "$HOME/.acontrol"
HUB_TAGS_URL = "https://hub.docker.com/v2/repositories/amneziavpn/amneziawg-go/tags?page_size=50"

START_SH = """#!/bin/sh
# Amnezia Control: точка входа контейнера AmneziaWG
awg-quick down /opt/amnezia/awg/awg0.conf >/dev/null 2>&1
awg-quick up /opt/amnezia/awg/awg0.conf 2>/dev/null || true
iptables -t nat -C POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null \\
  || iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE
iptables -C FORWARD -i awg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -j ACCEPT
iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \\
  || iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
exec tail -f /dev/null
"""

DOCKERFILE = """FROM amneziavpn/amneziawg-go:latest
RUN apk add --no-cache bash iptables iproute2 2>/dev/null \\
  || (apt-get update && apt-get install -y --no-install-recommends bash iptables iproute2) \\
  || true
COPY start.sh /opt/amnezia/start.sh
RUN chmod +x /opt/amnezia/start.sh
ENTRYPOINT ["/opt/amnezia/start.sh"]
"""

# идемпотентный подъём интерфейса + NAT внутри контейнера
_BRINGUP = (
    "awg-quick down /opt/amnezia/awg/awg0.conf >/dev/null 2>&1; "
    "awg-quick up /opt/amnezia/awg/awg0.conf; "
    "iptables -t nat -C POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null "
    "|| iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE; "
    "iptables -C FORWARD -i awg0 -j ACCEPT 2>/dev/null "
    "|| iptables -A FORWARD -i awg0 -j ACCEPT; "
    "iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null "
    "|| iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"
)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# порядок параметров obfuscation в awg0.conf (AmneziaWG 2.0)
_AWG_CONF_ORDER = [
    "Jc", "Jmin", "Jmax",
    "S1", "S2", "S3", "S4",
    "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5",
]


def _cps_packet() -> str:
    """Один CPS-джанк-пакет (Custom Protocol Signature) из валидных тегов awg 2.0.
    Проверено на amneziawg-go 0.0.20250522: допустимы <b 0xHEX> (статичные байты),
    <r N> (случайные байты), <rd N> (случайные цифры), <rc N> (случайные символы),
    <t> (таймштамп). Тег <c> НЕ поддерживается («Invalid argument»)."""
    parts: list[str] = []
    if random.random() < 0.5:
        parts.append(f"<b 0x{secrets.token_hex(random.randint(4, 14))}>")
    if random.random() < 0.35:
        parts.append("<t>")
    if random.random() < 0.3:
        parts.append(f"<rd {random.randint(8, 24)}>")
    if random.random() < 0.3:
        parts.append(f"<rc {random.randint(8, 24)}>")
    parts.append(f"<r {random.randint(24, 160)}>")  # всегда есть случайные байты
    random.shuffle(parts)
    return "".join(parts)


def generate_awg_params() -> dict[str, object]:
    """Параметры обфускации AmneziaWG 2.0. Наличие I1 переводит клиента в режим
    2.0 — иначе приложение AmneziaVPN метит конфиг как «AmneziaWG Legacy»."""
    jc = random.randint(3, 10)
    jmin = random.randint(4, 12)
    jmax = random.randint(jmin + 50, jmin + 900)
    while True:
        s1 = random.randint(15, 150)
        s2 = random.randint(15, 150)
        if s1 != s2 and s1 + 56 != s2 and s2 + 56 != s1:
            break
    hs: set[int] = set()
    while len(hs) < 4:
        hs.add(random.randint(5, 2**31 - 1))
    h1, h2, h3, h4 = sorted(hs)
    # 2.0: S3 — джанк cookie-пакета (0..64), S4 — джанк transport-пакета (0..32)
    s3 = random.randint(0, 64)
    s4 = random.randint(0, 32)
    return {
        "Jc": jc, "Jmin": jmin, "Jmax": jmax,
        "S1": s1, "S2": s2, "S3": s3, "S4": s4,
        "H1": h1, "H2": h2, "H3": h3, "H4": h4,
        "I1": _cps_packet(), "I2": _cps_packet(), "I3": _cps_packet(),
        "I4": _cps_packet(), "I5": _cps_packet(),
    }


def generate_server_config(port: int) -> dict[str, str]:
    priv, pub = awg.generate_keypair()
    psk = base64.b64encode(secrets.token_bytes(32)).decode()
    p = generate_awg_params()
    conf = (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {SUBNET}\n"
        f"ListenPort = {port}\n"
        + "".join(f"{k} = {p[k]}\n" for k in _AWG_CONF_ORDER)
    )
    return {"priv": priv, "pub": pub, "psk": psk, "conf": conf}


def build_script(mode: str, port: int, cfg: dict[str, str]) -> str:
    """mode: 'deploy' или 'update' — оба тянут свежий базовый образ.

    Явный `docker pull` обязателен: без него buildkit не оставляет базовый
    образ тегированным, и версию (digest) потом не прочитать.
    """
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
        'sudo mkdir -p "$BUILD" "$D"',
        f'echo {_b64(DOCKERFILE)} | base64 -d | sudo tee "$BUILD/Dockerfile" >/dev/null',
        f'echo {_b64(START_SH)} | base64 -d | sudo tee "$BUILD/start.sh" >/dev/null',
        "",
        f'log "[4/6] базовый образ {BASE_IMAGE} + сборка"',
        f'sudo docker pull {BASE_IMAGE} 2>&1 | tail -1',
        # `| tail` маскирует код возврата build → без проверки PIPESTATUS битая
        # сборка прошла бы дальше к rm+run (снос рабочего контейнера ради
        # несобравшегося образа). Прерываемся ДО удаления контейнера.
        'sudo docker build -t $IMG "$BUILD" 2>&1 | tail -3; '
        '[ ${PIPESTATUS[0]} -eq 0 ] || { echo DEPLOY_ERROR; exit 1; }',
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
        'sudo docker exec $CONT wg show awg0 | grep -E "interface|listening" || true',
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
        # свой контейнер — образ acontrol-awg (с любым тегом); всё прочее чужое
        if image.split(":", 1)[0] != IMAGE:
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
    if tag == "awg":
        conts = await all_awg_containers(conn)
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
    cmd = (
        f"docker inspect --format '{{{{index .RepoDigests 0}}}}' {BASE_IMAGE} 2>/dev/null "
        f"|| sudo docker inspect --format '{{{{index .RepoDigests 0}}}}' {BASE_IMAGE} 2>/dev/null"
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
    for tag in data.get("results", []):
        name = tag.get("name", "")
        digest = tag.get("digest", "")
        if name == "latest":
            latest_digest = digest
            latest_updated = tag.get("last_updated", "")
        elif digest and _is_version_tag(name):
            digest_to_version.setdefault(digest, name)
    return {
        "latest_digest": latest_digest,
        "latest_version": digest_to_version.get(latest_digest),
        "latest_updated": latest_updated,
        "digest_to_version": digest_to_version,
    }
