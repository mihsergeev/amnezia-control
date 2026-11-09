"""Управление XRay (VLESS+REALITY) на ноде.

Модель Amnezia: контейнер amnezia-xray, конфиг /opt/amnezia/xray/server.json
(VLESS inbound на 443, REALITY). Клиенты — UUID'ы в inbounds[0].settings.clients,
имена в /opt/amnezia/xray/clientsTable (массив {clientId, userData}). Дефолтный
UUID (xray_uuid.key) из пользовательского списка исключаётся. Ключи REALITY:
xray_public.key, xray_short_id.key. Выдача/отзыв — правка server.json + docker restart.

Дополнительные VLESS-входы (например, XHTTP за fallback основного на том же 443)
получают тот же набор клиентов: панель держит их списки в зеркале основного.
"""

import asyncio
import base64
import hashlib
import json
import re
import shlex
import struct
import uuid
import zlib
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import quote

import asyncssh

# Версия xray-core, которую ставит панель: установка, обновление и переустановка.
# Закреплена, а не releases/latest. В 26.10.31 MPTCP выключен по умолчанию
# (CVE-2026-98432); GODEBUG и sysctl ниже сохраняют защиту при пересоздании.
# Полное исправление требует обновления ядра Linux на хосте. Старые ClientHello
# без X25519MLKEM768 upstream REALITY больше не поддерживает. Выданный панелью
# профиль firefox с клиентом 26.3.27 (FirefoxAuto148) проверен на 26.10.31
# реальным трафиком; серверный конфиг, UUID и ключи при обновлении сохраняются.
# Это не подтверждает совместимость более старых XRay и клиентов на sing-box.
XRAY_RELEASE = "v26.10.31"
DEFAULT_REALITY_SITE = "www.googletagmanager.com"
XRAY_DIR = "/opt/amnezia/xray"
SERVER_JSON = f"{XRAY_DIR}/server.json"
CLIENTS_TABLE = f"{XRAY_DIR}/clientsTable"
FLOW = "xtls-rprx-vision"
# отпечаток TLS клиента: с весны 2026 ТСПУ чаще режет REALITY с отпечатком chrome
FINGERPRINT = "firefox"
CONTAINER_NAME = "amnezia-xray"
STATS_API_PORT = 10085  # локальный gRPC-API xray (127.0.0.1) для чтения статистики
STATS_QUERY_TIMEOUT = 5
_DOCKER = 'DOCKER=$({ [ -w /var/run/docker.sock ] || [ -w /run/docker.sock ]; } && echo docker || echo "sudo -n docker"); '
_BINDINGS_FORMAT = r'{{range $k, $v := .HostConfig.PortBindings}}{{range $v}}{{printf "%s|%s|%s\n" $k .HostIp .HostPort}}{{end}}{{end}}'


class XrayError(Exception):
    pass


class XrayNotDeployed(XrayError):
    """Контейнера XRay на ноде нет (API отвечает 409, как AWG 3.1)."""


@dataclass
class XrayClient:
    client_id: str  # UUID
    name: str
    creation_date: str
    stats_key: str = ""


async def _run(conn: asyncssh.SSHClientConnection, cmd: str) -> str:
    result = await conn.run(cmd, check=False)
    if result.exit_status != 0:
        err = (result.stderr or "").strip() or (result.stdout or "").strip()
        raise XrayError(err or f"код {result.exit_status}")
    return result.stdout or ""


def _docker_exec(container: str, inner: str) -> str:
    return _DOCKER + f"$DOCKER exec {shlex.quote(container)} sh -c {shlex.quote(inner)}"


def _docker_exec_i(container: str, inner: str) -> str:
    return _DOCKER + f"$DOCKER exec -i {shlex.quote(container)} sh -c {shlex.quote(inner)}"


async def _write_file(conn, container: str, path: str, payload: str) -> None:
    """Пишет файл в контейнер через временный и mv: при ошибке (например, диск
    полон) старый файл остается целым, а ошибка доходит до вызывающего. Если
    файл смонтирован отдельно и mv на него нельзя, запись отменяется."""
    tmp = f"{path}.acontrol-tmp"
    inner = (
        f"umask 077; cat > {tmp} && {{ mv -f {tmp} {path} 2>/dev/null; }} "
        f"|| {{ rm -f {tmp}; exit 1; }}"
    )
    result = await conn.run(_docker_exec_i(container, inner), input=payload, check=False)
    if result.exit_status != 0:
        err = (result.stderr or "").strip() or f"код {result.exit_status}"
        raise XrayError(f"не удалось записать {path}: {err}")


async def detect_container(conn: asyncssh.SSHClientConnection) -> str:
    # || true: без контейнера grep отдает 1, и наружу уходило голое "код 1"
    cmd = _DOCKER + "$DOCKER ps --format '{{.Names}}' | grep -m1 amnezia-xray || true"
    out = (await _run(conn, cmd)).strip()
    if not out:
        raise XrayNotDeployed("XRay на сервере не развернут - сначала разверните его.")
    return out.splitlines()[0].strip()


async def deployment_bind_ip(conn: asyncssh.SSHClientConnection, port: int) -> str | None:
    """Адрес переустановки, в том числе когда контейнер остановлен."""
    result = await conn.run(
        _DOCKER + f"$DOCKER container inspect -f {shlex.quote(_BINDINGS_FORMAT)} {CONTAINER_NAME}",
        check=False,
    )
    if result.exit_status == 0:
        binding = re.fullmatch(r"[0-9]+/tcp\|([^|\s]*)\|([0-9]+)", (result.stdout or "").strip())
        if binding and int(binding[2]) == port:
            return binding[1]
    return None


async def _read_server(conn, container) -> dict:
    text = await _run(conn, _docker_exec(container, f"cat {SERVER_JSON}"))
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise XrayError("не удалось прочитать server.json") from exc


async def _write_server(conn, container, data: dict) -> None:
    payload = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
    await _write_file(conn, container, SERVER_JSON, payload)


async def _read_table(conn, container) -> list:
    text = await _run(conn, _docker_exec(container, f"cat {CLIENTS_TABLE} 2>/dev/null"))
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


async def _write_table(conn, container, data: list) -> None:
    payload = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
    await _write_file(conn, container, CLIENTS_TABLE, payload)


async def _default_uuid(conn, container) -> str:
    out = await _run(
        conn, _docker_exec(container, f"cat {XRAY_DIR}/xray_uuid.key 2>/dev/null")
    )
    return out.strip()


def _client_list(server: dict) -> list:
    try:
        return server["inbounds"][0]["settings"]["clients"]
    except (KeyError, IndexError, TypeError):
        return []


def _extra_vless(server: dict) -> list[dict]:
    """VLESS-входы кроме основного (inbounds[0])."""
    inbounds = server.get("inbounds") or []
    return [
        i for i in inbounds[1:] if isinstance(i, dict) and i.get("protocol") == "vless"
    ]


def _uses_flow(inbound: dict) -> bool:
    """Vision (flow) бывает только у TCP-транспорта под TLS/REALITY."""
    ss = inbound.get("streamSettings") or {}
    return (ss.get("network") or "tcp") in ("tcp", "raw") and ss.get("security") in (
        "reality", "tls",
    )


def sync_extra_inbounds(server: dict) -> bool:
    """Делает списки клиентов дополнительных VLESS-входов зеркалом основного.

    Без этого клиент, выданный панелью, работал бы только через основной вход.
    Возвращает True, если конфиг изменился."""
    changed = False
    primary = [c for c in _client_list(server) if isinstance(c, dict) and c.get("id")]
    for inbound in _extra_vless(server):
        flow = _uses_flow(inbound)
        want = []
        for c in primary:
            entry = {"id": c["id"], "email": c.get("email") or c["id"]}
            if "level" in c:
                entry["level"] = c["level"]
            if flow and c.get("flow"):
                entry["flow"] = c["flow"]
            want.append(entry)
        settings = inbound.setdefault("settings", {})
        if settings.get("clients") != want:
            settings["clients"] = want
            changed = True
    return changed


def xhttp_fallback_path(server: dict) -> str | None:
    """Путь XHTTP-входа, на который основной вход отдаёт fallback.

    Такой вход доступен клиентам на том же порту и с теми же ключами REALITY,
    что и основной; клиенту нужен только транспорт xhttp и этот путь."""
    inbounds = server.get("inbounds") or []
    if not inbounds or not isinstance(inbounds[0], dict):
        return None
    fallbacks = (inbounds[0].get("settings") or {}).get("fallbacks") or []
    dests = {str(f.get("dest")) for f in fallbacks if isinstance(f, dict)}
    if not dests:
        return None
    for inbound in _extra_vless(server):
        ss = inbound.get("streamSettings") or {}
        if ss.get("network") != "xhttp":
            continue
        listen = str(inbound.get("listen") or "")
        port = inbound.get("port")
        names = {listen} if listen else set()
        if port is not None:
            names |= {str(port), f"{listen or '127.0.0.1'}:{port}"}
        if names & dests:
            return (ss.get("xhttpSettings") or {}).get("path") or "/"
    return None


def ensure_stats_config(server: dict) -> bool:
    """Идемпотентно включает StatsService + пер-юзер статистику в server.json.

    Ключ статистики Xray — email клиента. UUID заполняет пустое поле.
    Возвращает True, если конфиг изменился (нужен рестарт Xray)."""
    changed = False
    if server.get("stats") is None:
        server["stats"] = {}
        changed = True
    api = server.get("api") or {}
    if not api.get("tag"):
        api["tag"] = "api"
        changed = True
    server["api"] = api
    services = api.get("services") or []
    if "StatsService" not in services:
        api["services"] = [*services, "StatsService"]
        changed = True
    clients = [c for c in _client_list(server) if isinstance(c, dict) and c.get("id")]
    policy = server["policy"] = server.get("policy") or {}
    levels = policy["levels"] = policy.get("levels") or {}
    for level in {"0", *(str(c.get("level", 0)) for c in clients)}:
        settings = levels.setdefault(level, {})
        for flag in ("statsUserUplink", "statsUserDownlink"):
            if settings.get(flag) is not True:
                settings[flag] = True
                changed = True
    system = policy["system"] = policy.get("system") or {}
    for flag in ("statsInboundUplink", "statsInboundDownlink"):
        if system.get(flag) is not True:
            system[flag] = True
            changed = True
    inbounds = server.setdefault("inbounds", [])
    if not any(isinstance(i, dict) and i.get("tag") == "api" for i in inbounds):
        inbounds.append({
            "listen": "127.0.0.1",
            "port": STATS_API_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
            "tag": "api",
        })
        changed = True
    routing = server["routing"] = server.get("routing") or {}
    rules = routing["rules"] = routing.get("rules") or []
    if not any(
        isinstance(r, dict) and "api" in (r.get("inboundTag") or [])
        and r.get("outboundTag") == api["tag"] for r in rules
    ):
        rules.insert(
            0,
            {"type": "field", "inboundTag": ["api"], "outboundTag": api["tag"]},
        )
        changed = True
    for c in clients:
        if not c.get("email"):
            c["email"] = c["id"]
            changed = True
    if sync_extra_inbounds(server):
        changed = True
    return changed


async def stage_update_stats(conn, container) -> tuple[str, str] | None:
    """Готовит новый конфиг отдельно; действующий файл и скрипт его не содержат."""
    raw = await _run(conn, _docker_exec(container, f"cat {SERVER_JSON}"))
    try:
        server = json.loads(raw)
    except ValueError as exc:
        raise XrayError("не удалось прочитать server.json") from exc
    if not isinstance(server, dict):
        raise XrayError("некорректный server.json")
    if not ensure_stats_config(server):
        return None
    result = await conn.run(
        'umask 077; D="$HOME/.acontrol/xray"; mkdir -p "$D" && chmod 700 "$D" '
        '&& F=$(mktemp "$D/stats.XXXXXXXX") || exit 1; '
        'if cat > "$F"; then basename "$F"; else rm -f -- "$F"; exit 1; fi',
        input=json.dumps(server, indent=4, ensure_ascii=False) + "\n", check=False,
    )
    name = (result.stdout or "").strip()
    if result.exit_status != 0 or not re.fullmatch(r"stats\.[a-zA-Z0-9]{8}", name):
        raise XrayError("не удалось подготовить новый server.json для обновления")
    return name, hashlib.sha256(raw.encode()).hexdigest()


async def discard_staged_stats(conn, name: str) -> None:
    with suppress(asyncssh.Error, OSError):
        await conn.run(f'rm -f -- "$HOME/.acontrol/xray/"{shlex.quote(name)}', check=False)


async def read_client_stats(conn, container) -> dict[str, dict] | None:
    """Счетчики StatsService. None — статистика недоступна, {} — счетчиков пока нет."""
    inner = (
        f'xray api statsquery --server=127.0.0.1:{STATS_API_PORT} '
        f'-pattern "user>>>" 2>/dev/null'
    )
    try:
        async with asyncio.timeout(STATS_QUERY_TIMEOUT):
            out = await _run(conn, _docker_exec(container, inner))
        data = json.loads(out)
    except (XrayError, ValueError, asyncssh.Error, OSError):
        return None
    if not isinstance(data, dict):
        return None
    counters = data.get("stat", [])
    if not isinstance(counters, list):
        return None
    res: dict[str, dict] = {}
    for stat in counters:
        if not isinstance(stat, dict) or not isinstance(stat.get("name"), str):
            return None
        parts = stat["name"].split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        uid, direction = parts[1], parts[3]
        try:
            val = int(stat.get("value", 0) or 0)
        except (ValueError, TypeError):
            return None
        entry = res.setdefault(uid, {"up": 0, "down": 0})
        if direction == "uplink":
            entry["up"] = val
        elif direction == "downlink":
            entry["down"] = val
    return res


async def _read_all(conn, container) -> tuple[dict, str, list]:
    """server.json, UUID по умолчанию и clientsTable одним docker exec: сбор
    статистики читает их каждый цикл, а каждый exec стоит демону docker."""
    inner = (
        f"cat {SERVER_JSON}; echo; echo ===UUID===; "
        f"cat {XRAY_DIR}/xray_uuid.key 2>/dev/null; echo; echo ===TABLE===; "
        f"cat {CLIENTS_TABLE} 2>/dev/null"
    )
    text = await _run(conn, _docker_exec(container, inner))
    head, _, rest = text.partition("===UUID===")
    uuid_text, _, table_text = rest.partition("===TABLE===")
    try:
        server = json.loads(head)
    except (json.JSONDecodeError, ValueError) as exc:
        raise XrayError("не удалось прочитать server.json") from exc
    try:
        table = json.loads(table_text)
    except (json.JSONDecodeError, ValueError):
        table = []
    return server, uuid_text.strip(), table if isinstance(table, list) else []


async def read_clients(
    conn: asyncssh.SSHClientConnection, container: str | None = None
) -> list[XrayClient]:
    container = container or await detect_container(conn)
    server, default, table = await _read_all(conn, container)
    names = {
        e.get("clientId"): e.get("userData", {})
        for e in table
        if isinstance(e, dict)
    }
    configured = [c for c in _client_list(server) if isinstance(c, dict)]
    default_stats_key = next((c.get("email") for c in configured if c.get("id") == default), None)
    clients: list[XrayClient] = []
    for c in configured:
        uid = c.get("id")
        if not uid or uid == default:
            continue
        ud = names.get(uid, {})
        stats_key = c.get("email") or ""
        clients.append(
            XrayClient(
                client_id=uid,
                name=ud.get("clientName", "—") or "—",
                creation_date=ud.get("creationDate", ""),
                stats_key="" if stats_key == default_stats_key else stats_key,
            )
        )
    return clients


def client_stats_by_id(clients: list[XrayClient], stats: dict[str, dict] | None) -> dict[str, dict]:
    """StatsService indexes traffic by the configured email, not by UUID."""
    if not stats:
        return {}
    counts = Counter(c.stats_key for c in clients if c.stats_key)
    return {
        c.client_id: stats[c.stats_key]
        for c in clients
        if c.stats_key in stats and counts[c.stats_key] == 1
    }


async def read_server_bits(conn, container) -> dict:
    """REALITY-параметры сервера для сборки клиентского конфига."""
    inner = (
        f"echo ===PUB===; cat {XRAY_DIR}/xray_public.key 2>/dev/null; "
        f"echo ===SID===; cat {XRAY_DIR}/xray_short_id.key 2>/dev/null; echo ===END==="
    )
    binding_format = "{{json .HostConfig.PortBindings}}"
    inspect = f"$DOCKER inspect -f {shlex.quote(binding_format)} {shlex.quote(container)}"
    bundle = await _run(
        conn, _docker_exec(container, inner)
        + f" && ({_DOCKER}echo ===BINDINGS===; {inspect} 2>/dev/null || true)",
    )

    def _sec(name):
        m = f"==={name}==="
        s = bundle.find(m)
        if s == -1:
            return ""
        rest = bundle[s + len(m):]
        nxt = rest.find("\n===")
        return (rest[:nxt] if nxt != -1 else rest).strip("\n").strip()

    server = await _read_server(conn, container)
    inbound = (server.get("inbounds") or [{}])[0]
    port = inbound.get("port", 443)
    port = int(port) if str(port).isdigit() else 443
    raw_bindings = _sec("BINDINGS")
    if raw_bindings:
        bindings = json.loads(raw_bindings) or {}
        host_ports = {item.get("HostPort", "") for item in bindings.get(f"{port}/tcp", []) or []}
        if len(host_ports) == 1:
            published, = host_ports
            if published.isdecimal() and 1 <= int(published) <= 65535:
                port = int(published)
    reality = (inbound.get("streamSettings") or {}).get("realitySettings", {})
    site = (reality.get("serverNames") or [DEFAULT_REALITY_SITE])[0]
    clients = _client_list(server)
    flow = clients[0].get("flow", FLOW) if clients else FLOW
    return {
        "pub": _sec("PUB"),
        "short": _sec("SID"),
        "site": site,
        "port": port,
        "flow": flow or FLOW,
        "xhttp_path": xhttp_fallback_path(server),
    }


async def node_version(conn, container) -> str | None:
    """Версия xray-core в контейнере (напр. '25.8.3')."""
    out = await _run(
        conn, _docker_exec(container, "xray version 2>/dev/null | head -1")
    )
    m = re.search(r"[Xx]ray\s+v?(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def version_tuple(version: str) -> tuple[int, ...]:
    """'v26.3.27' / '26.3.27' -> (26, 3, 27) для сравнения версий xray-core."""
    return tuple(int(x) for x in re.findall(r"\d+", version or "")[:3])


def assemble_xray_link(
    *, host, description, dns1, dns2, client_id, port, pub, short, site, flow,
    xhttp_path: str | None = None,
) -> str:
    """vpn:// «Для приложения AmneziaVPN» для XRay/REALITY-клиента.

    xhttp_path: собрать вариант с транспортом XHTTP (без Vision) вместо TCP."""
    users = {"id": client_id, "encryption": "none"}
    if flow and not xhttp_path:
        users["flow"] = flow
    stream: dict = {"network": "tcp"}
    if xhttp_path:
        stream = {"network": "xhttp", "xhttpSettings": {"path": xhttp_path}}
    stream |= {
        "security": "reality",
        "realitySettings": {
            "fingerprint": FINGERPRINT,
            "serverName": site,
            "publicKey": pub,
            "shortId": short,
            "spiderX": "",
        },
    }
    client = {
        "log": {"loglevel": "error"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"udp": True}}
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {"address": host, "port": int(port), "users": [users]}
                    ]
                },
                "streamSettings": stream,
            }
        ],
    }
    last_config = json.dumps(client, separators=(",", ":"), ensure_ascii=False)
    container_obj = {
        "container": "amnezia-xray",
        "xray": {
            "last_config": last_config,
            "port": str(port),
            "transport_proto": "tcp",
        },
    }
    top = {
        "containers": [container_obj],
        "defaultContainer": "amnezia-xray",
        "description": description,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": host,
    }
    payload = json.dumps(top, ensure_ascii=False, sort_keys=True).encode()
    compressed = struct.pack(">I", len(payload)) + zlib.compress(payload)
    return "vpn://" + base64.urlsafe_b64encode(compressed).decode().rstrip("=")


def build_vless_uri(
    *, host, port, client_id, pub, short, site, flow, label,
    xhttp_path: str | None = None,
) -> str:
    """Ссылка vless:// для Happ, v2rayN/v2rayNG, INCY, Shadowrocket и т.п."""
    params = [("type", "xhttp" if xhttp_path else "tcp"), ("encryption", "none")]
    if xhttp_path:
        params += [("path", xhttp_path), ("mode", "auto")]
    elif flow:
        params.append(("flow", flow))
    params += [
        ("security", "reality"),
        ("sni", site),
        ("fp", FINGERPRINT),
        ("pbk", pub),
        ("sid", short),
    ]
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params)
    addr = f"[{host}]" if ":" in host else host
    return f"vless://{client_id}@{addr}:{int(port)}?{query}#{quote(label, safe='')}"


def client_configs(
    bits: dict, *, host, description, dns1, dns2, client_id, name,
) -> list[dict]:
    """Все варианты конфига клиента: Vision всегда, XHTTP, если на сервере есть
    XHTTP-вход за fallback. У каждого варианта есть vpn:// (AmneziaVPN) и vless://."""
    variants = [("vision", "VLESS Reality (Vision)", None, "")]
    if bits.get("xhttp_path"):
        variants.append(("xhttp", "VLESS XHTTP Reality", bits["xhttp_path"], " XHTTP"))
    out = []
    for key, label, xhttp_path, suffix in variants:
        common = dict(
            client_id=client_id, port=bits["port"], pub=bits["pub"],
            short=bits["short"], site=bits["site"], flow=bits["flow"],
            xhttp_path=xhttp_path,
        )
        out.append({
            "key": key,
            "label": label,
            "amnezia": assemble_xray_link(
                host=host, description=f"{description}{suffix}", dns1=dns1,
                dns2=dns2, **common,
            ),
            "uri": build_vless_uri(
                host=host, label=f"{description}{suffix} {name}".strip(), **common,
            ),
        })
    return out


async def _restart(conn, container) -> None:
    await _run(conn, _DOCKER + f"$DOCKER restart {shlex.quote(container)} >/dev/null")
    # проверим, что контейнер поднялся с новым конфигом
    out = await _run(
        conn,
        _DOCKER + f"$DOCKER ps --format '{{{{.Names}}}}' | grep -Fx {shlex.quote(container)} || true",
    )
    if container not in out:
        raise XrayError("контейнер xray не поднялся после рестарта (проверьте server.json)")


async def issue_client(
    conn: asyncssh.SSHClientConnection,
    container: str,
    name: str,
    host: str,
    description: str,
    dns1: str,
    dns2: str,
) -> tuple[XrayClient, list[dict]]:
    """Выдаёт клиента: новый UUID → clients[] + clientsTable → restart → конфиги
    (см. client_configs; первый вариант Vision, его vpn:// и есть прежний config_amnezia)."""
    cid = str(uuid.uuid4())
    server = await _read_server(conn, container)
    _client_list(server).append({"id": cid, "flow": FLOW, "email": cid})
    ensure_stats_config(server)  # самолечение: включаем статистику, если ещё нет
    await _write_server(conn, container, server)

    date = (await _run(conn, 'date "+%a %b %e %H:%M:%S %Y"')).strip()
    table = await _read_table(conn, container)
    table.append(
        {"clientId": cid, "userData": {"clientName": name, "creationDate": date}}
    )
    await _write_table(conn, container, table)

    bits = await read_server_bits(conn, container)
    await _restart(conn, container)

    configs = client_configs(
        bits, host=host, description=description, dns1=dns1, dns2=dns2,
        client_id=cid, name=name,
    )
    return XrayClient(client_id=cid, name=name, creation_date=date), configs


async def pause_client(
    conn: asyncssh.SSHClientConnection, container: str, client_id: str
) -> dict:
    """Ставит на паузу: убирает UUID из clients[] (как revoke), но возвращает его
    dict {id, flow, email} — чтобы resume вернул того же клиента (тот же UUID →
    клиентский конфиг не меняется)."""
    if not client_id:
        raise XrayError("некорректный clientId")
    server = await _read_server(conn, container)
    entry = next(
        (c for c in _client_list(server)
         if isinstance(c, dict) and c.get("id") == client_id),
        None,
    )
    if entry is None:
        raise XrayError("Клиент не найден")
    server["inbounds"][0]["settings"]["clients"] = [
        c for c in _client_list(server)
        if not (isinstance(c, dict) and c.get("id") == client_id)
    ]
    ensure_stats_config(server)
    await _write_server(conn, container, server)
    table = await _read_table(conn, container)
    await _write_table(
        conn, container, [e for e in table if e.get("clientId") != client_id]
    )
    await _restart(conn, container)
    return entry


async def resume_client(
    conn: asyncssh.SSHClientConnection, container: str,
    client_entry: dict, name: str,
) -> None:
    """Возобновляет клиента: возвращает его dict в clients[] + clientsTable."""
    cid = client_entry.get("id")
    if not cid or not isinstance(cid, str):
        raise XrayError("некорректные данные паузы")
    # данные паузы могли приехать из файла переноса: в server.json пускаем
    # только поля клиента VLESS, а не любой объект из файла
    client_entry = {
        k: v for k, v in client_entry.items()
        if k in ("id", "flow", "email", "level") and isinstance(v, (str, int))
    }
    server = await _read_server(conn, container)
    if not any(
        isinstance(c, dict) and c.get("id") == cid for c in _client_list(server)
    ):
        _client_list(server).append(client_entry)
    ensure_stats_config(server)
    await _write_server(conn, container, server)
    date = (await _run(conn, 'date "+%a %b %e %H:%M:%S %Y"')).strip()
    table = await _read_table(conn, container)
    if not any(e.get("clientId") == cid for e in table):
        table.append(
            {"clientId": cid, "userData": {"clientName": name, "creationDate": date}}
        )
    await _write_table(conn, container, table)
    await _restart(conn, container)


async def revoke_client(
    conn: asyncssh.SSHClientConnection, container: str, client_id: str
) -> None:
    """Отзывает клиента: удаляет UUID из clients[] и clientsTable → restart."""
    if not client_id:
        raise XrayError("некорректный clientId")
    server = await _read_server(conn, container)
    try:
        clients = server["inbounds"][0]["settings"]["clients"]
    except (KeyError, IndexError, TypeError) as exc:
        raise XrayError("некорректный server.json") from exc
    server["inbounds"][0]["settings"]["clients"] = [
        c for c in clients if not (isinstance(c, dict) and c.get("id") == client_id)
    ]
    ensure_stats_config(server)  # самолечение статистики при любой правке клиентов
    await _write_server(conn, container, server)

    table = await _read_table(conn, container)
    table = [e for e in table if e.get("clientId") != client_id]
    await _write_table(conn, container, table)

    await _restart(conn, container)


_XRAY_DOCKERFILE = """FROM alpine:3.15
LABEL maintainer="AmneziaVPN"
ARG XRAY_RELEASE="v26.10.31"
RUN apk add --no-cache curl unzip bash openssl netcat-openbsd dumb-init rng-tools xz jq
RUN apk --update upgrade --no-cache
RUN mkdir -p /opt/amnezia/xray
RUN curl -fsSL --retry 3 --connect-timeout 15 --max-time 180 \\
  https://github.com/XTLS/Xray-core/releases/download/${XRAY_RELEASE}/Xray-linux-64.zip -o /root/xray.zip \\
  && if [ "$XRAY_RELEASE" = "v26.10.31" ]; then \\
    echo 'e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214  /root/xray.zip' | sha256sum -c -; \\
  fi \\
  && unzip -q /root/xray.zip -d /usr/bin/ \\
  && chmod a+x /usr/bin/xray \\
  && /usr/bin/xray version \\
  && rm -f /root/xray.zip
ENV TZ=Asia/Shanghai
ENV GODEBUG=multipathtcp=0
ENTRYPOINT ["dumb-init","tail","-f","/dev/null"]
"""


def build_deploy_script(
    port: int, site: str, xray_release: str = XRAY_RELEASE, *,
    dest: str = "", require_fresh: bool = False, preserve_port: bool = False,
    staged_stats: tuple[str, str] | None = None,
) -> str:
    """Скрипт build-on-target: ставит docker, собирает amnezia-xray, конфигурит, запускает.

    Запускается от ssh_user (не root), поэтому все привилегированные операции —
    через sudo, а файлы в /opt пишутся через `base64 -d | sudo tee` (redirect
    выполняется НЕ-root'ом до sudo). Маркеры DEPLOY_DONE / DEPLOY_ERROR.
    xray_release — тег релиза XTLS/Xray-core (для деплоя/обновления ядра).
    """
    site = site or DEFAULT_REALITY_SITE
    dest = dest or f"{site}:443"
    if not re.fullmatch(r"v?\d+\.\d+\.\d+", xray_release or ""):
        xray_release = XRAY_RELEASE
    elif not xray_release.startswith("v"):
        xray_release = f"v{xray_release}"
    port = int(port)
    stats_name, stats_hash = staged_stats or ("", "")
    stats_file = f'"$HOME/.acontrol/xray/"{shlex.quote(stats_name)}' if stats_name else ""
    dockerfile_b64 = base64.b64encode(_XRAY_DOCKERFILE.encode()).decode()
    fresh_guard = """\
if sudo test -f "$D/server.json" || sudo docker container inspect "$C" >/dev/null 2>&1; then
  fail "Xray already has a configuration or container. Leave SNI and Dest blank to reuse the existing configuration."
fi
""" if require_fresh else ""
    tls_check = f"""\
log "проверка TLS 1.3 и HTTP/2 на Dest"
TLS_RESULT=$(sudo docker run --rm -e LC_ALL=C --entrypoint timeout "$IMG" 10 openssl s_client -tls1_3 -alpn h2 \\
  -connect {shlex.quote(dest)} -servername {shlex.quote(site)} \\
  -verify_hostname {shlex.quote(site)} -verify_return_error </dev/null 2>&1) \\
  && grep -Fxq 'ALPN protocol: h2' <<< "$TLS_RESULT" \\
  || fail "The REALITY Dest did not negotiate TLS 1.3 and HTTP/2 using the configured SNI."
""" if require_fresh else ""
    return f"""set +e
fail() {{ echo "DEPLOY_ERROR: $1"; exit 1; }}
log(){{ echo "[$(date +%H:%M:%S)] $*"; }}
XRAY_SERVER_PORT={port}
INBOUND_PORT=$XRAY_SERVER_PORT
XRAY_SITE_NAME={shlex.quote(json.dumps(site))}
XRAY_DEST={shlex.quote(json.dumps(dest))}
IMG=amnezia-xray
C=amnezia-xray
BUILD=/opt/amnezia-build/xray
D=/opt/amnezia/xray
STATS_FILE={stats_file}
STATS_DIR=
STATS_NEXT=
STATS_BACKUP=
STATS_APPLIED=
WORK=
OLD=
NEW_CONFIG=
DEPLOYED=
cleanup() {{
  if [ -z "$DEPLOYED" ] && [ -n "$WORK" ] && sudo test -s "$WORK/container-id"; then
    NEW_ID=$(sudo cat "$WORK/container-id")
    sudo docker rm -f "$NEW_ID" >/dev/null 2>&1 || true
  fi
  if [ -n "$STATS_APPLIED" ] && [ -z "$DEPLOYED" ]; then
    if ! sudo mv -f -- "$STATS_BACKUP" "$D/server.json"; then
      log "Could not restore previous Xray configuration. Kept backup at $STATS_BACKUP."
      STATS_BACKUP=
    fi
  fi
  if [ -n "$OLD" ] && [ -z "$DEPLOYED" ]; then
    if ! sudo docker rename "$OLD" "$C"; then
      log "Could not restore previous Xray container name. Kept container $OLD."
    elif [ "$EXISTING" = true ]; then
      sudo docker start "$C" >/dev/null || log "Could not restart previous Xray container."
    fi
  fi
  if [ -n "$NEW_CONFIG" ] && [ -z "$DEPLOYED" ]; then sudo rm -f "$D/server.json"; fi
  if [ -n "$STATS_FILE" ]; then rm -f -- "$STATS_FILE"; fi
  if [ -n "$STATS_NEXT" ]; then sudo rm -f -- "$STATS_NEXT"; fi
  if [ -n "$STATS_DIR" ]; then sudo rmdir -- "$STATS_DIR"; fi
  if [ -n "$STATS_BACKUP" ]; then sudo rm -f -- "$STATS_BACKUP"; fi
  if [ -n "$WORK" ]; then sudo rm -rf -- "$WORK"; fi
}}
trap cleanup EXIT
trap 'fail "Xray deployment interrupted"' HUP INT TERM

{fresh_guard}
# У контейнера с нестандартной публикацией не меняем ни внешний порт,
# ни порт VLESS внутри, ни адрес привязки.
BIND=
EXISTING=$(sudo docker inspect -f '{{{{.State.Running}}}}' "$C" 2>/dev/null) || EXISTING=
if [ -n "$EXISTING" ]; then
  BINDING=$(sudo docker inspect -f {shlex.quote(_BINDINGS_FORMAT)} "$C") || fail "could not read existing port bindings"
  [[ "$BINDING" =~ ^([0-9]+)/tcp\\|([^\\|[:space:]]*)\\|([0-9]+)$ ]] || fail "Unsupported Xray port bindings. The existing container was kept."
  INBOUND_PORT=${{BASH_REMATCH[1]}}
  BIND=${{BASH_REMATCH[2]}}
  PUBLISHED_PORT=${{BASH_REMATCH[3]}}
  if [ {int(preserve_port)} -eq 0 ] && [ "$PUBLISHED_PORT" != "$XRAY_SERVER_PORT" ]; then
    fail "Xray already uses external port $PUBLISHED_PORT. Retry with this port to keep existing profiles working."
  fi
  XRAY_SERVER_PORT=$PUBLISHED_PORT
fi

# Порт должен быть свободен ДО сборки и генерации ключей. Панель проверяет это
# сама; здесь страховка на случай вызова в обход окна установки. Сосед на
# другом адресе не мешает, если XRay привязан к своему адресу
OTHER=$(sudo docker ps --filter "publish=$XRAY_SERVER_PORT/tcp" --format '{{{{.Names}}}}|{{{{.Ports}}}}' 2>/dev/null | grep -v "^$C|" | while IFS='|' read -r n p; do
  [ -z "$BIND" ] && {{ echo "$n"; continue; }}
  case ", $p" in *", 0.0.0.0:$XRAY_SERVER_PORT->"*|*", [::]:$XRAY_SERVER_PORT->"*|*", :::$XRAY_SERVER_PORT->"*|*", $BIND:$XRAY_SERVER_PORT->"*) echo "$n" ;; esac
done | head -1)
[ -n "$OTHER" ] && fail "port $XRAY_SERVER_PORT/tcp busy: $OTHER"

log "[1/5] docker"
command -v docker >/dev/null 2>&1 || {{ curl -fsSL https://get.docker.com | sudo sh >/dev/null || fail "docker install"; }}

log "[2/5] Dockerfile"
sudo mkdir -p "$BUILD" "$D" || fail mkdir
echo {dockerfile_b64} | base64 -d | sudo tee "$BUILD/Dockerfile" >/dev/null || fail dockerfile

log "[3/5] docker build (xray {xray_release})"
sudo docker build --build-arg XRAY_RELEASE={xray_release} -t "$IMG" "$BUILD" 2>&1 | tail -3
[ ${{PIPESTATUS[0]}} -eq 0 ] || fail build

log "[4/5] конфиг"
WORK=$(mktemp -d) || fail "could not create Xray working directory"

CONFIG_DIR=$D
if [ -n "$EXISTING" ]; then
  MOUNT=$(sudo docker inspect -f '{{{{range .Mounts}}}}{{{{println .Source .Destination}}}}{{{{end}}}}' "$C") || fail "could not read existing mounts"
  if ! grep -Fxq "$D $D" <<< "$MOUNT"; then
    CONFIG_DIR=$WORK/config
    mkdir "$CONFIG_DIR" || fail "could not stage Xray configuration"
    sudo docker cp "$C:$D/." "$CONFIG_DIR/" || fail "could not copy existing Xray configuration"
  fi
  sudo test -s "$CONFIG_DIR/server.json" || fail "missing existing Xray configuration"
fi
if sudo test -f "$CONFIG_DIR/server.json"; then
  CONFIG_PORT=$(sudo docker run --rm -v "$CONFIG_DIR":/config:ro --entrypoint jq "$IMG" \\
    -er '.inbounds[0] | select(.protocol == "vless") | .port | tostring | select(test("^[0-9]+$"))' /config/server.json) \\
    || fail "could not read the existing VLESS inbound port"
  [ "$CONFIG_PORT" = "$INBOUND_PORT" ] || fail "The existing VLESS inbound uses port $CONFIG_PORT. Its configuration was kept."
  if [ "$CONFIG_DIR" != "$D" ]; then
    sudo cp -a "$CONFIG_DIR/." "$D/" || fail "could not save existing Xray configuration"
  fi
  log "конфиг уже есть — сохранён, клиенты не тронуты"
else
  {tls_check}  NEW_CONFIG=1
  # Внешний порт может совпадать с внутренним портом StatsService.
  if [ "$INBOUND_PORT" = {STATS_API_PORT} ]; then INBOUND_PORT=443; fi
  log "генерация ключей + server.json (новый сервер)"
  sudo docker run --rm -v "$D":/opt/amnezia/xray --entrypoint sh "$IMG" -c 'cd /opt/amnezia/xray; xray uuid > xray_uuid.key; openssl rand -hex 8 > xray_short_id.key; xray x25519 > xray_x25519.raw 2>&1' || fail keys
  UUID=$(sudo cat "$D/xray_uuid.key" | tr -d " \\r\\n")
  SID=$(sudo cat "$D/xray_short_id.key" | tr -d " \\r\\n")
  PRIV=$(sudo cat "$D/xray_x25519.raw" | grep -i private | head -1 | sed 's/.*: *//' | tr -d " \\r\\n")
  PUB=$(sudo cat "$D/xray_x25519.raw" | grep -iE 'public|password' | head -1 | sed 's/.*: *//' | tr -d " \\r\\n")
  echo "$PRIV" | sudo tee "$D/xray_private.key" >/dev/null
  echo "$PUB" | sudo tee "$D/xray_public.key" >/dev/null
  [ -n "$UUID" ] && [ -n "$PRIV" ] && [ -n "$PUB" ] || fail emptykeys
  sudo tee "$D/server.json" >/dev/null <<EOF || fail "could not write Xray configuration"
{{
    "log": {{ "loglevel": "error" }},
    "stats": {{}},
    "api": {{ "tag": "api", "services": [ "StatsService" ] }},
    "policy": {{ "levels": {{ "0": {{ "statsUserUplink": true, "statsUserDownlink": true }} }}, "system": {{ "statsInboundUplink": true, "statsInboundDownlink": true }} }},
    "inbounds": [
        {{
            "port": $INBOUND_PORT,
            "protocol": "vless",
            "settings": {{
                "clients": [ {{ "id": "$UUID", "flow": "{FLOW}", "email": "$UUID" }} ],
                "decryption": "none"
            }},
            "streamSettings": {{
                "network": "tcp",
                "security": "reality",
                "realitySettings": {{
                    "dest": $XRAY_DEST,
                    "serverNames": [ $XRAY_SITE_NAME ],
                    "privateKey": "$PRIV",
                    "shortIds": [ "$SID" ]
                }}
            }}
        }},
        {{
            "listen": "127.0.0.1",
            "port": {STATS_API_PORT},
            "protocol": "dokodemo-door",
            "settings": {{ "address": "127.0.0.1" }},
            "tag": "api"
        }}
    ],
    "outbounds": [ {{ "protocol": "freedom" }} ],
    "routing": {{ "rules": [ {{ "type": "field", "inboundTag": [ "api" ], "outboundTag": "api" }} ] }}
}}
EOF
  sudo test -f "$D/clientsTable" || echo "[]" | sudo tee "$D/clientsTable" >/dev/null
fi

CHECK_CONFIG=server.json
if [ -n "$STATS_FILE" ]; then
  [ -n "$EXISTING" ] || fail "Xray container changed during update. Retry the update."
  CONFIG_HASH=$(sudo sha256sum "$D/server.json") || fail "could not check existing Xray configuration"
  [ "${{CONFIG_HASH%% *}}" = {shlex.quote(stats_hash)} ] || fail "Xray configuration changed during update. Retry the update."
  STATS_DIR=$(sudo mktemp -d "$D/.server-next.XXXXXXXX") || fail "could not stage Xray statistics configuration"
  STATS_NEXT=$STATS_DIR/server.json
  sudo install -m 600 -- "$STATS_FILE" "$STATS_NEXT" || fail "could not stage Xray statistics configuration"
  STATS_BACKUP=$(sudo mktemp "$D/.server-previous.XXXXXXXX") || fail "could not keep previous Xray configuration"
  sudo cp -a -- "$D/server.json" "$STATS_BACKUP" || fail "could not keep previous Xray configuration"
  CHECK_CONFIG=${{STATS_DIR##*/}}/server.json
fi
sudo docker run --rm -v "$D":/opt/amnezia/xray:ro --entrypoint xray "$IMG" \\
  run -test -config "/opt/amnezia/xray/$CHECK_CONFIG" >/dev/null \\
  || fail "Xray rejected the configuration."

log "фаервол: открываю $XRAY_SERVER_PORT/tcp наружу (Docker публикует, но ufw/firewalld могут блочить)"
if command -v ufw >/dev/null 2>&1; then sudo ufw allow $XRAY_SERVER_PORT/tcp >/dev/null 2>&1 || true; sudo ufw route allow proto tcp from any to any port $XRAY_SERVER_PORT >/dev/null 2>&1 || true; fi
if command -v firewall-cmd >/dev/null 2>&1; then sudo firewall-cmd --permanent --add-port=$XRAY_SERVER_PORT/tcp >/dev/null 2>&1 && sudo firewall-cmd --reload >/dev/null 2>&1 || true; fi

log "[5/5] контейнер"
# В bridge-сети свой netns: host sysctl не заменяет его настройку. На ядрах
# без CONFIG_MPTCP этого sysctl нет, и Docker с ним отказался бы запускаться.
MPTCP_OPT=""
if [ -e /proc/sys/net/mptcp/enabled ]; then MPTCP_OPT="--sysctl net.mptcp.enabled=0"; fi
if [ -n "$EXISTING" ]; then
  sudo docker rename "$C" "$C-previous-$$" || fail "could not keep the previous Xray container"
  OLD="$C-previous-$$"
  if [ "$EXISTING" = true ]; then sudo docker stop "$OLD" >/dev/null || fail "could not stop previous Xray container"; fi
fi
if [ -n "$STATS_NEXT" ]; then
  STATS_APPLIED=1
  sudo mv -f -- "$STATS_NEXT" "$D/server.json" || fail "could not activate Xray statistics configuration"
fi
PROBE_HOST=$BIND
case "$PROBE_HOST" in ''|0.0.0.0) PROBE_HOST=127.0.0.1 ;; ::) PROBE_HOST=::1 ;; esac
case "$BIND" in *:*) BIND="[$BIND]" ;; esac
sudo docker run -d --name "$C" --cidfile "$WORK/container-id" --restart always --privileged --cap-add=NET_ADMIN $MPTCP_OPT \\
  -e GODEBUG=multipathtcp=0 \\
  -p "${{BIND:+$BIND:}}$XRAY_SERVER_PORT:$INBOUND_PORT/tcp" \\
  -v "$D":/opt/amnezia/xray \\
  --entrypoint sh "$IMG" -c "xray -config /opt/amnezia/xray/server.json" >/dev/null \\
  || fail run
sleep 4
STATE=$(sudo docker inspect -f '{{{{.State.Status}}}}|{{{{.RestartCount}}}}' "$C")
CONTAINER_IP=$(sudo docker inspect -f '{{{{with index .NetworkSettings.Networks "bridge"}}}}{{{{.IPAddress}}}}{{{{end}}}}' "$C")
# Сокет docker-proxy на хосте принимает TCP, даже если за ним никто не слушает.
if [ "$STATE" != 'running|0' ] || [ -z "$CONTAINER_IP" ] \\
  || ! sudo docker exec "$C" timeout 3 nc -z "$CONTAINER_IP" "$INBOUND_PORT" \\
  || ! timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$PROBE_HOST" "$XRAY_SERVER_PORT"; then
  sudo docker logs "$C" 2>&1 | tail
  fail "Xray did not start listening on its published port."
fi
DEPLOYED=1
if [ -n "$OLD" ]; then sudo docker rm "$OLD" >/dev/null || log "Could not remove previous Xray container."; fi
OLD=
NEW_CONFIG=
log "xray запущен на порту ${{BIND:+$BIND:}}$XRAY_SERVER_PORT"
echo "DEPLOY_DONE"
"""


async def build_client_link(
    conn: asyncssh.SSHClientConnection,
    container: str,
    client_id: str,
    host: str,
    description: str,
    dns1: str,
    dns2: str,
    name: str = "",
) -> list[dict]:
    """Пересобирает конфиги существующего клиента (UUID живёт в server.json)."""
    server = await _read_server(conn, container)
    ids = [c.get("id") for c in _client_list(server) if isinstance(c, dict)]
    if client_id not in ids:
        raise XrayError("Клиент не найден")
    bits = await read_server_bits(conn, container)
    return client_configs(
        bits, host=host, description=description, dns1=dns1, dns2=dns2,
        client_id=client_id, name=name,
    )
