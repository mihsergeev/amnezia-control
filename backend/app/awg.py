"""Чтение и управление AmneziaWG на ноде через SSH + docker exec.

Модель Amnezia: интерфейс awg0, конфиг /opt/amnezia/awg/awg0.conf
([Interface] с обфускация-параметрами + [Peer]-блоки), имена клиентов
в clientsTable (JSON), общий PSK на всех пиров.

Клиентские ключи генерируются на панели (X25519); на ноду уходит только
публичный ключ клиента — приватный кладётся лишь в скачиваемый конфиг.
"""

import base64
import ipaddress
import json
import random
import re
import shlex
import struct
import zlib
from dataclasses import dataclass, field

import asyncssh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

AWG_DIR = "/opt/amnezia/awg"
AWG_PARAM_KEYS = [
    "Jc", "Jmin", "Jmax",
    "S1", "S2", "S3", "S4",
    "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5",
]
# выбирает docker или sudo docker в зависимости от прав ssh-пользователя
_DOCKER = 'DOCKER=$(docker info >/dev/null 2>&1 && echo docker || echo "sudo -n docker"); '


class AwgError(Exception):
    pass


@dataclass
class AwgClient:
    name: str
    public_key: str
    address: str
    latest_handshake: int | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    endpoint: str = ""


@dataclass
class AwgState:
    container: str
    interface: str
    listen_port: int
    server_public_key: str
    endpoint: str
    address: str
    params: dict[str, str] = field(default_factory=dict)
    clients: list[AwgClient] = field(default_factory=list)


def generate_keypair() -> tuple[str, str]:
    """Возвращает (private_b64, public_b64) в формате WireGuard."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode()


def derive_public_key(private_b64: str) -> str:
    """Публичный ключ WireGuard из приватного."""
    priv = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(pub_raw).decode()


# порядок ключей параметров как у Amnezia (для совместимости формата)
_AMNEZIA_PARAM_KEYS = [
    "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5",
    "Jc", "Jmax", "Jmin",
    "S1", "S2", "S3", "S4",
]


def dns_pair(dns: str) -> tuple[str, str]:
    parts = [p.strip() for p in dns.split(",") if p.strip()]
    dns1 = parts[0] if parts else "1.1.1.1"
    dns2 = parts[1] if len(parts) > 1 else dns1
    return dns1, dns2


def build_amnezia_link(
    conf_text: str,
    host: str,
    description: str,
    dns1: str,
    dns2: str,
    container: str = "amnezia-awg2",
) -> str:
    """Строит vpn://-ссылку формата «Для приложения AmneziaVPN» из .conf."""
    interface, peers = parse_conf(conf_text)
    peer = peers[0] if peers else {}
    client_priv = interface.get("PrivateKey", "")
    client_pub = derive_public_key(client_priv) if client_priv else ""
    client_ip = interface.get("Address", "").split("/")[0]
    subnet = (
        str(ipaddress.ip_network(f"{client_ip}/24", strict=False).network_address)
        if client_ip
        else ""
    )
    endpoint = peer.get("Endpoint", f"{host}:0")
    port = int(endpoint.rsplit(":", 1)[-1]) if ":" in endpoint else 0
    params = {k: interface.get(k, "") for k in _AMNEZIA_PARAM_KEYS}

    # DNS в конфиге шаблонизируем, как делает Amnezia
    config_str = re.sub(
        r"^DNS = .*$", "DNS = $PRIMARY_DNS, $SECONDARY_DNS", conf_text, flags=re.M
    )

    last_config = {
        **params,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "clientId": client_pub,
        "client_ip": client_ip,
        "client_priv_key": client_priv,
        "client_pub_key": client_pub,
        "config": config_str,
        "hostName": host,
        "mtu": "1376",
        "persistent_keep_alive": "25",
        "port": port,
        "psk_key": peer.get("PresharedKey", ""),
        "server_pub_key": peer.get("PublicKey", ""),
    }
    awg_obj = {
        **params,
        "last_config": json.dumps(
            last_config, indent=4, ensure_ascii=False, sort_keys=True
        )
        + "\n",
        "port": str(port),
        "protocol_version": "2",
        "subnet_address": subnet,
        "transport_proto": "udp",
    }
    top = {
        "containers": [{"awg": awg_obj, "container": container}],
        "defaultContainer": container,
        "description": description,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": host,
    }
    payload = json.dumps(top, ensure_ascii=False, sort_keys=True).encode()
    compressed = struct.pack(">I", len(payload)) + zlib.compress(payload)
    return "vpn://" + base64.urlsafe_b64encode(compressed).decode().rstrip("=")


def build_fullaccess_awg_object(conf_text: str) -> dict:
    """Собирает `awg`-объект контейнера для full-access ссылки приложения.

    В отличие от клиентской ссылки (build_amnezia_link) full-access НЕ содержит
    last_config — только параметры протокола (H1-H4 диапазонами, I1-I5, Jc/S…),
    порт, subnet и, главное, protocol_version="2". Без этого объекта приложение
    AmneziaVPN не распознаёт версию 2 и помечает сервер как «AmneziaWG Legacy».
    Формат сверен байт-в-байт с экспортом самого приложения.
    """
    interface, _peers = parse_conf(conf_text)
    params = {k: interface.get(k, "") for k in _AMNEZIA_PARAM_KEYS}
    listen_port = int(interface.get("ListenPort", "0") or 0)
    server_ip = interface.get("Address", "").split("/")[0]
    subnet = (
        str(ipaddress.ip_network(f"{server_ip}/24", strict=False).network_address)
        if server_ip
        else ""
    )
    return {
        **params,
        "port": str(listen_port),
        "protocol_version": "2",
        "subnet_address": subnet,
        "transport_proto": "udp",
    }


async def read_awg_conf(
    conn: asyncssh.SSHClientConnection,
    container: str,
    interface_name: str = "awg0",
) -> str:
    """Читает текст awg0.conf из контейнера (для сборки full-access объекта)."""
    interface_name = _safe_interface(interface_name)
    return await _run(
        conn, _docker_exec(container, f"cat {AWG_DIR}/{interface_name}.conf")
    )


def parse_conf(text: str) -> tuple[dict[str, str], list[dict[str, str]]]:
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    section: str | None = None
    cur: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if s == "[Interface]":
            section = "iface"
            continue
        if s == "[Peer]":
            if cur:
                peers.append(cur)
            cur = {}
            section = "peer"
            continue
        if s.startswith("#"):
            # I1–I5 (CPS) у Amnezia в СЕРВЕРНОМ конфиге закомментированы
            # (# I1 = ...): awg-quick их не применяет к интерфейсу, они хранятся
            # лишь чтобы раздать клиентам. Вычитываем их как обычные параметры,
            # иначе клиентские конфиги (и приложение по full-access) остались бы
            # без CPS и рукопожатие с 2.0-клиентом не сошлось бы.
            k, _, v = s.lstrip("#").strip().partition("=")
            k, v = k.strip(), v.strip()
            if section == "iface" and v and k in ("I1", "I2", "I3", "I4", "I5"):
                interface[k] = v
            continue
        if not s or "=" not in s:
            continue
        key, _, value = s.partition("=")
        key, value = key.strip(), value.strip()
        if section == "iface":
            interface[key] = value
        elif section == "peer":
            cur[key] = value
    if cur:
        peers.append(cur)
    return interface, peers


def _parse_dump(text: str) -> dict[str, dict]:
    """wg dump: первая строка — интерфейс, дальше пиры (8 полей)."""
    stats: dict[str, dict] = {}
    lines = [ln for ln in text.splitlines() if ln.strip()]
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pub, _psk, endpoint, _allowed, handshake, rx, tx, _keep = parts[:8]
        stats[pub] = {
            "endpoint": "" if endpoint == "(none)" else endpoint,
            "latest_handshake": int(handshake) if handshake.isdigit() else 0,
            "rx_bytes": int(rx) if rx.isdigit() else 0,
            "tx_bytes": int(tx) if tx.isdigit() else 0,
        }
    return stats


def _split_sections(text: str) -> list[list[str]]:
    sections: list[list[str]] = []
    cur: list[str] = []
    for line in text.splitlines():
        if line.strip() in ("[Interface]", "[Peer]"):
            if cur:
                sections.append(cur)
            cur = [line]
        else:
            cur.append(line)
    if cur:
        sections.append(cur)
    return sections


def remove_peer_from_conf(conf_text: str, public_key: str) -> str:
    kept = []
    for section in _split_sections(conf_text):
        head = section[0].strip()
        is_target_peer = head == "[Peer]" and any(
            ln.strip().startswith("PublicKey") and public_key in ln for ln in section
        )
        if not is_target_peer:
            kept.append(section)
    lines = [ln for section in kept for ln in section]
    return "\n".join(lines).rstrip("\n") + "\n"


def allocate_ip(address_cidr: str, used: set[str]) -> str:
    network = ipaddress.ip_network(address_cidr, strict=False)
    server_ip = ipaddress.ip_interface(address_cidr).ip
    taken = set(used) | {str(server_ip)}
    for host in network.hosts():
        if str(host) not in taken:
            return str(host)
    raise AwgError("В подсети не осталось свободных адресов")


def _docker_exec(container: str, inner: str, interactive: bool = False) -> str:
    flag = "-i " if interactive else ""
    return _DOCKER + f"$DOCKER exec {flag}{shlex.quote(container)} sh -c {shlex.quote(inner)}"


async def _run(conn: asyncssh.SSHClientConnection, cmd: str, *, stdin: str | None = None):
    result = await conn.run(cmd, input=stdin, check=False)
    if result.exit_status != 0:
        err = (result.stderr or "").strip() or (result.stdout or "").strip()
        raise AwgError(err or f"команда завершилась с кодом {result.exit_status}")
    return result.stdout or ""


_IFACE_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _safe_interface(name: str) -> str:
    if not _IFACE_RE.fullmatch(name):
        raise AwgError("Недопустимое имя интерфейса от ноды")
    return name


def _safe_ip(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise AwgError("Недопустимый IP-адрес клиента") from exc
    return ip


async def detect_container(conn: asyncssh.SSHClientConnection) -> str:
    """Основной awg-контейнер: предпочитаем «новый» (awg0), иначе legacy (wg0),
    иначе любой awg-контейнер по имени (свежий, ещё без конфига)."""
    conts = await detect_awg_containers(conn)
    if conts["new"]:
        return conts["new"]
    if conts["legacy"]:
        return conts["legacy"]
    cmd = _DOCKER + "$DOCKER ps --format '{{.Names}}' | grep -m1 amnezia-awg"
    out = (await _run(conn, cmd)).strip()
    if not out:
        raise AwgError("Контейнер amnezia-awg на сервере не найден")
    return out.splitlines()[0].strip()


async def detect_awg_containers(
    conn: asyncssh.SSHClientConnection,
) -> dict[str, str | None]:
    """Разделяет awg-контейнеры ноды на «новый» (AmneziaWG, awg0.conf) и «legacy»
    (старый AmneziaWG, только wg0.conf). Возвращает {"new": имя|None, "legacy": имя|None}.
    Различаем по РАНТАЙМ-конфигу внутри контейнера, а не по имени — имена
    (amnezia-awg2) у Amnezia и панели совпадают."""
    cmd = _DOCKER + (
        "for c in $($DOCKER ps --format '{{.Names}}' | grep -iE 'amnezia-awg|acontrol-awg'); do "
        "if $DOCKER exec \"$c\" test -f /opt/amnezia/awg/awg0.conf 2>/dev/null; then echo \"$c new\"; "
        "elif $DOCKER exec \"$c\" test -f /opt/amnezia/awg/wg0.conf 2>/dev/null; then echo \"$c legacy\"; fi; "
        "done"
    )
    out = await _run(conn, cmd)
    result: dict[str, str | None] = {"new": None, "legacy": None}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in result and result[parts[1]] is None:
            result[parts[1]] = parts[0]
    return result


async def read_state(
    conn: asyncssh.SSHClientConnection,
    endpoint_host: str,
    container: str | None = None,
) -> AwgState:
    if container is None:
        container = await detect_container(conn)
    iface_path = (
        await _run(conn, _docker_exec(container, f"ls {AWG_DIR}/*.conf 2>/dev/null | head -1"))
    ).strip()
    if not iface_path:
        raise AwgError("Конфиг awg0.conf не найден в контейнере")
    interface_name = iface_path.rsplit("/", 1)[-1].removesuffix(".conf")
    # имя интерфейса приходит от ноды и подставляется в команды — валидируем,
    # чтобы враждебная нода не могла внедрить shell-метасимволы
    interface_name = _safe_interface(interface_name)

    # printf с ведущим \n гарантирует перевод строки перед каждым маркером,
    # даже если предыдущий файл не заканчивается на \n (иначе разбор секций рвётся)
    bundle = await _run(
        conn,
        _docker_exec(
            container,
            f"printf '===CONF===\\n'; cat {AWG_DIR}/{interface_name}.conf; "
            f"printf '\\n===PUB===\\n'; cat {AWG_DIR}/wireguard_server_public_key.key; "
            f"printf '\\n===TABLE===\\n'; cat {AWG_DIR}/clientsTable; "
            f"printf '\\n===DUMP===\\n'; wg show {interface_name} dump",
        ),
    )
    conf_text = _section(bundle, "CONF")
    server_pub = _section(bundle, "PUB").strip()
    table_text = _section(bundle, "TABLE")
    dump_text = _section(bundle, "DUMP")

    interface, peers = parse_conf(conf_text)
    stats = _parse_dump(dump_text)
    names = _names_from_table(table_text)
    params = {k: interface[k] for k in AWG_PARAM_KEYS if k in interface}
    listen_port = int(interface.get("ListenPort", "0") or 0)

    clients = []
    for peer in peers:
        pub = peer.get("PublicKey", "")
        allowed = peer.get("AllowedIPs", "")
        st = stats.get(pub, {})
        clients.append(
            AwgClient(
                name=names.get(pub, "—"),
                public_key=pub,
                address=allowed,
                latest_handshake=(st.get("latest_handshake") or None),
                rx_bytes=st.get("rx_bytes", 0),
                tx_bytes=st.get("tx_bytes", 0),
                endpoint=st.get("endpoint", ""),
            )
        )

    return AwgState(
        container=container,
        interface=interface_name,
        listen_port=listen_port,
        server_public_key=server_pub,
        endpoint=f"{endpoint_host}:{listen_port}",
        address=interface.get("Address", ""),
        params=params,
        clients=clients,
    )


def _section(bundle: str, name: str) -> str:
    marker = f"==={name}==="
    start = bundle.find(marker)
    if start == -1:
        return ""
    start += len(marker)
    rest = bundle[start:]
    next_marker = rest.find("\n===")
    return (rest[:next_marker] if next_marker != -1 else rest).strip("\n")


def _names_from_table(table_text: str) -> dict[str, str]:
    try:
        data = json.loads(table_text)
    except (json.JSONDecodeError, ValueError):
        return {}
    names = {}
    for entry in data:
        cid = entry.get("clientId")
        name = entry.get("userData", {}).get("clientName")
        if cid and name:
            names[cid] = name
    return names


def build_client_config(
    *,
    client_private: str,
    address: str,
    server_public: str,
    preshared: str,
    endpoint: str,
    params: dict[str, str],
    dns: str,
) -> str:
    lines = [
        "[Interface]",
        f"Address = {address}/32",
        f"DNS = {dns}",
        f"PrivateKey = {client_private}",
    ]
    for key in AWG_PARAM_KEYS:
        v = params.get(key)
        if not v:  # пропускаем пустые (I2–I5 у 2.0 пустые)
            continue
        # H1–H4 у 2.0-сервера — диапазон «low-high»; клиент берёт КОНКРЕТНОЕ
        # значение внутри (сервер принимает любой заголовок из диапазона),
        # как это делает приложение Amnezia в клиентском конфиге.
        if key in ("H1", "H2", "H3", "H4") and "-" in v:
            lo, _, hi = v.partition("-")
            try:
                v = str(random.randint(int(lo), int(hi)))
            except ValueError:
                pass
        lines.append(f"{key} = {v}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_public}",
        f"PresharedKey = {preshared}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {endpoint}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


async def create_client(
    conn: asyncssh.SSHClientConnection,
    state: AwgState,
    name: str,
    dns: str,
    fixed_ip: str | None = None,
) -> tuple[AwgClient, str]:
    if fixed_ip:
        ip = _safe_ip(fixed_ip)
    else:
        used = {c.address.split("/")[0] for c in state.clients if c.address}
        ip = allocate_ip(state.address, used)
    client_priv, client_pub = generate_keypair()

    # PSK читаем на ноде, чтобы не гонять секрет через панель
    inner = (
        f'PSK=$(cat {AWG_DIR}/wireguard_psk.key); '
        f"wg set {state.interface} peer {shlex.quote(client_pub)} "
        f"preshared-key {AWG_DIR}/wireguard_psk.key allowed-ips {ip}/32 && "
        f"printf '\\n[Peer]\\nPublicKey = %s\\nPresharedKey = %s\\nAllowedIPs = %s/32\\n' "
        f'{shlex.quote(client_pub)} "$PSK" {ip} >> {AWG_DIR}/{state.interface}.conf && '
        f"printf '%s' \"$PSK\""
    )
    psk = (await _run(conn, _docker_exec(state.container, inner))).strip()

    await _append_to_table(conn, state, client_pub, name, ip)

    config = build_client_config(
        client_private=client_priv,
        address=ip,
        server_public=state.server_public_key,
        preshared=psk,
        endpoint=state.endpoint,
        params=state.params,
        dns=dns,
    )
    client = AwgClient(name=name, public_key=client_pub, address=f"{ip}/32")
    return client, config


async def _read_table(conn, container) -> list:
    text = await _run(conn, _docker_exec(container, f"cat {AWG_DIR}/clientsTable"))
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []


async def _write_table(conn, container, data: list) -> None:
    # завершающий \n обязателен: без него разбор секций при следующем чтении рвётся
    payload = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
    cmd = _docker_exec(container, f"cat > {AWG_DIR}/clientsTable", interactive=True)
    await _run(conn, cmd, stdin=payload)


async def _append_to_table(conn, state, pub, name, ip) -> None:
    data = await _read_table(conn, state.container)
    date = (await _run(conn, 'date "+%a %b %e %H:%M:%S %Y"')).strip()
    data.append(
        {
            "clientId": pub,
            "userData": {
                "allowedIps": f"{ip}/32",
                "clientName": name,
                "creationDate": date,
            },
        }
    )
    await _write_table(conn, state.container, data)


async def pause_client(
    conn: asyncssh.SSHClientConnection, state: "AwgState", public_key: str
) -> dict:
    """Ставит клиента на паузу: снимает пира (как revoke), но возвращает его IP —
    чтобы resume вернул того же пира с тем же адресом (клиентский конфиг не
    меняется). PSK общий (в wireguard_psk.key), перечитывается при resume."""
    target = next(
        (c for c in state.clients if c.public_key == public_key), None
    )
    if target is None:
        raise AwgError("Клиент не найден")
    ip = target.address.split("/")[0] if target.address else ""
    await revoke_client(conn, state.container, state.interface, public_key)
    return {"ip": ip}


async def resume_client(
    conn: asyncssh.SSHClientConnection, state: "AwgState",
    public_key: str, name: str, ip: str,
) -> None:
    """Возобновляет клиента: возвращает пира с прежним pubkey/IP/PSK."""
    ip = _safe_ip(ip)
    inner = (
        f'PSK=$(cat {AWG_DIR}/wireguard_psk.key); '
        f"wg set {state.interface} peer {shlex.quote(public_key)} "
        f"preshared-key {AWG_DIR}/wireguard_psk.key allowed-ips {ip}/32 && "
        f"printf '\\n[Peer]\\nPublicKey = %s\\nPresharedKey = %s\\nAllowedIPs = %s/32\\n' "
        f'{shlex.quote(public_key)} "$PSK" {ip} >> {AWG_DIR}/{state.interface}.conf'
    )
    await _run(conn, _docker_exec(state.container, inner))
    await _append_to_table(conn, state, public_key, name, ip)


async def revoke_client(
    conn: asyncssh.SSHClientConnection, container: str, interface: str, public_key: str
) -> None:
    interface = _safe_interface(interface)
    # снимаем пира вживую
    await _run(
        conn,
        _docker_exec(container, f"wg set {interface} peer {shlex.quote(public_key)} remove"),
    )
    # убираем из конфига
    conf = await _run(conn, _docker_exec(container, f"cat {AWG_DIR}/{interface}.conf"))
    new_conf = remove_peer_from_conf(conf, public_key)
    await _run(
        conn,
        _docker_exec(container, f"cat > {AWG_DIR}/{interface}.conf", interactive=True),
        stdin=new_conf,
    )
    # убираем из clientsTable
    data = await _read_table(conn, container)
    data = [e for e in data if e.get("clientId") != public_key]
    await _write_table(conn, container, data)
