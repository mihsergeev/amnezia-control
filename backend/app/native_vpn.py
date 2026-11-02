"""Native WireGuard/OpenVPN lifecycle, isolated from Amnezia installations."""

import json
import re
import shlex

from app import awg, openvpn
from app.native_deploy import LABEL, SPECS

PROTOCOLS = tuple(SPECS)


class NativeError(Exception):
    pass


class NativeNotDeployed(NativeError):
    pass


def exec_command(container: str, command: str, interactive=False) -> str:
    return awg._DOCKER + f"$DOCKER exec {'-i ' if interactive else ''}{shlex.quote(container)} sh -c {shlex.quote(command)}"


async def run(conn, command: str, *, payload: str | None = None) -> str:
    result = await conn.run(command, input=payload, check=False, timeout=60)
    if result.exit_status != 0:
        # PKI/state commands can contain private material in stdout. Never put
        # their output or command arguments in API errors, audits, or logs.
        raise NativeError("Не удалось выполнить операцию нативного VPN")
    return result.stdout or ""


async def detect(conn, protocol: str, *, running=True) -> str:
    spec = SPECS[protocol]
    command = awg._DOCKER + f"$DOCKER container inspect {shlex.quote(spec.container)} 2>/dev/null"
    inspection = await conn.run(command, check=False, timeout=30)
    if inspection.exit_status != 0:
        listing = await conn.run(awg._DOCKER + "$DOCKER ps -a --format '{{.Names}}'",
                                 check=False, timeout=30)
        if listing.exit_status != 0 or spec.container in (listing.stdout or "").splitlines():
            raise NativeError("Не удалось проверить контейнер нативного протокола")
        raise NativeNotDeployed("Нативный протокол не установлен на сервере")
    try:
        items = json.loads(inspection.stdout or "")
        item = items[0] if isinstance(items, list) and len(items) == 1 else {}
    except (ValueError, IndexError):
        item = {}
    if not item:
        raise NativeError("Не удалось прочитать сведения о контейнере")
    if (item.get("Config", {}).get("Labels") or {}).get(LABEL) != protocol:
        raise NativeError("Контейнер не принадлежит выбранному нативному протоколу")
    if running and item.get("State", {}).get("Running") is not True:
        raise NativeError("Контейнер нативного протокола не запущен")
    return spec.container


async def metadata(conn, protocol: str) -> dict:
    spec = SPECS[protocol]
    container = await detect(conn, protocol)
    raw = await run(conn, exec_command(container, f"cat {spec.data_path}/native.json"))
    return _metadata(raw, protocol)


def _metadata(raw: str, protocol: str) -> dict:
    try:
        value = json.loads(raw)
        port = int(value["port"])
        if value["protocol"] != protocol or not 1 <= port <= 65535 or value["transport"] not in {"udp", "tcp"}:
            raise ValueError()
        if protocol == "wireguard" and value["transport"] != "udp":
            raise ValueError()
        return {"port": port, "transport": value["transport"]}
    except (ValueError, KeyError, TypeError):
        raise NativeError("Повреждены параметры нативного протокола") from None


async def installed_metadata(conn, protocol: str) -> dict | None:
    """Read an owned listener even after an interrupted installation or stop."""
    # Container ownership/errors must still be validated before host access.
    try:
        await detect(conn, protocol, running=False)
    except NativeNotDeployed:
        pass
    spec = SPECS[protocol]
    source = """import json, pathlib, sys
d = pathlib.Path(sys.argv[1]); protocol = sys.argv[2]
paths = [d.parent, d, d / '.native-protocol', d / 'data', d / 'data/native.json']
if any(p.is_symlink() for p in paths): raise SystemExit(2)
if not d.exists(): print('null'); raise SystemExit(0)
if (d / '.native-protocol').read_text().strip() != protocol: raise SystemExit(2)
p = d / 'data/native.json'
if not p.exists():
    if (d / 'data').exists() and any((d / 'data').iterdir()): raise SystemExit(2)
    print('null'); raise SystemExit(0)
if not p.is_file() or p.stat().st_size > 4096: raise SystemExit(2)
print(p.read_text())
"""
    raw = await run(conn, "sudo -n python3 - " + shlex.quote(spec.directory) + " " + shlex.quote(protocol), payload=source)
    return None if raw.strip() == "null" else _metadata(raw, protocol)


async def deployment_prerequisites(conn):
    result = await conn.run("command -v docker >/dev/null && command -v python3 >/dev/null && "
                            "command -v flock >/dev/null && sudo -n docker info >/dev/null 2>&1",
                            check=False, timeout=30)
    if result.exit_status != 0:
        raise NativeNotDeployed("Для установки нативного VPN нужны работающий Docker, Python 3, flock и служебный доступ sudo без пароля")


def client_id(protocol: str, value: str) -> str:
    if protocol == "wireguard":
        try:
            return awg._safe_key(value, "client public key")
        except awg.AwgError:
            raise ValueError("Некорректный открытый ключ WireGuard") from None
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise ValueError("Некорректный идентификатор OpenVPN")
    return value


async def table(conn, protocol: str) -> list:
    spec = SPECS[protocol]
    await detect(conn, protocol)
    raw = await run(conn, exec_command(spec.container, f"cat {spec.data_path}/clientsTable"))
    try:
        values = json.loads(raw)
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            raise ValueError()
        return values
    except ValueError:
        raise NativeError("Не удалось прочитать список клиентов нативного VPN") from None


async def write_file(conn, protocol: str, path: str, payload: str, mode="600"):
    spec = SPECS[protocol]
    # All paths are fixed application paths or an already validated client CN.
    temporary = path + ".native-tmp"
    command = f"umask 077; cat > {shlex.quote(temporary)} && chmod {mode} {shlex.quote(temporary)} && mv -f {shlex.quote(temporary)} {shlex.quote(path)}"
    await run(conn, exec_command(spec.container, command, True), payload=payload)


async def write_table(conn, protocol: str, values: list):
    await write_file(conn, protocol, f"{SPECS[protocol].data_path}/clientsTable",
                     json.dumps(values, ensure_ascii=False, indent=2) + "\n")


async def wg_state(conn, host: str):
    container = await detect(conn, "wireguard")
    try:
        value = await awg.read_state(conn, host, container=container)
    except awg.AwgError:
        raise NativeError("Не удалось прочитать состояние WireGuard") from None
    if value.params or value.interface != "wg0":
        raise NativeError("Конфигурация не является стандартным WireGuard")
    return value


async def verify_wireguard_runtime(conn, host: str):
    value = await wg_state(conn, host)
    raw = await run(conn, exec_command(value.container,
        "wg show wg0 public-key; printf '\\n===PEERS===\\n'; wg show wg0 peers"))
    public, marker, peers = raw.partition("\n===PEERS===\n")
    if not marker or public.strip() != value.server_public_key or set(peers.split()) != {
        client.public_key for client in value.clients
    }:
        raise NativeError("Рантайм WireGuard не совпадает с восстановленным конфигом")


async def version(conn, protocol: str) -> str:
    container = await detect(conn, protocol)
    command = "wg --version" if protocol == "wireguard" else "openvpn --version"
    result = await run(conn, exec_command(container, command + " | head -1"))
    return result.strip()[:160]


async def state(conn, protocol: str, host: str) -> dict:
    spec = SPECS[protocol]
    info = await metadata(conn, protocol)
    if protocol == "wireguard":
        value = await wg_state(conn, host)
        return {"container": spec.container, "interface": value.interface,
                "listen_port": value.listen_port, "server_public_key": value.server_public_key,
                "endpoint": value.endpoint, "address": value.address,
                "clients": [client.__dict__ for client in value.clients], **info}
    values = await table(conn, protocol)
    try:
        status = await openvpn.read_status_map(conn, spec.container)
    except Exception:
        status = {}
    clients = []
    for client in openvpn.parse_clients(json.dumps(values)):
        current = status.get(client.client_id, {})
        clients.append(client.__dict__ | {"connected": bool(current),
            "rx_bytes": current.get("rx", 0), "tx_bytes": current.get("tx", 0),
            "since": current.get("since", "")})
    return {"container": spec.container, "clients": clients, **info}


def ovpn_profile(host: str, port: int, transport: str, dns: str, bits: dict) -> str:
    # All credentials are inline. No Cloak/Shadowsocks/localhost listener is
    # required by this ordinary OpenVPN profile.
    if any(character in host for character in "\r\n\t "):
        raise NativeError("Недопустимый адрес сервера OpenVPN")
    lines = ["client", "dev tun", f"proto {'udp' if transport == 'udp' else 'tcp-client'}",
             f"remote {host} {port}", "resolv-retry infinite", "nobind", "persist-key", "persist-tun",
             "remote-cert-tls server", "tls-version-min 1.2", "auth SHA256",
             "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "key-direction 1",
             "ifconfig-ipv6 fd84:6e61:7469::2/64 fd84:6e61:7469::1", "redirect-gateway ipv6", "block-ipv6",
             "auth-nocache", "verb 3", "setenv opt block-outside-dns"]
    if dns.strip():
        lines.append('pull-filter ignore "dhcp-option DNS"')
    lines += [f"dhcp-option DNS {value.strip()}" for value in dns.split(",") if value.strip()]
    for name in ("ca", "cert", "key", "tls-auth"):
        lines += [f"<{name}>", bits[name].strip(), f"</{name}>"]
    return "\n".join(lines) + "\n"


async def issue(conn, protocol: str, name: str, host: str, dns: str, *, reserved=None,
                fixed_ip: str | None = None) -> tuple[dict, str]:
    if protocol == "wireguard":
        value = await wg_state(conn, host)
        try:
            client, config = await awg.create_client(conn, value, name, dns, reserved=reserved, fixed_ip=fixed_ip)
        except awg.AwgError:
            raise NativeError("Не удалось выдать профиль WireGuard") from None
        config = config.replace("[Interface]\n", "[Interface]\nMTU = 1380\n", 1)
        return client.__dict__, config
    spec = SPECS[protocol]
    listener = await metadata(conn, protocol)
    values = await table(conn, protocol)
    cid = openvpn._new_client_id()
    key, csr = openvpn._gen_key_csr(cid)
    try:
        certificate = await openvpn._sign_csr(conn, spec.container, cid, csr)
    except openvpn.OpenVpnError:
        raise NativeError("Не удалось подписать сертификат OpenVPN") from None
    raw = await run(conn, exec_command(spec.container,
        f"printf '===CA===\\n'; cat {spec.data_path}/ca.crt; printf '\\n===TA===\\n'; cat {spec.data_path}/ta.key"))
    bits = {"ca": openvpn._section(raw, "CA"), "cert": certificate, "key": key,
            "tls-auth": openvpn._section(raw, "TA")}
    if not bits["ca"] or not bits["tls-auth"]:
        raise NativeError("Неполная конфигурация сервера OpenVPN")
    config = ovpn_profile(host, listener["port"], listener["transport"], dns, bits)
    date = (await run(conn, 'date -u "+%Y-%m-%dT%H:%M:%SZ"')).strip()
    values.append({"clientId": cid, "userData": {"clientName": name, "creationDate": date}})
    await write_table(conn, protocol, values)
    return {"client_id": cid, "name": name, "creation_date": date}, config


async def disconnect(conn, cid: str):
    cid = client_id("openvpn-native", cid)
    spec = SPECS["openvpn-native"]
    # OpenVPN may consume 'quit' before flushing the preceding command reply.
    # A single command plus socat's bounded EOF grace also waits for kill ACK.
    command = f"printf 'kill %s\\n' {shlex.quote(cid)} | socat -t 3 - UNIX-CONNECT:/run/openvpn/management.sock"
    result = await run(conn, exec_command(spec.container, command))
    if "SUCCESS:" not in result and "ERROR: common name" not in result:
        raise NativeError("Не удалось отключить сессию OpenVPN")


async def revoke(conn, protocol: str, cid: str):
    cid = client_id(protocol, cid)
    await detect(conn, protocol)
    if protocol == "wireguard":
        try:
            await awg.revoke_client(conn, SPECS[protocol].container, "wg0", cid)
        except awg.AwgError:
            raise NativeError("Не удалось отозвать WireGuard") from None
        return
    spec = SPECS[protocol]
    values = await table(conn, protocol)
    exists = any(item.get("clientId") == cid for item in values)
    if not exists:
        return
    pki = f"{spec.data_path}/pki"
    status = f"awk -F '\\t' '$NF == \"/CN={cid}\" {{print $1}}' {pki}/index.txt | tail -1"
    command = (f"cd /usr/share/easy-rsa && STATUS=$({status}) && "
               f"{{ [ \"$STATUS\" = R ] || EASYRSA_PKI={pki} EASYRSA_BATCH=1 ./easyrsa revoke {shlex.quote(cid)} >/dev/null 2>&1; }} && "
               f"EASYRSA_PKI={pki} EASYRSA_BATCH=1 ./easyrsa gen-crl >/dev/null 2>&1 && "
               f"cp {pki}/crl.pem {spec.data_path}/crl.pem && chmod 644 {spec.data_path}/crl.pem")
    await run(conn, exec_command(spec.container, command))
    await disconnect(conn, cid)
    await write_table(conn, protocol, [item for item in values if item.get("clientId") != cid])


async def pause(conn, protocol: str, cid: str, host: str) -> dict:
    cid = client_id(protocol, cid)
    if protocol == "wireguard":
        try:
            return await awg.pause_client(conn, await wg_state(conn, host), cid)
        except awg.AwgError:
            raise NativeError("Не удалось приостановить WireGuard") from None
    await detect(conn, protocol)
    spec = SPECS[protocol]
    if not any(item.get("clientId") == cid for item in await table(conn, protocol)):
        raise LookupError("Клиент не найден")
    await write_file(conn, protocol, f"{spec.data_path}/ccd/{cid}", "disable\n", "644")
    await disconnect(conn, cid)
    return {}


async def resume(conn, protocol: str, cid: str, name: str, data: dict, host: str):
    cid = client_id(protocol, cid)
    if protocol == "wireguard":
        try:
            await awg.resume_client(conn, await wg_state(conn, host), cid, name, data["ip"])
        except (awg.AwgError, KeyError):
            raise NativeError("Не удалось возобновить WireGuard") from None
    else:
        await detect(conn, protocol)
        await run(conn, exec_command(SPECS[protocol].container,
            f"rm -f {SPECS[protocol].data_path}/ccd/{shlex.quote(cid)}"))


async def rename(conn, protocol: str, cid: str, name: str) -> bool:
    values = await table(conn, protocol)
    match = next((value for value in values if value.get("clientId") == cid), None)
    if match is None:
        return False
    match.setdefault("userData", {})["clientName"] = name
    await write_table(conn, protocol, values)
    return True
