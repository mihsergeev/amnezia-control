"""Live batch operations for AmneziaWG and WireGuard."""

import ipaddress
import shlex
from dataclasses import dataclass
from datetime import datetime

from app import awg


class PlanConflict(awg.AwgError):
    pass


@dataclass
class NodeState:
    interface: awg.AwgState
    config: str
    peers: dict[str, dict]
    runtime: dict[str, dict]
    table: list[dict]


async def runtime_peers(conn, state: awg.AwgState) -> dict[str, dict]:
    interface = awg._safe_interface(state.interface)
    dump = await awg._run(conn, awg._docker_exec(state.container, f"wg show {interface} dump"))
    lines = dump.splitlines()
    if not lines or lines[0].split("\t")[1:2] != [state.server_public_key]:
        raise awg.AwgError("Публичный ключ интерфейса VPN отличается от сохраненного")
    peers = {}
    for row in lines[1:]:
        fields = row.split("\t")
        if len(fields) < 8 or fields[0] in peers:
            raise awg.AwgError("Не удалось прочитать действующие пиры VPN")
        peers[fields[0]] = {"PresharedKey": fields[1], "AllowedIPs": fields[3]}
    return peers


async def read(conn, state: awg.AwgState) -> NodeState:
    config = await awg.read_awg_conf(conn, state.container, state.interface)
    _, values = awg.parse_conf(config)
    peers = {row.get("PublicKey"): row for row in values}
    if None in peers or len(peers) != len(values):
        raise awg.AwgError("Сохраненный список пиров VPN содержит некорректные записи")
    return NodeState(
        interface=state, config=config, peers=peers,
        runtime=await runtime_peers(conn, state),
        table=await awg._read_table(conn, state.container),
    )


def _occupied(node: NodeState, paused: dict, *, exclude=frozenset()):
    values = [entry.get("AllowedIPs", "") for peers in (node.peers, node.runtime)
              for key, entry in peers.items() if key not in exclude]
    values.extend(item["data"].get("ip", "") for cid, item in paused.items() if cid not in exclude)
    for value in values:
        for ip in value.replace(",", " ").split():
            if ip != "(none)":
                yield ipaddress.ip_network(ip, strict=False)


def _available(address, occupied, count):
    interface = ipaddress.IPv4Interface(address)
    network = interface.network
    cursor = int(network.network_address) + (network.prefixlen < 31)
    end = int(network.broadcast_address) - (network.prefixlen < 31)
    blocked = sorted((int(item.network_address), int(item.broadcast_address))
                     for item in occupied if item.version == 4)
    blocked.append((int(interface.ip), int(interface.ip)))
    blocked.sort()
    result = []
    for first, last in blocked + [(end + 1, end + 1)]:
        while cursor < first and cursor <= end:
            result.append(str(ipaddress.IPv4Address(cursor)))
            if len(result) == count:
                return result
            cursor += 1
        cursor = max(cursor, last + 1)
    raise PlanConflict("В подсети не хватило свободных адресов для всей группы")


async def plan(conn, node: NodeState, paused: dict, names: list[str],
               dns: str, *, native: bool) -> list[dict]:
    state = node.interface
    known = {str(item.get("userData", {}).get("clientName", "")).casefold()
             for item in node.table if isinstance(item.get("userData"), dict)}
    known.update(row["name"].casefold() for row in paused.values())
    if known.intersection(name.casefold() for name in names):
        raise PlanConflict("Имена уже заняты на этом сервере. Укажите другой префикс.")
    addresses = _available(state.address, _occupied(node, paused), len(names))
    psk = await _psk(conn, state)
    endpoint = state.endpoint
    host, _, port = endpoint.rpartition(":")
    if ":" in host and not host.startswith("["):
        endpoint = f"[{host}]:{port}"
    result = []
    keys = set(node.peers) | set(node.runtime) | set(paused)
    for name, ip in zip(names, addresses, strict=True):
        private, key = awg.generate_keypair()
        if key in keys:
            raise awg.AwgError("Не удалось сгенерировать уникальный ключ VPN")
        keys.add(key)
        config = awg.build_client_config(
            client_private=private, address=ip, server_public=state.server_public_key,
            preshared=psk, endpoint=endpoint, params=state.params, dns=dns,
        )
        if native:
            config = config.replace("[Interface]\n", "[Interface]\nMTU = 1380\n", 1)
        result.append({"client_id": key, "name": name, "ip": ip, "config": config})
    return result


async def _psk(conn, state):
    raw = await awg._run(conn, awg._docker_exec(state.container, f"cat {awg.AWG_DIR}/wireguard_psk.key"))
    return awg._safe_key(raw.strip(), "PSK")


def _expected(item, state, psk):
    interface, peers = awg.parse_conf(item["config"])
    cid = awg._safe_key(item["client_id"], "публичный ключ пира")
    ip = awg._safe_ip(item["ip"])
    if len(peers) != 1 or peers[0]["PublicKey"] != state.server_public_key \
            or peers[0]["PresharedKey"] != psk or interface["Address"] != f"{ip}/32" \
            or any(interface.get(key) != value for key, value in state.params.items()):
        raise PlanConflict("Параметры VPN изменились после подготовки группы")
    return cid, {"PublicKey": cid, "AllowedIPs": f"{ip}/32", "PresharedKey": psk}


def _matches(peer, expected):
    return all(peer.get(field) == expected[field] for field in ("AllowedIPs", "PresharedKey"))


async def apply(conn, node: NodeState, paused: dict, items: list[dict]) -> None:
    if not items:
        return
    state = node.interface
    psk = await _psk(conn, state)
    expected = dict(_expected(item, state, psk) for item in items)
    occupied = list(_occupied(node, paused, exclude=expected))
    for cid, peer in expected.items():
        ip = ipaddress.IPv4Interface(peer["AllowedIPs"]).ip
        if cid in paused or any(ip in network for network in occupied) or any(
            cid in source and not _matches(source[cid], peer) for source in (node.peers, node.runtime)
        ):
            raise PlanConflict("Параметры пиров изменились после подготовки группы")
    conf = node.config
    for cid, peer in expected.items():
        if cid not in node.peers:
            conf = conf.rstrip("\n") + "\n\n[Peer]\n" + "".join(
                f"{key} = {value}\n" for key, value in peer.items()
            )
    table = node.table.copy()
    table_ids = {row.get("clientId") for row in table}
    date = datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Y")
    for item in items:
        if item["client_id"] not in table_ids:
            table.append({
                "clientId": item["client_id"],
                "userData": {"clientName": item["name"], "creationDate": date,
                             "allowedIps": f"{item['ip']}/32"},
            })
    path = f"{awg.AWG_DIR}/{state.interface}.conf"
    if conf != node.config:
        await awg._write_file(conn, state.container, path, conf)
    if table != node.table:
        await awg._write_table(conn, state.container, table)

    # One invocation, restricted to new peers. Existing sessions stay in place.
    args = " ".join(
        f"peer {shlex.quote(cid)} preshared-key {awg.AWG_DIR}/wireguard_psk.key allowed-ips {peer['AllowedIPs']}"
        for cid, peer in expected.items() if cid not in node.runtime
    )
    if args:
        await awg._run(conn, awg._docker_exec(state.container, f"wg set {state.interface} {args}"))
    current = await runtime_peers(conn, state)
    if any(cid not in current or not _matches(current[cid], peer) for cid, peer in expected.items()):
        raise awg.AwgError("Не удалось подтвердить добавление всех пиров в работающий интерфейс")


async def revoke(conn, node: NodeState, ids: list[str]) -> None:
    state = node.interface
    selected = set(ids)
    conf = node.config
    for cid in selected & node.peers.keys():
        conf = awg.remove_peer_from_conf(conf, cid)
    if conf != node.config:
        await awg._write_file(conn, state.container, f"{awg.AWG_DIR}/{state.interface}.conf", conf)
    table = [row for row in node.table if row.get("clientId") not in selected]
    if table != node.table:
        await awg._write_table(conn, state.container, table)
    peers = selected & node.runtime.keys()
    if peers:
        args = " ".join(f"peer {shlex.quote(cid)} remove" for cid in sorted(peers))
        await awg._run(conn, awg._docker_exec(state.container, f"wg set {state.interface} {args}"))
    if selected.intersection(await runtime_peers(conn, state)):
        raise awg.AwgError("Не удалось подтвердить отзыв всех пиров")
