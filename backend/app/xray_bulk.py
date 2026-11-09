"""Reconcile selected VLESS clients in server.json, clientsTable and live Xray."""

import json
import shlex
import uuid
from dataclasses import dataclass
from datetime import datetime

from app import xray


class ManagementUnavailable(xray.XrayError):
    pass


class PlanConflict(xray.XrayError):
    pass


def _management_address(server: dict) -> str | None:
    # VLESS can reach TCP loopback via Freedom. HandlerService has no auth.
    if ((server.get("api") or {}).get("listen") == xray.MANAGEMENT_API_LISTEN
            and not _management_socket_referenced(server)):
        return f"unix:{xray.MANAGEMENT_API_SOCKET}"
    return None


def _management_socket_referenced(server: dict) -> bool:
    # REALITY and VLESS fallbacks can dial a configured Unix destination.
    # Check the reserved basename too, to catch aliases such as /var/run.
    reserved = xray.MANAGEMENT_API_SOCKET.rpartition("/")[2]
    return reserved in json.dumps({key: value for key, value in server.items() if key != "api"})


def _remove_legacy_stats_listener(server: dict, api: dict) -> bool:
    """Move a dedicated legacy stats route without changing custom routing."""
    routing = server.get("routing") or {}
    rules = routing.get("rules") or []
    api_rules = [rule for rule in rules if rule.get("outboundTag") == api.get("tag")]
    if len(api_rules) != 1:
        return False
    rule, = api_rules
    tags = rule.get("inboundTag") or []
    if len(tags) != 1 or rule != {"type": "field", "inboundTag": tags, "outboundTag": api["tag"]}:
        return False
    tag, = tags
    if any(other is not rule and tag in (other.get("inboundTag") or []) for other in rules):
        return False
    inbounds = server.get("inbounds") or []
    matches = [inbound for inbound in inbounds if inbound.get("tag") == tag]
    if len(matches) != 1:
        return False
    inbound, = matches
    if (inbound.get("protocol") not in {"dokodemo-door", "tunnel"}
            or inbound.get("listen") not in {"localhost", "127.0.0.1", "::1", "[::1]"}
            or set(inbound) - {"listen", "port", "protocol", "settings", "tag"}):
        return False
    inbounds.remove(inbound)
    rules.remove(rule)
    if not rules:
        routing.pop("rules")
    if not routing:
        server.pop("routing")
    return True


def configure_management(server: dict) -> bool:
    """Stage management for a normal Xray update, never change a live node here."""
    api = server["api"]
    services = api.get("services") or []
    has_handler = xray._api_has_service(api, "handlerservice")
    changed = False
    listen = api.get("listen")
    referenced = _management_socket_referenced(server)
    if referenced or listen != xray.MANAGEMENT_API_LISTEN:
        if referenced:
            safe_to_move = False
        elif listen:
            host, _, _ = listen.rpartition(":")
            safe_to_move = host in {"localhost", "127.0.0.1", "[::1]"} and xray._stats_api_address(server) is not None
        else:
            safe_to_move = _remove_legacy_stats_listener(server, api)
        if not safe_to_move:
            if has_handler:
                api["services"] = [service for service in services if str(service).lower() != "handlerservice"]
                return True
            return False
        api["listen"] = xray.MANAGEMENT_API_LISTEN
        changed = True
    if not has_handler:
        api["services"] = [*services, "HandlerService"]
        changed = True
    inbounds = server.get("inbounds") or []
    tags = {inbound.get("tag") for inbound in inbounds}
    for inbound in inbounds:
        if inbound.get("protocol") != "vless" or inbound.get("tag"):
            continue
        tag = "acontrol-vless"
        suffix = 0
        while tag in tags:
            suffix += 1
            tag = f"acontrol-vless-{suffix}"
        inbound["tag"] = tag
        tags.add(tag)
        changed = True
    return changed


@dataclass
class NodeState:
    container: str
    server: dict
    table: list[dict]
    default: str
    address: str
    inbounds: list[dict]
    runtime: dict[str, dict[str, dict]]


def _clients(inbound, *, create=False):
    return xray._vless_clients(inbound["settings"], create=create)


async def _runtime(conn, container, address, inbounds):
    result = {}
    for inbound in inbounds:
        tag = inbound["tag"]
        command = f"xray api inbounduser -s {shlex.quote(address)} -tag {shlex.quote(tag)}"
        try:
            raw = await xray._run(conn, xray._docker_exec(container, command))
            document = json.loads(raw)
            rows = document.get("users", [])
            if not isinstance(rows, list) or any(not row.get("account", {}).get("id") for row in rows):
                raise ValueError
            by_id = {row["account"]["id"]: row for row in rows}
            if len(by_id) != len(rows):
                raise ValueError
            result[tag] = by_id
        except (xray.XrayError, AttributeError, TypeError, ValueError):
            raise ManagementUnavailable(
                "Локальный API управления Xray недоступен. Проверьте или обновите Xray."
            ) from None
    return result


async def read(conn, container: str) -> NodeState:
    server = await xray._read_server(conn, container)
    inbounds = server.get("inbounds") or []
    if not inbounds or not xray._uses_flow(inbounds[0]) \
            or (inbounds[0].get("streamSettings") or {}).get("security") != "reality" \
            or inbounds[0].get("protocol") != "vless":
        raise ManagementUnavailable("Основной вход не является VLESS REALITY Vision")
    vless = [inbound for inbound in inbounds if inbound.get("protocol") == "vless"]
    tags = [inbound.get("tag") for inbound in inbounds]
    if any(not inbound.get("tag") or tags.count(inbound["tag"]) != 1 for inbound in vless):
        raise ManagementUnavailable("У входов VLESS отсутствуют уникальные теги. Обновите Xray.")
    address = _management_address(server)
    if not address or not xray._api_has_service(server.get("api") or {}, "handlerservice"):
        raise ManagementUnavailable("В Xray не включен локальный API управления. Обновите Xray.")
    for inbound in vless:
        if any(not isinstance(row, dict) or not row.get("id") for row in _clients(inbound)):
            raise xray.XrayError("Список клиентов Xray содержит некорректные записи")
    # Legacy read_table tolerates corrupt JSON. Bulk writes must preserve all names.
    raw = await xray._run(conn, xray._docker_exec(
        container, f"if [ -e {xray.CLIENTS_TABLE} ]; then cat {xray.CLIENTS_TABLE}; fi",
    ))
    try:
        table = json.loads(raw) if raw.strip() else []
        if not isinstance(table, list) or any(not isinstance(row, dict) for row in table):
            raise ValueError
    except ValueError:
        raise xray.XrayError("Не удалось прочитать clientsTable. Изменения отменены.") from None
    default_path = f"{xray.XRAY_DIR}/xray_uuid.key"
    default = (await xray._run(conn, xray._docker_exec(
        container, f"if [ -e {default_path} ]; then cat {default_path}; fi",
    ))).strip()
    runtime = await _runtime(conn, container, address, vless)
    return NodeState(container, server, table, default, address, vless, runtime)


def plan(node: NodeState, paused: dict, names: list[str]) -> list[dict]:
    known = {str(item.get("userData", {}).get("clientName", "")).casefold()
             for item in node.table if isinstance(item.get("userData"), dict)}
    known.update(row["name"].casefold() for row in paused.values())
    if known.intersection(name.casefold() for name in names):
        raise PlanConflict("Имена уже заняты на этом сервере. Укажите другой префикс.")
    occupied = set(paused) | {node.default}
    for inbound in node.inbounds:
        occupied.update(row["id"] for row in _clients(inbound))
        occupied.update(node.runtime[inbound["tag"]])
    items = []
    for name in names:
        cid = str(uuid.uuid4())
        if cid in occupied:
            raise xray.XrayError("Не удалось сгенерировать уникальный UUID")
        occupied.add(cid)
        items.append({"client_id": cid, "name": name})
    return items


def _same_user(existing, email, flow):
    return existing.get("email") == email and existing["account"].get("flow", "") == flow


async def apply(conn, node: NodeState, items: list[dict]) -> None:
    if not items:
        return
    added = []
    changed = False
    expected = {}
    for inbound in node.inbounds:
        tag = inbound["tag"]
        clients = _clients(inbound, create=True)
        stored = {row["id"]: row for row in clients}
        runtime = node.runtime[tag]
        additions = []
        flow = xray.FLOW if xray._uses_flow(inbound) else ""
        expected[tag] = {}
        for item in items:
            cid = item["client_id"]
            entry = {"id": cid, "email": cid}
            if flow:
                entry["flow"] = flow
            expected[tag][cid] = flow
            if cid in stored and any(stored[cid].get(key) != value for key, value in entry.items()):
                raise xray.XrayError("Параметры клиента Xray изменились после подготовки")
            if cid in runtime and not _same_user(runtime[cid], cid, flow):
                raise xray.XrayError("Параметры действующего клиента Xray изменились после подготовки")
            if any(key != cid and row.get("email", "").casefold() == cid for key, row in runtime.items()):
                raise xray.XrayError("Идентификатор занят другим клиентом Xray")
            if cid not in stored:
                clients.append(entry)
                changed = True
            if cid not in runtime:
                additions.append(entry)
        if additions:
            added.append({
                "tag": tag, "port": 1, "protocol": "vless",
                "settings": {"decryption": "none", "clients": additions},
            })
    if changed:
        await xray._write_server(conn, node.container, node.server)
    table = node.table.copy()
    table_ids = {row.get("clientId") for row in table}
    date = datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Y")
    for item in items:
        if item["client_id"] not in table_ids:
            table.append({"clientId": item["client_id"],
                          "userData": {"clientName": item["name"], "creationDate": date}})
    if table != node.table:
        await xray._write_table(conn, node.container, table)
    if added:
        command = f"xray api adu -s {shlex.quote(node.address)} -timeout 60 stdin:"
        await conn.run(
            xray._docker_exec_i(node.container, command),
            input=json.dumps({"inbounds": added}), check=False,
        )
    current = await _runtime(conn, node.container, node.address, node.inbounds)
    for tag, users in expected.items():
        if any(cid not in current[tag] or not _same_user(current[tag][cid], cid, flow)
               for cid, flow in users.items()):
            raise xray.XrayError("Не удалось подтвердить выдачу всех клиентов в работающем Xray")


def canonical_uuid(value: str) -> str | None:
    try:
        return str(uuid.UUID(value))
    except ValueError:
        # Xray accepts custom identifiers of at most 30 bytes and deterministically
        # converts them to a UUID. Bulk revoke only acts on explicit UUIDs.
        return None


async def revoke(conn, node: NodeState, ids: list[str]) -> dict[str, str]:
    default = canonical_uuid(node.default)
    errors = {}
    candidates = {}
    for cid in ids:
        canon = canonical_uuid(cid)
        if canon is None:
            errors[cid] = "Групповой отзыв Xray требует UUID клиента"
        elif canon == default:
            errors[cid] = "Служебный UUID Xray нельзя отозвать группой"
        else:
            candidates[cid] = canon
    # A configured user without email may not appear in GetInboundUsers.
    for inbound in node.inbounds:
        clients = {canonical_uuid(row["id"]): row for row in _clients(inbound)}
        runtime = node.runtime[inbound["tag"]]
        for cid, canon in candidates.items():
            if (canon in clients and not clients[canon].get("email")) or (
                canon in runtime and not runtime[canon].get("email")
            ):
                errors[cid] = "У клиента Xray отсутствует email для локального API"
                continue
            if canon in runtime:
                email = runtime[canon]["email"].casefold()
                if any(key != canon and str(row.get("email") or "").casefold() == email
                       for source in (clients, runtime) for key, row in source.items()):
                    errors[cid] = "У клиента Xray неоднозначный email для локального API"
    selected = {canon for cid, canon in candidates.items() if cid not in errors}
    changed = False
    for inbound in node.inbounds:
        clients = _clients(inbound)
        filtered = [row for row in clients if canonical_uuid(row["id"]) not in selected]
        if filtered != clients:
            clients[:] = filtered
            changed = True
    if changed:
        await xray._write_server(conn, node.container, node.server)
    table = [row for row in node.table
             if not isinstance(row.get("clientId"), str) or canonical_uuid(row["clientId"]) not in selected]
    if table != node.table:
        await xray._write_table(conn, node.container, table)
    for tag, users in node.runtime.items():
        emails = [users[cid]["email"] for cid in selected if cid in users]
        if emails:
            args = " ".join(shlex.quote(email) for email in emails)
            command = (f"xray api rmu -s {shlex.quote(node.address)} -timeout 60 "
                       f"-tag {shlex.quote(tag)} -- {args}")
            await conn.run(xray._docker_exec(node.container, command), check=False)
    current = await _runtime(conn, node.container, node.address, node.inbounds)
    for cid, canon in candidates.items():
        if canon in selected and any(canon in users for users in current.values()):
            errors[cid] = "Не удалось подтвердить отзыв клиента в работающем Xray"
    return errors
