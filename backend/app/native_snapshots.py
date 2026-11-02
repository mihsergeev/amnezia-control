"""Keep native node snapshots paired with their private panel-side metadata.

Client private keys stay in the panel database. Restoring a node-only archive
would otherwise resurrect a revoked peer or silently lose a client's export.
The caller holds the protocol operation lock throughout node and DB changes.
"""

import json
import re
from datetime import datetime

from sqlalchemy import delete, select

from app.models import AppSetting, AwgNote, ClientLimit, ClientName, NativeVpnConfig, PausedClient, Server

PROTOCOLS = ("wireguard", "openvpn-native")
_SNAP_ID = re.compile(r"\d{8}-\d{6}\Z")
_TABLES = {
    "profiles": (NativeVpnConfig, ("client_id", "name", "config", "created_at")),
    "notes": (AwgNote, ("public_key", "note", "updated_at")),
    "limits": (ClientLimit, ("client_id", "name", "expires_at", "created_at")),
    "paused": (PausedClient, ("client_id", "name", "data", "paused_at")),
    "names": (ClientName, ("client_id", "name", "updated_at")),
}
_DATES = {"created_at", "updated_at", "expires_at", "paused_at"}


def _prefix(server_id: int, protocol: str) -> str:
    if protocol not in PROTOCOLS or not isinstance(server_id, int) or server_id <= 0:
        raise ValueError("Некорректный протокол или сервер снимка")
    return f"native_snapshot:{server_id}:{protocol}:"


def _key(server_id: int, protocol: str, snapshot_id: str) -> str:
    if not isinstance(snapshot_id, str) or not _SNAP_ID.fullmatch(snapshot_id):
        raise ValueError("Некорректный идентификатор снимка")
    key = _prefix(server_id, protocol) + snapshot_id
    if len(key) > 64:
        raise ValueError("Слишком длинный идентификатор снимка")
    return key


def _identity(server) -> dict:
    return {"id": server.id, "host": server.host, "ssh_port": server.ssh_port, "ssh_user": server.ssh_user}


def _listener(value: dict) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Повреждены параметры снимка")
    port, transport = value.get("port"), value.get("transport")
    if type(port) is not int or not 1 <= port <= 65535 or transport not in ("udp", "tcp"):
        raise ValueError("Повреждены параметры снимка")
    return {"port": port, "transport": transport}


async def capture(session, server_id: int, protocol: str) -> dict:
    _prefix(server_id, protocol)
    result = {}
    for label, (model, fields) in _TABLES.items():
        rows = await session.scalars(select(model).where(model.server_id == server_id, model.protocol == protocol))
        result[label] = [{field: value.isoformat() if isinstance(value := getattr(row, field), datetime) else value
                          for field in fields} for row in rows]
    return result


async def save(session, server, protocol: str, snapshot_id: str, listener: dict) -> None:
    key = _key(server.id, protocol, snapshot_id)
    value = {"schema": 1, "server": _identity(server), "protocol": protocol,
             "listener": _listener(listener), "rows": await capture(session, server.id, protocol)}
    row = await session.get(AppSetting, key)
    if row is not None:
        # A timestamp collision must not silently relabel an older node archive.
        raise ValueError("Метаданные снимка уже сохранены")
    session.add(AppSetting(key=key, value=json.dumps(value, ensure_ascii=False)))
    await session.commit()


def _validated_rows(manifest: dict) -> dict:
    raw = manifest.get("rows") if isinstance(manifest, dict) else None
    if not isinstance(raw, dict) or set(raw) != set(_TABLES):
        raise ValueError("Неполные метаданные снимка")
    parsed = {}
    for label, (_, fields) in _TABLES.items():
        values = raw[label]
        if not isinstance(values, list):
            raise ValueError("Повреждены метаданные снимка")
        parsed[label] = []
        seen = set()
        for value in values:
            if not isinstance(value, dict) or set(value) != set(fields):
                raise ValueError("Повреждены метаданные снимка")
            item = dict(value)
            for field in fields:
                entry = item[field]
                if field in _DATES:
                    if entry is None and field == "expires_at":
                        continue
                    if not isinstance(entry, str):
                        raise ValueError("Повреждена дата снимка")
                    try:
                        item[field] = datetime.fromisoformat(entry)
                    except ValueError:
                        raise ValueError("Повреждена дата снимка") from None
                elif not isinstance(entry, str):
                    raise ValueError("Повреждены метаданные снимка")
            identifier = item.get("client_id", item.get("public_key"))
            if not identifier or identifier in seen:
                raise ValueError("Повреждены идентификаторы клиентов снимка")
            seen.add(identifier)
            parsed[label].append(item)
    return parsed


async def load(session, server, protocol: str, snapshot_id: str) -> dict:
    row = await session.get(AppSetting, _key(server.id, protocol, snapshot_id))
    if row is None:
        raise ValueError("Нет метаданных панели для этого снимка; восстановление запрещено")
    try:
        value = json.loads(row.value)
    except (ValueError, TypeError):
        raise ValueError("Повреждены метаданные снимка") from None
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("server") != _identity(server) or value.get("protocol") != protocol:
        raise ValueError("Снимок относится к другому серверу или протоколу")
    listener = _listener(value.get("listener"))
    if protocol == "wireguard" and listener["transport"] != "udp":
        raise ValueError("Повреждены параметры WireGuard в снимке")
    _validated_rows(value)
    return value


async def apply(session, server_id: int, protocol: str, manifest: dict, *, commit=False) -> None:
    _prefix(server_id, protocol)
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or manifest.get("protocol") != protocol or not isinstance(manifest.get("server"), dict) or manifest["server"].get("id") != server_id:
        raise ValueError("Снимок относится к другому серверу или протоколу")
    # Parse everything before deleting any row, including dates and duplicates.
    rows = _validated_rows(manifest)
    for label, (model, _) in _TABLES.items():
        await session.execute(delete(model).where(model.server_id == server_id, model.protocol == protocol))
        for value in rows[label]:
            session.add(model(server_id=server_id, protocol=protocol, **value))
    await session.flush()
    if commit:
        await session.commit()


async def prune(session, server_id: int, protocol: str, snapshot_ids) -> None:
    prefix = _prefix(server_id, protocol)
    keep = {_key(server_id, protocol, value) for value in snapshot_ids}
    rows = await session.scalars(select(AppSetting).where(AppSetting.key.startswith(prefix, autoescape=True)))
    for row in rows:
        if row.key not in keep:
            await session.delete(row)
    await session.commit()


async def delete_server(session, server_id: int) -> None:
    """A removed server must not leave private profiles in snapshot manifests."""
    for protocol in PROTOCOLS:
        await session.execute(delete(AppSetting).where(
            AppSetting.key.startswith(_prefix(server_id, protocol), autoescape=True)))


async def export_server(session, server_id: int) -> list[dict]:
    """Include paired metadata in the same private server-transfer archive."""
    server = await session.get(Server, server_id)
    if server is None:
        raise ValueError("Сервер снимка отсутствует")
    records = []
    for protocol in PROTOCOLS:
        prefix = _prefix(server_id, protocol)
        rows = await session.scalars(select(AppSetting).where(
            AppSetting.key.startswith(prefix, autoescape=True)).order_by(AppSetting.key))
        for row in rows:
            snapshot_id = row.key[len(prefix):]
            _key(server_id, protocol, snapshot_id)
            try:
                value = json.loads(row.value)
            except (ValueError, TypeError):
                raise ValueError("Повреждены метаданные снимка") from None
            _validate_transfer_manifest(value, protocol, server_id)
            if value["server"] != _identity(server):
                raise ValueError("Снимок относится к другому серверу")
            records.append({"snapshot_id": snapshot_id, "manifest": value})
    return records


def _validate_transfer_manifest(value: dict, protocol: str, server_id: int) -> None:
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("protocol") != protocol:
        raise ValueError("Повреждены метаданные снимка")
    identity = value.get("server")
    if not isinstance(identity, dict) or set(identity) != {"id", "host", "ssh_port", "ssh_user"} or type(identity.get("id")) is not int or identity["id"] != server_id:
        raise ValueError("Снимок относится к другому серверу")
    if not isinstance(identity["host"], str) or not identity["host"] or not isinstance(identity["ssh_user"], str) or not identity["ssh_user"] or type(identity["ssh_port"]) is not int or not 1 <= identity["ssh_port"] <= 65535:
        raise ValueError("Повреждена идентификация сервера снимка")
    listener = _listener(value.get("listener"))
    if protocol == "wireguard" and listener["transport"] != "udp":
        raise ValueError("Повреждены параметры WireGuard в снимке")
    _validated_rows(value)


async def import_server(session, server, records: list[dict]) -> None:
    """Rewrite only node identity; validate the whole batch before any insert.

    The transfer caller owns the transaction and has already restored the
    matching server-side archives. Never overwrite an existing snapshot.
    """
    if not isinstance(records, list):
        raise ValueError("Повреждены метаданные снимков переноса")
    prepared = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"snapshot_id", "manifest"}:
            raise ValueError("Повреждены метаданные снимков переноса")
        value = record["manifest"]
        if not isinstance(value, dict) or not isinstance(value.get("server"), dict):
            raise ValueError("Повреждены метаданные снимка")
        protocol = value.get("protocol")
        key = _key(server.id, protocol, record["snapshot_id"])
        _validate_transfer_manifest(value, protocol, value["server"].get("id"))
        if dict(value["server"], id=server.id) != _identity(server):
            raise ValueError("Снимок относится к другому серверу")
        if key in prepared or await session.get(AppSetting, key) is not None:
            raise ValueError("Метаданные снимка уже сохранены")
        copied = dict(value, server=_identity(server))
        prepared[key] = json.dumps(copied, ensure_ascii=False)
    for key, value in prepared.items():
        session.add(AppSetting(key=key, value=value))
    await session.flush()
