"""Optional presentation labels, keyed independently of VPN credentials."""

from sqlalchemy import delete, select

from app.models import ClientMetadata


async def labels_map(session, server_id, protocol):
    rows = await session.scalars(select(ClientMetadata).where(
        ClientMetadata.server_id == server_id, ClientMetadata.protocol == protocol))
    return {row.client_id: {"group_name": row.group_name, "device_name": row.device_name}
            for row in rows}


async def enrich(session, server_id, protocol, clients):
    labels = await labels_map(session, server_id, protocol)
    for client in clients:
        client.update(labels.get(client.get("public_key", client.get("client_id")),
                                 {"group_name": "", "device_name": ""}))
    return clients


async def set_labels(session, server_id, protocol, client_id, group_name="", device_name=""):
    row = await session.scalar(select(ClientMetadata).where(
        ClientMetadata.server_id == server_id, ClientMetadata.protocol == protocol,
        ClientMetadata.client_id == client_id))
    if not group_name and not device_name:
        if row is not None:
            await session.delete(row)
    elif row is None:
        session.add(ClientMetadata(server_id=server_id, protocol=protocol,
                    client_id=client_id, group_name=group_name, device_name=device_name))
    else:
        row.group_name, row.device_name = group_name, device_name
    await session.flush()


async def clear(session, server_id, protocol, client_id):
    await session.execute(delete(ClientMetadata).where(
        ClientMetadata.server_id == server_id, ClientMetadata.protocol == protocol,
        ClientMetadata.client_id == client_id))


async def move(session, server_id, protocol, old_id, new_id):
    labels = (await labels_map(session, server_id, protocol)).get(old_id)
    await clear(session, server_id, protocol, old_id)
    if labels:
        await set_labels(session, server_id, protocol, new_id, **labels)
