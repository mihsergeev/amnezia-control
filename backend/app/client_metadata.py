"""Optional presentation labels, keyed independently of VPN credentials."""

from sqlalchemy import delete, select

from app.metadata_schemas import metadata_identity
from app.models import ClientMetadata


async def labels_map(session, server_id, protocol):
    rows = await session.scalars(select(ClientMetadata).where(
        ClientMetadata.server_id == server_id, ClientMetadata.protocol == protocol))
    return {row.client_id: {"group_name": row.group_name, "device_name": row.device_name}
            for row in rows}


async def enrich(session, server_id, protocol, clients):
    labels = await labels_map(session, server_id, protocol)
    canonical = {metadata_identity(protocol, cid): value for cid, value in labels.items()}
    for client in clients:
        cid = client.get("public_key", client.get("client_id"))
        client.update(labels.get(cid, canonical.get(metadata_identity(protocol, cid),
                                 {"group_name": "", "device_name": ""})))
    return clients


async def set_labels(session, server_id, protocol, client_id, group_name="", device_name=""):
    if protocol == "xray":
        # Single edits and bulk grouping must share the same UUID identity.
        # Clearing aliases first also handles labels restored from older data.
        await clear(session, server_id, protocol, client_id)
        if group_name or device_name:
            session.add(ClientMetadata(server_id=server_id, protocol=protocol,
                        client_id=metadata_identity(protocol, client_id),
                        group_name=group_name, device_name=device_name))
        await session.flush()
        return
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
    ids = [client_id]
    if protocol == "xray":
        identity = metadata_identity(protocol, client_id)
        stored_ids = await session.scalars(select(ClientMetadata.client_id).where(
            ClientMetadata.server_id == server_id, ClientMetadata.protocol == protocol))
        ids = [cid for cid in stored_ids if metadata_identity(protocol, cid) == identity]
    await session.execute(delete(ClientMetadata).where(
        ClientMetadata.server_id == server_id, ClientMetadata.protocol == protocol,
        ClientMetadata.client_id.in_(ids)))


async def set_group(session, server_id, protocol, client_ids, group_name):
    """Update presentation grouping while keeping each device label intact."""
    query = select(ClientMetadata).where(ClientMetadata.server_id == server_id,
                                         ClientMetadata.protocol == protocol)
    if protocol != "xray":
        query = query.where(ClientMetadata.client_id.in_(client_ids))
    rows = list(await session.scalars(query))
    for cid in client_ids:
        identity = metadata_identity(protocol, cid)
        matches = [row for row in rows if metadata_identity(protocol, row.client_id) == identity]
        # The request carries the ID currently displayed in the UI. Keep its
        # exact device label when older UUID aliases have separate metadata.
        row = next((row for row in matches if row.client_id == cid), None)
        if row is None:
            row = next((row for row in matches if row.client_id == identity), next(iter(matches), None))
        cid = identity
        for alias in matches:
            if alias is not row:
                await session.delete(alias)
        if len(matches) > 1:
            # Remove a canonical alias before renaming the retained row onto
            # its unique key. Both flushes remain in the caller's transaction.
            await session.flush()
        if row is None:
            if group_name:
                session.add(ClientMetadata(server_id=server_id, protocol=protocol,
                            client_id=cid, group_name=group_name, device_name=""))
        elif not group_name and not row.device_name:
            await session.delete(row)
        else:
            row.client_id = cid
            row.group_name = group_name
    await session.flush()


async def move(session, server_id, protocol, old_id, new_id):
    stored = await labels_map(session, server_id, protocol)
    labels = stored.get(old_id)
    if labels is None and protocol == "xray":
        identity = metadata_identity(protocol, old_id)
        labels = stored.get(identity)
        if labels is None:
            labels = next((value for cid, value in stored.items()
                           if metadata_identity(protocol, cid) == identity), None)
    await clear(session, server_id, protocol, old_id)
    if labels:
        await set_labels(session, server_id, protocol, new_id, **labels)
