"""Database journal shared by issue retries and existing revoke paths."""

from sqlalchemy import select

from app.models import BulkClientIssue


async def pending(session, server_id, protocol):
    return await session.scalars(select(BulkClientIssue).where(
        BulkClientIssue.server_id == server_id,
        BulkClientIssue.protocol == protocol,
        BulkClientIssue.complete.is_(False),
    ))


async def reserve_ips(session, server_id, protocol) -> set[str]:
    if protocol not in ("awg3", "wireguard"):
        return set()
    return {item["ip"] for row in await pending(session, server_id, protocol)
            for item in row.items if not item.get("cancelled")}


async def request_cancel(session, server_id, protocol, client_ids) -> None:
    """Persist the intent before a revoke can change the node without an ACK."""
    if protocol not in ("awg3", "wireguard", "xray"):
        return
    selected = set(client_ids)
    changed = False
    for row in await pending(session, server_id, protocol):
        items = [
            item | {"revoke_pending": True}
            if item["client_id"] in selected and not item.get("cancelled") else item
            for item in row.items
        ]
        if items != row.items:
            row.items = items
            changed = True
    if changed:
        await session.commit()


async def cancel_clients(session, server_id, protocol, client_ids) -> None:
    if protocol not in ("awg3", "wireguard", "xray"):
        return
    selected = set(client_ids)
    for row in await pending(session, server_id, protocol):
        if any(item["client_id"] in selected for item in row.items):
            row.items = [
                {"client_id": item["client_id"], "name": item["name"], "cancelled": True}
                if item["client_id"] in selected else item
                for item in row.items
            ]
            row.complete = all(item.get("cancelled") for item in row.items)


async def cancel_protocol(session, server_id, protocol) -> None:
    for row in await pending(session, server_id, protocol):
        row.items = [{"client_id": item["client_id"], "name": item["name"], "cancelled": True}
                     for item in row.items]
        row.complete = True
