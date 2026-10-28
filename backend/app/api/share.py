"""Сервисы одноразовых ссылок и выдача ссылки на конфиг (см. app/share.py)."""

import secrets

from fastapi import APIRouter, HTTPException, status

from app import audit, settings_store, share
from app.deps import CurrentUser, SessionDep
from app.schemas import ShareLinkOut, ShareRequest, ShareServiceIn, ShareServiceOut

router = APIRouter(prefix="/share", tags=["share"])


@router.get("/services", response_model=list[ShareServiceOut])
async def list_services(_: CurrentUser, session: SessionDep) -> list[dict]:
    return await settings_store.get_share_services(session)


@router.post("/services", response_model=list[ShareServiceOut])
async def add_service(
    body: ShareServiceIn, user: CurrentUser, session: SessionDep
) -> list[dict]:
    try:
        base = share.normalize_url(body.url)
        engine = await share.detect_engine(base)
    except share.ShareError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    services = await settings_store.get_share_services(session)
    if any(s["url"] == base for s in services):
        raise HTTPException(status.HTTP_409_CONFLICT, "этот сервис уже добавлен")
    services.append({
        "id": secrets.token_hex(4), "name": body.name.strip(), "url": base, "engine": engine,
    })
    await settings_store.set_share_services(session, services)
    await audit.record(session, user.username, "share_service_add", body.name, base)
    return services


@router.delete("/services/{service_id}", response_model=list[ShareServiceOut])
async def delete_service(
    service_id: str, user: CurrentUser, session: SessionDep
) -> list[dict]:
    services = await settings_store.get_share_services(session)
    gone = [s for s in services if s["id"] == service_id]
    if not gone:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "сервис не найден")
    services = [s for s in services if s["id"] != service_id]
    await settings_store.set_share_services(session, services)
    await audit.record(
        session, user.username, "share_service_delete", gone[0]["name"], gone[0]["url"]
    )
    return services


@router.post("", response_model=ShareLinkOut)
async def create_link(
    body: ShareRequest, user: CurrentUser, session: SessionDep
) -> ShareLinkOut:
    services = await settings_store.get_share_services(session)
    svc = next((s for s in services if s["id"] == body.service_id), None)
    if svc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "сервис не найден")
    try:
        url = await share.create_link(svc["engine"], svc["url"], body.text)
    except share.ShareError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"{svc['name']}: {exc}"
        ) from exc
    # в журнал - кому и через какой сервис, но не сам конфиг и не ссылку
    await audit.record(session, user.username, "share_link", body.target, svc["name"])
    return ShareLinkOut(url=url, ttl_days=share.TTL_DAYS)
