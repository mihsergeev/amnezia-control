"""Управление ключами интеграционного API. Только под пользовательским JWT:
выпускать ключи может лишь вошедший админ, сам ключ такого права не даёт."""

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app import apikeys, audit
from app.deps import CurrentUser, SessionDep
from app.models import ApiKey
from app.models import Server
from app.schemas import (
    ApiKeyCreated,
    ApiKeyCreateRequest,
    ApiKeyOut,
    ApiKeyUpdateRequest,
)

router = APIRouter(prefix="/apikeys", tags=["api-keys"])


@router.get("", response_model=list[ApiKeyOut])
async def list_keys(_: CurrentUser, session: SessionDep) -> list[ApiKey]:
    rows = await session.scalars(select(ApiKey).order_by(ApiKey.id.desc()))
    return list(rows)


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_key(
    body: ApiKeyCreateRequest, user: CurrentUser, session: SessionDep
) -> ApiKeyCreated:
    """Выпускает ключ. Полный ключ возвращается ЕДИНСТВЕННЫЙ раз — в БД хэш."""
    key, prefix, key_hash = apikeys.generate()
    row = ApiKey(name=body.name.strip(), prefix=prefix, key_hash=key_hash)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    await audit.record(session, user.username, "apikey_create", row.name)
    # собираем из базовой схемы + секрет: так новые поля ApiKeyOut подхватятся
    # автоматически и не придётся дублировать их перечисление
    base = ApiKeyOut.model_validate(row, from_attributes=True)
    return ApiKeyCreated(**base.model_dump(), key=key)


@router.put("/{key_id}", response_model=ApiKeyOut)
async def update_key(
    key_id: int, body: ApiKeyUpdateRequest, user: CurrentUser, session: SessionDep
) -> ApiKey:
    """Срок действия и серверы ключа. Настраиваются после выпуска, в списке."""
    row = await session.get(ApiKey, key_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ключ не найден")
    ids = sorted(set(body.server_ids))
    if ids:
        known = set(await session.scalars(select(Server.id).where(Server.id.in_(ids))))
        missing = [i for i in ids if i not in known]
        if missing:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, f"нет серверов с id {missing}"
            )
    row.servers = ",".join(str(i) for i in ids)
    row.expires_at = body.expires_at
    await session.commit()
    await session.refresh(row)
    exp = body.expires_at.isoformat() if body.expires_at else "бессрочно"
    await audit.record(
        session, user.username, "apikey_update", row.name,
        f"серверы: {row.servers or 'все'}, срок: {exp}",
    )
    return row


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(key_id: int, user: CurrentUser, session: SessionDep) -> None:
    """Отзыв необратим: ключ остаётся в списке (видно, что был), но не работает."""
    row = await session.get(ApiKey, key_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ключ не найден")
    row.revoked = True
    await session.commit()
    await audit.record(session, user.username, "apikey_revoke", row.name)
