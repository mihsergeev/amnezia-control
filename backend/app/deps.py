from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import apikeys
from app.config import get_settings
from app.db import get_session
from app.models import ApiKey, User
from app.security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)
# Интеграционный API: ключ в заголовке X-API-Key. Отдельная схема (не JWT) —
# машине незачем логиниться пользователем, а в Swagger видно, чем авторизоваться.
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ],
    session: SessionDep,
) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Недействительный или отсутствующий токен"
    )
    if credentials is None:
        raise unauthorized
    payload = decode_access_token(credentials.credentials, get_settings().jwt_secret)
    if payload is None:
        raise unauthorized
    user = await session.scalar(select(User).where(User.username == payload["sub"]))
    if user is None:
        raise unauthorized
    # токен, выпущенный до смены пароля (иная version), больше не действителен
    if payload.get("ver", 0) != user.token_version:
        raise unauthorized
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def get_api_client(
    key: Annotated[str | None, Security(api_key_scheme)],
    session: SessionDep,
) -> ApiKey:
    """Аутентификация интеграции по ключу из X-API-Key.

    Права ключа узкие и фиксированные: клиентские операции AmneziaWG + чтение
    списка серверов. Управление серверами (деплой/удаление/full-access/настройки)
    ключом НЕДОСТУПНО — такие ручки остаются под пользовательским JWT.
    """
    if not key:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Требуется заголовок X-API-Key"
        )
    row = await apikeys.authenticate(session, key)
    if row is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Недействительный или отозванный API-ключ"
        )
    return row


ApiClient = Annotated[ApiKey, Depends(get_api_client)]
