from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import apikeys, ratelimit, remembered_sessions
from app.debug_context import mark_authenticated
from app.clientip import client_ip
from app.config import get_settings
from app.db import get_session
from app.models import ApiKey, RememberedSession, User
from app.security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)
# Интеграционный API: ключ в заголовке X-API-Key. Отдельная схема (не JWT) —
# машине незачем логиниться пользователем, а в Swagger видно, чем авторизоваться.
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)

SessionDep = Annotated[AsyncSession, Depends(get_session)]
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]

# неудачных X-API-Key с адреса до блокировки: выше, чем у входа, чтобы
# интеграция со старым ключом не запирала соседнюю с того же адреса так быстро
APIKEY_MAX_FAILURES = 30


async def get_current_user(
    credentials: BearerCredentials, session: SessionDep, request: Request,
) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Недействительный или отсутствующий токен"
    )
    if credentials is None:
        raise unauthorized
    payload = decode_access_token(credentials.credentials, get_settings().jwt_secret)
    if payload is None:
        raise unauthorized
    query = select(User).where(User.username == payload["sub"])
    sid = payload.get("sid")
    if "sid" in payload:
        if not isinstance(sid, str) or not remembered_sessions.SESSION_ID.fullmatch(sid):
            raise unauthorized
        query = query.where(exists().where(
            RememberedSession.id == sid,
            RememberedSession.user_id == User.id,
            RememberedSession.token_version == User.token_version,
            *remembered_sessions.active_at(remembered_sessions.utcnow()),
        ))
    user = await session.scalar(query)
    if user is None:
        raise unauthorized
    # токен, выпущенный до смены пароля (иная version), больше не действителен
    if payload.get("ver", 0) != user.token_version:
        raise unauthorized
    request.state.remembered_session_id = sid
    mark_authenticated()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def _get_api_key(key: str | None, session: SessionDep, request: Request) -> ApiKey:
    if not key:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Требуется заголовок X-API-Key"
        )
    limit_key = f"apikey:{ratelimit.ip_key(client_ip(request))}"
    # проверки с одного адреса по очереди: иначе пачка параллельных запросов
    # проходила is_locked раньше первой записанной неудачи, и каждый гонял
    # bcrypt в общем пуле потоков (тормозя вход и степ-ап)
    async with ratelimit.serialized(limit_key):
        if ratelimit.is_locked(limit_key):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Слишком много неверных API-ключей с этого адреса, подождите",
            )
        row = await apikeys.authenticate(session, key)
        if row is None:
            ratelimit.record_failure(limit_key, max_failures=APIKEY_MAX_FAILURES)
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Недействительный или отозванный API-ключ"
            )
    mark_authenticated()
    return row


async def get_api_client(
    key: Annotated[str | None, Security(api_key_scheme)],
    session: SessionDep,
    request: Request,
) -> ApiKey:
    row = await _get_api_key(key, session, request)
    if row.scope != "clients":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ключ не разрешает клиентские операции")
    return row


async def get_stats_reader(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    key: Annotated[str | None, Security(api_key_scheme)],
    session: SessionDep,
    request: Request,
) -> ApiKey | None:
    if credentials is not None or key is None:
        await get_current_user(credentials, session, request)
        return None
    row = await _get_api_key(key, session, request)
    if row.scope != "stats":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ключ не разрешает читать статистику")
    return row


ApiClient = Annotated[ApiKey, Depends(get_api_client)]
StatsReader = Annotated[ApiKey | None, Depends(get_stats_reader)]
