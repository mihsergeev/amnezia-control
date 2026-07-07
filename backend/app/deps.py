from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_session
from app.models import User
from app.security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)

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
    username = decode_access_token(credentials.credentials, get_settings().jwt_secret)
    if username is None:
        raise unauthorized
    user = await session.scalar(select(User).where(User.username == username))
    if user is None:
        raise unauthorized
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
