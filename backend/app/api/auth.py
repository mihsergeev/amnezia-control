from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app import audit, totp
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import User
from app.schemas import (
    LoginRequest,
    TokenResponse,
    TwoFASetupOut,
    TwoFAStatusOut,
    TwoFAVerifyRequest,
    UserOut,
)
from app.security import create_access_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, session: SessionDep) -> TokenResponse:
    user = await session.scalar(select(User).where(User.username == body.username))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Неверный логин или пароль")
    if user.totp_enabled:
        # detail — машиночитаемый маркер для фронта (показать поле кода)
        if not body.otp:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2fa_required")
        if not totp.verify(user.totp_secret, body.otp):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2fa_invalid")
    settings = get_settings()
    token = create_access_token(
        user.username, settings.jwt_secret, settings.jwt_ttl_minutes
    )
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> User:
    return user


@router.get("/2fa", response_model=TwoFAStatusOut)
async def twofa_status(user: CurrentUser) -> TwoFAStatusOut:
    return TwoFAStatusOut(enabled=user.totp_enabled)


@router.post("/2fa/setup", response_model=TwoFASetupOut)
async def twofa_setup(user: CurrentUser, session: SessionDep) -> TwoFASetupOut:
    if user.totp_enabled:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "2FA уже включена — сначала отключите её",
        )
    secret = totp.random_secret()
    user.totp_secret = secret  # ожидающий подтверждения секрет (enabled ещё False)
    await session.commit()
    return TwoFASetupOut(
        secret=secret,
        otpauth_uri=totp.provisioning_uri(secret, user.username),
    )


@router.post("/2fa/enable", response_model=TwoFAStatusOut)
async def twofa_enable(
    body: TwoFAVerifyRequest, user: CurrentUser, session: SessionDep
) -> TwoFAStatusOut:
    if user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "2FA уже включена")
    if not user.totp_secret:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Сначала запросите настройку (setup)"
        )
    if not totp.verify(user.totp_secret, body.otp):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неверный код")
    user.totp_enabled = True
    await session.commit()
    await audit.record(session, user.username, "2fa_enable", user.username)
    return TwoFAStatusOut(enabled=True)


@router.post("/2fa/disable", response_model=TwoFAStatusOut)
async def twofa_disable(
    body: TwoFAVerifyRequest, user: CurrentUser, session: SessionDep
) -> TwoFAStatusOut:
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "2FA не включена")
    if not totp.verify(user.totp_secret, body.otp):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неверный код")
    user.totp_enabled = False
    user.totp_secret = ""
    await session.commit()
    await audit.record(session, user.username, "2fa_disable", user.username)
    return TwoFAStatusOut(enabled=False)
