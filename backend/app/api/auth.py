from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select, update

from app import alerts, audit, ratelimit, stepup, totp
from app.clientip import client_ip
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import User
from app.schemas import (
    LoginRequest,
    PasswordChangeRequest,
    StepUpRequest,
    TokenResponse,
    TwoFASetupOut,
    TwoFAStatusOut,
    TwoFAVerifyRequest,
    UserOut,
)
from app.security import averify_password, create_access_token, hash_password

router = APIRouter(prefix="/auth", tags=["auth"])

# фиктивный хэш для сравнения при несуществующем юзере — выравнивает время
# ответа, чтобы по задержке нельзя было перечислять логины
_DUMMY_HASH = hash_password("no-such-user-timing-guard")

# Лимит по логину сверх лимита по адресу: перебор с многих адресов (ботнет)
# лимит по IP не держит. Порог выше, чем по адресу, чтобы чужие попытки не
# запирали админа так же быстро, как сам перебор.
USER_MAX_FAILURES = 30


def _client_key(request: Request) -> str:
    return client_ip(request)


def _user_key(username: str) -> str:
    return f"user:{username}"


async def _record_failure(session, settings, key: str, username: str, action: str) -> None:
    """Пишет неудачный вход в журнал; на переходе в блокировку — алерт (брутфорс)."""
    locked_now = ratelimit.record_failure(ratelimit.ip_key(key))
    user_locked = ratelimit.record_failure(
        _user_key(username), max_failures=USER_MAX_FAILURES
    )
    await audit.record(session, username, action, key)
    if locked_now:
        await audit.record(
            session, username, "login_lockout", key,
            f"{ratelimit.MAX_FAILURES} неудачных попыток",
        )
        await alerts.security_alert(
            session, settings,
            f"🚨 Amnezia Control: {ratelimit.MAX_FAILURES} неудачных попыток входа "
            f"подряд с IP {key} — вход временно заблокирован.",
        )
    if user_locked:
        await audit.record(
            session, username, "login_lockout", username,
            f"{USER_MAX_FAILURES} неудачных попыток на логин",
        )
        await alerts.security_alert(
            session, settings,
            f"🚨 Amnezia Control: {USER_MAX_FAILURES} неудачных попыток входа под "
            f"«{username}» с разных адресов — вход под этим логином временно "
            "заблокирован.",
        )


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest, request: Request, session: SessionDep
) -> TokenResponse:
    settings = get_settings()
    key = _client_key(request)
    if ratelimit.is_locked(ratelimit.ip_key(key)) or ratelimit.is_locked(
        _user_key(body.username)
    ):
        # в журнал не пишем: блокировку уже записали и прислали алертом, а
        # строка на каждый запрос давала раздувать журнал без входа
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Слишком много попыток входа — подождите несколько минут",
        )
    user = await session.scalar(select(User).where(User.username == body.username))
    # verify_password вызываем всегда (в т.ч. по фиктивному хэшу), чтобы время
    # ответа не зависело от существования логина
    password_ok = await averify_password(
        body.password, user.password_hash if user else _DUMMY_HASH
    )
    if user is None or not password_ok:
        await _record_failure(session, settings, key, body.username, "login_fail")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Неверный логин или пароль")
    if user.totp_enabled:
        # detail — машиночитаемый маркер для фронта (показать поле кода)
        if not body.otp:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2fa_required")
        if not await _consume_otp(session, user, body.otp):
            await _record_failure(session, settings, key, body.username, "login_2fa_fail")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2fa_invalid")
    ratelimit.clear(ratelimit.ip_key(key))
    ratelimit.clear(_user_key(body.username))
    token = create_access_token(
        user.username, settings.jwt_secret, settings.jwt_ttl_minutes,
        user.token_version,
    )
    await audit.record(session, user.username, "login_ok", key)
    return TokenResponse(access_token=token)


async def _consume_otp(session, user: User, otp: str) -> bool:
    """Проверяет код и атомарно помечает его использованным (защита от повтора).

    Счетчик двигается одним UPDATE с условием: два параллельных запроса с одним
    кодом раньше оба проходили между проверкой и записью."""
    counter = totp.matched_counter(user.totp_secret, otp)
    if counter is None:
        return False
    res = await session.execute(
        update(User)
        .where(User.id == user.id, User.totp_last_counter < counter)
        .values(totp_last_counter=counter)
    )
    await session.commit()  # фиксируем счётчик ДО audit (у audit свой rollback)
    return res.rowcount == 1


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, user: CurrentUser, session: SessionDep) -> None:
    """Выход с отзывом токена. Пользователь в панели один, поэтому отзываются
    все его сессии: иначе украденный токен жил бы до конца срока."""
    user.token_version += 1
    await session.commit()
    await audit.record(session, user.username, "logout", _client_key(request))


@router.post("/password", response_model=TokenResponse)
async def change_password(
    body: PasswordChangeRequest, request: Request, user: CurrentUser, session: SessionDep
) -> TokenResponse:
    """Смена пароля из UI: проверяет текущий, инвалидирует все старые токены."""
    try:
        await stepup.verify(user, body.current_password, request)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_403_FORBIDDEN:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Неверный текущий пароль"
            ) from exc
        raise
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # все ранее выданные токены становятся недействительны
    await session.commit()
    await audit.record(session, user.username, "password_change", user.username)
    settings = get_settings()
    await alerts.security_alert(
        session, settings,
        f"🔑 Amnezia Control: пароль администратора «{user.username}» изменён "
        f"(IP {_client_key(request)}).",
    )
    token = create_access_token(
        user.username, settings.jwt_secret, settings.jwt_ttl_minutes,
        user.token_version,
    )
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> User:
    return user


@router.get("/2fa", response_model=TwoFAStatusOut)
async def twofa_status(user: CurrentUser) -> TwoFAStatusOut:
    return TwoFAStatusOut(enabled=user.totp_enabled)


@router.post("/2fa/setup", response_model=TwoFASetupOut)
async def twofa_setup(
    body: StepUpRequest, request: Request, user: CurrentUser, session: SessionDep
) -> TwoFASetupOut:
    if user.totp_enabled:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "2FA уже включена — сначала отключите её",
        )
    await stepup.verify(user, body.password, request)
    secret = totp.random_secret()
    user.totp_secret = secret  # ожидающий подтверждения секрет (enabled ещё False)
    await session.commit()
    return TwoFASetupOut(
        secret=secret,
        otpauth_uri=totp.provisioning_uri(secret, user.username),
    )


@router.post("/2fa/enable", response_model=TwoFAStatusOut)
async def twofa_enable(
    body: TwoFAVerifyRequest, request: Request, user: CurrentUser, session: SessionDep
) -> TwoFAStatusOut:
    if user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "2FA уже включена")
    if not user.totp_secret:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Сначала запросите настройку (setup)"
        )
    await stepup.verify(user, body.password, request)
    if not totp.verify(user.totp_secret, body.otp):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неверный код")
    user.totp_enabled = True
    await session.commit()
    await audit.record(session, user.username, "2fa_enable", user.username)
    await alerts.security_alert(
        session, get_settings(),
        f"🔐 Amnezia Control: у «{user.username}» включена 2FA "
        f"(IP {_client_key(request)}).",
    )
    return TwoFAStatusOut(enabled=True)


@router.post("/2fa/disable", response_model=TwoFAStatusOut)
async def twofa_disable(
    body: TwoFAVerifyRequest, request: Request, user: CurrentUser, session: SessionDep
) -> TwoFAStatusOut:
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "2FA не включена")
    # пароль и код под одним лимитером степ-апа, и счетчик сбрасывается только
    # если верны оба: иначе с известным паролем 6 цифр перебирались бы без конца
    key = stepup._key(request)
    if ratelimit.is_locked(key):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Слишком много неверных попыток — подождите немного.",
        )
    if not await averify_password(body.password, user.password_hash):
        ratelimit.record_failure(key)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Неверный пароль")
    if not await _consume_otp(session, user, body.otp):
        ratelimit.record_failure(key)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неверный код")
    ratelimit.clear(key)
    user.totp_enabled = False
    user.totp_secret = ""
    await session.commit()
    await audit.record(session, user.username, "2fa_disable", user.username)
    await alerts.security_alert(
        session, get_settings(),
        f"⚠️ Amnezia Control: у «{user.username}» отключена 2FA "
        f"(IP {_client_key(request)}).",
    )
    return TwoFAStatusOut(enabled=False)
