import time

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select, update

from app import alerts, apikeys, audit, ratelimit, stepup, totp
from app.clientip import client_ip
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import ApiKey, User
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

# Адреса недавних успешных входов: блокировка логина на них не действует, иначе
# любой без пароля держал бы админа запертым со всех адресов. Только в памяти:
# после рестарта адрес снова попадет сюда с первым успешным входом.
KNOWN_IP_TTL = 30 * 24 * 3600
KNOWN_IP_PER_USER = 20
KNOWN_USERS_MAX = 100
_known_ips: dict[str, dict[str, float]] = {}


def _remember_ip(username: str, ip_key: str, now: float | None = None) -> None:
    t = time.time() if now is None else now
    ips = _known_ips.setdefault(username, {})
    ips[ip_key] = t
    for k in [k for k, ts in ips.items() if t - ts > KNOWN_IP_TTL]:
        ips.pop(k, None)
    while len(ips) > KNOWN_IP_PER_USER:
        ips.pop(min(ips, key=ips.get), None)
    while len(_known_ips) > KNOWN_USERS_MAX:
        _known_ips.pop(next(iter(_known_ips)), None)


def _known_ip(username: str, ip_key: str, now: float | None = None) -> bool:
    t = time.time() if now is None else now
    ts = _known_ips.get(username, {}).get(ip_key)
    return ts is not None and t - ts <= KNOWN_IP_TTL


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
            alerts.Card(
                "crit", "🔑", alerts.t("Подбор пароля к панели"),
                alerts.t("{n} неудачных входов подряд с {ip}, адрес временно заблокирован",
                         n=ratelimit.MAX_FAILURES, ip=key),
            ),
        )
    if user_locked:
        await audit.record(
            session, username, "login_lockout", username,
            f"{USER_MAX_FAILURES} неудачных попыток на логин",
        )
        await alerts.security_alert(
            session, settings,
            alerts.Card(
                "crit", "🔑", alerts.t("Подбор пароля к «{user}»", user=username),
                alerts.t("{n} неудачных входов с разных адресов, логин временно заблокирован",
                         n=USER_MAX_FAILURES),
            ),
        )


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest, request: Request, session: SessionDep
) -> TokenResponse:
    settings = get_settings()
    key = _client_key(request)
    ipk = ratelimit.ip_key(key)
    user_locked = ratelimit.is_locked(_user_key(body.username))
    if ratelimit.is_locked(ipk) or (
        user_locked and not _known_ip(body.username, ipk)
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
        if not await stepup.consume_otp(session, user, body.otp):
            await _record_failure(session, settings, key, body.username, "login_2fa_fail")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2fa_invalid")
    ratelimit.clear(ipk)
    # счетчик логина не сбрасываем, если он заперт чужим перебором: вход с
    # известного адреса не должен открывать логин для всех остальных
    if not user_locked:
        ratelimit.clear(_user_key(body.username))
    _remember_ip(user.username, ipk)
    token = create_access_token(
        user.username, settings.jwt_secret, settings.jwt_ttl_minutes,
        user.token_version,
    )
    await audit.record(session, user.username, "login_ok", key)
    return TokenResponse(access_token=token)


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
        if exc.status_code == status.HTTP_403_FORBIDDEN and exc.detail == "Неверный пароль":
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Неверный текущий пароль"
            ) from exc
        raise
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # все ранее выданные токены становятся недействительны
    # Смена пароля закрывает и постоянный доступ интеграций: ключ мог быть
    # выпущен до обнаружения чужой сессии. Отзываем в той же транзакции.
    await session.execute(update(ApiKey).where(ApiKey.revoked.is_(False)).values(revoked=True))
    await session.commit()
    apikeys._ok_cache.clear()
    await audit.record(session, user.username, "password_change", user.username)
    settings = get_settings()
    await alerts.security_alert(
        session, settings,
        alerts.Card("warn", "🔑", alerts.t("Сменен пароль «{user}»", user=user.username),
                    alerts.t("с {ip}", ip=_client_key(request))),
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
        alerts.Card("ok", "🔐", alerts.t("Включена 2FA у «{user}»", user=user.username),
                    alerts.t("с {ip}", ip=_client_key(request))),
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
    try:
        await stepup.verify(user, body.password, request, otp=body.otp)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_403_FORBIDDEN and exc.detail != "Неверный пароль":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неверный код") from exc
        raise
    user.totp_enabled = False
    user.totp_secret = ""
    await session.commit()
    await audit.record(session, user.username, "2fa_disable", user.username)
    await alerts.security_alert(
        session, get_settings(),
        alerts.Card("warn", "🔐", alerts.t("Отключена 2FA у «{user}»", user=user.username),
                    alerts.t("с {ip}", ip=_client_key(request))),
    )
    return TwoFAStatusOut(enabled=False)
