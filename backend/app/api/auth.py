import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy import delete, select, update

from app import alerts, apikeys, audit, ratelimit, remembered_sessions, stepup, totp
from app.clientip import client_ip
from app.config import get_settings
from app.deps import BearerCredentials, CurrentUser, SessionDep, get_current_user
from app.models import ApiKey, AuditLog, RememberedSession, User
from app.schemas import (
    LoginRequest,
    PasswordChangeRequest,
    RememberedSessionOut,
    StepUpRequest,
    TokenResponse,
    TwoFAChangeOut,
    TwoFASetupOut,
    TwoFAStatusOut,
    TwoFAVerifyRequest,
    UserOut,
)
from app.security import averify_password, create_access_token, hash_password


class AuthRoute(APIRoute):
    def get_route_handler(self):
        handle = super().get_route_handler()

        async def no_store(request: Request) -> Response:
            try:
                response = await handle(request)
            except RequestValidationError as exc:
                # Pydantic also includes the submitted value in each error.
                errors = [{key: error[key] for key in ("loc", "msg", "type")} for error in exc.errors()]
                response = JSONResponse({"detail": errors}, status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)
            except HTTPException as exc:
                exc.headers = {**(exc.headers or {}), "Cache-Control": "no-store"}
                raise
            response.headers["Cache-Control"] = "no-store"
            return response

        return no_store


router = APIRouter(prefix="/auth", tags=["auth"], route_class=AuthRoute)

# фиктивный хэш для сравнения при несуществующем юзере — выравнивает время
# ответа, чтобы по задержке нельзя было перечислять логины
_DUMMY_HASH = hash_password("no-such-user-timing-guard")

# Лимит по логину сверх лимита по адресу: перебор с многих адресов (ботнет)
# лимит по IP не держит. Порог выше, чем по адресу, чтобы чужие попытки не
# запирали админа так же быстро, как сам перебор.
USER_MAX_FAILURES = 30

# Адреса недавних успешных входов: блокировка логина на них не действует, иначе
# любой без пароля держал бы админа запертым со всех адресов. Держим в памяти,
# а после рестарта один раз поднимаем из журнала (login_ok): иначе перебор
# сразу после перезапуска запирал админа и на его обычном адресе.
KNOWN_IP_TTL = 30 * 24 * 3600
KNOWN_IP_PER_USER = 20
KNOWN_USERS_MAX = 100
_known_ips: dict[str, dict[str, float]] = {}
_known_loaded = False


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


async def _load_known_ips(session) -> None:
    """Поднимает адреса успешных входов за KNOWN_IP_TTL из журнала."""
    global _known_loaded
    if _known_loaded:
        return
    since = datetime.now(timezone.utc) - timedelta(seconds=KNOWN_IP_TTL)
    rows = (await session.execute(
        select(AuditLog.username, AuditLog.target, AuditLog.ts)
        .where(AuditLog.action == "login_ok", AuditLog.ts >= since)
        .order_by(AuditLog.ts)
    )).all()
    _known_loaded = True
    for username, target, ts in rows:
        if ts is None:
            continue
        if ts.tzinfo is None:  # SQLite отдает время без зоны, пишется оно в UTC
            ts = ts.replace(tzinfo=timezone.utc)
        ipk = ratelimit.ip_key(target or "")
        known = _known_ips.get(username, {}).get(ipk)
        if known is None or known < ts.timestamp():
            _remember_ip(username, ipk, ts.timestamp())


def _client_key(request: Request) -> str:
    return client_ip(request)


def _user_key(username: str) -> str:
    return f"user:{username}"


async def _bump_token_version(session, user: User) -> int:
    # Два уже авторизованных запроса могут держать одну старую ORM-версию.
    # Инкремент в БД не дает второму logout/password затереть отзыв первого.
    return await session.scalar(
        update(User).where(User.id == user.id)
        .values(token_version=User.token_version + 1)
        .returning(User.token_version)
        .execution_options(synchronize_session=False)
    )


def _count_failure(key: str, username: str) -> tuple[bool, bool]:
    """Считает неудачу в лимитере (внутри очереди попыток). Возвращает, какой
    из ключей эта попытка перевела в блокировку."""
    return (
        ratelimit.record_failure(ratelimit.ip_key(key)),
        ratelimit.record_failure(_user_key(username), max_failures=USER_MAX_FAILURES),
    )


# Алерты о блокировках: не чаще одного каждого вида за ALERT_EVERY. Перебор с
# множества адресов (IPv6 /48 - это 65536 ключей /64) иначе засыпал бы канал
# алертов. Пропущенные считаются и попадают в следующий алерт, в журнал
# аудита каждая блокировка пишется как раньше.
ALERT_EVERY = 600
_alert_last: dict[str, float] = {}
_alert_skipped: dict[str, int] = {}


def _alert_due(kind: str, now: float | None = None) -> tuple[bool, int]:
    t = time.time() if now is None else now
    if t - _alert_last.get(kind, float("-inf")) < ALERT_EVERY:
        _alert_skipped[kind] = _alert_skipped.get(kind, 0) + 1
        return False, 0
    _alert_last[kind] = t
    return True, _alert_skipped.pop(kind, 0)


def _with_skipped(text, skipped: int):
    if not skipped:
        return text
    return alerts.t("{what}. Еще блокировок после прошлого алерта: {n}", what=text, n=skipped)


async def _report_failure(
    session, settings, key: str, username: str, action: str, trips: tuple[bool, bool],
    known_user: bool = True,
) -> None:
    """Пишет неудачный вход в журнал; на переходе в блокировку — алерт (брутфорс).
    Вызывается после очереди попыток: отправка алерта не должна ее держать."""
    locked_now, user_locked = trips
    # логин из запроса чужой: длиннее колонки журнала он ронял бы запись
    shown = username[:64]
    await audit.record(session, shown, action, key)
    if locked_now:
        await audit.record(
            session, shown, "login_lockout", key,
            f"{ratelimit.MAX_FAILURES} неудачных попыток",
        )
        due, skipped = _alert_due("ip")
        if due:
            await alerts.security_alert(
                session, settings,
                alerts.Card(
                    "crit", "🔑", alerts.t("Подбор пароля к панели"),
                    _with_skipped(alerts.t(
                        "{n} неудачных входов подряд с {ip}, адрес временно заблокирован",
                        n=ratelimit.MAX_FAILURES, ip=key), skipped),
                ),
            )
    if user_locked:
        await audit.record(
            session, shown, "login_lockout", shown,
            f"{USER_MAX_FAILURES} неудачных попыток на логин",
        )
        # логина нет в панели - запирать нечего, а текст в алерте был бы
        # чужой (вплоть до ссылки, которую мессенджер сделает кликабельной)
        due, skipped = _alert_due("user") if known_user else (False, 0)
        if due:
            await alerts.security_alert(
                session, settings,
                alerts.Card(
                    "crit", "🔑", alerts.t("Подбор пароля к «{user}»", user=shown),
                    _with_skipped(alerts.t(
                        "{n} неудачных входов с разных адресов, логин временно заблокирован",
                        n=USER_MAX_FAILURES), skipped),
                ),
            )


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest, request: Request, response: Response, session: SessionDep,
) -> TokenResponse:
    settings = get_settings()
    key = _client_key(request)
    ipk = ratelimit.ip_key(key)
    ukey = _user_key(body.username)
    failure = ""
    async with ratelimit.serialized(ipk, ukey):
        user_locked = ratelimit.is_locked(ukey)
        if user_locked and not _known_ip(body.username, ipk):
            await _load_known_ips(session)
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
            failure, detail = "login_fail", "Неверный логин или пароль"
        elif user.totp_enabled:
            # detail — машиночитаемый маркер для фронта (показать поле кода)
            if not body.otp:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2fa_required")
            if not await stepup.consume_otp(session, user, body.otp):
                failure, detail = "login_2fa_fail", "2fa_invalid"
        if failure:
            trips = _count_failure(key, body.username)
            known_user = user is not None
        else:
            ratelimit.clear(ipk)
            # счетчик логина не сбрасываем, если он заперт чужим перебором: вход с
            # известного адреса не должен открывать логин для всех остальных
            if not user_locked:
                ratelimit.clear(ukey)
            _remember_ip(user.username, ipk)
    if failure:
        await _report_failure(session, settings, key, body.username, failure, trips, known_user)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail)
    remembered = await remembered_sessions.start_login(
        session, user, request, settings.jwt_secret, body.remember,
    )
    sid = None
    if remembered is not None:
        row, cookie = remembered
        sid = row.id
        remembered_sessions.set_cookie(response, cookie, remembered_sessions.expires_at(row))
    elif remembered_sessions.COOKIE_NAME in request.cookies:
        remembered_sessions.clear_cookie(response)
    token = create_access_token(
        user.username, settings.jwt_secret, settings.jwt_ttl_minutes,
        user.token_version, session_id=sid,
    )
    await audit.record(session, user.username, "login_ok", key, "Запомнен вход" if sid else "")
    return TokenResponse(access_token=token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, response: Response, session: SessionDep) -> TokenResponse:
    if not remembered_sessions.valid_browser_request(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Запрос обновления сессии отклонен")
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Недействительная или завершенная сессия")
    settings = get_settings()
    proof = remembered_sessions.read_cookie(request, settings.jwt_secret)
    if proof is None:
        raise unauthorized
    try:
        rotated, replay_user_id = await remembered_sessions.rotate(session, proof, settings.jwt_secret)
    except remembered_sessions.ConcurrentRotation as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Сессия уже обновляется") from exc
    if rotated is None:
        if replay_user_id is not None:
            username = await session.scalar(select(User.username).where(User.id == replay_user_id))
            await audit.record(session, username or "", "session_replay", _client_key(request))
        # A late response must not overwrite a cookie from a newer refresh or
        # a fresh login. The browser replaces or removes it on explicit login.
        raise unauthorized
    row, cookie = rotated
    username = await session.scalar(select(User.username).where(
        User.id == row.user_id, User.token_version == row.token_version,
    ))
    if username is None:
        raise unauthorized
    token = create_access_token(
        username, settings.jwt_secret, settings.jwt_ttl_minutes, row.token_version, session_id=row.id,
    )
    remembered_sessions.set_cookie(response, cookie, remembered_sessions.expires_at(row))
    await audit.record(session, username, "session_refresh", _client_key(request))
    return TokenResponse(access_token=token)


@router.get("/sessions", response_model=list[RememberedSessionOut])
async def list_sessions(request: Request, user: CurrentUser, session: SessionDep) -> list[RememberedSessionOut]:
    rows = await session.scalars(select(RememberedSession).where(
        RememberedSession.user_id == user.id,
        RememberedSession.token_version == user.token_version,
        *remembered_sessions.active_at(remembered_sessions.utcnow()),
    ).order_by(RememberedSession.last_used_at.desc(), RememberedSession.id))
    current = request.state.remembered_session_id
    return [RememberedSessionOut(
        id=row.id, user_agent=row.user_agent, current=row.id == current,
        created_at=remembered_sessions.as_utc(row.created_at),
        last_used_at=remembered_sessions.as_utc(row.last_used_at),
        expires_at=remembered_sessions.expires_at(row),
    ) for row in rows]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: str, request: Request, response: Response, user: CurrentUser, session: SessionDep,
) -> None:
    if not remembered_sessions.SESSION_ID.fullmatch(session_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сессия не найдена")
    revoked = await session.scalar(delete(RememberedSession).where(
        RememberedSession.id == session_id,
        RememberedSession.user_id == user.id,
        RememberedSession.token_version == user.token_version,
    ).returning(RememberedSession.id))
    if revoked is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сессия не найдена")
    await session.commit()
    proof = remembered_sessions.read_cookie(request, get_settings().jwt_secret)
    if proof is not None and proof.session_id == revoked:
        remembered_sessions.clear_cookie(response)
    await audit.record(session, user.username, "session_revoke", _client_key(request))


async def logout(request: Request, user: User, session: SessionDep) -> None:
    """Выход с отзывом токена. Пользователь в панели один, поэтому отзываются
    все его сессии: иначе украденный токен жил бы до конца срока."""
    await _bump_token_version(session, user)
    await session.commit()
    await audit.record(session, user.username, "logout", _client_key(request))


@router.post("/logout", name="logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout_request(
    request: Request, response: Response, credentials: BearerCredentials, session: SessionDep,
) -> None:
    try:
        user = await get_current_user(credentials, session, request)
    except HTTPException:
        proof = remembered_sessions.read_cookie(request, get_settings().jwt_secret)
        if proof is None or not remembered_sessions.valid_browser_request(request):
            raise
        user = await remembered_sessions.authenticate_cookie(session, proof)
        if user is None:
            raise
    await logout(request, user, session)
    remembered_sessions.clear_cookie(response)


@router.post("/password", response_model=TokenResponse)
async def change_password(
    body: PasswordChangeRequest, request: Request, response: Response, user: CurrentUser, session: SessionDep,
) -> TokenResponse:
    """Смена пароля из UI: проверяет текущий, инвалидирует все старые токены."""
    old_version = user.token_version
    old_hash = user.password_hash
    totp_enabled = user.totp_enabled
    totp_secret = user.totp_secret
    try:
        await stepup.verify(user, body.current_password, request)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_403_FORBIDDEN and exc.detail == "Неверный пароль":
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Неверный текущий пароль"
            ) from exc
        raise
    # Пока проверялся пароль, другой запрос мог сменить его или отозвать сессию.
    # Записываем новый пароль и версию только для проверенных учетных данных.
    token_version = await session.scalar(
        update(User).where(
            User.id == user.id,
            User.token_version == old_version,
            User.password_hash == old_hash,
            User.totp_enabled.is_(totp_enabled),
            User.totp_secret == totp_secret,
        ).values(
            password_hash=hash_password(body.new_password),
            token_version=User.token_version + 1,
        ).returning(User.token_version).execution_options(synchronize_session=False)
    )
    if token_version is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Учетные данные изменились. Войдите заново.")
    # Смена пароля закрывает и постоянный доступ интеграций: ключ мог быть
    # выпущен до обнаружения чужой сессии. Отзываем в той же транзакции.
    await session.execute(update(ApiKey).where(ApiKey.revoked.is_(False)).values(revoked=True))
    await session.commit()
    remembered_sessions.clear_cookie(response)
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
        token_version,
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
    user.totp_last_counter = 0  # счетчик повтора относится только к этому секрету
    await session.commit()
    return TwoFASetupOut(
        secret=secret,
        otpauth_uri=totp.provisioning_uri(secret, user.username),
    )


@router.post("/2fa/enable", response_model=TwoFAChangeOut)
async def twofa_enable(
    body: TwoFAVerifyRequest, request: Request, response: Response, user: CurrentUser, session: SessionDep,
) -> TwoFAChangeOut:
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
    # 2FA включают, когда опасаются за пароль: сессии, открытые без кода,
    # отзываем, иначе украденный до включения токен жил бы до конца срока
    token_version = await _bump_token_version(session, user)
    await session.commit()
    remembered_sessions.clear_cookie(response)
    settings = get_settings()
    token = create_access_token(
        user.username, settings.jwt_secret, settings.jwt_ttl_minutes, token_version,
    )
    await audit.record(session, user.username, "2fa_enable", user.username)
    await alerts.security_alert(
        session, get_settings(),
        alerts.Card("ok", "🔐", alerts.t("Включена 2FA у «{user}»", user=user.username),
                    alerts.t("с {ip}", ip=_client_key(request))),
    )
    return TwoFAChangeOut(enabled=True, access_token=token)


@router.post("/2fa/disable", response_model=TwoFAChangeOut)
async def twofa_disable(
    body: TwoFAVerifyRequest, request: Request, response: Response, user: CurrentUser, session: SessionDep,
) -> TwoFAChangeOut:
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
    token_version = await _bump_token_version(session, user)
    await session.commit()
    remembered_sessions.clear_cookie(response)
    settings = get_settings()
    token = create_access_token(
        user.username, settings.jwt_secret, settings.jwt_ttl_minutes, token_version,
    )
    await audit.record(session, user.username, "2fa_disable", user.username)
    await alerts.security_alert(
        session, settings,
        alerts.Card("warn", "🔐", alerts.t("Отключена 2FA у «{user}»", user=user.username),
                    alerts.t("с {ip}", ip=_client_key(request))),
    )
    return TwoFAChangeOut(enabled=False, access_token=token)
