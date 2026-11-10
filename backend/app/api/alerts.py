from fastapi import APIRouter, HTTPException, Request, status

from app import alerts, audit, settings_store, stepup
from app.clientip import client_ip
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.schemas import AlertConfigIn, AlertConfigOut, AlertTestResult

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _out(cfg: dict) -> AlertConfigOut:
    return AlertConfigOut(
        telegram_token_set=bool(cfg["telegram_token"]),
        telegram_chat=cfg["telegram_chat"],
        telegram_api=cfg["telegram_api"],
        webhook_set=bool(cfg["webhook"]),
        lang=cfg["lang"],
        enabled=alerts.alerts_enabled(cfg),
    )


@router.get("", response_model=AlertConfigOut)
async def get_alerts(_: CurrentUser, session: SessionDep) -> AlertConfigOut:
    cfg = await settings_store.get_alert_config(session, get_settings())
    return _out(cfg)


@router.put("", response_model=AlertConfigOut)
async def put_alerts(
    body: AlertConfigIn, request: Request, user: CurrentUser, session: SessionDep
) -> AlertConfigOut:
    # со степ-апом: подменой адреса Telegram API или вебхука укравший сессию
    # увел бы токен бота и дальше читал бы security-алерты
    await stepup.verify(user, body.password, request, otp=body.otp)
    old = await settings_store.get_alert_config(session, get_settings())
    await settings_store.set_alert_config(
        session,
        body.telegram_token,
        body.telegram_chat,
        body.webhook,
        telegram_api=body.telegram_api, lang=body.lang,
    )
    cfg = await settings_store.get_alert_config(session, get_settings())
    channels = []
    if cfg["telegram_token"] and cfg["telegram_chat"]:
        channels.append("telegram")
    if cfg["webhook"]:
        channels.append("webhook")
    await audit.record(
        session, user.username, "alerts_update", "",
        ", ".join(channels) or "выключено",
    )
    # алерт уходит в старые каналы: туда, где его увидит настоящий админ
    if alerts.alerts_enabled(old) and any(
        old[k] != cfg[k] for k in ("telegram_token", "telegram_chat", "telegram_api", "webhook")
    ):
        try:
            await alerts.send_card(
                old, get_settings(),
                alerts.Card("warn", "🔔", alerts.t("Изменены каналы алертов"),
                            alerts.t("{user} с {ip}", user=user.username, ip=client_ip(request))),
            )
        except Exception:  # noqa: BLE001 - best-effort, как security_alert
            pass
    return _out(cfg)


@router.post("/test", response_model=AlertTestResult)
async def test_alerts(user: CurrentUser, session: SessionDep) -> AlertTestResult:
    cfg = await settings_store.get_alert_config(session, get_settings())
    if not alerts.alerts_enabled(cfg):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Каналы алертов не настроены"
        )
    errors = await alerts.send_card(
        cfg, get_settings(), alerts.Card("info", "", alerts.t("Тестовый алерт"), alerts.t("канал работает"))
    )
    await audit.record(
        session, user.username, "alerts_test", "",
        "; ".join(errors) if errors else "ok",
    )
    return AlertTestResult(sent=not errors, errors=errors)
