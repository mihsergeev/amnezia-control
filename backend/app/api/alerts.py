from fastapi import APIRouter, HTTPException, status

from app import alerts, audit, settings_store
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.schemas import AlertConfigIn, AlertConfigOut, AlertTestResult

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _out(cfg: dict) -> AlertConfigOut:
    return AlertConfigOut(**cfg, enabled=alerts.alerts_enabled(cfg))


@router.get("", response_model=AlertConfigOut)
async def get_alerts(_: CurrentUser, session: SessionDep) -> AlertConfigOut:
    cfg = await settings_store.get_alert_config(session, get_settings())
    return _out(cfg)


@router.put("", response_model=AlertConfigOut)
async def put_alerts(
    body: AlertConfigIn, user: CurrentUser, session: SessionDep
) -> AlertConfigOut:
    await settings_store.set_alert_config(
        session, body.telegram_token, body.telegram_chat, body.webhook,
        telegram_api=body.telegram_api,
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
    return _out(cfg)


@router.post("/test", response_model=AlertTestResult)
async def test_alerts(user: CurrentUser, session: SessionDep) -> AlertTestResult:
    cfg = await settings_store.get_alert_config(session, get_settings())
    if not alerts.alerts_enabled(cfg):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Каналы алертов не настроены"
        )
    errors = await alerts.send_alert(cfg, "🔔 Тестовый алерт Amnezia Control")
    await audit.record(
        session, user.username, "alerts_test", "",
        "; ".join(errors) if errors else "ok",
    )
    return AlertTestResult(sent=not errors, errors=errors)
