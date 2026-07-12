"""Пульс для хостового watchdog: формат файла и self-тест канала алертов."""

from app import heartbeat


def test_heartbeat_write_format(tmp_path):
    p = str(tmp_path / "heartbeat")
    heartbeat._write(
        p,
        {"telegram_token": "TOK", "telegram_chat": "CHAT", "telegram_api": "", "webhook": ""},
        True,
    )
    content = open(p, encoding="utf-8").read()
    assert "\nalerts_ok=1\n" in content
    assert "\ntg_token=TOK\n" in content
    assert "\ntg_chat=CHAT\n" in content
    assert "\ntg_api=https://api.telegram.org\n" in content  # пустой → дефолт
    assert content.startswith("ts=")


def test_heartbeat_write_alerts_broken(tmp_path):
    p = str(tmp_path / "heartbeat")
    heartbeat._write(p, {"telegram_token": "T", "telegram_chat": "C"}, False)
    assert "\nalerts_ok=0\n" in open(p, encoding="utf-8").read()


async def test_alert_channel_ok_without_telegram():
    # нет канала или только вебхук — тестировать нечем, считаем ок
    assert await heartbeat._alert_channel_ok({}) is True
    assert await heartbeat._alert_channel_ok({"webhook": "https://ex/hook"}) is True
