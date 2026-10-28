import json
from datetime import datetime, timedelta, timezone

import pytest

from app import alerts, cascade, cascadewatch, config, settings_store
from app.db import Base, create_engine_and_factory
from app.models import Cascade, Server

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
OK = "CASCADE_GW=yes\nCASCADE_TPROXY=active\nCASCADE_TUN=UNKNOWN\nCASCADE_EGRESS=198.51.100.3\nCASCADE_RU=203.0.113.2\n"
NO_EXIT = "CASCADE_GW=yes\nCASCADE_TPROXY=active\nCASCADE_TUN=UNKNOWN\nCASCADE_EGRESS=\nCASCADE_RU=203.0.113.2\n"


@pytest.fixture
async def factory(tmp_path):
    config.get_settings.cache_clear()
    engine, factory = create_engine_and_factory(
        f"sqlite+aiosqlite:///{(tmp_path / 'w.db').as_posix()}"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with factory() as s:
        for sid, name in ((1, "vpn-b"), (2, "fi-exit")):
            s.add(Server(id=sid, name=name, host=f"203.0.113.{sid}", ssh_port=22, ssh_user="acontrol"))
        s.add(Cascade(id=1, entry_server_id=1, exit_server_id=2, transport="gre", status="ready"))
        await s.commit()
        await settings_store.set_alert_config(s, "TOKEN", "123", "")
    yield factory
    await engine.dispose()
    config.get_settings.cache_clear()


@pytest.fixture
def sent(monkeypatch):
    out: list[str] = []

    async def fake_send(cfg, text, *, html_text=None):
        out.append(text)
        return []

    monkeypatch.setattr(alerts, "send_alert", fake_send)
    return out


def _check(text):
    async def run(entry):
        if isinstance(text, Exception):
            raise text
        return text
    return run


async def _health(factory) -> dict:
    async with factory() as s:
        return json.loads((await s.get(Cascade, 1)).result or "{}").get("health", {})


def test_health_reasons() -> None:
    kv = cascade.parse_kv(OK)
    assert cascade.health("gre", kv, cascade.check_result(kv)) == (True, "")
    kv = cascade.parse_kv(NO_EXIT)
    assert cascade.health("gre", kv, cascade.check_result(kv))[1] == "через выход интернет не открывается"
    kv = cascade.parse_kv(OK.replace("CASCADE_TUN=UNKNOWN", "CASCADE_TUN="))
    assert cascade.health("gre", kv, cascade.check_result(kv)) == (False, "нет GRE-туннеля")
    assert cascade.health("vless", kv, cascade.check_result(kv)) == (True, "")


async def test_alert_only_after_grace_and_once(factory, sent) -> None:
    settings = config.get_settings()
    grace = settings.cascade_down_minutes
    for minutes in (0, 4, grace - 1):
        await cascadewatch.watch_once(factory, settings, now=NOW + timedelta(minutes=minutes),
                                      check=_check(NO_EXIT))
    assert sent == []  # короткий отказ дежурного не будит
    h = await _health(factory)
    assert h["ok"] is False and h["since"] == NOW.isoformat()
    for minutes in (grace, grace + 2, grace + 30):
        await cascadewatch.watch_once(factory, settings, now=NOW + timedelta(minutes=minutes),
                                      check=_check(NO_EXIT))
    assert len(sent) == 1
    assert sent[0].splitlines()[:3] == [
        "🔴 vpn-b", "Каскад не работает больше 10 мин",
        "через выход интернет не открывается, выход fi-exit",
    ]
    await cascadewatch.watch_once(factory, settings, now=NOW + timedelta(minutes=60), check=_check(OK))
    assert len(sent) == 2 and "снова работает" in sent[1]
    assert (await _health(factory))["ok"] is True


async def test_short_failure_resets_and_ssh_errors_are_ignored(factory, sent) -> None:
    settings = config.get_settings()
    grace = settings.cascade_down_minutes
    await cascadewatch.watch_once(factory, settings, now=NOW, check=_check(NO_EXIT))
    await cascadewatch.watch_once(factory, settings, now=NOW + timedelta(minutes=2), check=_check(OK))
    # серия прервалась: отсчет заново, восстановления без аварии тоже не шлем
    await cascadewatch.watch_once(factory, settings, now=NOW + timedelta(minutes=grace + 1),
                                  check=_check(NO_EXIT))
    assert sent == []
    assert (await _health(factory))["since"] == (NOW + timedelta(minutes=grace + 1)).isoformat()
    # вход недоступен по SSH: состояние не трогаем, алерта о каскаде нет
    await cascadewatch.watch_once(factory, settings, now=NOW + timedelta(hours=5),
                                  check=_check(OSError("timed out")))
    assert sent == [] and (await _health(factory))["ok"] is False


async def test_not_ready_cascade_is_not_checked(factory, sent) -> None:
    async with factory() as s:
        (await s.get(Cascade, 1)).status = "installing"
        await s.commit()
    calls = []

    async def check(entry):
        calls.append(entry.id)
        return NO_EXIT

    await cascadewatch.watch_once(factory, config.get_settings(), now=NOW, check=check)
    assert calls == []
