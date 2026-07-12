"""Бэкап/восстановление: раньше дамп молча терял 7 из 13 таблиц (сроки клиентов,
настройки алертов, журнал). Тесты фиксируют, что теперь эти таблицы попадают в
архив и корректно восстанавливаются."""

import gzip
import io
import json
import tarfile

import httpx

from app.api.backup import _skip_data_dir, verify_archive


def _mk_archive(manifest_tables, dump, with_key=True):
    """Синтетический бэкап-архив для тестов verify_archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add(n, d):
            info = tarfile.TarInfo(n)
            info.size = len(d)
            tar.addfile(info, io.BytesIO(d))
        add("MANIFEST.json", json.dumps({"tables": manifest_tables}).encode())
        add("db.json", json.dumps(dump).encode())
        if with_key:
            add("data/ssh/id_ed25519", b"FAKE-KEY")
    return buf.getvalue()


def test_verify_archive_ok():
    ok = _mk_archive({"users": 1, "servers": 0}, {"users": [{"id": 1}], "servers": []})
    assert verify_archive(ok) == []


def test_verify_archive_catches_problems():
    # битый/оборванный файл
    assert verify_archive(b"not a tar.gz")
    # число строк не сходится с манифестом (обрыв записи)
    bad = _mk_archive({"users": 5}, {"users": [{"id": 1}]})
    assert any("users" in e for e in verify_archive(bad))
    # нет админа — после restore не войти
    assert any("админ" in e for e in verify_archive(_mk_archive({"users": 0}, {"users": []})))
    # нет приватного ssh-ключа панели
    nok = _mk_archive({"users": 1}, {"users": [{"id": 1}]}, with_key=False)
    assert any("ssh" in e for e in verify_archive(nok))


async def test_light_backup_omits_traffic_history(client, auth_headers):
    """По умолчанию бэкап лёгкий: историю трафика не тащим, конфиг-таблицы — да."""
    await _make_state(client, auth_headers)
    dump = _read_db_json((await client.get("/api/backup", headers=auth_headers)).content)
    assert "client_traffic_samples" not in dump
    assert "traffic_samples" not in dump
    assert dump["servers"] and "app_settings" in dump  # конфиг на месте


def test_skip_data_dir_excludes_postgres_and_rollback_variants():
    # сырые файлы кластера и откатные каталоги после апгрейда — НЕ в бэкап
    for d in ("postgres", "postgres.v17", "postgres.bak", "pgdata", "backups"):
        assert _skip_data_dir(d), d
    # полезная нагрузка (ssh-ключи и пр.) — остаётся
    for d in ("ssh", "keys", "config"):
        assert not _skip_data_dir(d), d


async def _make_state(client: httpx.AsyncClient, h: dict) -> int:
    """Создаёт сервер + срок клиента + настройки алертов. Возвращает id сервера."""
    r = await client.post(
        "/api/servers",
        headers=h,
        json={"name": "srv-bkp", "host": "203.0.113.50", "ssh_port": 2221,
              "ssh_user": "acontrol"},
    )
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    # срок действия клиента → строка в client_limits
    r = await client.post(
        f"/api/servers/{sid}/limit",
        headers=h,
        json={"protocol": "awg", "client_id": "PUBKEY123", "name": "phone",
              "expires_at": "2030-01-01T00:00:00+00:00"},
    )
    assert r.status_code == 204, r.text
    # настройки алертов → строки в app_settings
    r = await client.put(
        "/api/alerts",
        headers=h,
        json={"telegram_token": "secret-token-42", "telegram_chat": "12345",
              "webhook": ""},
    )
    assert r.status_code == 200, r.text
    return sid


def _read_db_json(archive: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        return json.loads(tar.extractfile("db.json").read())


async def test_backup_includes_previously_dropped_tables(client, auth_headers):
    await _make_state(client, auth_headers)
    r = await client.get("/api/backup", headers=auth_headers)
    assert r.status_code == 200
    dump = _read_db_json(r.content)

    # раньше этих таблиц в дампе не было — теперь есть и не пусты
    assert dump["client_limits"], "сроки клиентов должны быть в бэкапе"
    assert dump["app_settings"], "настройки алертов (токен) должны быть в бэкапе"
    assert dump["audit_log"], "журнал действий должен быть в бэкапе"
    # секрет алертов реально уехал в архив
    assert any("secret-token-42" in s.get("value", "") for s in dump["app_settings"])
    assert dump["client_limits"][0]["client_id"] == "PUBKEY123"


async def test_backup_restore_roundtrip_preserves_expiry_and_alerts(
    client, auth_headers
):
    await _make_state(client, auth_headers)
    archive = (await client.get("/api/backup", headers=auth_headers)).content

    # сносим срок клиента и настройки алертов
    r = await client.get("/api/servers", headers=auth_headers)
    sid = r.json()[0]["id"]
    await client.post(
        f"/api/servers/{sid}/limit",
        headers=auth_headers,
        json={"protocol": "awg", "client_id": "PUBKEY123", "name": "phone",
              "expires_at": None},
    )
    await client.put(
        "/api/alerts", headers=auth_headers,
        json={"telegram_token": "", "telegram_chat": "", "webhook": ""},
    )
    cfg = (await client.get("/api/alerts", headers=auth_headers)).json()
    assert not cfg["telegram_token_set"] if "telegram_token_set" in cfg else True

    # восстановление из архива
    r = await client.post(
        "/api/backup/restore", headers=auth_headers, content=archive
    )
    assert r.status_code == 200, r.text
    restored = r.json()["restored"]
    assert restored["client_limits"] >= 1
    assert restored["app_settings"] >= 1

    # срок клиента вернулся (иначе истёкшие клиенты никогда не отзовутся)
    dump = _read_db_json(
        (await client.get("/api/backup", headers=auth_headers)).content
    )
    assert any(
        cl["client_id"] == "PUBKEY123" and cl["expires_at"]
        for cl in dump["client_limits"]
    )
    # токен алертов вернулся (иначе restore тихо выключил бы алерты)
    assert any(
        "secret-token-42" in s.get("value", "") for s in dump["app_settings"]
    )


async def test_backup_archive_is_gzip(client, auth_headers):
    r = await client.get("/api/backup", headers=auth_headers)
    assert r.headers["content-type"] == "application/gzip"
    # реально распаковывается
    assert gzip.decompress(r.content)[:2] != b""
