"""Бэкап/восстановление: раньше дамп молча терял 7 из 13 таблиц (сроки клиентов,
настройки алертов, журнал). Тесты фиксируют, что теперь эти таблицы попадают в
архив и корректно восстанавливаются."""

import gzip
import io
import json
import tarfile

import httpx
import pytest

from app import apikeys
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
    dump = _read_db_json((await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})).content)
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
              "webhook": "", "password": "testpass"},
    )
    assert r.status_code == 200, r.text
    return sid


def _read_db_json(archive: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        return json.loads(tar.extractfile("db.json").read())


async def test_backup_includes_previously_dropped_tables(client, auth_headers):
    await _make_state(client, auth_headers)
    r = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
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
    archive = (await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})).content

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
        json={"telegram_token": "", "telegram_chat": "", "webhook": "", "password": "testpass"},
    )
    cfg = (await client.get("/api/alerts", headers=auth_headers)).json()
    assert not cfg["telegram_token_set"]

    # восстановление из архива
    r = await client.post(
        "/api/backup/restore", content=archive,
        headers={**auth_headers, "X-Confirm-Password": "testpass"}
    )
    assert r.status_code == 200, r.text
    restored = r.json()["restored"]
    # старые токены restore отзывает, новый приходит в ответе
    auth_headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert restored["client_limits"] >= 1
    assert restored["app_settings"] >= 1

    # срок клиента вернулся (иначе истёкшие клиенты никогда не отзовутся)
    dump = _read_db_json(
        (await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})).content
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
    r = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
    assert r.headers["content-type"] == "application/gzip"
    # реально распаковывается
    assert gzip.decompress(r.content)[:2] != b""


def test_backup_covers_every_table():
    """Новая таблица должна попасть в бэкап или в явный список исключений:
    так из бэкапа пропадали каскады и торрент-попадания."""
    from app.api.backup import _MODELS, _NOT_BACKED_UP
    from app.db import Base

    covered = {m.__tablename__ for m in _MODELS}
    assert covered | set(_NOT_BACKED_UP) == set(Base.metadata.tables)
    names = [m.__tablename__ for m in _MODELS]
    # зависимые от серверов таблицы восстанавливаются после servers
    assert names.index("servers") < names.index("cascades")


def test_skip_data_dir_excludes_tls_and_heartbeat():
    # ключи TLS/ACME Caddy и пульс с токеном Telegram в бэкап не идут
    for d in ("caddy", "heartbeat", "heartbeat.tmp"):
        assert _skip_data_dir(d), d


def _tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for n, d in files.items():
            info = tarfile.TarInfo(n)
            info.size = len(d)
            tar.addfile(info, io.BytesIO(d))
    return buf.getvalue()


@pytest.mark.parametrize("reverse", [False, True])
async def test_restore_rejects_archive_path_conflict_before_mutation(
    client, auth_headers, tmp_path, reverse,
):
    created = await client.post("/api/servers", headers=auth_headers, json={
        "name": "srv-bkp", "host": "203.0.113.50",
    })
    assert created.status_code == 201, created.text
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    marker = data / "marker.txt"
    marker.write_bytes(b"before")
    collision = [("data/folder", b"file"), ("data/folder/conflict", b"child")]
    if reverse:
        collision.reverse()
    archive = _tar({
        "db.json": b'{"servers": []}',
        "data/marker.txt": b"after",
        **dict(collision),
    })
    response = await client.post(
        "/api/backup/restore", content=archive,
        headers={**auth_headers, "X-Confirm-Password": "testpass"},
    )
    assert response.status_code == 400, response.text
    assert "конфликт файла и каталога" in response.json()["detail"]
    servers = await client.get("/api/servers", headers=auth_headers)
    assert [server["name"] for server in servers.json()] == ["srv-bkp"]
    assert marker.read_bytes() == b"before"
    assert not (data / "folder").exists()


async def test_restore_retires_keys_absent_from_older_archive(client, auth_headers):
    key, prefix, key_hash = apikeys.generate()
    headers = {**auth_headers, "X-Confirm-Password": "testpass"}
    key_headers = {"X-API-Key": key}
    older = _tar({"db.json": b'{"api_keys": []}'})
    newer = _tar({"db.json": json.dumps({"api_keys": [{
        "id": 1, "name": "integration", "prefix": prefix, "key_hash": key_hash,
        "revoked": False,
    }]}).encode()})

    # При переносе на чистую панель активный ключ архива сохраняет доступ.
    imported = await client.post("/api/backup/restore", content=newer, headers=headers)
    assert imported.status_code == 200, imported.text
    assert (await client.get("/api/v1/servers", headers=key_headers)).status_code == 200

    rolled_back = await client.post("/api/backup/restore", content=older, headers=headers)
    assert rolled_back.status_code == 200, rolled_back.text
    keys = (await client.get("/api/apikeys", headers=auth_headers)).json()
    assert len(keys) == 1 and keys[0]["revoked"] is True
    assert (await client.get("/api/v1/servers", headers=key_headers)).status_code == 401

    issued = await client.post("/api/apikeys", headers=auth_headers, json={
        "name": "next integration", "password": "testpass",
    })
    assert issued.status_code == 201, issued.text

    restored = await client.post("/api/backup/restore", content=newer, headers=headers)
    assert restored.status_code == 200, restored.text
    assert (await client.get("/api/v1/servers", headers=key_headers)).status_code == 401


async def test_backup_restores_cascades_and_skips_secrets(client, auth_headers, tmp_path):
    from sqlalchemy import select, text

    from app.models import Cascade, Server, TorrentHit

    async with client.session_factory() as s:
        srv = Server(name="srv-bkp", host="203.0.113.50", ssh_port=22, ssh_user="acontrol")
        s.add(srv)
        await s.commit()
        sid = srv.id
    data = tmp_path / "data"
    (data / "caddy" / "data").mkdir(parents=True)
    (data / "caddy" / "data" / "acme.key").write_bytes(b"TLS-KEY")
    (data / "heartbeat").write_text("tg_token=secret\n")
    (data / "ssh").mkdir(exist_ok=True)
    (data / "ssh" / "id_ed25519").write_bytes(b"FAKE-KEY")
    from datetime import datetime, timezone
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    async with client.session_factory() as s:
        s.add(Cascade(id=7, entry_server_id=sid, exit_server_id=sid + 100,
                      transport="gre", status="ready"))
        s.add(TorrentHit(server_id=sid, protocol="awg", client_id="K=", hits=3,
                         first_seen=now, last_seen=now))
        await s.commit()

    archive = (await client.post("/api/backup/download", headers=auth_headers,
                                 json={"password": "testpass"})).content
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        names = set(tar.getnames())
    assert "data/ssh/id_ed25519" in names
    assert not any(n.startswith("data/caddy") or n == "data/heartbeat" for n in names)
    dump = _read_db_json(archive)
    assert dump["cascades"][0]["id"] == 7 and dump["torrent_hits"]

    async with client.session_factory() as s:
        await s.execute(text("DELETE FROM cascades"))
        await s.commit()
    h = {**auth_headers, "X-Confirm-Password": "testpass"}
    r = await client.post("/api/backup/restore", content=archive, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["restored"]["cascades"] == 1
    async with client.session_factory() as s:
        assert [c.id for c in await s.scalars(select(Cascade))] == [7]
        # новый каскад после restore получает свободный id
        s.add(Cascade(entry_server_id=sid + 1, exit_server_id=sid + 2, transport="gre"))
        await s.commit()
        assert sorted(await s.scalars(select(Cascade.id))) == [7, 8]

    # старый архив (без cascades и torrent_hits) не падает и их не трогает;
    # restore мог отозвать токены - входим заново
    login = await client.post("/api/auth/login", json={"username": "admin", "password": "testpass"})
    h = {"Authorization": f"Bearer {login.json()['access_token']}", "X-Confirm-Password": "testpass"}
    old = dict(dump)
    old.pop("cascades")
    old.pop("torrent_hits")
    r = await client.post(
        "/api/backup/restore", headers=h,
        content=_tar({"db.json": json.dumps(old).encode(), "data/ssh/id_ed25519": b"FAKE-KEY"}),
    )
    assert r.status_code == 200, r.text
    assert "cascades" not in r.json()["restored"]
    async with client.session_factory() as s:
        assert sorted(await s.scalars(select(Cascade.id))) == [7, 8]
