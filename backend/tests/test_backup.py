"""Бэкап/восстановление: раньше дамп молча терял 7 из 13 таблиц (сроки клиентов,
настройки алертов, журнал). Тесты фиксируют, что теперь эти таблицы попадают в
архив и корректно восстанавливаются."""

import gzip
import hashlib
import io
import json
import tarfile
import asyncio
from types import SimpleNamespace

import httpx
import pytest

from app import apikeys
from app.api.backup import _skip_data_dir, verify_archive
from sqlalchemy import delete, select
from app.models import AwgConfig, AwgSettingsChange, PausedClient, Server


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


@pytest.mark.parametrize("fault", [
    "file_write", "file_install", "stale_move", "database_commit", "lost_reply", "rollback_io_failure",
])
async def test_restore_preserves_panel_state_if_replacement_fails(
    client, auth_headers, tmp_path, monkeypatch, fault,
):
    import gc
    import os
    import sqlite3
    import stat
    from pathlib import Path

    from sqlalchemy.exc import DBAPIError, IntegrityError
    from sqlalchemy.ext.asyncio import AsyncSession

    from app import backup_files, native_snapshots, ssh_archives
    from app.api.backup import _build_archive
    from app.models import AppSetting, NativeVpnConfig

    data = tmp_path / "data"
    ssh_dir = data / "ssh"
    ssh_dir.mkdir(parents=True)
    key = data / "ssh/id_ed25519"
    stale_key = data / "ssh/jump_1"
    settings_file = data / "new/settings.txt"
    local_file = data / "flags.txt"
    key.write_bytes(b"synthetic archive key")
    async with client.session_factory() as session:
        server = Server(id=1, name="archive", host="192.0.2.10")
        awg = AwgConfig(server_id=1, public_key="public-test", name="awg-profile", config="awg archived")
        native = NativeVpnConfig(server_id=1, protocol="wireguard", client_id="test-client",
                                name="native-profile", config="native archived")
        session.add_all((server, awg, native))
        await session.commit()
        await native_snapshots.save(session, server, "wireguard", "20260101-000000",
                                    {"port": 51820, "transport": "udp"})

    download = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
    assert download.status_code == 200
    archived = _read_db_json(download.content)
    archive = _tar({
        "db.json": json.dumps(archived).encode(),
        "data/ssh/id_ed25519": key.read_bytes(),
        "data/flags.txt": b"archived flag",
        "data/new/settings.txt": b"archive-only file",
    })
    key.write_bytes(b"synthetic current key")
    local_file.write_bytes(b"current flag")
    stale_key.write_bytes(b"synthetic stale key")
    ssh_dir.chmod(0o750)
    local_file.chmod(0o640)
    before_modes = {path: stat.S_IMODE(path.stat().st_mode) for path in (ssh_dir, local_file, key, stale_key)}
    async with client.session_factory() as session:
        server = await session.get(Server, 1)
        server.name = "current"
        server.host = "192.0.2.11"
        (await session.scalar(select(AwgConfig))).config = "awg current"
        (await session.scalar(select(NativeVpnConfig))).config = "native current"
        await session.execute(delete(AppSetting))
        await session.commit()
        await native_snapshots.save(session, server, "wireguard", "20260102-000000",
                                    {"port": 51821, "transport": "udp"})

    def digest(content):
        return hashlib.sha256(content).hexdigest()

    async def panel_state():
        async with client.session_factory() as session:
            server = (await session.execute(select(Server.name, Server.host))).one()
            awg = await session.scalar(select(AwgConfig.config))
            native = await session.scalar(select(NativeVpnConfig.config))
            snapshot = (await session.execute(select(AppSetting.key, AppSetting.value))).one()
        return {
            "server": tuple(server), "awg": digest(awg.encode()), "native": digest(native.encode()),
            "snapshot": (snapshot.key, digest(snapshot.value.encode())),
            "files": {path.relative_to(data).as_posix(): digest(path.read_bytes())
                      for path in data.rglob("*")
                      if path.is_file() and path.relative_to(data).parts[0] != "debug-logs"},
        }

    before = await panel_state()
    restore_file = ssh_archives.restore_file
    replace = os.replace
    commit = AsyncSession.commit
    injected = []

    def fail_file_write(dest, member, tar, data_dir):
        if member.name == "data/new/settings.txt":
            injected.append(fault)
            raise OSError("synthetic file write failure")
        restore_file(dest, member, tar, data_dir)

    def fail_replace(src, dest):
        if fault == "rollback_io_failure" and Path(dest) == key and "original" in Path(src).parts:
            injected.append("rollback")
            raise OSError("synthetic rollback write failure")
        if ((fault in ("file_install", "rollback_io_failure") and Path(dest) == settings_file)
                or (fault == "stale_move" and Path(src) == stale_key)):
            assert key.read_bytes() == b"synthetic archive key"
            assert local_file.read_bytes() == b"archived flag"
            injected.append(fault)
            raise OSError("synthetic file replacement failure")
        return replace(src, dest)

    async def fail_database_commit(session):
        assert settings_file.read_bytes() == b"archive-only file"
        assert not stale_key.exists()
        injected.append(fault)
        if fault == "lost_reply":
            await commit(session)
            raise DBAPIError("COMMIT", None, ConnectionError("synthetic lost reply"), connection_invalidated=True)
        raise IntegrityError("COMMIT", None, sqlite3.IntegrityError("synthetic deferred constraint failure"))

    headers = {**auth_headers, "X-Confirm-Password": "testpass"}
    with monkeypatch.context() as faults:
        faults.setattr(client._transport, "raise_app_exceptions", False)
        if fault == "file_write":
            faults.setattr(ssh_archives, "restore_file", fail_file_write)
        elif fault in ("file_install", "stale_move", "rollback_io_failure"):
            faults.setattr(os, "replace", fail_replace)
        else:
            faults.setattr(AsyncSession, "commit", fail_database_commit)
        response = await client.post("/api/backup/restore", content=archive, headers=headers)

    assert response.status_code == 500
    if fault == "rollback_io_failure":
        assert injected == [fault, "rollback"]
        work, = data.glob(backup_files.WORK_PREFIX + "*")
        assert work.name in response.json()["detail"]
        assert "Не удалось полностью вернуть файлы" in response.json()["detail"]
        assert (work / "original/ssh/id_ed25519").read_bytes() == b"synthetic current key"
        restored = await panel_state()
        assert key.read_bytes() == b"synthetic archive key"
        assert local_file.read_bytes() == b"current flag"
        assert stale_key.read_bytes() == b"synthetic stale key"
        assert {field: value for field, value in restored.items() if field != "files"} == {
            field: value for field, value in before.items() if field != "files"
        }
        return
    assert injected == [fault]
    if fault == "lost_reply":
        gc.collect()
        work, = data.glob(backup_files.WORK_PREFIX + "*")
        assert work.name in response.json()["detail"]
        assert "Результат записи в БД неизвестен" in response.json()["detail"]
        if os.name != "nt":
            assert stat.S_IMODE(work.stat().st_mode) == 0o700
        assert (work / "original/ssh/id_ed25519").read_bytes() == b"synthetic current key"
        assert (work / "original/ssh/jump_1").read_bytes() == b"synthetic stale key"
        assert (work / "original/flags.txt").read_bytes() == b"current flag"
        assert json.loads((work / "changes.json").read_text())["new"] == ["new/settings.txt"]
        async with client.session_factory() as session:
            downloaded = await _build_archive(session, str(data), "0.0.0")
        with tarfile.open(fileobj=io.BytesIO(downloaded), mode="r:gz") as tar:
            assert not any(backup_files.WORK_PREFIX in name for name in tar.getnames())
    else:
        assert response.json()["detail"] == "Не удалось завершить восстановление панели"
        assert await panel_state() == before
        assert not (data / "new").exists()
        assert {path: stat.S_IMODE(path.stat().st_mode) for path in before_modes} == before_modes
        assert not list(data.glob(backup_files.WORK_PREFIX + "*"))
        retried = await client.post("/api/backup/restore", content=archive, headers=headers)
        assert retried.status_code == 200
    after = await panel_state()
    assert after["server"] == ("archive", "192.0.2.10")
    assert after["awg"] == digest(b"awg archived")
    assert after["native"] == digest(b"native archived")
    snapshot = archived["app_settings"][0]
    assert after["snapshot"] == (snapshot["key"], digest(snapshot["value"].encode()))
    assert {name: value for name, value in after["files"].items() if not name.startswith(backup_files.WORK_PREFIX)} == {
        "ssh/id_ed25519": digest(b"synthetic archive key"),
        "flags.txt": digest(b"archived flag"),
        "new/settings.txt": digest(b"archive-only file"),
    }
    assert stat.S_IMODE(local_file.stat().st_mode) == before_modes[local_file]
    if os.name != "nt":
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        assert stat.S_IMODE(ssh_dir.stat().st_mode) == 0o700


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


@pytest.mark.parametrize("phase,outcome", [("prepared", "rolledback"), ("applied", "rolledback"),
    ("applied", "committed"), ("done", None), ("rolledback", None)])
async def test_awg_journal_backup_restore_roundtrip_and_recovery(client, auth_headers, monkeypatch, phase, outcome):
    from test_awg_settings import prepare_case
    sid, _, remote, _, old = await prepare_case(client, auth_headers, monkeypatch)
    new = old.replace('10.73.1.7', '10.74.1.7')
    async with client.session_factory() as session:
        profile = await session.scalar(select(AwgConfig))
        paused = await session.scalar(select(PausedClient))
        old_paused = paused.data
        new_paused = old_paused.replace('10.73.1.8', '10.74.1.8')
        payload = {'profiles': [{'id': profile.id, 'old': old, 'new': new}],
                   'paused': [{'id': paused.id, 'old': old_paused, 'new': new_paused}]}
        profile.config = new if phase in ('applied', 'done') else old
        paused.data = new_paused if phase in ('applied', 'done') else old_paused
        session.add(AwgSettingsChange(id='a' * 32, server_id=sid, protocol='awg3', phase=phase,
                                      payload=payload if phase in ('prepared', 'applied') else {}))
        await session.commit()
    response = await client.post('/api/backup/download', headers=auth_headers, json={'password': 'testpass'})
    assert response.status_code == 200
    archive = response.content
    dump = _read_db_json(archive)
    assert dump['awg_settings_changes'][0]['phase'] == phase
    assert dump['awg_settings_changes'][0]['payload'] == (payload if phase in ('prepared', 'applied') else {})
    # Restore onto a clean target, rather than overwriting a live pending change.
    async with client.session_factory() as session:
        await session.execute(delete(AwgSettingsChange))
        await session.execute(delete(AwgConfig))
        await session.execute(delete(PausedClient))
        await session.commit()
    response = await client.post('/api/backup/restore', content=archive,
        headers=auth_headers | {'X-Confirm-Password': 'testpass'})
    assert response.status_code == 200, response.status_code
    assert response.json()['restored']['awg_settings_changes'] == 1
    headers = {'Authorization': 'Bearer ' + response.json()['access_token']}
    async with client.session_factory() as session:
        change = await session.get(AwgSettingsChange, 'a' * 32)
        assert change.phase == phase
        assert change.payload == (payload if phase in ('prepared', 'applied') else {})
    if phase in ('prepared', 'applied'):
        # An archived prepared operation must not undo a remotely committed
        # change. Unknown SSH also keeps an applied operation durable.
        remote['phase'] = 'committed' if phase == 'prepared' else 'missing'
        response = await client.get(f'/api/servers/{sid}/awg3/settings', headers=headers)
        assert response.status_code == 409
        assert 'rollback' not in remote['actions']
        async with client.session_factory() as session:
            change = await session.get(AwgSettingsChange, 'a' * 32)
            assert change.phase == phase and change.payload == payload
        remote['phase'] = outcome
        response = await client.get(f'/api/servers/{sid}/awg3/settings', headers=headers)
        assert response.status_code == 200
        async with client.session_factory() as session:
            assert (await session.scalar(select(AwgConfig))).config == (new if outcome == 'committed' else old)
            assert (await session.scalar(select(PausedClient))).data == (new_paused if outcome == 'committed' else old_paused)
            change = await session.get(AwgSettingsChange, 'a' * 32)
            assert change.phase == ('done' if outcome == 'committed' else 'rolledback') and change.payload == {}


@pytest.mark.parametrize('phase', ['prepared', 'applied', 'unrecognized'])
async def test_old_backup_cannot_erase_live_unresolved_awg_journal(client, auth_headers, tmp_path, phase):
    async with client.session_factory() as session:
        session.add(Server(id=1, name='original', host='192.0.2.10'))
        session.add(AwgSettingsChange(id='b' * 32, server_id=1, protocol='awg3', phase=phase,
                                      payload={'profiles': [], 'paused': []}))
        await session.commit()
    marker = tmp_path / 'data' / 'marker'
    marker.parent.mkdir(exist_ok=True)
    marker.write_bytes(b'before')
    archive = _tar({'db.json': b'{"servers": []}', 'data/marker': b'after'})
    response = await client.post('/api/backup/restore', content=archive,
        headers=auth_headers | {'X-Confirm-Password': 'testpass'})
    assert response.status_code == 409
    assert marker.read_bytes() == b'before'
    async with client.session_factory() as session:
        assert (await session.get(Server, 1)).name == 'original'
        assert (await session.get(AwgSettingsChange, 'b' * 32)).phase == phase


async def test_old_backup_discards_only_terminal_journal_when_replacing_servers(client, auth_headers):
    async with client.session_factory() as session:
        session.add(Server(id=1, name='original', host='192.0.2.10'))
        session.add(AwgSettingsChange(id='c' * 32, server_id=1, protocol='awg3', phase='done', payload={}))
        await session.commit()
    archive = _tar({'db.json': json.dumps({'servers': [{'id': 1, 'name': 'replacement',
        'host': '192.0.2.20', 'ssh_user': 'service'}]}).encode()})
    response = await client.post('/api/backup/restore', content=archive,
        headers=auth_headers | {'X-Confirm-Password': 'testpass'})
    assert response.status_code == 200
    async with client.session_factory() as session:
        assert (await session.get(Server, 1)).name == 'replacement'
        assert not list(await session.scalars(select(AwgSettingsChange)))


@pytest.mark.parametrize('invalid', ['missing_table', 'wrong_server', 'wrong_protocol', 'mixed_snapshot',
                                    'bad_id', 'bad_phase', 'bad_payload', 'bad_items', 'bad_profile_id',
                                    'omitted_profile', 'omitted_paused', 'partial_binding',
                                    'binding_bool_port', 'binding_bad_revision', 'binding_bad_address'])
async def test_restore_rejects_unbound_or_mixed_pending_journal_before_mutation(client, auth_headers, invalid):
    await _make_state(client, auth_headers)
    dump = {'servers': [{'id': 1, 'name': 'archived', 'host': '192.0.2.20', 'ssh_user': 'service'}],
            'awg_configs': [{'id': 1, 'server_id': 1, 'protocol': 'awg3', 'config': 'old'}], 'paused_clients': [],
            'awg_settings_changes': [{'id': 'd' * 32, 'server_id': 1, 'protocol': 'awg3', 'phase': 'prepared',
                'payload': {'profiles': [{'id': 1, 'old': 'old', 'new': 'new'}], 'paused': []}}]}
    if invalid == 'missing_table': dump.pop('awg_configs')
    elif invalid == 'wrong_server': dump['awg_configs'][0]['server_id'] = 2
    elif invalid == 'wrong_protocol': dump['awg_configs'][0]['protocol'] = 'awg'
    elif invalid == 'mixed_snapshot': dump['awg_configs'][0]['config'] = 'new'
    elif invalid == 'bad_id': dump['awg_settings_changes'][0]['id'] = 'invalid'
    elif invalid == 'bad_phase': dump['awg_settings_changes'][0]['phase'] = 'future'
    elif invalid == 'bad_payload': dump['awg_settings_changes'][0]['payload'] = []
    elif invalid == 'bad_profile_id': dump['awg_configs'][0]['id'] = []
    elif invalid.startswith('binding_') or invalid == 'partial_binding':
        binding = {'old_revision': 'e' * 64, 'old_port': 47500, 'old_address': '10.73.1.1/24'}
        if invalid == 'partial_binding': binding.pop('old_revision')
        elif invalid == 'binding_bool_port': binding['old_port'] = True
        elif invalid == 'binding_bad_revision': binding['old_revision'] = 'not-a-fingerprint'
        elif invalid == 'binding_bad_address': binding['old_address'] = '10.73.1.1/24\nmalformed'
        dump['awg_settings_changes'][0]['payload'].update(binding)
    elif invalid in ('omitted_profile', 'omitted_paused'):
        dump['awg_settings_changes'][0]['phase'] = 'applied'
        dump['awg_configs'][0]['config'] = 'new'
        if invalid == 'omitted_profile': dump['awg_settings_changes'][0]['payload']['profiles'] = []
        else: dump['paused_clients'] = [{'id': 1, 'server_id': 1, 'protocol': 'awg3',
            'client_id': 'synthetic-paused', 'data': 'new-paused'}]
    else: dump['awg_settings_changes'][0]['payload']['profiles'] = 'invalid'
    response = await client.post('/api/backup/restore', content=_tar({'db.json': json.dumps(dump).encode()}),
        headers=auth_headers | {'X-Confirm-Password': 'testpass'})
    assert response.status_code == 400
    async with client.session_factory() as session:
        assert (await session.get(Server, 1)).name == 'srv-bkp'
        assert not list(await session.scalars(select(AwgSettingsChange)))


@pytest.mark.parametrize('operation', ['update', 'recovery'])
async def test_backup_and_restore_exclude_live_awg_transactions(client, auth_headers, monkeypatch, operation):
    from test_awg_settings import prepare_case
    from app import awg_settings
    sid, body, remote, _, old = await prepare_case(client, auth_headers, monkeypatch)
    entered, release = asyncio.Event(), asyncio.Event()
    action = awg_settings.remote_action
    async def blocked(conn, token, verb):
        if verb == ('finalize' if operation == 'update' else 'status'):
            entered.set()
            await release.wait()
        return await action(conn, token, verb)
    monkeypatch.setattr(awg_settings, 'remote_action', blocked)
    if operation == 'recovery':
        async with client.session_factory() as session:
            profile = await session.scalar(select(AwgConfig))
            session.add(AwgSettingsChange(id='e' * 32, server_id=sid, protocol='awg3', phase='prepared',
                payload={'profiles': [{'id': profile.id, 'old': old, 'new': old}], 'paused': []}))
            await session.commit()
        task = asyncio.create_task(client.get(f'/api/servers/{sid}/awg3/settings', headers=auth_headers))
    else:
        task = asyncio.create_task(client.put(f'/api/servers/{sid}/awg3/settings', headers=auth_headers, json=body))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        response = await client.post('/api/backup/download', headers=auth_headers, json={'password': 'testpass'})
        assert response.status_code == 409
        response = await client.post('/api/backup/restore', content=_tar({'db.json': b'{"servers": []}'}),
            headers=auth_headers | {'X-Confirm-Password': 'testpass'})
        assert response.status_code == 409
    finally:
        release.set()
        await asyncio.wait_for(task, 5)
    response = await client.post('/api/backup/download', headers=auth_headers, json={'password': 'testpass'})
    assert response.status_code == 200
    dump = _read_db_json(response.content)
    assert dump['awg_settings_changes'][0]['phase'] in ('done', 'rolledback')


async def test_awg_writer_cannot_change_tables_mid_backup_snapshot(client, auth_headers, monkeypatch):
    from test_awg_settings import prepare_case
    from app.api import backup
    sid, body, remote, _, _ = await prepare_case(client, auth_headers, monkeypatch)
    entered, release = asyncio.Event(), asyncio.Event()
    async with client.session_factory() as session:
        scalars = session.scalars
        async def paused(query, *args, **kwargs):
            if query.column_descriptions[0]['entity'] is AwgConfig:
                entered.set()
                await release.wait()
            return await scalars(query, *args, **kwargs)
        monkeypatch.setattr(session, 'scalars', paused)
        task = asyncio.create_task(backup._build_archive(session, '', 'test'))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            response = await client.put(f'/api/servers/{sid}/awg3/settings', headers=auth_headers, json=body)
            assert response.status_code == 409 and remote['actions'] == []
        finally:
            release.set()
            archive = await asyncio.wait_for(task, 5)
    assert not _read_db_json(archive)['awg_settings_changes']


async def test_postgres_restore_reseeds_integer_ids_but_not_journal_tokens():
    from app.api.backup import _MODELS, _reset_sequences
    from sqlalchemy.dialects import postgresql

    queries = []

    class Session:
        bind = SimpleNamespace(dialect=postgresql.dialect())

        async def execute(self, query, params=None):
            queries.append((str(query), params))
            sequence = ('":test schema".servers_id_seq', 42) if params == {"table": "servers"} else None
            return SimpleNamespace(one_or_none=lambda: sequence)

        async def connection(self):
            return self

        async def exec_driver_sql(self, query):
            queries.append((query, None))

    await _reset_sequences(Session(), _MODELS)
    assert any(params == {"table": "servers"} for _, params in queries)
    assert ('ALTER SEQUENCE ":test schema".servers_id_seq RESTART WITH 42', None) in queries
    assert all('awg_settings_changes' not in query and 'setval' not in query for query, _ in queries)
