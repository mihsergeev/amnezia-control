import io
import json
import tarfile

import httpx
import pytest

from app import config
from app.bootstrap import ensure_admin
from app.db import Base
from app.main import create_app
from app.sshkeys import ensure_panel_key


@pytest.fixture
async def sqlite_client(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("VPNPANEL_DB_URL", f"sqlite+aiosqlite:///{(data / 'panel.db').as_posix()}")
    monkeypatch.setenv("VPNPANEL_DATA_DIR", data.as_posix())
    monkeypatch.setenv("VPNPANEL_ADMIN_PASSWORD", "testpass")
    monkeypatch.setenv("VPNPANEL_JWT_SECRET", "runtime-backup-test-secret-0123456789abcdef")
    config.get_settings.cache_clear()
    app = create_app()
    async with app.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await ensure_admin(app.state.session_factory, config.get_settings())
    ensure_panel_key(str(data))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        login = await client.post("/api/auth/login", json={"username": "admin", "password": "testpass"})
        client.headers["Authorization"] = "Bearer " + login.json()["access_token"]
        yield client, data
    await app.state.engine.dispose()
    config.get_settings.cache_clear()


async def test_sqlite_backup_excludes_live_database(sqlite_client):
    client, data = sqlite_client
    for suffix in ("-wal", "-shm", "-journal"):
        (data / ("panel.db" + suffix)).write_bytes(b"runtime-sidecar")
    r = await client.post("/api/backup/download", json={"password": "testpass"})
    assert r.status_code == 200, r.text
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
        names = tar.getnames()
    assert not any(n.startswith("data/panel.db") for n in names)
    assert "db.json" in names and "data/ssh/id_ed25519" in names


async def test_legacy_archive_cannot_overwrite_live_sqlite(sqlite_client):
    client, data = sqlite_client
    old_token = client.headers["Authorization"]
    r = await client.post("/api/backup/download", json={"password": "testpass"})
    assert r.status_code == 200, r.text
    # Старые версии клали raw SQLite в архив. JSON-восстановление должно
    # остаться единственным источником данных даже для такого архива.
    buf = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as src:
        files = {m.name: src.extractfile(m).read() for m in src.getmembers() if m.isfile()}
    files["data/panel.db"] = (data / "panel.db").read_bytes()
    with tarfile.open(fileobj=buf, mode="w:gz") as dst:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            dst.addfile(info, io.BytesIO(content))
    restored = await client.post("/api/backup/restore", headers={"X-Confirm-Password": "testpass"}, content=buf.getvalue())
    assert restored.status_code == 200, restored.text
    # Raw SQLite не должен откатить новое token_version, записанное restore.
    response = await client.get("/api/servers", headers={"Authorization": old_token})
    assert response.status_code == 401


async def test_restore_rejects_broken_expiry_before_changing_state(sqlite_client):
    client, data = sqlite_client
    r = await client.post("/api/backup/download", json={"password": "testpass"})
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as src:
        files = {m.name: src.extractfile(m).read() for m in src.getmembers() if m.isfile()}
    dump = json.loads(files["db.json"])
    dump["client_limits"] = [{
        "id": 1, "server_id": 1, "protocol": "awg", "client_id": "test-client",
        "expires_at": "not-a-date",
    }]
    files["db.json"] = json.dumps(dump).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as dst:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            dst.addfile(info, io.BytesIO(content))
    restored = await client.post("/api/backup/restore", headers={"X-Confirm-Password": "testpass"}, content=buf.getvalue())
    assert restored.status_code == 400
    assert (await client.get("/api/servers")).status_code == 200
