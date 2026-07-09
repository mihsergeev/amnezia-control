"""Тесты фиксов безопасности (аудит 09.07.2026)."""

import io
import json
import tarfile
import time

import httpx
import pytest

from app import totp


def _make_tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


async def test_restore_blocks_absolute_path_write(
    client: httpx.AsyncClient, auth_headers, tmp_path
):
    """Абсолютный путь внутри архива не должен вырваться за data_dir (RCE-фикс)."""
    data_dir = tmp_path / "data"
    escaped = tmp_path / "ESCAPED.txt"  # сосед data_dir — выход наружу
    archive = _make_tar(
        {
            "db.json": b"{}",
            # rel="/…/ESCAPED.txt" — абсолютный, os.path.join отбрасывает base
            "data/" + str(escaped): b"PWNED",
            "data/marker.txt": b"ok",  # легитимный файл — должен восстановиться
        }
    )
    r = await client.post(
        "/api/backup/restore", content=archive, headers=auth_headers
    )
    assert r.status_code == 200
    assert not escaped.exists()  # выход за data_dir заблокирован
    assert (data_dir / "marker.txt").read_bytes() == b"ok"  # обычный файл цел


async def test_restore_rejects_oversized_body(
    client: httpx.AsyncClient, auth_headers
):
    big = b"x" * (101 * 1024 * 1024)
    r = await client.post("/api/backup/restore", content=big, headers=auth_headers)
    assert r.status_code == 413


async def test_password_change_invalidates_old_tokens(
    client: httpx.AsyncClient
):
    r = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "testpass"}
    )
    old = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert (await client.get("/api/auth/me", headers=old)).status_code == 200

    r = await client.post(
        "/api/auth/password",
        json={"current_password": "testpass", "new_password": "newstrongpass1"},
        headers=old,
    )
    assert r.status_code == 200
    new = {"Authorization": f"Bearer {r.json()['access_token']}"}

    # старый токен больше не действителен, новый — работает
    assert (await client.get("/api/auth/me", headers=old)).status_code == 401
    assert (await client.get("/api/auth/me", headers=new)).status_code == 200
    # логин по новому паролю проходит
    r2 = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "newstrongpass1"}
    )
    assert r2.status_code == 200


async def test_password_change_wrong_current(client: httpx.AsyncClient, auth_headers):
    r = await client.post(
        "/api/auth/password",
        json={"current_password": "WRONG", "new_password": "whatever12"},
        headers=auth_headers,
    )
    assert r.status_code == 400


async def test_totp_code_not_replayable(client: httpx.AsyncClient, auth_headers):
    setup = (await client.post("/api/auth/2fa/setup", headers=auth_headers)).json()
    secret = setup["secret"]
    code = totp._hotp(secret, int(time.time() // 30))
    assert (
        await client.post(
            "/api/auth/2fa/enable", json={"otp": code}, headers=auth_headers
        )
    ).status_code == 200

    # первый вход с кодом — успех
    r1 = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "testpass", "otp": code},
    )
    assert r1.status_code == 200
    # тот же код повторно — отклонён (replay)
    r2 = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "testpass", "otp": code},
    )
    assert r2.status_code == 401
    assert r2.json()["detail"] == "2fa_invalid"


async def test_login_rate_limited_after_failures(client: httpx.AsyncClient):
    from app import ratelimit

    for _ in range(ratelimit.MAX_FAILURES):
        r = await client.post(
            "/api/auth/login", json={"username": "admin", "password": "bad"}
        )
        assert r.status_code == 401
    # следующая попытка блокируется независимо от правильности пароля
    r = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "testpass"}
    )
    assert r.status_code == 429


async def test_ssh_user_rejects_shell_metacharacters(
    client: httpx.AsyncClient, auth_headers
):
    r = await client.post(
        "/api/servers",
        json={"name": "x", "host": "203.0.113.9", "ssh_user": "ev;il`x`"},
        headers=auth_headers,
    )
    assert r.status_code == 422


def test_known_hosts_tofu(tmp_path):
    """TOFU-хелперы: запись host-ключа и последующее распознавание по host:port."""
    import asyncssh

    from app import sshops

    key_path = tmp_path / "ssh" / "id_ed25519"
    key_path.parent.mkdir(parents=True)
    kh = sshops._kh_path(key_path)
    host, port = "203.0.113.10", 2221

    assert not sshops._host_known(kh, host, port)  # изначально неизвестен

    hostkey = asyncssh.generate_private_key("ssh-ed25519")

    class FakeConn:
        def get_server_host_key(self):
            return hostkey

    sshops._record_host_key(kh, host, port, FakeConn())
    assert sshops._host_known(kh, host, port)  # записан и распознан
    assert not sshops._host_known(kh, host, 22)  # другой порт — не тот хост
    assert "[203.0.113.10]:2221" in kh.read_text()  # формат [host]:port

    # повторная запись не дублирует
    sshops._record_host_key(kh, host, port, FakeConn())
    assert kh.read_text().count("[203.0.113.10]:2221") == 1


def test_enforce_secrets_rejects_weak():
    from app.config import Settings
    from app.main import _enforce_secrets

    with pytest.raises(RuntimeError):
        _enforce_secrets(Settings(jwt_secret="changeme", admin_password="strongpass"))
    with pytest.raises(RuntimeError):
        _enforce_secrets(Settings(jwt_secret="x" * 40, admin_password="admin"))
    # debug — разрешаем слабые (локальная разработка)
    _enforce_secrets(Settings(debug=True, jwt_secret="changeme", admin_password="admin"))
    # сильные — ок
    _enforce_secrets(
        Settings(jwt_secret="a" * 40, admin_password="strong-enough-pass")
    )
