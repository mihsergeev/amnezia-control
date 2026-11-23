"""Пароль SSH уходит только хосту с подтвержденным или уже закрепленным ключом.

Раньше первый вход по паролю принимал любой ключ хоста (TOFU) и сразу отдавал
ему пароли SSH и sudo. Тесты поднимают настоящий SSH-сервер asyncssh."""
import asyncssh
import pytest

from app import sshops
from app.sshkeys import ensure_panel_key, key_paths


class _Server(asyncssh.SSHServer):
    seen: list[str] = []
    connections: list = []

    def connection_made(self, conn):
        _Server.connections.append(conn)

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        _Server.seen.append(password)
        return password == "fixture-password"


async def _listen(host_key, port=0):
    server = await asyncssh.listen("127.0.0.1", port, server_host_keys=[host_key], server_factory=_Server,
                                   process_factory=lambda process: process.exit(0))
    return server, server.sockets[0].getsockname()[1]


async def _stop(server):
    # Закрываем и принятые соединения: иначе они переживают тест вместе с циклом событий.
    server.close()
    await server.wait_closed()
    for conn in _Server.connections:
        conn.close()
        await conn.wait_closed()
    _Server.connections = []


@pytest.fixture
def panel(tmp_path):
    ensure_panel_key(str(tmp_path))
    _Server.seen = []
    _Server.connections = []
    return key_paths(str(tmp_path))[0]


def test_fingerprint_matches_ssh_keygen_format_with_or_without_prefix():
    key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
    shown = sshops.fingerprint(key)
    assert shown.startswith("SHA256:")
    assert sshops.same_fingerprint(shown, key)
    assert sshops.same_fingerprint(" " + shown.removeprefix("SHA256:") + "= ", key)
    assert not sshops.same_fingerprint("", key)
    other = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
    assert not sshops.same_fingerprint(sshops.fingerprint(other), key)


async def test_password_reaches_only_the_confirmed_key_and_pins_it(panel):
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server, port = await _listen(host_key)
    try:
        key, known = await sshops.fetch_host_key("127.0.0.1", port, panel, 5)
        assert known is False and sshops.fingerprint(key) == sshops.fingerprint(host_key.convert_to_public())
        assert _Server.seen == []  # получение ключа не входит на сервер

        # Подмена: показанный человеку ключ не тот, что у сервера, - пароль не уходит.
        impostor = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
        with pytest.raises(sshops.HostKeyChangedError):
            await sshops._tofu_connect("127.0.0.1", port, "root", panel, password="fixture-password",
                                       timeout=5, pinned_key=impostor)
        assert _Server.seen == []
        assert not sshops._host_known(sshops._kh_path(panel), "127.0.0.1", port)

        conn = await sshops._tofu_connect("127.0.0.1", port, "root", panel, password="fixture-password",
                                          timeout=5, pinned_key=key)
        conn.close()
        await conn.wait_closed()
        assert _Server.seen == ["fixture-password"]
        _key, known = await sshops.fetch_host_key("127.0.0.1", port, panel, 5)
        assert known is True
    finally:
        await _stop(server)

    # Тот же адрес с другим ключом: закрепленный ключ не дает его выдать за прежний.
    replaced, _ = await _listen(asyncssh.generate_private_key("ssh-ed25519"), port)
    try:
        with pytest.raises(sshops.HostKeyChangedError):
            await sshops.fetch_host_key("127.0.0.1", port, panel, 5)
    finally:
        await _stop(replaced)


async def test_new_host_shows_ed25519_and_pinned_rsa_is_queried_with_sha2(panel, monkeypatch):
    rsa, ed = asyncssh.generate_private_key("ssh-rsa"), asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[rsa, ed], server_factory=_Server,
                                   process_factory=lambda process: process.exit(0))
    port = server.sockets[0].getsockname()[1]
    try:
        key, known = await sshops.fetch_host_key("127.0.0.1", port, panel, 5)
        # человеку показываем ed25519: его сверяют через ssh_host_ed25519_key.pub
        assert known is False and key.get_algorithm() == "ssh-ed25519"
    finally:
        await _stop(server)

    # Закрепленный RSA-ключ запрашивается алгоритмами rsa-sha2-*, не только ssh-rsa (SHA-1).
    kh = sshops._kh_path(panel)
    kh.write_text(f"[127.0.0.1]:2222 {rsa.convert_to_public().export_public_key().decode().strip()}\n")
    seen = {}

    async def fake_get(host, port, **kwargs):
        seen.update(kwargs)
        return rsa.convert_to_public()

    monkeypatch.setattr(sshops.asyncssh, "get_server_host_key", fake_get)
    key, known = await sshops.fetch_host_key("127.0.0.1", 2222, panel, 5)
    assert known is True
    assert "rsa-sha2-512" in seen["server_host_key_algs"] and "rsa-sha2-256" in seen["server_host_key_algs"]


async def test_bootstrap_refuses_unconfirmed_or_mismatched_key_before_sending_password(panel):
    public = ensure_panel_key(str(panel.parent.parent))
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server, port = await _listen(host_key)
    try:
        result = await sshops.bootstrap_server("127.0.0.1", port, "root", "fixture-password", public, "192.0.2.7",
                                               timeout=5, key_path=panel)
        assert result.ok is False and "отпечаток" in result.error
        other = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
        result = await sshops.bootstrap_server("127.0.0.1", port, "root", "fixture-password", public, "192.0.2.7",
                                               timeout=5, key_path=panel, host_key_fingerprint=sshops.fingerprint(other))
        assert result.ok is False and "не совпадает" in result.error and "Пароль не отправлен" in result.error
        assert _Server.seen == []
    finally:
        await _stop(server)


async def test_host_key_endpoint_reports_fingerprint_and_refuses_changed_key(client, auth_headers, monkeypatch):
    sid = (await client.post("/api/servers", json={"name": "hk", "host": "192.0.2.30"}, headers=auth_headers)).json()["id"]
    shown = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()

    async def fetch(host, port, key_path, timeout=10, *, jump=None):
        assert (host, port) == ("192.0.2.30", 22)
        return shown, False

    monkeypatch.setattr(sshops, "fetch_host_key", fetch)
    response = await client.post(f"/api/servers/{sid}/host-key", headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json() == {"known": False, "fingerprint": sshops.fingerprint(shown), "key_type": "ssh-ed25519"}

    async def changed(*args, **kwargs):
        raise sshops.HostKeyChangedError("192.0.2.30:22")

    monkeypatch.setattr(sshops, "fetch_host_key", changed)
    response = await client.post(f"/api/servers/{sid}/host-key", headers=auth_headers)
    assert response.status_code == 409 and "подмена" in response.json()["detail"]


async def test_import_keeps_explicit_trust_on_first_use(client, auth_headers, monkeypatch):
    from app import server_ops

    calls = []

    async def bootstrap(session, server, password, settings, become_password=None, **kwargs):
        calls.append(kwargs)
        return False, "fixture"

    monkeypatch.setattr(server_ops, "bootstrap_and_check", bootstrap)
    response = await client.post("/api/import/bulk", json={"text": "192.0.2.31 root fixture-password"}, headers=auth_headers)
    assert response.status_code == 200, response.text
    assert calls == [{"trust_first_key": True}]
