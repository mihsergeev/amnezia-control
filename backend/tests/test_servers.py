import httpx

NEW_SERVER = {
    "name": "kz-admin",
    "host": "203.0.113.10",
    "ssh_port": 2221,
    "ssh_user": "ms-dev",
    "note": "тестовый стенд",
}


async def test_list_requires_auth(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/servers")
    assert response.status_code == 401


async def test_crud_flow(client: httpx.AsyncClient, auth_headers) -> None:
    # создание
    response = await client.post("/api/servers", json=NEW_SERVER, headers=auth_headers)
    assert response.status_code == 201
    created = response.json()
    assert created["name"] == "kz-admin"
    assert created["ssh_port"] == 2221
    server_id = created["id"]

    # список
    response = await client.get("/api/servers", headers=auth_headers)
    assert response.status_code == 200
    servers = response.json()
    assert len(servers) == 1
    assert servers[0]["id"] == server_id

    # чтение одного
    response = await client.get(f"/api/servers/{server_id}", headers=auth_headers)
    assert response.status_code == 200

    # обновление
    response = await client.patch(
        f"/api/servers/{server_id}",
        json={"name": "kz-admin-2", "note": ""},
        headers=auth_headers,
    )
    assert response.status_code == 200
    updated = response.json()
    assert updated["name"] == "kz-admin-2"
    assert updated["host"] == "203.0.113.10"

    # удаление
    response = await client.delete(f"/api/servers/{server_id}", headers=auth_headers)
    assert response.status_code == 200

    response = await client.get("/api/servers", headers=auth_headers)
    assert response.json() == []


async def test_get_missing_returns_404(client: httpx.AsyncClient, auth_headers) -> None:
    response = await client.get("/api/servers/9999", headers=auth_headers)
    assert response.status_code == 404


async def test_create_validates_port(client: httpx.AsyncClient, auth_headers) -> None:
    bad = dict(NEW_SERVER, ssh_port=99999)
    response = await client.post("/api/servers", json=bad, headers=auth_headers)
    assert response.status_code == 422


async def test_delete_default_keeps_key(client: httpx.AsyncClient, auth_headers) -> None:
    created = await client.post("/api/servers", json=NEW_SERVER, headers=auth_headers)
    sid = created.json()["id"]
    response = await client.delete(f"/api/servers/{sid}", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["key_removed"] is None  # снятие ключа не запрашивали
    listing = await client.get("/api/servers", headers=auth_headers)
    assert all(s["id"] != sid for s in listing.json())


async def test_delete_with_key_removal(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    from app import sshops

    class _Dummy:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    captured = {}

    async def fake_remove(conn, public_key):
        captured["key"] = public_key

    monkeypatch.setattr(sshops, "connect", lambda *a, **k: _Dummy())
    monkeypatch.setattr(sshops, "remove_authorized_key", fake_remove)

    created = await client.post("/api/servers", json=NEW_SERVER, headers=auth_headers)
    sid = created.json()["id"]
    response = await client.delete(
        f"/api/servers/{sid}?remove_key=true", headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["key_removed"] is True
    assert captured["key"].startswith("ssh-ed25519")


async def test_delete_key_removal_failure_still_deletes(
    client: httpx.AsyncClient, auth_headers, monkeypatch
) -> None:
    from app import sshops

    def boom(*a, **k):
        raise OSError("сервер недоступен")

    monkeypatch.setattr(sshops, "connect", boom)

    created = await client.post("/api/servers", json=NEW_SERVER, headers=auth_headers)
    sid = created.json()["id"]
    response = await client.delete(
        f"/api/servers/{sid}?remove_key=true", headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["key_removed"] is False  # не вышло, но сервер удалён
    listing = await client.get("/api/servers", headers=auth_headers)
    assert all(s["id"] != sid for s in listing.json())
