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


def test_delete_covers_all_server_scoped_tables() -> None:
    """Удаление сервера должно чистить ВСЕ таблицы с server_id — иначе секреты
    (OvpnConfig с приватным ключом клиента), паузы и кэши остаются сиротами."""
    from app import models
    from app.api.servers import _server_scoped_models

    names = {m.__tablename__ for m in _server_scoped_models()}
    # критично: конфиг с приватным ключом + пауза + кэш имён + история трафика
    assert "ovpn_configs" in names
    assert "paused_clients" in names
    assert "client_names" in names
    assert "traffic_samples" in names
    # не-серверные таблицы НЕ трогаем
    assert names.isdisjoint({"users", "servers", "app_settings", "audit_log"})
    # ровно все модели с колонкой server_id (авто-сверка — новые таблицы попадут)
    expected = {
        m.__tablename__
        for m in [
            models.AwgConfig, models.AwgNote, models.OvpnConfig, models.TrafficSample,
            models.ClientLimit, models.ClientName, models.ServerStatus,
            models.ClientTrafficSample, models.NodeMetric, models.PausedClient,
        ]
    }
    assert names == expected


async def test_reorder_sets_position_and_group(
    client: httpx.AsyncClient, auth_headers
) -> None:
    ids = []
    for i in range(3):
        r = await client.post(
            "/api/servers",
            json={"name": f"srv-{i}", "host": f"203.0.113.{i}", "ssh_user": "acontrol"},
            headers=auth_headers,
        )
        ids.append(r.json()["id"])
    # новый порядок: третий, первый, второй; двоим задаём группу
    order = [
        {"id": ids[2], "group_name": "prod"},
        {"id": ids[0], "group_name": "prod"},
        {"id": ids[1], "group_name": ""},
    ]
    r = await client.post(
        "/api/servers/order", json={"order": order}, headers=auth_headers
    )
    assert r.status_code == 204

    servers = (await client.get("/api/servers", headers=auth_headers)).json()
    # список приходит в порядке position
    assert [s["id"] for s in servers] == [ids[2], ids[0], ids[1]]
    by_id = {s["id"]: s for s in servers}
    assert by_id[ids[2]]["position"] == 0 and by_id[ids[2]]["group_name"] == "prod"
    assert by_id[ids[0]]["position"] == 1
    assert by_id[ids[1]]["position"] == 2 and by_id[ids[1]]["group_name"] == ""


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
