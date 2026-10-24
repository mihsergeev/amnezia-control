async def test_health_returns_ok(client) -> None:
    response = await client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["db"] == "ok"  # health теперь реально проверяет БД
    # версию без входа не отдаем, она в /api/config
    assert "version" not in body


async def test_version_in_config(client, auth_headers) -> None:
    r = await client.get("/api/config", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["version"]
