async def test_health_returns_ok(client) -> None:
    response = await client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["db"] == "ok"  # health теперь реально проверяет БД
    assert body["version"]
