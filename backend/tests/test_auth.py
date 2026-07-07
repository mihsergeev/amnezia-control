import httpx


async def test_login_ok(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "testpass"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"


async def test_login_wrong_password(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "wrong"}
    )
    assert response.status_code == 401


async def test_login_unknown_user(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/auth/login", json={"username": "nobody", "password": "testpass"}
    )
    assert response.status_code == 401


async def test_me_requires_token(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/auth/me")
    assert response.status_code == 401


async def test_me_with_token(client: httpx.AsyncClient, auth_headers) -> None:
    response = await client.get("/api/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["username"] == "admin"


async def test_me_with_garbage_token(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert response.status_code == 401
