import asyncio

import httpx

from app import stepup


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


async def test_concurrent_password_change_rejects_stale_credentials(
    client: httpx.AsyncClient, auth_headers, monkeypatch,
) -> None:
    verify = stepup.verify
    verified = asyncio.Event()
    resume = asyncio.Event()

    async def pause_first_verification(*args, **kwargs):
        await verify(*args, **kwargs)
        if not verified.is_set():
            verified.set()
            await resume.wait()

    monkeypatch.setattr(stepup, "verify", pause_first_verification)
    delayed = asyncio.create_task(client.post(
        "/api/auth/password", headers=auth_headers,
        json={"current_password": "testpass", "new_password": "delayed-password"},
    ))
    try:
        await asyncio.wait_for(verified.wait(), timeout=10)
        winner = await client.post(
            "/api/auth/password", headers=auth_headers,
            json={"current_password": "testpass", "new_password": "winning-password"},
        )
    finally:
        resume.set()
        stale = await delayed

    assert winner.status_code == 200
    assert stale.status_code == 409
    token = winner.json()["access_token"]
    assert (await client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {token}"},
    )).status_code == 200
    assert (await client.get("/api/auth/me", headers=auth_headers)).status_code == 401
    assert (await client.post("/api/auth/login", json={
        "username": "admin", "password": "winning-password",
    })).status_code == 200
    assert (await client.post("/api/auth/login", json={
        "username": "admin", "password": "delayed-password",
    })).status_code == 401
