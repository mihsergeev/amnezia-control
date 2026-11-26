"""Интеграционный API /api/v1 и ключи к нему.

Проверяем контур доступа (без ключа нельзя, отозванным нельзя, ключ не даёт
прав сверх клиентских) — ручки, ходящие по SSH, покрыты тестами api/awg.
"""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import update

from app import apikeys
from app.models import ApiKey, ClientTrafficSample, NodeMetric, NodeResourceSample, TrafficSample


async def _make_key(client: httpx.AsyncClient, headers: dict, name="integration") -> str:
    r = await client.post("/api/apikeys", json={"name": name, "password": "testpass"}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["key"]


def test_generate_and_split_roundtrip() -> None:
    key, prefix, key_hash = apikeys.generate()
    assert key.startswith("ack_")
    parsed = apikeys.split(key)
    assert parsed is not None and parsed[0] == prefix
    # секрет в ключе не равен хэшу — в БД уходит только хэш
    assert parsed[1] not in key_hash


def test_split_rejects_foreign_format() -> None:
    for bad in ("", "nope", "ack_only", "jwt_a_b", "ack__b", "ack_a_"):
        assert apikeys.split(bad) is None


async def test_key_created_once_and_listed(client, auth_headers):
    r = await client.post("/api/apikeys", json={"name": "other-panel", "password": "testpass"}, headers=auth_headers)
    assert r.status_code == 201
    body = r.json()
    assert body["key"].startswith("ack_") and body["name"] == "other-panel"

    lst = await client.get("/api/apikeys", headers=auth_headers)
    assert lst.status_code == 200
    row = lst.json()[0]
    assert row["prefix"] == body["prefix"]
    assert "key" not in row  # полный ключ больше нигде не отдаём
    assert row["revoked"] is False


async def test_v1_requires_api_key(client):
    r = await client.get("/api/v1/servers")
    assert r.status_code == 401


async def test_v1_rejects_jwt_instead_of_api_key(client, auth_headers):
    """Пользовательский JWT — не пропуск в интеграционный контур."""
    r = await client.get("/api/v1/servers", headers=auth_headers)
    assert r.status_code == 401


async def test_v1_works_with_api_key(client, auth_headers):
    key = await _make_key(client, auth_headers)
    r = await client.get("/api/v1/servers", headers={"X-API-Key": key})
    assert r.status_code == 200
    assert r.json() == []  # серверов ещё нет


async def test_stats_key_is_read_only_and_server_scoped(client, auth_headers):
    first = await _server(client, auth_headers, "192.0.2.41")
    second = await _server(client, auth_headers, "192.0.2.42")
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    raw_id = "fixture-client-id"
    async with client.session_factory() as session:
        for sid in (first, second):
            session.add_all([
                TrafficSample(server_id=sid, ts=now, rx_total=sid, clients_online=1),
                ClientTrafficSample(server_id=sid, protocol="xray", client_id=raw_id, rx=500, ts=now),
                NodeMetric(server_id=sid, ts=now),
                NodeResourceSample(server_id=sid, ts=now, cpu_pct=15, mem_pct=50, load1=0.2),
            ])
        await session.commit()

    created = await client.post(
        "/api/apikeys",
        json={"name": "monitoring", "password": "testpass", "scope": "stats"},
        headers=auth_headers,
    )
    assert created.status_code == 201 and created.json()["scope"] == "stats"
    data = created.json()
    updated = await client.put(
        f"/api/apikeys/{data['id']}",
        json={"server_ids": [first], "all_servers": False, "password": "testpass"},
        headers=auth_headers,
    )
    assert updated.status_code == 200 and updated.json()["scope"] == "stats"
    headers = {"X-API-Key": data["key"]}
    overview = (await client.get("/api/stats/overview", headers=headers)).json()
    assert [row["id"] for row in overview["per_server"]] == [first]
    history = (await client.get("/api/stats/history?by_server=true", headers=headers)).json()
    assert [row["server_id"] for row in history["servers"]] == [first]
    for path in ("nodes", "node-history", "top-clients"):
        response = await client.get(f"/api/stats/{path}", headers=headers)
        assert response.status_code == 200, response.text
        items = response.json()
        if path == "node-history":
            items = items["servers"]
        assert [row["server_id"] for row in items] == [first]
        if path == "top-clients":
            assert raw_id not in response.text and raw_id[:12] not in response.text
    for path in ("nodes", "node-history", "top-clients", "overview", "history"):
        response = await client.get(
            f"/api/stats/{path}?server_id={first}&server_id={second}", headers=headers
        )
        assert response.status_code == 403
    for path in ("/api/v1/servers", f"/api/v1/servers/{first}/clients/config?public_key=fixture"):
        assert (await client.get(path, headers=headers)).status_code == 403
    assert (await client.post(
        f"/api/v1/servers/{first}/clients", json={"name": "fixture"}, headers=headers
    )).status_code == 403
    assert (await client.get(
        f"/api/stats/client?server_id={first}&protocol=xray&client_id=fixture", headers=headers
    )).status_code == 401
    assert (await client.get("/api/stats/nodes")).status_code == 401
    legacy = await _make_key(client, auth_headers)
    assert (await client.get("/api/stats/nodes", headers={"X-API-Key": legacy})).status_code == 403
    assert (await client.get("/api/stats/nodes", headers=auth_headers)).status_code == 200

    # Restoring an old backup without the scope must not promote a cached key.
    async with client.session_factory() as session:
        await session.execute(update(ApiKey).where(ApiKey.id == data["id"]).values(scope="clients"))
        await session.commit()
    assert (await client.get("/api/v1/servers", headers=headers)).status_code == 401


async def test_revoked_key_stops_working(client, auth_headers):
    key = await _make_key(client, auth_headers)
    key_id = (await client.get("/api/apikeys", headers=auth_headers)).json()[0]["id"]

    assert (await client.get("/api/v1/servers", headers={"X-API-Key": key})).status_code == 200
    d = await client.delete(f"/api/apikeys/{key_id}", headers=auth_headers)
    assert d.status_code == 204
    r = await client.get("/api/v1/servers", headers={"X-API-Key": key})
    assert r.status_code == 401  # отозванный ключ больше не пускает


async def test_wrong_secret_with_valid_prefix_rejected(client, auth_headers):
    """Префикс открытый — подобрать по нему нельзя без секрета."""
    key = await _make_key(client, auth_headers)
    prefix = apikeys.split(key)[0]
    r = await client.get(
        "/api/v1/servers", headers={"X-API-Key": f"ack_{prefix}_wrongsecret"}
    )
    assert r.status_code == 401


async def test_api_key_cannot_manage_servers(client, auth_headers):
    """Ключ ограничен клиентскими операциями: админские ручки им недоступны."""
    key = await _make_key(client, auth_headers)
    hdr = {"X-API-Key": key}
    # создание сервера, full-access и выпуск новых ключей — только под JWT
    assert (await client.post("/api/servers", json={}, headers=hdr)).status_code == 401
    assert (
        await client.post("/api/servers/1/fullaccess", json={"password": "x"}, headers=hdr)
    ).status_code == 401
    assert (await client.delete("/api/servers/1/fullaccess", headers=hdr)).status_code == 401
    assert (
        await client.post("/api/apikeys", json={"name": "self", "password": "testpass"}, headers=hdr)
    ).status_code == 401


async def test_v1_unknown_server_404(client, auth_headers):
    key = await _make_key(client, auth_headers)
    r = await client.get(
        "/api/v1/servers/999/clients/config",
        params={"public_key": "abc="},
        headers={"X-API-Key": key},
    )
    assert r.status_code == 404


@pytest.mark.parametrize("path", ["/api/docs", "/api/openapi.json"])
async def test_docs_exposed_for_integrators(client, path):
    """Контракт должен быть читаем — иначе интегрировать вслепую."""
    r = await client.get(path)
    assert r.status_code == 200


async def test_docs_page_survives_strict_csp(client):
    """Регресс: штатная страница FastAPI грузила Swagger с внешнего CDN и
    инициализировала его ИНЛАЙН-скриптом — CSP панели (script-src 'self', без
    'unsafe-inline') резала и то, и другое, страница открывалась пустой.
    Своя страница обязана обходиться своим origin и внешними файлами."""
    html = (await client.get("/api/docs")).text
    assert "cdn.jsdelivr" not in html and "unpkg.com" not in html  # без CDN
    assert "<script>" not in html  # без инлайна: только <script src=...>
    for asset in ("/swagger/swagger-ui.css", "/swagger/swagger-ui-bundle.js",
                  "/swagger/swagger-init.js"):
        assert asset in html


async def _server(client, headers, host) -> int:
    r = await client.post(
        "/api/servers",
        json={"name": host, "host": host, "ssh_port": 22, "ssh_user": "amn"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_key_limited_to_servers(client, auth_headers):
    """Ключ с серверами видит только их, чужой сервер для него как несуществующий."""
    a = await _server(client, auth_headers, "203.0.113.21")
    b = await _server(client, auth_headers, "203.0.113.22")
    key = await _make_key(client, auth_headers)
    key_id = (await client.get("/api/apikeys", headers=auth_headers)).json()[0]["id"]
    h = {"X-API-Key": key}
    assert len((await client.get("/api/v1/servers", headers=h)).json()) == 2

    r = await client.put(
        f"/api/apikeys/{key_id}", json={"server_ids": [a], "password": "testpass"}, headers=auth_headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["server_ids"] == [a]
    assert [s["id"] for s in (await client.get("/api/v1/servers", headers=h)).json()] == [a]
    r = await client.get(f"/api/v1/servers/{b}/clients", headers=h)
    assert r.status_code == 404

    bad = await client.put(
        f"/api/apikeys/{key_id}", json={"server_ids": [9999], "password": "testpass"}, headers=auth_headers
    )
    assert bad.status_code == 400


async def test_expired_key_rejected(client, auth_headers):
    key = await _make_key(client, auth_headers)
    key_id = (await client.get("/api/apikeys", headers=auth_headers)).json()[0]["id"]
    h = {"X-API-Key": key}
    r = await client.put(
        f"/api/apikeys/{key_id}",
        json={"expires_at": "2099-01-01T00:00:00+00:00", "password": "testpass"},
        headers=auth_headers,
    )
    assert r.status_code == 200
    assert (await client.get("/api/v1/servers", headers=h)).status_code == 200
    await client.put(
        f"/api/apikeys/{key_id}",
        json={"expires_at": "2020-01-01T00:00:00+00:00", "password": "testpass"},
        headers=auth_headers,
    )
    assert (await client.get("/api/v1/servers", headers=h)).status_code == 401
