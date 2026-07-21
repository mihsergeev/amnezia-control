"""Интеграционный API /api/v1 и ключи к нему.

Проверяем контур доступа (без ключа нельзя, отозванным нельзя, ключ не даёт
прав сверх клиентских) — ручки, ходящие по SSH, покрыты тестами api/awg.
"""

import httpx
import pytest

from app import apikeys


async def _make_key(client: httpx.AsyncClient, headers: dict, name="integration") -> str:
    r = await client.post("/api/apikeys", json={"name": name}, headers=headers)
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
    r = await client.post("/api/apikeys", json={"name": "other-panel"}, headers=auth_headers)
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
    assert (
        await client.post("/api/apikeys", json={"name": "self"}, headers=hdr)
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
