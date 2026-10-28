"""Одноразовые ссылки на конфиг через сервисы секретов (app/share.py, /api/share)."""
import json

import httpx
import pytest

from app import share

BASE = "https://secret.example.com"


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_normalize_url_keeps_origin() -> None:
    assert share.normalize_url("https://secret.example.com/msg") == BASE
    assert share.normalize_url(" https://secret.example.com:8443/ ") == BASE + ":8443"
    with pytest.raises(share.ShareError):
        share.normalize_url("secret.example.com")


async def test_detect_engines() -> None:
    def pwpush(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v2/version":
            return httpx.Response(200, json={"application_version": "2.8.1"})
        return httpx.Response(404)

    def sup3r(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/msg":
            return httpx.Response(200, text="<title>sup3rS3cretMes5age</title>")
        return httpx.Response(404, text="not found")

    def other(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>hello</html>")

    assert await share.detect_engine(BASE, _client(pwpush)) == "pwpush"
    assert await share.detect_engine(BASE, _client(sup3r)) == "sup3rs3cret"
    with pytest.raises(share.ShareError):
        await share.detect_engine(BASE, _client(other))


async def test_sup3rs3cret_link_is_one_week() -> None:
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["path"] = req.url.path
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"token": "hvs.abc+/="})

    url = await share.create_link("sup3rs3cret", BASE, "vpn://config", _client(handler))
    assert seen["path"] == "/secret"
    assert "vpn://config" in seen["body"] and "168h" in seen["body"]
    assert url == f"{BASE}/getmsg?token=hvs.abc%2B%2F%3D"


async def test_pwpush_link_one_view() -> None:
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(req.content)
        return httpx.Response(201, json={"url_token": "tok", "html_url": f"{BASE}/p/tok/r"})

    url = await share.create_link("pwpush", BASE, "vpn://config", _client(handler))
    push = seen["body"]["push"]
    assert push["payload"] == "vpn://config"
    assert push["expire_after_views"] == 1 and push["expire_after_days"] == 7
    assert url == f"{BASE}/p/tok/r"


async def test_service_error_is_share_error() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    with pytest.raises(share.ShareError, match="500"):
        await share.create_link("pwpush", BASE, "x", _client(handler))


async def test_api_add_share_and_audit(client: httpx.AsyncClient, auth_headers, monkeypatch) -> None:
    async def fake_detect(base, client=None):
        return "pwpush"

    async def fake_create(engine, base, text, client=None):
        assert engine == "pwpush" and base == BASE and text == "vpn://secret-config"
        return f"{BASE}/p/tok/r"

    monkeypatch.setattr(share, "detect_engine", fake_detect)
    monkeypatch.setattr(share, "create_link", fake_create)

    r = await client.post("/api/share/services", json={"name": "Corp", "url": BASE + "/"},
                          headers=auth_headers)
    assert r.status_code == 200
    svc = r.json()[0]
    assert svc["url"] == BASE and svc["engine"] == "pwpush"
    # тот же сервис второй раз не добавляется
    r = await client.post("/api/share/services", json={"name": "Corp2", "url": BASE},
                          headers=auth_headers)
    assert r.status_code == 409

    r = await client.post("/api/share", json={
        "service_id": svc["id"], "text": "vpn://secret-config", "target": "alice",
    }, headers=auth_headers)
    assert r.status_code == 200
    assert r.json() == {"url": f"{BASE}/p/tok/r", "ttl_days": 7}

    # в журнале кто и через что, но не конфиг и не ссылка
    log = (await client.get("/api/audit", headers=auth_headers)).json()
    text = json.dumps(log, ensure_ascii=False)
    assert "share_link" in text and "alice" in text
    assert "secret-config" not in text and "/p/tok" not in text

    r = await client.delete(f"/api/share/services/{svc['id']}", headers=auth_headers)
    assert r.status_code == 200 and r.json() == []


async def test_api_requires_login(client: httpx.AsyncClient) -> None:
    r = await client.post("/api/share", json={"service_id": "x", "text": "y"})
    assert r.status_code == 401
