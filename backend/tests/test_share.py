"""Одноразовые ссылки на конфиг через сервисы секретов (app/share.py, /api/share)."""
import json

import httpx
import pytest

from app import settings_store, share

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


@pytest.mark.parametrize("engine", share.ENGINES)
async def test_secret_post_does_not_follow_redirect(engine: str) -> None:
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.host)
        return httpx.Response(307, headers={"Location": "http://other.example.org/redirect"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(share.ShareError, match="307"):
            await share.create_link(engine, BASE, "vpn://fixture", client)
    assert seen == ["secret.example.com"]


async def test_api_add_share_and_audit(client: httpx.AsyncClient, auth_headers, monkeypatch) -> None:
    async def fake_detect(base, client=None):
        return "pwpush"

    async def fake_create(engine, base, text, client=None):
        assert engine == "pwpush" and base == BASE and text == "vpn://secret-config"
        return f"{BASE}/p/tok/r"

    monkeypatch.setattr(share, "detect_engine", fake_detect)
    monkeypatch.setattr(share, "create_link", fake_create)

    r = await client.post("/api/share/services", json={"name": "Corp", "url": BASE + "/", "password": "testpass"},
                          headers=auth_headers)
    assert r.status_code == 200
    svc = r.json()[0]
    assert svc["url"] == BASE and svc["engine"] == "pwpush"
    # тот же сервис второй раз не добавляется
    r = await client.post("/api/share/services", json={"name": "Corp2", "url": BASE, "password": "testpass"},
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


async def test_share_service_rejects_credentials_before_network_or_audit(
    client, auth_headers, monkeypatch
):
    detected = []

    async def fake_detect(base, client=None):
        detected.append(base)
        return "pwpush"

    monkeypatch.setattr(share, "detect_engine", fake_detect)
    response = await client.post(
        "/api/share/services", headers=auth_headers,
        json={"name": "Example", "url": "https://test-user:test-password@secret.example.com", "password": "testpass"},
    )
    assert response.status_code == 400
    assert detected == []
    audit = (await client.get("/api/audit", headers=auth_headers)).text
    assert "test-password" not in audit


@pytest.mark.parametrize("engine,response", [
    ("sup3rs3cret", {"token": "test-token"}),
    ("pwpush", {"url_token": "test-token"}),
    ("pwpush", {"html_url": "https://test-user:test-password@secret.example.com/p/test-token/r"}),
])
async def test_old_service_credentials_stay_out_of_links(engine, response):
    base = "https://test-user:test-password@secret.example.com"

    def handler(request):
        assert request.headers.get("authorization", "").startswith("Basic ")
        return httpx.Response(200, json=response)

    url = await share.create_link(engine, base, "test-config", _client(handler))
    assert "test-password" not in url and "test-user" not in url
    assert url.startswith(BASE + "/")


async def test_old_service_credentials_stay_out_of_errors():
    base = "https://test-user:test-password@secret.example.com"

    def handler(request):
        raise httpx.ConnectError(f"connection failed: {base}", request=request)

    with pytest.raises(share.ShareError) as caught:
        await share.create_link("pwpush", base, "test-config", _client(handler))
    assert "test-password" not in str(caught.value)


async def test_delete_old_service_never_logs_credentials(client, auth_headers):
    base = "https://test-user:test-password@secret.example.com"
    async with client.session_factory() as session:
        await settings_store.set_share_services(session, [
            {"id": "test-service", "name": "Example", "engine": "pwpush", "url": base}
        ])
    listed = await client.get("/api/share/services", headers=auth_headers)
    assert listed.json()[0]["url"] == BASE
    deleted = await client.delete("/api/share/services/test-service", headers=auth_headers)
    assert deleted.status_code == 200
    audit = (await client.get("/api/audit", headers=auth_headers)).text
    assert "share_service_delete" in audit and "test-password" not in audit


@pytest.mark.parametrize("password", [None, "incorrect"])
async def test_registration_requires_stepup_before_network(client, auth_headers, monkeypatch, password):
    async def must_not_probe(*args, **kwargs):
        pytest.fail("unconfirmed service registration performed a network request")

    monkeypatch.setattr(share, "detect_engine", must_not_probe)
    body = {"name": "Example", "url": BASE}
    if password is not None:
        body["password"] = password
    response = await client.post("/api/share/services", headers=auth_headers, json=body)
    assert response.status_code == 403
    assert (await client.get("/api/share/services", headers=auth_headers)).json() == []


@pytest.mark.parametrize("url", [
    "https://secret.example.com:99999", "https://secret.example.com:bad",
    "https://secret.example.com:0", "https://secret.example.com\\path",
    "https://secret.example.com something", "javascript:alert(1)",
])
def test_invalid_service_destination(url):
    with pytest.raises(share.ShareError):
        share.normalize_url(url)


async def test_detection_does_not_follow_redirects():
    seen = []

    def handler(req):
        seen.append(req.url.host)
        return httpx.Response(302, headers={"Location": "https://other.example.org/msg"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(share.ShareError):
            await share.detect_engine(BASE, client)
    assert seen == ["secret.example.com", "secret.example.com"]


@pytest.mark.parametrize("url", [
    "https://other.example.org/p/token/r", "javascript:alert(1)",
    "//secret.example.com/p/token/r", "https://secret.example.com:99999/p/token/r",
])
async def test_pwpush_rejects_untrusted_returned_link(url):
    with pytest.raises(share.ShareError):
        await share.create_link("pwpush", BASE, "config", _client(
            lambda req: httpx.Response(200, json={"html_url": url})
        ))


@pytest.mark.parametrize("engine,data", [
    ("sup3rs3cret", []), ("sup3rs3cret", {"token": ["secret"]}),
    ("pwpush", []), ("pwpush", {"url_token": ["secret"]}),
])
async def test_bad_response_shape_is_share_error(engine, data):
    with pytest.raises(share.ShareError):
        await share.create_link(engine, BASE, "config", _client(
            lambda req: httpx.Response(200, json=data)
        ))
