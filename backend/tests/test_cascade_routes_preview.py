from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from app import cascadejob
from app.api import cascades
from app.db import get_session
from app.deps import get_current_user


PATH = "/api/cascades/routes/preview"


@pytest.fixture
async def preview_client(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Destination preview must not access SSH or a database session")

    app = FastAPI()
    app.include_router(cascades.router, prefix="/api")
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="fixture")
    app.dependency_overrides[get_session] = forbidden
    monkeypatch.setattr(cascadejob, "connect", forbidden)
    monkeypatch.setattr(cascades, "_locked", forbidden)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client


async def test_preview_requires_authentication(client):
    response = await client.post(PATH, json={"destinations": ["example.com"]})
    assert response.status_code == 401


async def test_preview_uses_route_contract_in_input_order_without_ssh_or_database(preview_client):
    values = ["faß.example", "fass.example", "BÜCHER.example.", "ς.example", "σ.example",
              "a\u200db.example", "ｅｘａｍｐｌｅ.com", "example。com", " 192.0.2.1 ",
              "198.51.100.0/24", "198.51.100.1/24", "*.example.com", "https://example.com",
              "API.IPIFY.ORG.", "", "a" * 254, "example..com"]
    response = await preview_client.post(PATH, json={"destinations": values})
    assert response.status_code == 200
    valid = lambda value: {"valid": True, "destination": value}
    invalid = {"valid": False, "error": "invalid_destination"}
    assert response.json() == {"results": [
        valid("fass.example"), valid("fass.example"), valid("xn--bcher-kva.example"),
        valid("xn--4xa.example"), valid("xn--4xa.example"), valid("ab.example"),
        valid("example.com"), valid("example.com"), valid("192.0.2.1"), valid("198.51.100.0/24"),
        invalid, invalid, invalid, {"valid": False, "error": "reserved_destination"}, invalid, invalid, invalid,
    ]}


@pytest.mark.parametrize("body", [
    {}, {"destinations": "example.com"}, {"destinations": [123]}, {"destinations": [None]},
    {"destinations": ["x" * 1025]}, {"destinations": ["example.com"] * 201},
])
async def test_preview_rejects_oversized_or_wrong_shape_requests(preview_client, body):
    response = await preview_client.post(PATH, json=body)
    assert response.status_code == 422


async def test_preview_limits_include_all_items_and_accept_empty_request(preview_client):
    assert (await preview_client.post(PATH, json={"destinations": []})).json() == {"results": []}
    response = await preview_client.post(PATH, json={"destinations": ["x" * 1024] * 200})
    assert response.status_code == 200
    assert response.json() == {"results": [{"valid": False, "error": "invalid_destination"}] * 200}
