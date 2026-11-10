import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app import cascade_recovery
from app.api import cascades as api
from app.models import Cascade, Server


@pytest.mark.parametrize("scenario", ["registered", "forgotten", "failed_retry"])
async def test_entry_recovery_only_uses_entry_and_keeps_retryable_state(
    client, auth_headers, session_factory, monkeypatch, scenario
):
    async with session_factory() as session:
        entry = Server(name="entry", host="192.0.2.10")
        exit_node = Server(name="exit", host="198.51.100.20")
        session.add_all([entry, exit_node])
        await session.flush()
        entry_id = entry.id
        routes = [{"destination": "example.org", "via": "entry"}]
        if scenario != "forgotten":
            session.add(Cascade(id=7, entry_server_id=entry_id, exit_server_id=exit_node.id,
                                transport="vless", status="error" if scenario == "failed_retry" else "ready",
                                params=json.dumps({"runtime_layout": 2, "entry_country": "RU", "routes": routes,
                                                   "runtime_owner": ("b" if scenario == "failed_retry" else "a") * 32})))
        await session.commit()

    marker = {"cascade_id": 7, "transport": "vless", "owner": "a" * 32, "layout": 2}
    writes = []
    fail_cleanup = True

    class Connection:
        async def run(self, command, **kwargs):
            if command == cascade_recovery.INSPECT:
                return SimpleNamespace(exit_status=0, stdout=json.dumps(marker))
            if "AC_CASCADE_OPERATION_PAYLOAD" not in command:
                assert "ACTUAL=" in command and "CASCADE_AVAILABLE" in command
                return SimpleNamespace(exit_status=0, stdout="CASCADE_AVAILABLE")
            writes.append(command)
            if fail_cleanup:
                return SimpleNamespace(exit_status=73, stdout="CASCADE_RECOVERY_CLEANUP_STARTED\nCASCADE_RECOVERY_TPROXY_FAILED")
            return SimpleNamespace(exit_status=0, stdout="CASCADE_REMOVED=yes")

    @asynccontextmanager
    async def locked(server):
        assert server.id == entry_id
        yield Connection()

    monkeypatch.setattr(api, "_locked", locked)
    url = f"/api/cascades/entry-recovery/{entry_id}"
    preview = await client.get(url, headers=auth_headers)
    assert preview.status_code == 200 and not writes
    details = preview.json()
    assert details["routes"] == (routes if scenario != "forgotten" else [])
    assert bool(details["resume"]) == (scenario == "failed_retry")
    wrong = await client.post(url, headers=auth_headers, json={"token": "0" * 64})
    assert wrong.status_code == 409 and not writes

    response = await client.post(url, headers=auth_headers, json={"token": details["token"]})
    assert response.status_code == 409 and len(writes) == 1
    assert "TPROXY" in response.json()["detail"]
    async with session_factory() as session:
        assert bool(await session.get(Cascade, 7)) == (scenario != "forgotten")

    fail_cleanup = False
    response = await client.post(url, headers=auth_headers, json={"token": details["token"]})
    assert response.status_code == 200 and len(writes) == 2
    async with session_factory() as session:
        row = await session.get(Cascade, 7)
        if scenario == "failed_retry":
            assert row.status == "error" and json.loads(row.params)["runtime_owner"] == "b" * 32
        else:
            assert row is None
        assert await session.get(Server, entry_id) is not None


async def test_entry_recovery_refuses_unowned_files(client, auth_headers, session_factory, monkeypatch):
    async with session_factory() as session:
        entry = Server(name="entry", host="192.0.2.10")
        session.add(entry)
        await session.commit()
        entry_id = entry.id

    class Connection:
        async def run(self, command, **kwargs):
            assert command == cascade_recovery.INSPECT
            return SimpleNamespace(exit_status=73, stdout="")

    @asynccontextmanager
    async def locked(server):
        yield Connection()

    monkeypatch.setattr(api, "_locked", locked)
    url = f"/api/cascades/entry-recovery/{entry_id}"
    for method, kwargs in [("GET", {}), ("POST", {"json": {"token": "0" * 64}})]:
        response = await client.request(method, url, headers=auth_headers, **kwargs)
        assert response.status_code == 409


async def test_create_reports_old_gateway_before_installing(client, auth_headers, session_factory, monkeypatch):
    async with session_factory() as session:
        session.add_all([Server(id=1, name="entry", host="192.0.2.10", last_check_ok=True),
                         Server(id=2, name="exit", host="198.51.100.20", last_check_ok=True)])
        await session.commit()

    class Connection:
        async def run(self, command, **kwargs):
            assert "CASCADE_ENTRY_RECOVERY_REQUIRED" in command
            return SimpleNamespace(exit_status=73, stdout="CASCADE_ENTRY_RECOVERY_REQUIRED\n")

    @asynccontextmanager
    async def locked(server):
        yield Connection()

    monkeypatch.setattr(api, "_locked", locked)
    response = await client.post("/api/cascades", headers=auth_headers,
                                 json={"entry_id": 1, "exit_id": 2, "transport": "vless"})
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "cascade_entry_recovery_required"
    async with session_factory() as session:
        assert await session.get(Cascade, 1) is None


async def test_scoped_recovery_keeps_draft_after_remote_reply_is_lost(
    client, auth_headers, session_factory, monkeypatch,
):
    params = {"runtime_layout": 2, "runtime_owner": "b" * 32, "entry_country": "RU",
              "routes": [{"destination": "example.org", "via": "entry"}]}
    async with session_factory() as session:
        session.add_all([Server(id=1, name="entry", host="192.0.2.10"),
                         Server(id=2, name="exit", host="198.51.100.20")])
        await session.flush()
        session.add(Cascade(id=7, entry_server_id=1, exit_server_id=2, transport="vless",
                            status="error", params=json.dumps(params)))
        await session.commit()

    marker = {"cascade_id": 6, "transport": "awg", "owner": "a" * 32, "layout": 2}
    runtime = marker

    class Connection:
        async def run(self, command, **kwargs):
            nonlocal runtime
            if command == cascade_recovery.INSPECT:
                return SimpleNamespace(exit_status=0, stdout=json.dumps(runtime))
            if "AC_CASCADE_OPERATION_PAYLOAD" not in command:
                return SimpleNamespace(exit_status=0, stdout="")
            if runtime is not None:
                runtime = None
                raise TimeoutError()
            return SimpleNamespace(exit_status=0, stdout="CASCADE_REMOVED=yes\n")

    @asynccontextmanager
    async def locked(server):
        yield Connection()

    monkeypatch.setattr(api, "_locked", locked)
    url = "/api/cascades/entry-recovery/1"
    details = (await client.get(url, headers=auth_headers, params={"cascade_id": 7})).json()
    assert details["resume"]["id"] == 7
    request = {"token": details["token"], "cascade_id": 7}
    assert (await client.post(url, headers=auth_headers, json=request)).status_code == 502
    assert (await client.post(url, headers=auth_headers, json=request)).status_code == 409
    details = (await client.get(url, headers=auth_headers, params={"cascade_id": 7})).json()
    request["token"] = details["token"]
    assert (await client.post(url, headers=auth_headers, json=request)).status_code == 200
    async with session_factory() as session:
        row = await session.get(Cascade, 7)
        assert row.status == "error" and json.loads(row.params) == params


async def test_waiting_delete_cannot_remove_replacement_with_reused_id(
    client, auth_headers, session_factory, monkeypatch,
):
    async with session_factory() as session:
        session.add(Cascade(id=7, entry_server_id=1, exit_server_id=2, transport="vless",
                            status="ready", params=json.dumps({"runtime_owner": "a" * 32})))
        await session.commit()

    replaced = False

    @asynccontextmanager
    async def hold(kind, server_id):
        nonlocal replaced
        if not replaced:
            async with session_factory() as session:
                await session.delete(await session.get(Cascade, 7))
                await session.flush()
                session.add(Cascade(id=7, entry_server_id=1, exit_server_id=2, transport="vless",
                                    status="ready", params=json.dumps({"runtime_owner": "b" * 32})))
                await session.commit()
            replaced = True
        yield

    monkeypatch.setattr(api.nodelock, "hold", hold)
    response = await client.delete("/api/cascades/7", headers=auth_headers)
    assert replaced and response.status_code == 404
    async with session_factory() as session:
        assert json.loads((await session.get(Cascade, 7)).params)["runtime_owner"] == "b" * 32
