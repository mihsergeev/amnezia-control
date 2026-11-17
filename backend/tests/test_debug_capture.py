import asyncio
import io
import json
import threading
from pathlib import Path
from types import SimpleNamespace
import zipfile

from fastapi import HTTPException

from app import debug_context, deploywatch
from app.deps import CurrentUser
from app.debuglog import DebugLogStore
from app.models import Server


PRIVATE = "private-node.example.invalid 198.51.100.38 password=do-not-export token=keep-private"


def _route(client, endpoint, path="/api/servers/{server_id}/diagnostic-test", status_code=200):
    endpoint.__module__ = "app.api.servers"
    client._transport.app.add_api_route(path, endpoint, methods=["POST"], status_code=status_code)


async def test_http_failure_records_fixed_cause_and_keeps_response(client, auth_headers):
    async def endpoint(server_id: int, _: CurrentUser):
        try:
            raise TimeoutError(PRIVATE)
        except TimeoutError as exc:
            raise HTTPException(502, f"SSH timed out: {PRIVATE}", headers={"Retry-After": "2"}) from exc

    _route(client, endpoint)
    response = await client.post("/api/servers/7/diagnostic-test", headers=auth_headers)
    assert response.status_code == 502
    assert response.headers["Retry-After"] == "2"
    assert PRIVATE in response.json()["detail"]  # The feature must not alter API behavior.
    listed = await client.get("/api/debug-logs", headers=auth_headers)
    events = listed.json()["events"]
    assert len(events) == 1
    assert events[0]["code"] == "timeout"
    assert events[0]["server_id"] == 7
    assert events[0]["stage"] == "request"
    archive = await client.get("/api/debug-logs/download", headers=auth_headers)
    with zipfile.ZipFile(io.BytesIO(archive.content)) as bundle:
        body = b"\n".join(bundle.read(name) for name in bundle.namelist()).decode()
    assert PRIVATE not in body
    for value in PRIVATE.split():
        assert value not in body
    assert "timeout" in body


async def test_validation_does_not_export_submitted_values(client, auth_headers):
    async def endpoint(server_id: int, _: CurrentUser):
        return {}

    _route(client, endpoint)
    response = await client.post("/api/servers/private-secret/diagnostic-test", headers=auth_headers,
                                 json={"private_key": PRIVATE})
    assert response.status_code == 422
    events = (await client.get("/api/debug-logs", headers=auth_headers)).json()["events"]
    assert len(events) == 1 and events[0]["code"] == "validation"
    assert "server_id" not in events[0]
    assert "private-secret" not in json.dumps(events)
    assert PRIVATE not in json.dumps(events)


async def test_no_auth_noise_and_background_error_survives_closed_request(client, auth_headers):
    release = asyncio.Event()
    finished = asyncio.Event()

    async def endpoint(server_id: int, _: CurrentUser):
        async def task():
            await release.wait()
            await debug_context.arecord(operation="deploy", stage="install", text="entry ownership " + PRIVATE)
            finished.set()

        asyncio.create_task(task())
        return {"accepted": True}

    _route(client, endpoint)
    denied = await client.post("/api/servers/8/diagnostic-test")
    assert denied.status_code == 401
    assert (await client.get("/api/debug-logs", headers=auth_headers)).json()["events"] == []
    assert (await client.post("/api/servers/8/diagnostic-test", headers=auth_headers)).status_code == 200
    release.set()
    await asyncio.wait_for(finished.wait(), timeout=2)
    events = (await client.get("/api/debug-logs", headers=auth_headers)).json()["events"]
    assert {event["code"] for event in events} == {"request_completed", "entry_ownership"}
    assert len({event["correlation_id"] for event in events}) == 1
    assert all(event["server_id"] == 8 for event in events)
    assert PRIVATE not in json.dumps(events)


async def test_accepted_task_is_not_reported_as_completed(client, auth_headers):
    async def endpoint(server_id: int, _: CurrentUser):
        return {"accepted": True}

    _route(client, endpoint, status_code=202)
    assert (await client.post("/api/servers/8/diagnostic-test", headers=auth_headers)).status_code == 202
    events = (await client.get("/api/debug-logs", headers=auth_headers)).json()["events"]
    assert len(events) == 1
    assert events[0]["code"] == "accepted"
    assert events[0]["summary"] == "Задача принята к выполнению"
    assert events[0]["stage"] == "request"


async def test_deploywatch_persists_detached_install_failure(tmp_path, monkeypatch, session_factory):
    async with session_factory() as session:
        session.add(Server(id=4, name="Synthetic node", host="203.0.113.40", ssh_port=2222, ssh_user="current-service"))
        await session.commit()
    class Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    async def status(*_args, **_kwargs):
        return {"state": "error", "log": "DEPLOY_ERROR: command not found " + PRIVATE}

    async def alert(*_args, **_kwargs):
        pass

    monkeypatch.setattr(deploywatch, "_POLL_SECONDS", 0)
    connections = []
    def connect(*args, **kwargs):
        connections.append((args[:3], kwargs))
        assert args[:3] == ("203.0.113.40", 2222, "current-service")
        assert kwargs == {}
        return Connection()
    monkeypatch.setattr(deploywatch.sshops, "connect", connect)
    monkeypatch.setattr(deploywatch.deploy, "read_status", status)
    monkeypatch.setattr(deploywatch.alerts, "maybe_alert", alert)
    store = DebugLogStore(tmp_path / "debug-logs")
    await deploywatch._watch("198.51.100.38", 2221, "test", "awg3", PRIVATE, 4, session_factory,
                             SimpleNamespace(data_dir=str(tmp_path), ssh_connect_timeout=1), store)
    events = DebugLogStore(tmp_path / "debug-logs").read()
    assert [event["code"] for event in events] == ["dependency_missing", "started"]
    assert all(event["operation"] == "deploy" and event["protocol"] == "awg3" for event in events)
    assert len({event["correlation_id"] for event in events}) == 1
    assert len(connections) == 1
    assert PRIVATE not in (tmp_path / "debug-logs" / "events.jsonl").read_text(encoding="utf-8")


async def test_unhandled_exception_keeps_original_failure_and_safe_location(client, auth_headers):
    async def endpoint(server_id: int, _: CurrentUser):
        raise RuntimeError(PRIVATE)

    _route(client, endpoint)
    try:
        await client.post("/api/servers/9/diagnostic-test", headers=auth_headers)
    except RuntimeError as exc:
        assert str(exc) == PRIVATE
    else:
        raise AssertionError("original exception was swallowed")
    events = (await client.get("/api/debug-logs", headers=auth_headers)).json()["events"]
    assert len(events) == 1 and events[0]["code"] == "unexpected"
    assert events[0]["locations"]
    assert all(frame["module"].startswith("app.") for frame in events[0]["locations"])
    assert PRIVATE not in json.dumps(events)


async def test_diagnostics_do_not_block_unrelated_async_work(tmp_path, monkeypatch):
    store = DebugLogStore(tmp_path / "logs")
    heartbeat = threading.Event()
    original = store.record

    def contended_record(**fields):
        # An unrelated event-loop callback must run while storage is waiting.
        assert heartbeat.wait(timeout=1), "diagnostics blocked the event loop"
        return original(**fields)

    monkeypatch.setattr(store, "record", contended_record)
    asyncio.get_running_loop().call_later(0.03, heartbeat.set)
    with debug_context.bind(store=store, operation="deploy", protocol="awg3", server_id=3):
        await debug_context.arecord(code="completed", level="info", stage="install")
    assert store.read()[0]["server_id"] == 3


async def test_late_deploy_poll_failure_is_recorded(tmp_path, monkeypatch, session_factory):
    async with session_factory() as session:
        session.add(Server(id=3, name="Synthetic relay", host="203.0.113.3", ssh_port=2203, ssh_user="relay-service"))
        session.add(Server(id=4, name="Synthetic target", host="203.0.113.4", ssh_port=2204, ssh_user="current-service", ssh_jump_server_id=3))
        await session.commit()
    class Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    calls = 0

    async def status(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            # The watcher must resolve current metadata on every poll; queued
            # spawn arguments and the preceding SSH session can both be stale.
            async with session_factory() as session:
                target = await session.get(Server, 4)
                target.host = "203.0.113.44"
                target.ssh_port = 2205
                await session.commit()
            return {"state": "running", "log": ""}
        if calls == 2:
            raise TimeoutError(PRIVATE)
        return {"state": "error", "log": "DEPLOY_ERROR: entry ownership " + PRIVATE}

    async def alert(*_args, **_kwargs):
        pass

    monkeypatch.setattr(deploywatch, "_POLL_SECONDS", 0)
    connections = []
    def connect(*args, **kwargs):
        connections.append(args[:3])
        assert kwargs == {"jump": deploywatch.sshops.Jump("203.0.113.3", 2203, 4)}
        return Connection()
    monkeypatch.setattr(deploywatch.sshops, "connect", connect)
    monkeypatch.setattr(deploywatch.deploy, "read_status", status)
    monkeypatch.setattr(deploywatch.alerts, "maybe_alert", alert)
    store = DebugLogStore(tmp_path / "logs")
    await deploywatch._watch("198.51.100.38", 2221, "test", "awg3", PRIVATE, 4, session_factory,
                             SimpleNamespace(data_dir=str(tmp_path), ssh_connect_timeout=1), store)
    events = store.read()
    assert {event["code"] for event in events} == {"started", "timeout", "entry_ownership"}
    assert len({event["correlation_id"] for event in events}) == 1
    assert connections == [("203.0.113.4", 2204, "current-service"),
                           ("203.0.113.44", 2205, "current-service"),
                           ("203.0.113.44", 2205, "current-service")]
    assert PRIVATE not in json.dumps(events)
