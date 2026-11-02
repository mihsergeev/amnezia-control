import asyncio
import io
import json
import socket
import subprocess
import threading
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app import cascade, cascade_probe
from app.api import cascades as api
from app.models import Server


def worker_namespace():
    scope = {"__name__": "probe_test"}
    exec(compile(cascade_probe.WORKER, "probe_worker", "exec"), scope)
    return scope


def test_transfer_confirms_receiver_bytes_and_digest_without_rounding():
    worker = worker_namespace()
    result = {}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        token = b"test-token"
        thread = threading.Thread(target=lambda: result.update(worker["receive"](
            listener, token, cascade_probe.PAYLOAD_BYTES)))
        thread.start()
        sent = worker["send"]("127.0.0.1", listener.getsockname()[1], token,
                              cascade_probe.PAYLOAD_BYTES)
        thread.join(timeout=20)
    assert not thread.is_alive()
    assert sent["digest_matches"] is True
    verdict = cascade_probe.verdict(sent, result)
    assert verdict["ok"] is True
    assert verdict["bytes"] == cascade_probe.PAYLOAD_BYTES
    assert verdict["secs"] == sent["secs"] > 0
    assert verdict["mbps"] > 0


@pytest.mark.parametrize("count", [0, 2 * 1024 * 1024, cascade_probe.PAYLOAD_BYTES - 1])
def test_partial_transfer_never_passes(count):
    verdict = cascade_probe.verdict({"bytes": count, "sent": count, "secs": 0.003,
                                     "digest_matches": True}, {"bytes": count})
    assert verdict["status"] == "failed" and verdict["ok"] is False
    assert verdict["bytes"] == count


def test_short_transfer_keeps_real_time_and_requires_digest():
    total = cascade_probe.PAYLOAD_BYTES
    sent = {"bytes": total, "sent": total, "secs": 0.00123456789, "digest_matches": True}
    assert cascade_probe.verdict(sent, {"bytes": total})["secs"] == 0.00123456789
    sent["digest_matches"] = False
    assert cascade_probe.verdict(sent, {"bytes": total})["ok"] is False


def test_reality_config_has_no_direct_fallback_and_restricts_exit_receiver():
    entry, exit_ = cascade_probe.xray_configs(cascade.new_vless_params(), "203.0.113.20", 8443, 43123)
    assert entry["inbounds"][0]["listen"] == "127.0.0.1"
    assert [item["protocol"] for item in entry["outbounds"]] == ["vless"]
    assert entry["outbounds"][0]["streamSettings"]["security"] == "reality"
    assert exit_["outbounds"][0]["protocol"] == "blackhole"
    assert exit_["routing"]["rules"] == [{"inboundTag": ["from-entry"], "ip": ["127.0.0.1/32"],
                                            "port": "1", "outboundTag": "receiver"}]
    assert exit_["outbounds"][1]["settings"]["finalRules"] == [
        {"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"], "port": "1"}]
    assert "geoip:" not in json.dumps(exit_)


def test_reality_receiver_final_rule_and_routing_bind_same_actual_port():
    _, config = cascade_probe.xray_configs(cascade.new_vless_params(), "203.0.113.20", 8443, 43123)
    worker_namespace()["bind_receiver"](config, 43199)
    assert config["routing"]["rules"][0]["port"] == "43199"
    assert config["outbounds"][1]["settings"]["finalRules"] == [
        {"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"], "port": "43199"}]


@pytest.mark.parametrize("occupied,alias_failure,delete_failure,atomic_failure,create_interrupt", [
    (False, False, False, False, False), (False, True, False, False, False),
    (True, False, False, False, False), (False, True, True, False, False),
    (False, False, False, True, False), (False, False, False, False, True),
])
def test_worker_partial_gre_setup_cleans_exact_owned_interface_and_rules(
    tmp_path, monkeypatch, occupied, alias_failure, delete_failure, atomic_failure, create_interrupt,
):
    worker = worker_namespace()
    config = {"tag": "a" * 32, "interface": "acp1234567890", "container": "probe-test",
              "transport": "gre", "role": "exit", "peer_ip": "203.0.113.20", "peer_source": "203.0.113.20",
              "inner": "198.51.100.1", "peer_inner": "198.51.100.2",
              "network": "198.51.100.0/30", "lease": 100, "cleanup_rules": [], "gre_key": 123456}
    calls, events, state = [], [], {"link": occupied, "rules": [], "alias": ""}
    def command(args, required=True):
        calls.append(args)
        data, code = b"", 0
        if args[:4] == ["ip", "link", "show", "dev"]: code = 0 if occupied else 1
        elif args[:4] == ["ip", "-j", "-4", "route"]:
            data = json.dumps([{"prefsrc": "203.0.113.10"}] if "get" in args else []).encode()
        elif args[:4] == ["ip", "-j", "-4", "address"]: data = b"[]"
        elif args[:4] == ["ip", "-j", "-d", "link"]:
            if "dev" in args:
                data = json.dumps([{"ifindex": 42, "ifalias": state["alias"], "linkinfo": {
                    "info_kind": "gre", "info_data": {"local": "203.0.113.10", "remote": config["peer_ip"],
                                                       "ikey": 123456, "okey": 123456}}}]).encode()
            else: data = b"[]"
        elif args[:3] == ["ip", "link", "add"]:
            assert "alias" not in args
            state["link"] = True
            if create_interrupt: raise worker["WorkerStopped"]()
        elif args[:3] == ["ip", "link", "set"] and "alias" in args:
            if alias_failure: raise worker["Unavailable"]("resource operation failed")
            state["alias"] = config["tag"]
        elif args[:3] == ["ip", "address", "add"]: raise worker["Unavailable"]("resource operation failed")
        elif args[:4] == ["ip", "-j", "link", "show"]:
            data = json.dumps([{"ifindex": 42}]).encode()
        elif args[:3] == ["ip", "link", "del"]:
            if delete_failure: code = 1
            else: state["link"] = False
        elif args[0] == "iptables":
            operation, spec = args[3], args[4:]
            if operation == "-I": state["rules"].append(spec)
            elif operation == "-C": code = 0 if spec in state["rules"] else 1
            elif operation == "-D": state["rules"].remove(spec)
        return subprocess.CompletedProcess(args, code, data, b"")
    worker["command"] = command
    worker["shutil"] = SimpleNamespace(which=lambda _: "/test/tool")
    worker["Path"] = lambda value: tmp_path
    worker["emit"] = lambda **value: events.append(value)
    worker["sys"] = SimpleNamespace(stdin=io.StringIO(json.dumps(config) + "\n"))
    worker["os"] = SimpleNamespace(umask=lambda _: None, fork=lambda: 123,
                                    kill=lambda *args: None, waitpid=lambda *args: (123, 0))
    worker["signal"] = SimpleNamespace(SIGTERM=15, SIGALRM=14, signal=lambda *args: None,
                                        alarm=lambda _: None)
    if atomic_failure:
        replace = type(tmp_path).replace
        writes = []
        def atomic_replace(path, target):
            writes.append(True)
            if len(writes) == 2:
                old = json.loads(target.read_text())
                assert old["key"] == 123456 and "ifindex" not in old
                raise worker["WorkerStopped"]()
            return replace(path, target)
        monkeypatch.setattr(type(tmp_path), "replace", atomic_replace)
    worker["main"]()
    assert state["link"] is (occupied or delete_failure) and not state["rules"]
    assert events[-1] == {"event": "cleanup", "ok": not delete_failure}
    if delete_failure:
        owner = tmp_path / ("acontrol-probe-" + config["tag"]) / "link-owner.json"
        assert owner.is_file() and json.loads(owner.read_text())["key"] == 123456
    else: assert not list(tmp_path.iterdir())
    assert [call for call in calls if call[:3] == ["ip", "link", "del"]] == (
        [] if occupied else [["ip", "link", "del", config["interface"]]])


def test_gre_key_ownership_parser_handles_iproute2_representations():
    worker = worker_namespace()
    assert worker["gre_key"](123456) == worker["gre_key"]("123456") == worker["gre_key"]("0.1.226.64")
    assert worker["gre_key"]("invalid") == -1


def test_gre_watchdog_needs_no_docker_and_removes_empty_private_lease(tmp_path):
    worker = worker_namespace()
    config = {"tag": "a" * 32, "interface": "acp1234567890", "container": "probe-test",
              "transport": "gre", "lease": 100, "cleanup_rules": []}
    calls = []
    class ChildExit(BaseException): pass
    def command(args, required=True):
        calls.append(args)
        assert args[0] != "docker"
        return subprocess.CompletedProcess(args, 1, b"", b"")
    def child_exit(code): raise ChildExit(code)
    worker["command"] = command
    worker["Path"] = lambda _: tmp_path
    worker["sys"] = SimpleNamespace(stdin=io.StringIO(json.dumps(config) + "\n"))
    worker["os"] = SimpleNamespace(umask=lambda _: None, fork=lambda: 0, setsid=lambda: None,
        devnull="null", O_RDWR=2, open=lambda *args: 99, dup2=lambda *args: None, _exit=child_exit)
    worker["signal"] = SimpleNamespace(SIGTERM=15, SIG_DFL=0, signal=lambda *args: None)
    worker["time"] = SimpleNamespace(sleep=lambda _: None)
    with pytest.raises(ChildExit): worker["main"]()
    assert calls and not list(tmp_path.iterdir())


class Process:
    def __init__(self, events):
        self.events = asyncio.Queue()
        for event in events:
            self.events.put_nowait(json.dumps(event) + "\n")
        self.stdout = SimpleNamespace(readline=self.events.get)
        self.writes = []
        self.stdin = SimpleNamespace(write=self.writes.append, write_eof=lambda: None)


async def test_setup_unavailable_is_not_a_fake_transport_measurement(monkeypatch):
    process = Process([{"event": "unavailable", "error": "required local image is unavailable; install it separately"},
                       {"event": "cleanup", "ok": True}])
    async def start(*args): return process
    async def port(*args): return 43123
    monkeypatch.setattr(cascade_probe, "_start", start)
    monkeypatch.setattr(cascade_probe, "_port", port)
    result = await cascade_probe.run(None, None, "203.0.113.10", "203.0.113.20", "awg")
    assert result["status"] == "unavailable" and result["ok"] is None
    assert result["secs"] is None and result["mbps"] is None
    assert result["bytes"] == 0 and "образа" in result["error"]


async def test_cleanup_failure_overrides_full_measurement(monkeypatch):
    size = cascade_probe.PAYLOAD_BYTES
    exit_ = Process([{"event": "ready", "receiver_port": 43123},
                     {"event": "result", "bytes": size}, {"event": "cleanup", "ok": False}])
    entry = Process([{"event": "ready"}, {"event": "result", "bytes": size,
                       "sent": size, "secs": 0.2, "digest_matches": True},
                     {"event": "cleanup", "ok": True}])
    processes = iter([exit_, entry])
    async def start(*args): return next(processes)
    monkeypatch.setattr(cascade_probe, "_start", start)
    result = await cascade_probe.run(None, None, "203.0.113.10", "203.0.113.20", "gre")
    assert result["status"] == "failed" and result["ok"] is False
    assert "очистка" in result["error"]
    assert entry.writes[0] == "go\n"


async def test_cancellation_waits_for_cleanup_of_both_partially_started_workers(monkeypatch):
    exit_ = Process([{"event": "ready", "receiver_port": 43123}])
    entry = Process([])
    started = asyncio.Event()
    processes = iter([exit_, entry])
    async def start(*args):
        process = next(processes)
        if process is entry: started.set()
        return process
    closed = []
    async def close(process):
        await asyncio.sleep(0)
        closed.append(process)
        return True
    monkeypatch.setattr(cascade_probe, "_start", start)
    monkeypatch.setattr(cascade_probe, "_close", close)
    task = asyncio.create_task(cascade_probe.run(None, None, "203.0.113.10", "203.0.113.20", "gre"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    assert set(closed) == {exit_, entry}


async def add_servers(session_factory):
    async with session_factory() as session:
        rows = [Server(name="entry", host="203.0.113.10", last_check_ok=True),
                Server(name="exit", host="203.0.113.20", country="ZZ", last_check_ok=True)]
        session.add_all(rows)
        await session.commit()
        return [row.id for row in rows]


def mock_pair(monkeypatch, same_host=False):
    @asynccontextmanager
    async def locked(*args): yield object(), object()
    async def addresses(*args): return "192.0.2.10", "203.0.113.20"
    async def ipv4(host): return "203.0.113.20" if same_host else host
    async def addrs(host): return {"203.0.113.20" if same_host else host}
    async def route(*args): return "192.168.1.10"
    async def geo(*args): raise OSError("unavailable")
    monkeypatch.setattr(api, "_locked_pair", locked)
    monkeypatch.setattr(api, "_addresses", addresses)
    monkeypatch.setattr(api, "_ipv4", ipv4)
    monkeypatch.setattr(api.server_ops, "_host_addrs", addrs)
    monkeypatch.setattr(api.cascade, "_route_src", route)
    monkeypatch.setattr(api.geo, "ip_info", geo)


def measured(transport):
    return {"transport": transport, "measurement": transport, "run_id": "f" * 32,
            "requested_bytes": cascade_probe.PAYLOAD_BYTES, "status": "ok", "ok": True,
            "bytes": cascade_probe.PAYLOAD_BYTES, "secs": 0.25, "mbps": 671.08864,
            "error": "", "entry_port": 43123, "exit_port": 43124}


async def test_transport_api_requires_jwt_and_rejects_unknown_transport(client, auth_headers):
    body = {"entry_id": 1, "exit_id": 2, "transport": "awg"}
    assert (await client.post("/api/cascades/probe-transport", json=body)).status_code == 401
    assert (await client.post("/api/cascades/probe-transport", json=body,
                              headers={"X-API-Key": "synthetic-test-key"})).status_code == 401
    body["transport"] = "tcp"
    assert (await client.post("/api/cascades/probe-transport", json=body,
                              headers=auth_headers)).status_code == 422


async def test_transport_api_preserves_measurement_on_geo_error_and_binds_endpoint_ports(
    client, auth_headers, session_factory, monkeypatch,
):
    entry, exit_ = await add_servers(session_factory)
    mock_pair(monkeypatch)
    # Documentation networks model public/private endpoints without real IPs.
    monkeypatch.setattr(api.cascade, "_is_public", lambda value: value.startswith("203.0.113."))
    captured = []
    async def run(*args, **kwargs):
        captured.append((args, kwargs))
        return measured("awg")
    monkeypatch.setattr(cascade_probe, "run", run)
    response = await client.post("/api/cascades/probe-transport", headers=auth_headers,
        json={"entry_id": entry, "exit_id": exit_, "transport": "awg", "entry_port": 43123, "exit_port": 43124})
    assert response.status_code == 200
    result = response.json()
    assert result["ok"] is True and result["exit_country"] == "ZZ"
    assert result["entry_ip"] == "203.0.113.10"
    assert captured[0][0][2:7] == ("203.0.113.10", "203.0.113.20", "awg", 43123, 43124)
    assert captured[0][1]["entry_source_ip"] == "203.0.113.10"
    assert api._last_probe[(entry, exit_)]["awg"]["measurement"] == "awg"
    assert "tcp" not in api._last_probe[(entry, exit_)]


async def test_transport_api_rejects_two_records_resolving_to_same_host(
    client, auth_headers, session_factory, monkeypatch,
):
    entry, exit_ = await add_servers(session_factory)
    mock_pair(monkeypatch, same_host=True)
    async def run(*args, **kwargs): pytest.fail("must not mutate a node")
    monkeypatch.setattr(cascade_probe, "run", run)
    response = await client.post("/api/cascades/probe-transport", headers=auth_headers,
        json={"entry_id": entry, "exit_id": exit_, "transport": "gre"})
    assert response.status_code == 400


async def test_transport_api_rechecks_free_pair_after_lock(
    client, auth_headers, session_factory, monkeypatch,
):
    from fastapi import HTTPException
    entry, exit_ = await add_servers(session_factory)
    mock_pair(monkeypatch)
    calls = []
    async def ensure(*args):
        calls.append(True)
        if len(calls) == 2: raise HTTPException(409, "busy")
    monkeypatch.setattr(api, "_ensure_free", ensure)
    response = await client.post("/api/cascades/probe-transport", headers=auth_headers,
        json={"entry_id": entry, "exit_id": exit_, "transport": "gre"})
    assert response.status_code == 409 and len(calls) == 2


async def test_repeated_transport_requests_do_not_queue_extra_probe(
    client, auth_headers, session_factory, monkeypatch,
):
    entry, exit_ = await add_servers(session_factory)
    mock_pair(monkeypatch)
    started, release = asyncio.Event(), asyncio.Event()
    calls = []
    async def run(*args, **kwargs):
        calls.append(True); started.set()
        await release.wait()
        return measured("gre")
    monkeypatch.setattr(cascade_probe, "run", run)
    async def request():
        return await client.post("/api/cascades/probe-transport", headers=auth_headers,
            json={"entry_id": entry, "exit_id": exit_, "transport": "gre"})
    task = asyncio.create_task(request())
    await started.wait()
    try:
        assert (await request()).status_code == 409
    finally: release.set()
    assert (await task).status_code == 200 and len(calls) == 1


async def test_legacy_gre_delegates_to_owned_adapter_without_fixed_interface(monkeypatch):
    calls = []
    async def run(*args, **kwargs):
        calls.append(args)
        return measured("gre")
    monkeypatch.setattr(cascade_probe, "run", run)
    result = await cascade.probe_gre(None, None, "203.0.113.10", "203.0.113.20")
    assert result["ok"] is True and calls[0][-1] == "gre"
    assert not hasattr(cascade, "_tmp_gre")


async def test_transport_api_disconnect_waits_for_cleanup_before_unlock(
    client, auth_headers, session_factory, monkeypatch,
):
    from app import nodelock
    entry, exit_ = await add_servers(session_factory)
    mock_pair(monkeypatch)
    started, cleaned = asyncio.Event(), asyncio.Event()
    async def run(*args, **kwargs):
        started.set()
        try: await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            cleaned.set()
    async def disconnected(self): return started.is_set()
    monkeypatch.setattr(cascade_probe, "run", run)
    monkeypatch.setattr(api.Request, "is_disconnected", disconnected)
    response = await client.post("/api/cascades/probe-transport", headers=auth_headers,
        json={"entry_id": entry, "exit_id": exit_, "transport": "gre"})
    assert response.status_code == 499 and cleaned.is_set()
    async with nodelock.hold("cascade", entry, wait=0.1), nodelock.hold("cascade", exit_, wait=0.1):
        pass


async def test_start_stdin_write_failure_still_drains_cleanup(monkeypatch):
    process = Process([{"event": "cleanup", "ok": True}])
    def closed_writer(value): raise BrokenPipeError()
    process.stdin.write = closed_writer
    class Connection:
        async def run(self, *args, **kwargs): return SimpleNamespace(exit_status=0)
        async def create_process(self, *args): return process
    with pytest.raises(cascade_probe.PrerequisiteError):
        await cascade_probe._start(Connection(), {"transport": "gre"})
    assert process.events.empty()


@pytest.mark.parametrize("change,stored", [(None, True), ("port", False), ("endpoint", False)])
async def test_create_binds_new_awg_measurement_to_effective_endpoints_and_ports(
    client, auth_headers, session_factory, monkeypatch, change, stored,
):
    entry, exit_ = await add_servers(session_factory)
    mock_pair(monkeypatch)
    async def preflight(*args): pass
    async def port(conn, requested, reserved=None): return requested
    monkeypatch.setattr(api, "_awg_preflight", preflight)
    monkeypatch.setattr(api, "_awg_port", port)
    monkeypatch.setattr(api.cascade_awg, "new_params", lambda: {})
    monkeypatch.setattr(api.cascadejob, "spawn", lambda *args: None)
    result = measured("awg") | {"entry_ip": "203.0.113.10", "exit_ip": "203.0.113.20"}
    if change == "endpoint": result["exit_ip"] = "203.0.113.21"
    cached = {"awg": result, "tcp": {"ok": True, "bytes": 123, "secs": 1, "mbps": 0}}
    before = json.dumps(cached, sort_keys=True)
    monkeypatch.setitem(api._last_probe, (entry, exit_), cached)
    response = await client.post("/api/cascades", headers=auth_headers, json={
        "entry_id": entry, "exit_id": exit_, "transport": "awg",
        "entry_port": 43125 if change == "port" else 43123, "exit_port": 43124,
    })
    assert response.status_code == 202
    saved = response.json()["probe"]
    assert ("awg" in saved) is stored
    assert saved["tcp"] == cached["tcp"]
    assert json.dumps(cached, sort_keys=True) == before


def test_bound_vless_measurement_uses_its_own_measured_exit_port():
    result = measured("vless") | {"entry_ip": "203.0.113.10", "exit_ip": "203.0.113.20"}
    params = {"entry_ip": "203.0.113.10", "exit_ip": "203.0.113.20", "port": 43124}
    assert api._bound_probe({"vless": result}, "vless", params)["vless"] == result
    assert api._bound_probe({"vless": result}, "vless", params | {"port": 8443}) == {}


async def test_occupied_requested_port_is_unavailable_without_starting_resources(monkeypatch):
    async def owner(*args, **kwargs): return "existing-service"
    async def start(*args): pytest.fail("occupied port must not create temporary resources")
    monkeypatch.setattr(cascade_probe.deploy, "port_owner", owner)
    monkeypatch.setattr(cascade_probe, "_start", start)
    result = await cascade_probe.run(None, None, "203.0.113.10", "203.0.113.20", "awg", 43123, 43124)
    assert result["status"] == "unavailable" and result["ok"] is None
    assert result["error"] == "Для проверки нет свободного порта"
    assert result["secs"] is None and result["mbps"] is None


async def test_awg_auto_ports_match_installer_candidates(monkeypatch):
    choices = []
    async def owner(conn, port, protocol):
        choices.append((port, protocol)); return None
    process = Process([{"event": "unavailable"}, {"event": "cleanup", "ok": True}])
    async def start(*args): return process
    monkeypatch.setattr(cascade_probe.deploy, "port_owner", owner)
    monkeypatch.setattr(cascade_probe, "_start", start)
    await cascade_probe.run(None, None, "203.0.113.10", "203.0.113.20", "awg")
    assert choices == [(cascade_probe.cascade_awg.PORTS[0], "udp")] * 2


async def test_close_terminates_blocked_receiver_but_waits_for_confirmed_cleanup(monkeypatch):
    process = Process([])
    terminated = []
    process.terminate = lambda: terminated.append(True)
    events = iter([TimeoutError(), {"event": "failed"}, {"event": "cleaning"},
                   {"event": "cleanup", "ok": True}])
    async def event(process):
        item = next(events)
        if isinstance(item, Exception): raise item
        return item
    monkeypatch.setattr(cascade_probe, "_event", event)
    assert await cascade_probe._close(process) is True
    assert terminated == [True]
