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


@pytest.mark.parametrize("release", ["go", "close", ""])
def test_exit_receiver_deadline_starts_after_delayed_entry_preparation(tmp_path, release):
    worker = worker_namespace()
    config = {"tag": "a" * 32, "interface": "acp1234567890", "container": "probe-test",
              "transport": "gre", "role": "exit", "peer_ip": "203.0.113.20", "peer_source": "203.0.113.20",
              "inner": "198.51.100.1", "peer_inner": "198.51.100.2", "total": 4, "token": "test-token",
              "network": "198.51.100.0/30", "lease": 100, "cleanup_rules": [], "gre_key": 123456}
    events, deadlines, stopped = [], [], []
    clock = {"now": 0}

    class Connection:
        def __init__(self):
            self.parts = iter([b"test-token", b"data"])

        def __enter__(self): return self
        def __exit__(self, *args): return False
        def settimeout(self, _seconds): pass
        def recv(self, _size): return next(self.parts)
        def sendall(self, _data): pass

    class Listener:
        closed = False

        def setsockopt(self, *_args): pass
        def bind(self, _address): pass
        def listen(self, _backlog): pass
        def getsockname(self): return (config["inner"], 43123)
        def settimeout(self, seconds): deadlines.append((clock["now"], seconds))
        def accept(self): return Connection(), (config["peer_inner"], 12345)
        def close(self): self.closed = True

    listener = Listener()

    class Input:
        count = 0

        def readline(self):
            self.count += 1
            if self.count == 1:
                return json.dumps(config) + "\n"
            if self.count == 2:
                assert events[-1]["event"] == "ready"
                assert deadlines == []
                # Entry preparation takes longer than the old 25-second accept
                # deadline; virtual time advances without any real sleeping.
                clock["now"] = 31
                return release + "\n" if release else ""
            return "close\n"

    def command(args, required=True):
        data, code = b"", 0
        if args[:4] == ["ip", "link", "show", "dev"]:
            code = 1
        elif args[:4] == ["ip", "-j", "-4", "route"]:
            data = json.dumps([{"prefsrc": "203.0.113.10"}] if "get" in args else []).encode()
        elif args[:4] == ["ip", "-j", "-4", "address"]:
            data = b"[]"
        elif args[:4] == ["ip", "-j", "-d", "link"]:
            data = json.dumps([{"ifindex": 42, "ifalias": config["tag"]}] if "dev" in args else []).encode()
        elif args[:4] == ["ip", "-j", "link", "show"]:
            data = b'[{"ifindex":42}]'
        return subprocess.CompletedProcess(args, code, data, b"")

    worker["command"] = command
    worker["Path"] = lambda _value: tmp_path
    worker["shutil"] = SimpleNamespace(which=lambda _: "/test/tool")
    worker["sys"] = SimpleNamespace(stdin=Input())
    worker["os"] = SimpleNamespace(umask=lambda _: None, fork=lambda: 123,
        kill=lambda *args: stopped.append(args), waitpid=lambda *args: (123, 0))
    worker["signal"] = SimpleNamespace(SIGTERM=15, SIGALRM=14, signal=lambda *args: None, alarm=lambda _: None)
    worker["socket"] = SimpleNamespace(socket=lambda: listener, SOL_SOCKET=1, SO_REUSEADDR=2)
    worker["time"] = SimpleNamespace(monotonic_ns=lambda: clock["now"] * 1_000_000_000)
    worker["emit"] = lambda **value: events.append(value)
    worker["main"]()
    results = [event for event in events if event["event"] == "result"]
    assert bool(results) is (release == "go")
    assert deadlines == ([(31, 25)] if release == "go" else [])
    if results:
        assert results[0]["bytes"] == 4
    assert listener.closed and stopped == [(123, 15)]
    assert events[-1] == {"event": "cleanup", "ok": True}
    assert not list(tmp_path.iterdir())


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
        return subprocess.CompletedProcess(args, 1, b"", b'Device "acp1234567890" does not exist.\n')
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


@pytest.mark.parametrize(("error", "absent"), [
    (b"error: no such object: probe-test\n", True),
    (b"Error response from daemon: No such container: probe-test\n", True),
    (b"permission denied while trying to connect to the docker API\n", False),
    (b"Error response from daemon: No such container: other-probe-test\n", False),
])
def test_awg_watchdog_distinguishes_absent_container_from_unknown_state(tmp_path, error, absent):
    worker = worker_namespace()
    config = {"tag": "a" * 32, "interface": "acp1234567890", "container": "probe-test",
              "transport": "awg", "lease": 100, "cleanup_rules": []}

    class ChildExit(BaseException): pass

    def command(args, required=True):
        if args == ["docker", "container", "inspect", "probe-test"]:
            return subprocess.CompletedProcess(args, 1, b"[]", error)
        assert args == ["ip", "-j", "-d", "link", "show", "dev", config["interface"]]
        return subprocess.CompletedProcess(args, 1, b"", b'Device "acp1234567890" does not exist.\n')

    def child_exit(code): raise ChildExit(code)

    worker["command"] = command
    worker["Path"] = lambda value: tmp_path
    worker["sys"] = SimpleNamespace(stdin=io.StringIO(json.dumps(config) + "\n"))
    worker["os"] = SimpleNamespace(umask=lambda _: None, fork=lambda: 0, setsid=lambda: None,
        devnull="null", O_RDWR=2, open=lambda *args: 99, dup2=lambda *args: None, _exit=child_exit)
    worker["signal"] = SimpleNamespace(SIGTERM=15, SIG_DFL=0, signal=lambda *args: None)
    worker["time"] = SimpleNamespace(sleep=lambda _: None)
    with pytest.raises(ChildExit):
        worker["main"]()
    assert bool(list(tmp_path.iterdir())) is not absent


@pytest.mark.parametrize("launch_code", [124, 125])
def test_awg_keeps_watchdog_only_when_container_launch_may_be_pending(tmp_path, launch_code):
    worker = worker_namespace()
    config = {"tag": "a" * 32, "interface": "acp1234567890", "container": "probe-test",
              "transport": "awg", "role": "exit", "inner": "198.51.100.1", "peer_inner": "198.51.100.2",
              "network": "198.51.100.0/30", "lease": 100, "awg_config": "", "images": ["test-image"],
              "xray_version": "unused"}
    events, stopped = [], []

    def command(args, required=True):
        if args[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, b'[{"Id":"test-image-id"}]', b"")
        if args[:3] == ["docker", "container", "inspect"]:
            return subprocess.CompletedProcess(args, 1, b"[]", b"error: no such object: probe-test\n")
        if args[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(args, launch_code, b"", b"")
        if args[:3] == ["ip", "-j", "-4"]:
            return subprocess.CompletedProcess(args, 0, b"[]", b"")
        assert args[0] == "ip" and args[-1] == config["interface"]
        return subprocess.CompletedProcess(args, 1, b"", b'Device "acp1234567890" does not exist.\n')

    worker["command"] = command
    worker["Path"] = lambda value: tmp_path
    worker["shutil"] = SimpleNamespace(which=lambda _: "/test/tool")
    worker["sys"] = SimpleNamespace(stdin=io.StringIO(json.dumps(config) + "\n"))
    worker["os"] = SimpleNamespace(umask=lambda _: None, fork=lambda: 123,
        kill=lambda *args: stopped.append(args), waitpid=lambda *args: (123, 0))
    worker["signal"] = SimpleNamespace(SIGTERM=15, SIGALRM=14, signal=lambda *args: None, alarm=lambda _: None)
    worker["emit"] = lambda **value: events.append(value)
    worker["main"]()
    confirmed = launch_code == 125
    assert events[-1] == {"event": "cleanup", "ok": confirmed}
    assert stopped == ([(123, 15)] if confirmed else [])
    assert bool(list(tmp_path.iterdir())) is not confirmed


class Process:
    def __init__(self, events):
        self.events = asyncio.Queue()
        for event in events:
            self.events.put_nowait(json.dumps(event) + "\n")
        self.started = asyncio.Event()
        self.stdout = SimpleNamespace(readline=self.readline)
        self.writes = []
        self.stdin = SimpleNamespace(write=self.write, write_eof=lambda: None)

    async def readline(self):
        line = await self.events.get()
        if json.loads(line).get("event") == "result":
            await self.started.wait()
        return line

    def write(self, value):
        self.writes.append(value)
        if value == "go\n":
            self.started.set()


async def test_setup_unavailable_is_not_a_fake_transport_measurement(monkeypatch):
    process = Process([{"event": "unavailable", "error": "local_image_missing"},
                       {"event": "cleanup", "ok": True}])
    async def start(*args): return process
    async def port(*args): return 43123
    async def prepare(*args): pytest.fail("ordinary checks must not prepare an image")
    monkeypatch.setattr(cascade_probe, "_start", start)
    monkeypatch.setattr(cascade_probe, "_port", port)
    monkeypatch.setattr(cascade_probe, "_prepare", prepare)
    result = await cascade_probe.run(None, None, "203.0.113.10", "203.0.113.20", "awg")
    assert result["status"] == "unavailable" and result["ok"] is None
    assert result["secs"] is None and result["mbps"] is None
    assert result["bytes"] == 0 and "образа" in result["error"]
    assert result["reason"] == "local_image_missing"


def test_docker_daemon_error_is_not_reported_as_missing_image():
    worker = worker_namespace()
    def command(args):
        return subprocess.CompletedProcess(args, 1, b"", b"Cannot connect to the Docker daemon")
    with pytest.raises(worker["Unavailable"], match="resource operation failed"):
        worker["local_image"](["example"], "0", command, None)


@pytest.mark.parametrize("transport", ["awg", "vless"])
async def test_opt_in_prepares_both_nodes_before_starting_measurement(monkeypatch, transport):
    size = cascade_probe.PAYLOAD_BYTES
    nodes = [object(), object()]
    processes = iter([
        Process([{"event": "ready", "receiver_port": 43123}, {"event": "result", "bytes": size},
                 {"event": "cleanup", "ok": True}]),
        Process([{"event": "ready"}, {"event": "result", "bytes": size, "sent": size,
                                      "secs": 0.2, "digest_matches": True}, {"event": "cleanup", "ok": True}]),
    ])
    prepared = set()
    async def prepare(node, config):
        prepared.add(node)
        if transport == "awg":
            assert cascade_probe.AWG_PROBE_IMAGE in config["images"]
            script = config["build_script"]
            assert cascade_probe.deploy.AWG3_GO_TAG in script and cascade_probe.deploy.AWG3_TOOLS_TAG in script
            assert "systemctl" not in script and "docker tag" not in script
        else:
            assert config["images"][0] == cascade.XRAY_IMAGE and config["build_script"] == ""
        return 0
    async def start(node, config):
        assert prepared == set(nodes)
        return next(processes)
    async def port(*args): return 43123
    monkeypatch.setattr(cascade_probe, "_prepare", prepare)
    monkeypatch.setattr(cascade_probe, "_start", start)
    monkeypatch.setattr(cascade_probe, "_port", port)
    result = await cascade_probe.run(*nodes, "203.0.113.10", "203.0.113.20", transport,
                                     prepare_missing_image=True)
    assert result["status"] == "ok" and result["bytes"] == size


@pytest.mark.parametrize("code,status,reason", [(2, "unavailable", "local_image_missing"),
                                                (4, "failed", None), (5, "unavailable", None)])
async def test_failed_preparation_stops_before_measurement(monkeypatch, code, status, reason):
    async def prepare(node, config): return code if node == "exit" else 0
    async def start(*args): pytest.fail("measurement must not start after failed image preparation")
    async def port(*args): return 43123
    monkeypatch.setattr(cascade_probe, "_prepare", prepare)
    monkeypatch.setattr(cascade_probe, "_start", start)
    monkeypatch.setattr(cascade_probe, "_port", port)
    result = await cascade_probe.run("exit", "entry", "203.0.113.10", "203.0.113.20", "awg",
                                     prepare_missing_image=True)
    assert result["status"] == status and result["reason"] == reason
    assert result["bytes"] == 0


async def test_cancelling_preparation_closes_stdin_and_waits_for_worker():
    waiting, eof, cleaned = asyncio.Event(), asyncio.Event(), asyncio.Event()
    async def wait_closed():
        waiting.set()
        await eof.wait()
        await asyncio.sleep(0)
        cleaned.set()
    async def create_process(*args):
        return SimpleNamespace(wait_closed=wait_closed, stdin=SimpleNamespace(write_eof=eof.set))
    connection = SimpleNamespace(create_process=create_process)
    task = asyncio.create_task(cascade_probe._prepare(connection, {}))
    await waiting.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cleaned.is_set()


async def test_cleanup_failure_retains_full_measurement_and_identifies_side(monkeypatch):
    size = cascade_probe.PAYLOAD_BYTES
    exit_ = Process([{"event": "ready", "receiver_port": 43123},
                     {"event": "result", "bytes": size}, {"event": "cleanup", "ok": False}])
    entry = Process([{"event": "ready"}, {"event": "result", "bytes": size,
                       "sent": size, "secs": 0.2, "digest_matches": True},
                     {"event": "cleanup", "ok": True}])
    writes = []
    for role, process in (("exit", exit_), ("entry", entry)):
        def write(value, role=role, process=process):
            writes.append((role, value))
            process.write(value)
        process.stdin.write = write
    processes = iter([exit_, entry])
    async def start(*args): return next(processes)
    monkeypatch.setattr(cascade_probe, "_start", start)
    result = await cascade_probe.run(None, None, "203.0.113.10", "203.0.113.20", "gre")
    assert result["status"] == "failed" and result["ok"] is False
    assert result["error"] == cascade_probe.CLEANUP_ERROR
    assert result["transfer_ok"] is True and result["bytes"] == size
    assert result["cleanup_failed"] == ["exit"]
    assert exit_.writes[0] == "go\n"
    assert entry.writes[0] == "go\n"
    assert writes[:2] == [("exit", "go\n"), ("entry", "go\n")]


async def test_gre_probe_uses_routed_entry_address_for_exit_peer_and_firewall(monkeypatch):
    async def start(connection, config):
        assert config["role"] == "exit"
        assert config["peer_ip"] == config["peer_source"] == "203.0.113.30"
        assert config["cleanup_rules"][0][4] == "203.0.113.30"
        return Process([{"event": "unavailable"}, {"event": "cleanup", "ok": True}])

    monkeypatch.setattr(cascade_probe, "_start", start)
    result = await cascade_probe.run(None, None, "203.0.113.10", "203.0.113.20", "gre",
                                     entry_source_ip="203.0.113.30")
    assert result["status"] == "unavailable"


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
    async def available(*args): return None
    monkeypatch.setattr(api, "_locked_pair", locked)
    monkeypatch.setattr(api, "_addresses", addresses)
    monkeypatch.setattr(api, "_entry_creation_available", available)
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
    body.update(transport="gre", prepare_missing_image=True)
    assert (await client.post("/api/cascades/probe-transport", json=body,
                              headers=auth_headers)).status_code == 422


@pytest.mark.parametrize("prepare", [{}, {"prepare_missing_image": True}])
async def test_transport_api_preserves_measurement_on_geo_error_and_binds_endpoint_ports(
    client, auth_headers, session_factory, monkeypatch, prepare,
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
        json={"entry_id": entry, "exit_id": exit_, "transport": "awg", "entry_port": 43123,
              "exit_port": 43124, **prepare})
    assert response.status_code == 200
    result = response.json()
    assert result["ok"] is True and result["exit_country"] == "ZZ"
    assert result["entry_ip"] == "203.0.113.10"
    assert captured[0][0][2:7] == ("203.0.113.10", "203.0.113.20", "awg", 43123, 43124)
    assert captured[0][1]["entry_source_ip"] == "203.0.113.10"
    assert captured[0][1]["prepare_missing_image"] == bool(prepare)
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


@pytest.mark.parametrize("reserved_exit", [False, True])
async def test_awg_auto_ports_match_installer_candidates(monkeypatch, reserved_exit):
    choices = []
    async def owner(conn, port, protocol):
        choices.append((port, protocol)); return None
    process = Process([{"event": "unavailable"}, {"event": "cleanup", "ok": True}])
    async def start(*args): return process
    monkeypatch.setattr(cascade_probe.deploy, "port_owner", owner)
    monkeypatch.setattr(cascade_probe, "_start", start)
    ports = cascade_probe.cascade_awg.PORTS
    reserved = {ports[0]} if reserved_exit else set()
    await cascade_probe.run(None, None, "203.0.113.10", "203.0.113.20", "awg",
                            reserved_exit_ports=reserved)
    assert choices == [(ports[0], "udp"), (ports[int(reserved_exit)], "udp")]


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
