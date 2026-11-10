"""Privacy and durability tests for the deliberately narrow support log schema."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4
import zipfile

from fastapi import FastAPI
import httpx
import pytest

from app import debuglog
from app.api.debug_logs import router
from app.debuglog import DebugLogStore, MAX_BYTES, classify, record_event
from app.deps import get_current_user
from app.db import get_session


@pytest.fixture
def store(tmp_path):
    return DebugLogStore(tmp_path / "debug-logs")


def unpack(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert set(archive.namelist()) == {"events.json", "README.txt"}
        assert sum(item.file_size for item in archive.infolist()) <= MAX_BYTES + 2048
        return json.loads(archive.read("events.json")), archive.read("README.txt").decode()


@pytest.mark.parametrize(("text", "code"), [
    ("entry ownership denied", "entry_ownership"),
    ("cleanup failed", "cleanup"),
    ("SSH host key changed", "hostkey"),
    ("timed out", "timeout"),
    ("authentication failed", "auth"),
    ("Permission denied", "permission"),
    ("command not found", "dependency_missing"),
    ("download failed", "download"),
    ("connection refused", "connect"),
    ("state conflict", "conflict"),
    ("incomplete result", "integrity"),
    ("validation failed", "validation"),
    ("unclassified diagnostic", "unexpected"),
    ("private-node.example.invalid unknown issue", "unexpected"),
    ("invalid input", "validation"),
    ("SSH-ключ панели не авторизован (выполните настройку сервера)", "auth"),
    ("Панель не нашла адрес сервера в DNS. Укажите IP или доступный панели домен.", "connect"),
    ("DEPLOY_ERROR: не дождался конца установки", "timeout"),
    ("Host-ключ ноды ИЗМЕНИЛСЯ", "hostkey"),
    ("Неверный пароль или на сервере запрещен вход по паролю", "auth"),
])
def test_classification_only_fixed_codes(text, code):
    assert classify(text) == code


def test_hostile_input_never_persisted_or_exported(store):
    hostile = "TOKEN_SENTINEL_abcdef -----BEGIN PRIVATE KEY-----\nAddress=192.0.2.44\nName=PrivateCustomer\nPOST /sensitive BODY_SENTINEL"
    event = store.record(operation="deploy", text="timeout " + hostile, protocol=hostile, stage=hostile, server_id=hostile, correlation_id=hostile, exc=RuntimeError(hostile))
    assert event["code"] == "timeout"
    assert event["summary"] == debuglog.SUMMARIES["timeout"]
    assert {"protocol", "stage", "server_id", "locations"}.isdisjoint(event)
    exported, readme = unpack(store.download(hostile))
    raw = (store.directory / "events.jsonl").read_text(encoding="utf-8") + json.dumps(exported) + readme
    for marker in ("TOKEN_SENTINEL", "PRIVATE KEY", "192.0.2.44", "PrivateCustomer", "BODY_SENTINEL", "sensitive"):
        assert marker not in raw
    assert "Version: unknown" in readme
    assert "platform" not in readme.lower()
    assert record_event(None, text=hostile) is None


def test_allowed_metadata_and_order_filters(store):
    first = store.record(operation="ssh", level="warning", code="connect", protocol="awg3", stage="entry", server_id=7)
    second = store.record(operation="deploy", level="info", code="completed")
    assert store.read()[0] == second
    assert store.read(level="warning", operation="ssh") == [first]
    assert first["server_id"] == 7
    assert first["protocol"] == "awg3"
    assert first["stage"] == "entry"
    assert first["correlation_id"] != second["correlation_id"]
    assert store.read(limit=1) == [second]
    exported, readme = unpack(store.download("0.84.40", level="warning", operation="ssh"))
    assert exported["events"] == [first]
    assert "Version: 0.84.40" in readme


def test_retention_prunes_disk_and_download(store, monkeypatch):
    current = datetime(2026, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(debuglog, "_utcnow", lambda: current)
    old = store.record(code="started")
    current += timedelta(days=8)
    recent = store.record(code="completed")
    assert store.read() == [recent]
    assert old["id"] not in (store.directory / "events.jsonl").read_text()
    exported, _ = unpack(store.download())
    assert exported["events"] == [recent]


def test_store_and_export_size_bounded(store, monkeypatch):
    monkeypatch.setattr(debuglog, "MAX_BYTES", 2048)
    for _ in range(30):
        store.record(operation="deploy", code="unexpected")
    assert 0 < len(store.read()) < 30
    assert sum(p.stat().st_size for p in store.directory.iterdir()) <= 2048
    data, _ = unpack(store.download())
    assert data["events"]
    assert data["max_bytes"] == 2048


def test_corrupt_disk_revalidated_before_list_and_zip(store):
    event = store.record(code="timeout")
    hostile = "DISK_SECRET_PRIVATE_SENTINEL"
    altered = dict(event, summary=hostile, config=hostile, stage=hostile, protocol=hostile, server_id=hostile, locations=[{"module": "app.main", "function": hostile, "line": 1}])
    invalid = dict(event, code=hostile)
    invalid_stack = dict(event, locations={"hostile": hostile})
    path = store.directory / "events.jsonl"
    path.write_bytes(b"not json\n\xff\xfe\n" + (json.dumps(invalid) + "\n" + json.dumps(invalid_stack) + "\n" + json.dumps(altered) + "\n").encode())
    exported, _ = unpack(store.download())
    assert len(exported["events"]) == 2
    assert all(item == event for item in exported["events"])
    assert hostile not in path.read_text(encoding="utf-8")
    assert hostile not in json.dumps(exported)


def test_oversized_disk_discarded_without_reading_arbitrary_payload(store, monkeypatch):
    store.record(code="started")
    monkeypatch.setattr(debuglog, "MAX_BYTES", 2048)
    path = store.directory / "events.jsonl"
    path.write_bytes(b"SECRET_OVERSIZED\n" * 1000)
    assert store.read() == []
    assert path.stat().st_size == 0


def test_disk_failures_are_nonfatal_and_never_log_raw_exception(store, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise OSError("DISK_ERROR_SECRET_SENTINEL")
    monkeypatch.setattr(debuglog.os, "write", fail)
    assert store.record(text="SENSITIVE_BODY") is None
    assert store.read() == []
    exported, _ = unpack(store.download())
    assert exported["events"] == []
    assert "DISK_ERROR_SECRET_SENTINEL" not in caplog.text


def test_multiple_instances_and_threads_serialize_writes(store):
    stores = [DebugLogStore(store.directory) for _ in range(8)]
    def append(index):
        return stores[index % len(stores)].record(code="completed", operation="ssh")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(append, range(120)))
    assert all(results)
    assert len(store.read(200)) == 120
    assert len({item["id"] for item in store.read(200)}) == 120


def test_multiple_processes_serialize_writes(store):
    script = "from pathlib import Path; from app.debuglog import DebugLogStore; import sys; s=DebugLogStore(Path(sys.argv[1])); assert all(s.record(code='completed') for _ in range(30))"
    processes = [subprocess.Popen([sys.executable, "-c", script, str(store.directory)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, (stdout, stderr)
    assert len(store.read(200)) == 60


def test_rejects_symlink_and_hardlink_files(store, tmp_path):
    target = tmp_path / "protected.txt"
    target.write_text("PROTECTED_VALUE")
    store.directory.mkdir()
    try:
        (store.directory / "events.jsonl").symlink_to(target)
    except OSError:
        pytest.skip("OS does not permit creating symlinks")
    assert store.record(code="completed") is None
    assert store.read() == []
    assert target.read_text() == "PROTECTED_VALUE"


def test_rejects_hardlinked_file(store, tmp_path):
    target = tmp_path / "protected.txt"
    target.write_text("PROTECTED_VALUE")
    store.directory.mkdir()
    os.link(target, store.directory / "events.jsonl")
    assert store.record(code="completed") is None
    assert target.read_text() == "PROTECTED_VALUE"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_private_permissions(store):
    store.record(code="completed")
    assert store.directory.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in store.directory.iterdir())


@pytest.mark.parametrize("authenticated", [False, True])
async def test_api_requires_user_jwt_and_returns_filtered_safe_archive(store, authenticated):
    app = FastAPI()
    app.state.debug_logs = store
    app.include_router(router, prefix="/api")
    async def session():
        yield None
    app.dependency_overrides[get_session] = session
    if authenticated:
        app.dependency_overrides[get_current_user] = lambda: object()
    one = store.record(operation="ssh", code="hostkey", level="warning")
    store.record(operation="deploy", code="completed", level="info")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        listing = await client.get("/api/debug-logs?level=warning&operation=ssh", headers={"X-API-Key": "integration-only"})
        archive = await client.get("/api/debug-logs/download?level=warning&operation=ssh")
        if not authenticated:
            assert listing.status_code == archive.status_code == 401
            return
        assert listing.status_code == archive.status_code == 200
        assert listing.json()["events"] == [one]
        assert listing.json()["retention_days"] == 7
        data, _ = unpack(archive.content)
        assert data["events"] == [one]
        assert listing.headers["cache-control"] == archive.headers["cache-control"] == "no-store"
        assert "attachment" in archive.headers["content-disposition"]
        assert (await client.get("/api/debug-logs?operation=PRIVATE_VALUE")).status_code == 422
        assert (await client.get("/api/debug-logs?limit=1000000")).status_code == 422


def test_exception_and_bounded_cause_chain_classified_without_persisting_text(store):
    cause = TimeoutError("CAUSE_PRIVATE_SENTINEL")
    outer = RuntimeError("OUTER_PRIVATE_SENTINEL")
    outer.__cause__ = cause
    cause.__cause__ = outer  # malicious/cyclic exceptions cannot loop forever
    event = store.record(exc=outer)
    assert event["code"] == "timeout"
    raw = (store.directory / "events.jsonl").read_text(encoding="utf-8")
    assert "PRIVATE_SENTINEL" not in raw
    class PermissionDenied(Exception):
        pass
    assert store.record(exc=PermissionDenied("SSH_PRIVATE_SENTINEL"))["code"] == "auth"


def test_only_known_application_source_locations_exported(store):
    event = store.record(code="unexpected")
    event["locations"] = [
        {"module": "app.debuglog", "function": "classify", "line": 1, "locals": "PRIVATE_SENTINEL"},
        {"module": "app.fake_private_module", "function": "classify", "line": 1},
        {"module": "app.debuglog", "function": "PRIVATE_SENTINEL", "line": 1},
        {"module": "app.debuglog", "function": "classify", "line": 999999},
        {"module": "app.debuglog", "function": {}, "line": 1},
    ]
    (store.directory / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
    result = store.read()[0]
    assert result["locations"] == [{"module": "app.debuglog", "function": "classify", "line": 1}]
    exported, _ = unpack(store.download())
    assert "PRIVATE_SENTINEL" not in json.dumps(exported)


def test_hot_append_does_not_reparse_full_journal(store, monkeypatch):
    seed = store.record(code="started")
    path = store.directory / "events.jsonl"
    path.write_text((json.dumps(seed, ensure_ascii=False, separators=(",", ":")) + "\n") * 10_000, encoding="utf-8")
    # The first event validates the externally changed file and establishes a
    # private cache. Further appends must not parse or rewrite 10,000 events.
    assert store.record(code="completed")
    def unexpected_load(*args, **kwargs):
        raise AssertionError("hot append reread the complete journal")
    monkeypatch.setattr(store, "_load", unexpected_load)
    before = path.stat().st_size
    assert all(store.record(code="completed") for _ in range(20))
    assert path.stat().st_size > before


def test_byte_limit_compaction_leaves_room_for_following_appends(store, monkeypatch):
    monkeypatch.setattr(debuglog, "MAX_BYTES", 2048)
    assert store.record(code="started")
    original_load = store._load
    calls = []
    def tracked_load(fd):
        calls.append(True)
        return original_load(fd)
    monkeypatch.setattr(store, "_load", tracked_load)
    for _ in range(30):
        assert store.record(code="completed")
        assert sum(path.stat().st_size for path in store.directory.iterdir()) <= 2048
    assert 0 < len(calls) < 20


def test_external_changes_invalidate_append_cache_and_are_sanitized(store):
    assert store.record(code="started")
    other = DebugLogStore(store.directory)
    assert other.record(code="completed")
    path = store.directory / "events.jsonl"
    with path.open("ab") as stream:
        stream.write(b'{"private":"DISK_PRIVATE_SENTINEL"}\n')
    assert store.record(code="completed")
    assert "DISK_PRIVATE_SENTINEL" not in path.read_text(encoding="utf-8")
    assert len(store.read()) == 3


def test_hot_append_prunes_as_soon_as_oldest_event_expires(store, monkeypatch):
    current = datetime(2026, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(debuglog, "_utcnow", lambda: current)
    old = store.record(code="started")
    current += timedelta(days=6)
    recent = store.record(code="completed")
    assert old["id"] in (store.directory / "events.jsonl").read_text()
    current += timedelta(days=1, seconds=1)
    newest = store.record(code="completed")
    assert old["id"] not in (store.directory / "events.jsonl").read_text()
    assert store.read() == [newest, recent]
