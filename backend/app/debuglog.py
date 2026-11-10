"""Bounded support diagnostics made only from explicitly allowed metadata.

Input text is classified in memory and is NEVER written. This is intentionally
not an ordinary logging handler: raw messages, commands and exception text have
no representation in the persisted schema.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any
from uuid import UUID, uuid4
import zipfile

RETENTION_DAYS = 7
MAX_BYTES = 5 * 1024 * 1024
MAX_RECORD_BYTES = 4096
MAX_EVENTS = 10_000
LEVELS = frozenset({"info", "warning", "error"})
OPERATIONS = frozenset({"request", "ssh", "deploy", "cascade", "probe", "clients", "backup", "import", "alerts", "system"})
PROTOCOLS = frozenset({"awg", "awg2", "awg3", "awg_legacy", "wg", "wireguard", "amneziawg", "openvpn", "xray", "vless", "shadowsocks", "trojan", "ipsec", "ikev2", "gre"})
STAGES = frozenset({"request", "prepare", "completed", "connect", "authenticate", "install", "configure", "start", "verify", "cleanup", "rollback", "restore", "export", "import", "collect", "update", "remove", "download", "entry", "exit", "gateway", "underlay", "route", "probe", "backup", "deploy", "clients"})
SUMMARIES = {
    "started": "Операция начата",
    "accepted": "Задача принята к выполнению",
    "request_completed": "Запрос обработан",
    "completed": "Операция завершена",
    "entry_ownership": "Не удалось подтвердить принадлежность входного узла",
    "cleanup": "Не удалось завершить очистку",
    "timeout": "Превышено время ожидания",
    "auth": "Ошибка аутентификации",
    "hostkey": "Не удалось проверить ключ SSH-сервера",
    "connect": "Не удалось установить соединение",
    "dependency_missing": "Отсутствует необходимая зависимость",
    "download": "Не удалось загрузить компонент",
    "validation": "Не пройдена проверка входных данных",
    "conflict": "Обнаружен конфликт состояния",
    "permission": "Недостаточно прав для операции",
    "integrity": "Операция завершена не полностью или нарушена целостность",
    "unexpected": "Непредвиденная ошибка операции",
}
# Classification is deliberately lossy. Matching text only selects a fixed code.
_CLASSIFIERS = (
    ("entry_ownership", ("entry ownership", "entry-ownership", "принадлежност", "входного узла")),
    ("cleanup", ("cleanup", "clean-up", "очистк")),
    ("hostkey", ("host key", "hostkey", "known_hosts", "host-ключ", "ключ сервера")),
    ("timeout", ("timeout", "timed out", "time out", "время ожидания", "таймаут", "тайм-аут", "не дождался конца установки", "не дождался завершения", "истекло время")),
    ("auth", ("authentication", "authenticationerror", "invalid credentials", "аутентификац", "не авторизован", "неверный пароль", "вход по паролю")),
    ("permission", ("permission denied", "permissionerror", "not permitted", "недостаточно прав")),
    ("dependency_missing", ("not found", "no such file", "missing dependency", "command not found", "зависимост")),
    ("download", ("download", "fetch failed", "загруз")),
    ("connect", ("connection", "connecterror", "unreachable", "соединени", "не нашла адрес сервера в dns", "gaierror", "name or service not known", "getaddrinfo")),
    ("conflict", ("conflict", "already exists", "конфликт")),
    ("integrity", ("incomplete", "integrity", "partial", "целостност", "не полностью")),
    ("validation", ("validation", "invalid input", "invalid value", "invalid configuration", "invalid request", "invalid format", "invalid json", "invalid argument", "invalid parameter", "invalid data", "valueerror", "проверк", "недопустим")),
)
_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()
_APP_ROOT = Path(__file__).resolve().parent


def classify(text: str | None) -> str:
    if not isinstance(text, str):
        return "unexpected"
    sample = text[:65536].lower()
    for code, markers in _CLASSIFIERS:
        if any(marker in sample for marker in markers):
            return code
    return "unexpected"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_correlation_id() -> str:
    return secrets.token_hex(16)


@lru_cache(maxsize=1)
def _source_locations() -> dict[str, tuple[Path, frozenset[str], int]]:
    """Finite inventory from installed application sources, never from log input."""
    inventory = {}
    for source in _APP_ROOT.rglob("*.py"):
        try:
            resolved = source.resolve()
            if source.is_symlink() or not resolved.is_relative_to(_APP_ROOT):
                continue
            contents = source.read_text(encoding="utf-8")
            tree = ast.parse(contents)
            functions = frozenset({"<module>"} | {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))})
            module = "app." + ".".join(source.relative_to(_APP_ROOT).with_suffix("").parts)
            inventory[module] = (resolved, functions, len(contents.splitlines()))
        except (OSError, ValueError, SyntaxError, UnicodeError):
            continue
    return inventory


def _safe_location(module: Any, function: Any, line: Any) -> dict[str, Any] | None:
    if not isinstance(module, str) or not isinstance(function, str) or type(line) is not int:
        return None
    known = _source_locations().get(module)
    if known and function in known[1] and 1 <= line <= known[2]:
        return {"module": module, "function": function, "line": line}
    return None


def _safe_stack(exc: BaseException | None) -> list[dict[str, Any]]:
    """Only actual package source locations, without paths, values or locals."""
    result = []
    tb = exc.__traceback__ if isinstance(exc, BaseException) else None
    while tb is not None:
        code = tb.tb_frame.f_code
        try:
            source = Path(code.co_filename).resolve()
            module = "app." + ".".join(source.relative_to(_APP_ROOT).with_suffix("").parts)
            known = _source_locations().get(module)
            location = _safe_location(module, code.co_name, tb.tb_lineno)
            if known and source == known[0] and location:
                result.append(location)
        except (OSError, ValueError):
            pass
        tb = tb.tb_next
    return result[-8:]


def _classify_exception(text: str | None, exc: BaseException | None) -> str:
    samples = [text[:8192] if isinstance(text, str) else ""]
    seen = set()
    while isinstance(exc, BaseException) and id(exc) not in seen and len(seen) < 4:
        seen.add(id(exc))
        # Some libraries use PermissionDenied for SSH authentication failure.
        if type(exc).__name__ == "PermissionDenied":
            samples.append("authentication")
        samples.append(type(exc).__name__[:128])
        try:
            samples.append(str(exc)[:8192])
        except Exception:
            pass
        exc = exc.__cause__ or exc.__context__
    return classify(" ".join(samples))


def _safe_event(value: Any) -> dict[str, Any] | None:
    """Rebuild even disk records; unknown fields and arbitrary strings never escape."""
    if not isinstance(value, dict):
        return None
    try:
        event_id = str(UUID(value["id"]))
        timestamp = datetime.fromisoformat(value["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None or value["level"] not in LEVELS or value["operation"] not in OPERATIONS or value["code"] not in SUMMARIES:
            return None
        correlation = value["correlation_id"]
        if not isinstance(correlation, str) or not re.fullmatch(r"[0-9a-f]{32}", correlation):
            return None
        event = {"id": event_id, "timestamp": _timestamp(timestamp), "level": value["level"], "operation": value["operation"], "code": value["code"], "summary": SUMMARIES[value["code"]], "correlation_id": correlation}
        for key, choices in (("protocol", PROTOCOLS), ("stage", STAGES)):
            if isinstance(value.get(key), str) and value[key] in choices:
                event[key] = value[key]
        server = value.get("server_id")
        if type(server) is int and 0 < server <= 2**31 - 1:
            event["server_id"] = server
        # Validate against a finite package-source inventory on read as well.
        locations = []
        frames = value.get("locations")
        for frame in frames[:8] if isinstance(frames, list) else []:
            if isinstance(frame, dict):
                location = _safe_location(frame.get("module"), frame.get("function"), frame.get("line"))
                if location:
                    locations.append(location)
        if locations:
            event["locations"] = locations
        return event
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return None


class DebugLogStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory).absolute()
        # This cache contains only file identity and a retention deadline. Every
        # external change forces full validation; exports always validate again.
        self._snapshot: tuple[int, int, int, int] | None = None
        self._expires_at: datetime | None = None
        self._last_now: datetime | None = None
        with _LOCKS_GUARD:
            self._lock = _LOCKS.setdefault(str(self.directory), threading.RLock())

    def _prepare(self) -> None:
        if self.directory.resolve() != self.directory:
            raise OSError("unsafe diagnostics directory")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or self.directory.resolve() != self.directory:
            raise OSError("unsafe diagnostics directory")
        info = self.directory.stat()
        if not stat.S_ISDIR(info.st_mode):
            raise OSError("unsafe diagnostics directory")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise OSError("unsafe diagnostics owner")
        if os.name == "nt":
            os.chmod(self.directory, 0o700)

    def _open(self, name: str, directory_fd: int | None = None) -> int:
        path = self.directory / name
        if path.is_symlink():
            raise OSError("unsafe diagnostics file")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(name, flags, 0o600, dir_fd=directory_fd) if directory_fd is not None else os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False) if directory_fd is not None else path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise OSError("unsafe diagnostics file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise OSError("unsafe diagnostics owner")
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextmanager
    def _locked(self):
        with self._lock:
            self._prepare()
            directory_fd = None
            if os.name != "nt":
                # Anchor every file operation to the verified directory inode.
                # A subsequent rename/symlink swap cannot redirect file access.
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                info = os.fstat(directory_fd)
                if info.st_uid != os.getuid():
                    os.close(directory_fd)
                    raise OSError("unsafe diagnostics owner")
                os.fchmod(directory_fd, 0o700)
            try:
                fd = self._open(".lock", directory_fd)
            except BaseException:
                if directory_fd is not None:
                    os.close(directory_fd)
                raise
            locked = False
            try:
                lock_size = os.fstat(fd).st_size
                if lock_size == 0:
                    os.write(fd, b"\0")
                elif lock_size != 1:
                    raise OSError("unsafe diagnostics lock")
                if os.name == "nt":
                    import msvcrt
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            os.lseek(fd, 0, os.SEEK_SET)
                            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.01)
                else:
                    import fcntl
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.01)
                locked = True
                yield directory_fd
            finally:
                if locked:
                    if os.name == "nt":
                        import msvcrt
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
                if directory_fd is not None:
                    os.close(directory_fd)

    def _load(self, fd: int) -> list[dict[str, Any]]:
        size = os.fstat(fd).st_size
        # An oversized/corrupt file is disposable diagnostics, never application state.
        if size > MAX_BYTES:
            return []
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, MAX_BYTES)
        cutoff, now = _utcnow() - timedelta(days=RETENTION_DAYS), _utcnow()
        events = []
        for line in raw.splitlines():
            if len(line) > MAX_RECORD_BYTES:
                continue
            try:
                event = _safe_event(json.loads(line))
                if event and cutoff <= datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) <= now + timedelta(minutes=1):
                    events.append(event)
            except (ValueError, UnicodeError, RecursionError):
                continue
        return events[-MAX_EVENTS:]

    @staticmethod
    def _signature(fd: int) -> tuple[int, int, int, int]:
        info = os.fstat(fd)
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

    def _remember(self, fd: int, events: list[dict[str, Any]], now: datetime) -> None:
        self._snapshot = self._signature(fd)
        self._expires_at = min((datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) + timedelta(days=RETENTION_DAYS) for event in events), default=None)
        self._last_now = now

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        while data:
            written = os.write(fd, data)
            if not written:
                raise OSError("diagnostics write failed")
            data = data[written:]

    def _save(self, fd: int, events: list[dict[str, Any]], *, max_bytes: int = MAX_BYTES) -> list[dict[str, Any]]:
        lines = []
        size = 1  # the separate locking file is exactly one byte
        kept = []
        for event in reversed(events[-MAX_EVENTS:]):
            line = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
            if len(line) > MAX_RECORD_BYTES or size + len(line) > min(max_bytes, MAX_BYTES):
                break
            size += len(line)
            lines.append(line)
            kept.append(event)
        data = b"".join(reversed(lines))
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        self._write_all(fd, data)
        return list(reversed(kept))

    def record(self, *, operation: str = "system", level: str = "error", code: str | None = None, text: str | None = None, protocol: str | None = None, stage: str | None = None, server_id: int | None = None, correlation_id: str | None = None, exc: BaseException | None = None) -> dict[str, Any] | None:
        try:
            chosen = code if isinstance(code, str) and code in SUMMARIES else _classify_exception(text, exc)
            event = {"id": str(uuid4()), "timestamp": _timestamp(_utcnow()), "level": level if level in LEVELS else "error", "operation": operation if operation in OPERATIONS else "system", "code": chosen, "correlation_id": correlation_id if isinstance(correlation_id, str) and re.fullmatch(r"[0-9a-f]{32}", correlation_id) else new_correlation_id(), "protocol": protocol, "stage": stage, "server_id": server_id, "locations": _safe_stack(exc)}
            event = _safe_event(event)
            if event is None:
                return None
            with self._locked() as directory_fd:
                fd = self._open("events.jsonl", directory_fd)
                try:
                    now = _utcnow()
                    signature = self._signature(fd)
                    line = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                    if len(line) > MAX_RECORD_BYTES:
                        return None
                    trusted = (self._snapshot == signature and self._expires_at is not None
                               and now < self._expires_at
                               and self._last_now is not None
                               and now >= self._last_now - timedelta(minutes=1))
                    if trusted and signature[2] + len(line) + 1 <= MAX_BYTES:
                        # The record has already passed the same schema checks
                        # as an export. Holding the process lock makes this
                        # append safe across all instances and worker processes.
                        os.lseek(fd, 0, os.SEEK_END)
                        self._write_all(fd, line)
                        self._snapshot = self._signature(fd)
                        self._expires_at = min(self._expires_at, datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) + timedelta(days=RETENTION_DAYS))
                        self._last_now = now
                    else:
                        events = self._load(fd) + [event]
                        # Leave space for a batch of new events after reaching
                        # the byte limit, rather than rewriting on every append.
                        budget = MAX_BYTES * 3 // 4 if signature[2] + len(line) + 1 > MAX_BYTES else MAX_BYTES
                        kept = self._save(fd, events, max_bytes=budget)
                        self._remember(fd, kept, now)
                finally:
                    os.close(fd)
            return event
        except Exception:
            # Diagnostics must never break an operation or print an exception.
            return None

    def read(self, limit: int = 200, *, level: str | None = None, operation: str | None = None) -> list[dict[str, Any]]:
        try:
            with self._locked() as directory_fd:
                fd = self._open("events.jsonl", directory_fd)
                try:
                    events = self._load(fd)
                    events = self._save(fd, events)
                    self._remember(fd, events, _utcnow())
                finally:
                    os.close(fd)
            selected = [event for event in reversed(events) if (level is None or event["level"] == level) and (operation is None or event["operation"] == operation)]
            return selected[:max(1, min(int(limit), MAX_EVENTS))]
        except Exception:
            return []

    def download(self, version: str = "unknown", *, level: str | None = None, operation: str | None = None) -> bytes:
        return build_archive(self.read(MAX_EVENTS, level=level, operation=operation), version)


def build_archive(events: list[dict[str, Any]], version: str = "unknown") -> bytes:
    # Revalidation is intentional even when the caller already read the store.
    safe = []
    size = 1024  # fixed JSON wrapper, README and ZIP metadata fit within this reserve
    for item in events[:MAX_EVENTS]:
        checked = _safe_event(item)
        if checked is not None:
            record_size = len(json.dumps(checked, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1
            if record_size > MAX_RECORD_BYTES or size + record_size > MAX_BYTES:
                continue
            size += record_size
            safe.append(checked)
    safe_version = version if isinstance(version, str) and re.fullmatch(r"\d{1,4}\.\d{1,4}\.\d{1,4}(?:-(?:rc|beta|alpha)\.\d{1,4})?", version) else "unknown"
    payload = json.dumps({"events": safe, "retention_days": RETENTION_DAYS, "max_bytes": MAX_BYTES}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    readme = f"Amnezia Control support diagnostics\nVersion: {safe_version}\nRetention: 7 days\nStore limit: 5 MiB\nOnly allowlisted event codes and metadata are included.\nNo raw logs, messages, commands, configurations, host details or credentials.\n".encode("utf-8")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in (("events.json", payload), ("README.txt", readme)):
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 0
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, content)
    return stream.getvalue()


def get_store(request: Any) -> DebugLogStore | None:
    store = getattr(request.app.state, "debug_logs", None)
    return store if isinstance(store, DebugLogStore) else None


def record_event(store: DebugLogStore | None, **kwargs: Any) -> dict[str, Any] | None:
    try:
        return store.record(**kwargs) if store is not None else None
    except Exception:
        return None


emit_event = record_event
