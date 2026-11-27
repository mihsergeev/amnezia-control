import asyncio
import json
from typing import Annotated, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

_SOCKET_PATH = "/run/acontrol-updater/control.sock"
_FRAME_LIMIT = 4096
_IO_TIMEOUT = 2

InstallVersion = Annotated[
    str, Field(pattern=r"^(0|[1-9][0-9]{0,7})\.(0|[1-9][0-9]{0,7})\.(0|[1-9][0-9]{0,7})$")
]
InstallationPhase = Literal[
    "idle", "queued", "verifying", "backing_up", "installing", "checking",
    "succeeded", "rolling_back", "rolled_back", "failed", "recovery_required",
]
_BUSY_PHASES = {"queued", "verifying", "backing_up", "installing", "checking", "rolling_back"}
_ERROR_CODES = {
    "busy", "incompatible", "verification_failed", "backup_failed", "install_failed",
    "health_failed", "interrupted", "recovery_failed", "unusable_state",
}


class WorkerStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    phase: InstallationPhase
    version: InstallVersion | None
    error: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")] | None

    @property
    def public_error(self) -> str | None:
        if self.error is None or self.error in _ERROR_CODES:
            return self.error
        return "installation_rejected"


class WorkerInstallReply(WorkerStatus):
    accepted: bool

    @property
    def busy(self) -> bool:
        return self.phase in _BUSY_PHASES or self.error == "busy"


_Reply = TypeVar("_Reply", bound=WorkerStatus)


def _unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate reply fields")
    return fields


async def _exchange(message: dict[str, str]) -> bytes | None:
    # Some platforms do not support AF_UNIX asyncio streams.
    connect = getattr(asyncio, "open_unix_connection", None)
    if connect is None:
        return None
    writer = None
    try:
        async with asyncio.timeout(_IO_TIMEOUT):
            reader, writer = await connect(_SOCKET_PATH, limit=_FRAME_LIMIT)
            writer.write(json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n")
            await writer.drain()
            frame = await reader.readuntil(b"\n")
            if len(frame) <= _FRAME_LIMIT:
                return frame
    except (OSError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, NotImplementedError):
        pass
    finally:
        if writer is not None:
            writer.close()
    return None


def _parse(frame: bytes | None, reply: type[_Reply]) -> _Reply | None:
    if frame is None:
        return None
    try:
        return reply.model_validate(json.loads(frame.decode("ascii"), object_pairs_hook=_unique_fields))
    except (ValueError, RecursionError):
        return None


async def get_status() -> WorkerStatus | None:
    return _parse(await _exchange({"action": "status"}), WorkerStatus)


async def request_install(version: str) -> WorkerInstallReply | None:
    frame = await _exchange({"action": "install", "version": version})
    reply = _parse(frame, WorkerInstallReply)
    if reply is not None and (
        not reply.accepted or (reply.version == version and reply.error is None and reply.phase != "idle")
    ):
        return reply
    return None
