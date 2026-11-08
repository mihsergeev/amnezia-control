import logging

from fastapi import HTTPException, status

log = logging.getLogger("acontrol.conflict")


def conflict(
    reason: str, detail: str, *, cascade_id: int | None = None,
    server_id: int | None = None, side: str | None = None,
) -> HTTPException:
    # The response may contain names and SSH details. Log only controlled fields.
    log.warning("HTTP 409 reason=%s cascade_id=%s server_id=%s side=%s",
                reason, cascade_id, server_id, side)
    return HTTPException(status.HTTP_409_CONFLICT, detail)
