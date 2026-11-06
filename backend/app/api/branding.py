import base64
import hashlib
import json
import re

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

from app import audit
from app.deps import CurrentUser, SessionDep
from app.logo_png import MAX_PNG_BYTES, normalize_png
from app.models import AppSetting


router = APIRouter(prefix="/branding", tags=["branding"])
_SETTING = "panel_logo"
_THEMES = ("light", "dark")
_MAX_BASE64 = ((MAX_PNG_BYTES + 2) // 3) * 4
# Both encoded variants, their JSON fields and a small envelope. Stay below
# nginx's default 1 MiB request limit even for a direct backend request.
_MAX_REQUEST = 2 * _MAX_BASE64 + 128
_VERSION = re.compile(r"[0-9a-f]{64}")
_NO_CACHE = {"Cache-Control": "no-store"}
_INVALID = "Нужны корректные PNG для светлой и темной темы"
_TOO_LARGE = "Изображения логотипа слишком большие"


def _decode_png(value: str) -> bytes:
    if len(value) > _MAX_BASE64:
        raise ValueError("PNG too large")
    return normalize_png(base64.b64decode(value, validate=True))


async def _load_branding(session: SessionDep) -> dict[str, str] | None:
    raw = await session.scalar(select(AppSetting.value).where(AppSetting.key == _SETTING))
    if not raw or len(raw) > _MAX_REQUEST + 128:
        return None
    try:
        record = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    if (
        not isinstance(record, dict)
        or not isinstance(record.get("version"), str)
        or not _VERSION.fullmatch(record["version"])
        or not all(isinstance(record.get(theme), str) for theme in _THEMES)
    ):
        return None
    return record


@router.get("")
async def get_branding(response: Response, session: SessionDep) -> dict[str, str | None]:
    response.headers.update(_NO_CACHE)
    record = await _load_branding(session)
    return {"version": record["version"] if record else None}


@router.get("/logo/{theme}", response_class=Response)
async def get_logo(theme: str, session: SessionDep, v: str | None = None) -> Response:
    not_found = HTTPException(404, "Логотип не найден", headers=_NO_CACHE)
    if theme not in _THEMES or v is None or not _VERSION.fullmatch(v):
        raise not_found
    record = await _load_branding(session)
    if not record or record["version"] != v:
        raise not_found
    try:
        image = _decode_png(record[theme])
    except ValueError:
        raise not_found from None
    return Response(
        image,
        media_type="image/png",
        headers={
            "Cache-Control": "private, max-age=31536000, immutable",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.put("")
async def update_branding(
    request: Request, response: Response, session: SessionDep, user: CurrentUser
) -> dict[str, str]:
    # Bound the whole request even without Content-Length. Don't expose the
    # payload in FastAPI's validation errors for malformed JSON or fields.
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_REQUEST:
            raise HTTPException(413, _TOO_LARGE)
        body.extend(chunk)
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        raise HTTPException(400, _INVALID) from None
    if (
        not isinstance(data, dict)
        or data.keys() != set(_THEMES)
        or not all(isinstance(data[theme], str) for theme in _THEMES)
    ):
        raise HTTPException(400, _INVALID)
    if any(len(data[theme]) > _MAX_BASE64 for theme in _THEMES):
        raise HTTPException(413, _TOO_LARGE)
    try:
        images = {theme: _decode_png(data[theme]) for theme in _THEMES}
    except ValueError:
        raise HTTPException(400, _INVALID) from None

    version = hashlib.sha256(images["light"] + images["dark"]).hexdigest()
    record = {theme: base64.b64encode(image).decode("ascii") for theme, image in images.items()}
    record["version"] = version
    insert = pg_insert if session.get_bind().dialect.name == "postgresql" else sqlite_insert
    stmt = insert(AppSetting).values(key=_SETTING, value=json.dumps(record, separators=(",", ":")))
    try:
        await session.execute(stmt.on_conflict_do_update(
            index_elements=[AppSetting.key], set_={"value": stmt.excluded.value}
        ))
        await session.commit()
    except SQLAlchemyError:
        # Database exceptions can include all bound parameters, including the PNGs.
        raise HTTPException(503, "Не удалось сохранить логотип", headers=_NO_CACHE) from None
    await audit.record(session, user.username, "branding.update")
    response.headers.update(_NO_CACHE)
    return {"version": version}


@router.delete("")
async def reset_branding(
    response: Response, session: SessionDep, user: CurrentUser
) -> dict[str, None]:
    await session.execute(delete(AppSetting).where(AppSetting.key == _SETTING))
    await session.commit()
    await audit.record(session, user.username, "branding.reset")
    response.headers.update(_NO_CACHE)
    return {"version": None}
