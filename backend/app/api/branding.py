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
_SIZE_SETTING = "panel_logo_size"
_THEMES = ("light", "dark")
_MAX_BASE64 = ((MAX_PNG_BYTES + 2) // 3) * 4
# Both encoded variants, their JSON fields and a small envelope. Stay below
# nginx's default 1 MiB request limit even for a direct backend request.
_MAX_REQUEST = 2 * _MAX_BASE64 + 128
_VERSION = re.compile(r"[0-9a-f]{64}")
_NO_CACHE = {"Cache-Control": "no-store"}
_INVALID = "Нужны корректные PNG для светлой и темной темы"
_INVALID_SIZE = "Размер логотипа должен быть от 60 до 140% для компьютера и от 60 до 130% для телефона"
_TOO_LARGE = "Изображения логотипа слишком большие"


def _decode_png(value: str) -> bytes:
    if len(value) > _MAX_BASE64:
        raise ValueError("PNG too large")
    return normalize_png(base64.b64decode(value, validate=True))


def _parse_logo(raw: str | None) -> dict[str, str] | None:
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


def _valid_size(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.keys() == {"desktop", "mobile"}
        and all(
            type(value[screen]) is int and 60 <= value[screen] <= limit
            for screen, limit in (("desktop", 140), ("mobile", 130))
        )
    )


async def _metadata(session: SessionDep) -> dict[str, str | dict[str, int] | None]:
    rows = await session.execute(select(AppSetting.key, AppSetting.value).where(
        AppSetting.key.in_((_SETTING, _SIZE_SETTING))
    ))
    settings = {key: value for key, value in rows}
    logo = _parse_logo(settings.get(_SETTING))
    result: dict[str, str | dict[str, int] | None] = {"version": logo["version"] if logo else None}
    try:
        size = json.loads(settings.get(_SIZE_SETTING, "null"))
    except (ValueError, RecursionError):
        size = None
    if _valid_size(size):
        result["size"] = size
    return result


@router.get("")
async def get_branding(response: Response, session: SessionDep) -> dict[str, str | dict[str, int] | None]:
    response.headers.update(_NO_CACHE)
    return await _metadata(session)


@router.get("/logo/{theme}", response_class=Response)
async def get_logo(theme: str, session: SessionDep, v: str | None = None) -> Response:
    not_found = HTTPException(404, "Логотип не найден", headers=_NO_CACHE)
    if theme not in _THEMES or v is None or not _VERSION.fullmatch(v):
        raise not_found
    raw = await session.scalar(select(AppSetting.value).where(AppSetting.key == _SETTING))
    record = _parse_logo(raw)
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
) -> dict[str, str | dict[str, int] | None]:
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
    if not isinstance(data, dict) or not data.keys() <= {*_THEMES, "size"} or not data:
        raise HTTPException(400, _INVALID)
    values = {}
    if "size" in data:
        if not _valid_size(data["size"]):
            raise HTTPException(400, _INVALID_SIZE)
        values[_SIZE_SETTING] = data["size"]
    if any(theme in data for theme in _THEMES):
        if not all(isinstance(data.get(theme), str) for theme in _THEMES):
            raise HTTPException(400, _INVALID)
        if any(len(data[theme]) > _MAX_BASE64 for theme in _THEMES):
            raise HTTPException(413, _TOO_LARGE)
        try:
            images = {theme: _decode_png(data[theme]) for theme in _THEMES}
        except ValueError:
            raise HTTPException(400, _INVALID) from None
        record = {theme: base64.b64encode(image).decode("ascii") for theme, image in images.items()}
        record["version"] = hashlib.sha256(images["light"] + images["dark"]).hexdigest()
        values[_SETTING] = record

    insert = pg_insert if session.get_bind().dialect.name == "postgresql" else sqlite_insert
    stmt = insert(AppSetting).values([
        {"key": key, "value": json.dumps(value, separators=(",", ":"))}
        for key, value in sorted(values.items())
    ])
    try:
        await session.execute(stmt.on_conflict_do_update(
            index_elements=[AppSetting.key], set_={"value": stmt.excluded.value}
        ))
        result = await _metadata(session)
        await session.commit()
    except SQLAlchemyError:
        # Database exceptions can include all bound parameters, including the PNGs.
        raise HTTPException(503, "Не удалось сохранить логотип", headers=_NO_CACHE) from None
    await audit.record(session, user.username, "branding.update")
    response.headers.update(_NO_CACHE)
    return result


@router.delete("")
async def reset_branding(
    response: Response, session: SessionDep, user: CurrentUser
) -> dict[str, None]:
    await session.execute(delete(AppSetting).where(AppSetting.key.in_((_SETTING, _SIZE_SETTING))))
    await session.commit()
    await audit.record(session, user.username, "branding.reset")
    response.headers.update(_NO_CACHE)
    return {"version": None}
