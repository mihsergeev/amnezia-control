import base64
import hashlib
import json
import re
import unicodedata

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
_LOGIN_SIZE_SETTING = "panel_login_logo_size"
_TITLE_SETTINGS = {
    "header_title": "panel_header_title",
    "tab_title": "panel_tab_title",
}
_HIDE_HEADER_TITLE_SETTING = "panel_hide_header_title"
_SETTINGS = (_SETTING, _SIZE_SETTING, _LOGIN_SIZE_SETTING, _HIDE_HEADER_TITLE_SETTING, *_TITLE_SETTINGS.values())
_THEMES = ("light", "dark")
_MAX_BASE64 = ((MAX_PNG_BYTES + 2) // 3) * 4
# Both encoded variants, their JSON fields and a small envelope. Stay below
# nginx's default 1 MiB request limit even for a direct backend request.
_MAX_REQUEST = 2 * _MAX_BASE64 + 4096
_MAX_TITLE_LENGTH = 80
_VERSION = re.compile(r"[0-9a-f]{64}")
_NO_CACHE = {"Cache-Control": "no-store"}
_INVALID = "Нужны корректные PNG для светлой и темной темы"
_INVALID_SIZE = "Размер логотипа должен быть от 60 до 140% для компьютера и от 60 до 130% для телефона"
_INVALID_LOGIN_SIZE = "Размер логотипа на странице входа должен быть от 60 до 140%"
_TOO_LARGE = "Изображения логотипа слишком большие"

BrandingMetadata = dict[str, str | dict[str, int] | int | bool | None]


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


def _valid_scale(value: object, limit: int = 140) -> bool:
    return type(value) is int and 60 <= value <= limit


def _valid_size(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.keys() == {"desktop", "mobile"}
        and all(
            _valid_scale(value[screen], limit)
            for screen, limit in (("desktop", 140), ("mobile", 130))
        )
    )


def _valid_title(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= _MAX_TITLE_LENGTH
        and all(unicodedata.category(char) not in {"Cc", "Cs", "Zl", "Zp"} for char in value)
    )


async def _metadata(session: SessionDep) -> BrandingMetadata:
    rows = await session.execute(select(AppSetting.key, AppSetting.value).where(
        AppSetting.key.in_(_SETTINGS)
    ))
    settings = {key: value for key, value in rows}
    logo = _parse_logo(settings.get(_SETTING))
    result: BrandingMetadata = {"version": logo["version"] if logo else None}
    for key, field, validate in (
        (_SIZE_SETTING, "size", _valid_size),
        (_LOGIN_SIZE_SETTING, "login_size", _valid_scale),
        (_HIDE_HEADER_TITLE_SETTING, "hide_header_title", lambda value: type(value) is bool),
        *((key, field, _valid_title) for field, key in _TITLE_SETTINGS.items()),
    ):
        try:
            value = json.loads(settings.get(key, "null"))
        except (ValueError, RecursionError):
            continue
        if validate(value):
            result[field] = value
    return result


@router.get("")
async def get_branding(response: Response, session: SessionDep) -> BrandingMetadata:
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
) -> BrandingMetadata:
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
    fields = {*_THEMES, "size", "login_size", "hide_header_title", *_TITLE_SETTINGS}
    if not isinstance(data, dict) or not data.keys() <= fields or not data:
        raise HTTPException(400, _INVALID)
    values = {}
    if "size" in data:
        if not _valid_size(data["size"]):
            raise HTTPException(400, _INVALID_SIZE)
        values[_SIZE_SETTING] = data["size"]
    if "login_size" in data:
        if not _valid_scale(data["login_size"]):
            raise HTTPException(400, _INVALID_LOGIN_SIZE)
        values[_LOGIN_SIZE_SETTING] = data["login_size"]
    if "hide_header_title" in data:
        if type(data["hide_header_title"]) is not bool:
            raise HTTPException(400, "Некорректная настройка подписи в шапке")
        values[_HIDE_HEADER_TITLE_SETTING] = data["hide_header_title"]
    for field, key in _TITLE_SETTINGS.items():
        if field in data:
            value = data[field]
            if not _valid_title(value):
                raise HTTPException(400, "Название должно занимать одну строку и содержать не более 80 символов")
            values[key] = value.strip()
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
        raise HTTPException(503, "Не удалось сохранить оформление", headers=_NO_CACHE) from None
    await audit.record(session, user.username, "branding.update")
    response.headers.update(_NO_CACHE)
    return result


@router.delete("")
async def reset_branding(
    response: Response, session: SessionDep, user: CurrentUser
) -> dict[str, None]:
    await session.execute(delete(AppSetting).where(AppSetting.key.in_(_SETTINGS)))
    await session.commit()
    await audit.record(session, user.username, "branding.reset")
    response.headers.update(_NO_CACHE)
    return {"version": None}
