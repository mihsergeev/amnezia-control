"""Перенос ОДНОГО сервера между панелями: выгрузка в файл и загрузка из него.

Полный бэкап (`/backup`) переносит панель целиком — всё или ничего. Когда нужно
отделить один сервер (отдать проект другой команде, разнести парк по панелям),
он не годится: восстановление затирает всю принимающую панель.

Просто «добавить сервер» на новой панели тоже недостаточно. Живых клиентов она
подтянет с ноды, но панельная обвязка — сохранённые конфиги (без них клиенту
нельзя отдать файл или QR, только перевыпустить), заметки, сроки действия и
паузы — живёт в БД старой панели и потерялась бы молча.

Формат — обычный JSON: файл можно открыть и посмотреть, что именно уезжает.
Он содержит СЕКРЕТЫ (приватные ключи в сохранённых конфигах клиентов), поэтому
обращаться с ним нужно как с бэкапом.

SSH-ключ панели в файл НЕ кладём: он один на все ноды, и его переезд отдал бы
новой панели доступ ко всему парку старой. Принимающая панель ходит на ноду
своим ключом — после загрузки её нужно пустить на сервер (кнопка «Установить
ключ» / setup-script), об этом сообщает ответ на импорт.
"""

import json
from datetime import date, datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy import DateTime, func, insert, select

from app import audit
from app.config import get_settings
from app.db import Base
from app.deps import CurrentUser, SessionDep
from app.models import Server
from app.schemas import ServerImportResult

router = APIRouter(tags=["transfer"])

FORMAT = "acontrol-server-export"
FORMAT_VERSION = 1

# Влезать в файл переноса должно только то, что панель НЕ может перечитать с
# ноды. Рантайм-таблицы (статус проверки, метрики) осознанно пропускаем — они
# наполнятся сами при первом же опросе, а перенос устаревших значений только
# путал бы: новая панель показывала бы чужое «онлайн» до первой проверки.
_RUNTIME_TABLES = {"server_status", "node_metrics"}

# История трафика на активной ноде — сотни тысяч строк (у боевого сервера это
# ~0.8 млн). Тащим только по явному запросу, иначе файл раздувается в сотни
# мегабайт ради графиков, которые новая панель и так наберёт заново.
_HISTORY_TABLES = {"traffic_samples", "client_traffic_samples"}

# поля сервера, которые имеет смысл переносить: адрес, доступ и то, как карточка
# выглядит. id/position/результаты последней проверки — местные, их не берём
_SERVER_FIELDS = ("name", "host", "ssh_port", "ssh_user", "note", "group_name",
                  "country")

_MAX_IMPORT_BYTES = 200 * 1024 * 1024


def server_scoped_models() -> list:
    """Модели с колонкой server_id — «панельные хвосты» сервера.

    Список выводим из реестра моделей, а не пишем руками: новая таблица с
    server_id попадёт в перенос сама. Иначе её бы молча теряли при переезде —
    ровно так однажды потеряли конфиги OpenVPN при удалении сервера.
    """
    models = []
    for mapper in Base.registry.mappers:
        model = mapper.class_
        if model is Server:
            continue
        if "server_id" in model.__table__.columns:
            models.append(model)
    return models


def _jsonable(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _coerce_row(model, row: dict) -> dict:
    """Значения из JSON — к типам колонок: даты приезжают ISO-строками, а
    SQLAlchemy ждёт datetime (иначе вставка падает уже на приёме)."""
    out = {}
    for col in model.__table__.columns:
        if col.name not in row:
            continue
        val = row[col.name]
        if isinstance(val, str) and isinstance(col.type, DateTime):
            try:
                val = datetime.fromisoformat(val)
            except ValueError:
                val = None
        out[col.name] = val
    return out


def _selected_models(history: bool) -> list:
    skip = set(_RUNTIME_TABLES)
    if not history:
        skip |= _HISTORY_TABLES
    return [m for m in server_scoped_models() if m.__tablename__ not in skip]


@router.get("/servers/{server_id}/export")
async def export_server(
    server_id: int, user: CurrentUser, session: SessionDep, history: bool = False
) -> Response:
    """Выгрузка одного сервера со всей его панельной обвязкой в JSON-файл."""
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")

    tables: dict[str, list[dict]] = {}
    for model in _selected_models(history):
        rows = await session.scalars(
            select(model).where(model.server_id == server_id)
        )
        tables[model.__tablename__] = [
            {
                c.name: _jsonable(getattr(row, c.name))
                for c in row.__table__.columns
                # id локален для БД-источника: на приёме строки вставляются
                # заново, свой автоинкремент назначит принимающая панель
                if c.name not in ("id", "server_id")
            }
            for row in rows
        ]

    payload = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "panel_version": get_settings().version,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "with_history": history,
        "server": {f: getattr(server, f) for f in _SERVER_FIELDS},
        "tables": tables,
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode()

    await audit.record(session, user.username, "server_export", server.name, server.host)
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in server.name)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{safe}.acontrol-server.json"'
        },
    )


@router.post("/servers/import-file", response_model=ServerImportResult)
async def import_server_file(
    request: Request, user: CurrentUser, session: SessionDep
) -> ServerImportResult:
    """Загрузка сервера из файла, полученного через export_server."""
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > _MAX_IMPORT_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "файл слишком большой")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_IMPORT_BYTES:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "файл слишком большой"
            )
        chunks.append(chunk)
    try:
        payload = json.loads(b"".join(chunks))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "файл не читается как JSON"
        ) from exc

    if not isinstance(payload, dict) or payload.get("format") != FORMAT:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "не файл переноса сервера (ожидается выгрузка из раздела «Серверы»)",
        )
    if payload.get("format_version") != FORMAT_VERSION:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"версия формата {payload.get('format_version')} не поддерживается "
            f"(панель понимает {FORMAT_VERSION})",
        )
    spec = payload.get("server") or {}
    host, name = spec.get("host"), spec.get("name")
    if not host or not name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "в файле нет адреса сервера")

    ssh_port = int(spec.get("ssh_port") or 22)
    # тот же адрес и порт = тот же сервер. Молча заводить дубль нельзя: две
    # карточки начали бы независимо править один и тот же конфиг на ноде
    dup = await session.scalar(
        select(Server).where(Server.host == host, Server.ssh_port == ssh_port)
    )
    if dup is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Сервер {host}:{ssh_port} уже есть в панели («{dup.name}»). "
            "Удалите его или загружайте файл в другую панель.",
        )

    max_pos = await session.scalar(select(func.max(Server.position)))
    server = Server(
        name=name[:128],
        host=host[:255],
        ssh_port=ssh_port,
        ssh_user=(spec.get("ssh_user") or "root")[:64],
        note=spec.get("note") or "",
        group_name=(spec.get("group_name") or "")[:64],
        country=(spec.get("country") or "")[:2],
        position=(max_pos or 0) + 1,
    )
    session.add(server)
    await session.flush()

    by_table = {m.__tablename__: m for m in server_scoped_models()}
    imported: dict[str, int] = {}
    skipped: list[str] = []
    for table, rows in (payload.get("tables") or {}).items():
        model = by_table.get(table)
        if model is None or not rows:
            # таблица из более новой панели — пропускаем, но говорим об этом
            # вслух: тихо потерянные данные хуже, чем явно названные
            if model is None and rows:
                skipped.append(table)
            continue
        values = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            clean = _coerce_row(model, row)
            clean.pop("id", None)
            clean["server_id"] = server.id
            values.append(clean)
        if values:
            await session.execute(insert(model), values)
            imported[table] = len(values)

    await session.commit()
    await session.refresh(server)
    await audit.record(
        session, user.username, "server_import_file", server.name, server.host
    )
    return ServerImportResult(
        server_id=server.id,
        name=server.name,
        host=server.host,
        imported=imported,
        skipped_tables=skipped,
    )
