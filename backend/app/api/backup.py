"""Скачивание резервной копии панели: дамп БД (JSON) + data-каталог (SSH-ключ)."""

import io
import json
import os
import tarfile
from datetime import date, datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy import DateTime, delete, insert, select

from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import (
    AwgConfig,
    AwgNote,
    OvpnConfig,
    Server,
    TrafficSample,
    User,
)

router = APIRouter(prefix="/backup", tags=["backup"])

# порядок важен для восстановления (нет FK, но держим осмысленный порядок)
_MODELS = [User, Server, AwgConfig, AwgNote, OvpnConfig, TrafficSample]

_RESTORE = """# Восстановление Amnezia Control

Архив содержит полное состояние панели на момент бэкапа.

## Что внутри
- `db.json` — все таблицы БД (пользователи, серверы, выданные конфиги,
  заметки, метрики). Содержит СЕКРЕТЫ (хэш пароля админа, приватные ключи в
  сохранённых awg/ovpn-конфигах) — храните архив в безопасном месте.
- `data/` — рабочий каталог панели, включая SSH-ключ панели
  (`ssh/id_ed25519`). БЕЗ него восстановленная панель сгенерирует новый ключ и
  потеряет доступ ко всем нодам — ключ критичен.

## Как восстановить
1. Разверните панель заново (docker compose up), дайте применить миграции.
2. Остановите backend: `docker compose stop backend`.
3. Верните каталог: распакуйте `data/` в бинд-маунт `./data` панели
   (перезапишите `ssh/`), выставьте права `chmod 600 data/ssh/id_ed25519`.
4. Залейте `db.json` в БД: для каждой таблицы очистите её и вставьте строки из
   JSON (например, скриптом на стороне панели или psql/COPY). Даты — в ISO-8601.
5. Запустите backend: `docker compose start backend`.

Учётка админа также берётся из `.env` при старте — при восстановлении убедитесь,
что `.env` соответствует ожиданиям (иначе пароль пересинхронизируется из `.env`).
"""


def _to_jsonable(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _dump_row(row) -> dict:
    return {c.name: _to_jsonable(getattr(row, c.name)) for c in row.__table__.columns}


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = 0
    tar.addfile(info, io.BytesIO(data))


async def _build_archive(session, data_dir: str, version: str) -> bytes:
    dump: dict[str, list] = {}
    for model in _MODELS:
        rows = (await session.scalars(select(model))).all()
        dump[model.__tablename__] = [_dump_row(r) for r in rows]

    manifest = {
        "app": "Amnezia Control",
        "version": version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tables": {name: len(rows) for name, rows in dump.items()},
    }

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add_bytes(tar, "MANIFEST.json", json.dumps(manifest, indent=2).encode())
        _add_bytes(tar, "RESTORE.md", _RESTORE.encode())
        _add_bytes(
            tar, "db.json",
            json.dumps(dump, ensure_ascii=False, indent=2).encode("utf-8"),
        )
        # data-каталог панели (ssh-ключи и пр.). ВАЖНО: исключаем postgres —
        # его бинд-маунт лежит внутри ./data, но БД уже сохранена в db.json,
        # а сырые файлы кластера огромны и не нужны.
        if os.path.isdir(data_dir):
            for root, dirs, files in os.walk(data_dir):
                dirs[:] = [
                    d for d in dirs if d not in ("postgres", "pgdata", "backups")
                ]
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, data_dir).replace(os.sep, "/")
                    try:
                        with open(full, "rb") as fh:
                            _add_bytes(tar, f"data/{rel}", fh.read())
                    except OSError:
                        continue
    return buf.getvalue()


@router.get("")
async def download_backup(_: CurrentUser, session: SessionDep) -> Response:
    settings = get_settings()
    archive = await _build_archive(session, settings.data_dir, settings.version)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"acontrol-backup-{stamp}.tar.gz"
    return Response(
        content=archive,
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _coerce_row(model, row: dict) -> dict:
    """Приводит значения из JSON к типам колонок (ISO-строки → datetime)."""
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


@router.get("/list")
async def list_backups(_: CurrentUser) -> dict:
    from app import autobackup

    settings = get_settings()
    return {"backups": autobackup.list_backups(settings.data_dir)}


@router.post("/now")
async def backup_now(_: CurrentUser, session: SessionDep) -> dict:
    """Сделать бэкап немедленно (в data/backups), переиспользуя текущую сессию."""
    from app import autobackup

    settings = get_settings()
    d = autobackup.backups_dir(settings.data_dir)
    os.makedirs(d, exist_ok=True)
    archive = await _build_archive(session, settings.data_dir, settings.version)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = os.path.join(d, f"acontrol-backup-{stamp}.tar.gz")
    with open(path, "wb") as fh:
        fh.write(archive)
    autobackup._prune(d, settings.backup_keep)
    return {"filename": os.path.basename(path)}


@router.get("/file/{filename}")
async def download_saved_backup(filename: str, _: CurrentUser) -> Response:
    from app import autobackup

    settings = get_settings()
    if not autobackup.is_backup_name(filename):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "некорректное имя файла")
    path = os.path.join(autobackup.backups_dir(settings.data_dir), filename)
    if not os.path.isfile(path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "бэкап не найден")
    with open(path, "rb") as fh:
        data = fh.read()
    return Response(
        content=data,
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/restore")
async def restore_backup(
    request: Request, user: CurrentUser, session: SessionDep
) -> dict:
    """Восстановление из архива (тело запроса = tar.gz от GET /backup).

    ПЕРЕЗАПИСЫВАЕТ все таблицы и SSH-ключ панели данными из архива.
    """
    body = await request.body()
    try:
        tar = tarfile.open(fileobj=io.BytesIO(body), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "не удалось прочитать архив (ожидается .tar.gz)"
        ) from exc

    try:
        db_member = tar.extractfile("db.json")
        if db_member is None:
            raise KeyError
        dump = json.loads(db_member.read())
    except (KeyError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "в архиве нет валидного db.json"
        ) from exc

    # восстановление таблиц: очистка + вставка (в обратном порядке чистим — FK нет)
    restored: dict[str, int] = {}
    for model in reversed(_MODELS):
        await session.execute(delete(model))
    for model in _MODELS:
        rows = dump.get(model.__tablename__, [])
        for row in rows:
            if isinstance(row, dict):
                await session.execute(insert(model).values(**_coerce_row(model, row)))
        restored[model.__tablename__] = len(rows)
    await session.commit()

    # восстановление data/ (ssh-ключ и пр.), без postgres
    settings = get_settings()
    for m in tar.getmembers():
        if not (m.isfile() and m.name.startswith("data/")):
            continue
        rel = m.name[len("data/"):]
        if not rel or ".." in rel or rel.startswith(("postgres/", "pgdata/")):
            continue
        dest = os.path.join(settings.data_dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        src = tar.extractfile(m)
        if src is None:
            continue
        with open(dest, "wb") as fh:
            fh.write(src.read())
        if rel.endswith("id_ed25519"):
            try:
                os.chmod(dest, 0o600)
            except OSError:
                pass

    from app import audit

    await audit.record(
        session, user.username, "restore", "", f"строк: {sum(restored.values())}"
    )
    return {"restored": restored}
