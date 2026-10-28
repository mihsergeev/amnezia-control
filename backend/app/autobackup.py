"""Фоновый авто-бэкап БД: периодически пишет архив в data/backups с ротацией."""

import asyncio
import logging
import os
import re
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import alerts
from app.api.backup import _build_archive, verify_archive
from app.config import Settings

log = logging.getLogger("acontrol.autobackup")

# состояние прошлого авто-бэкапа — чтобы алертить только на переходах
# (упал / снова ок), а не каждый цикл
_last_backup_ok = True

_NAME_RE = re.compile(r"^acontrol-backup-\d{8}-\d{6}\.tar\.gz$")


def backups_dir(data_dir: str) -> str:
    return os.path.join(data_dir, "backups")


def ensure_backups_dir(data_dir: str) -> str:
    """Создаёт каталог бэкапов с правами 0700 (в нём лежат секреты)."""
    d = backups_dir(data_dir)
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def is_backup_name(name: str) -> bool:
    return bool(_NAME_RE.match(name))


def list_backups(data_dir: str) -> list[dict]:
    d = backups_dir(data_dir)
    if not os.path.isdir(d):
        return []
    out: list[dict] = []
    for fn in os.listdir(d):
        if not _NAME_RE.match(fn):
            continue
        st = os.stat(os.path.join(d, fn))
        out.append({
            "filename": fn,
            "size": st.st_size,
            "created": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
        })
    out.sort(key=lambda x: x["filename"], reverse=True)
    return out


def _prune(d: str, keep: int) -> None:
    files = sorted(
        (fn for fn in os.listdir(d) if _NAME_RE.match(fn)), reverse=True
    )
    for fn in files[max(keep, 1):]:
        try:
            os.remove(os.path.join(d, fn))
        except OSError:
            pass


async def write_backup(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> tuple[str, list[str]]:
    """Пишет бэкап и тут же прогоняет self-тест (перечитав с диска — ловит обрыв
    записи). Возвращает (путь, список проблем); пустой список = бэкап целый."""
    d = ensure_backups_dir(settings.data_dir)
    async with session_factory() as session:
        archive = await _build_archive(
            session, settings.data_dir, settings.version, settings.backup_include_traffic
        )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path, problems = save_checked(d, f"acontrol-backup-{stamp}.tar.gz", archive)
    if not problems:
        # старые копии чистим только после проверенной новой: при нехватке
        # места битый файл раньше оставался в ротации, а целый старый уже удален
        _prune(d, settings.backup_keep)
    return path, problems


def save_checked(d: str, name: str, archive: bytes) -> tuple[str, list[str]]:
    """Пишет архив во временный файл, перечитывает с диска и проверяет, и только
    целый переименовывает в настоящее имя. Битый удаляется."""
    path = os.path.join(d, name)
    tmp = path + ".part"
    try:
        with open(tmp, "wb") as fh:
            fh.write(archive)
            fh.flush()
            os.fsync(fh.fileno())
        with open(tmp, "rb") as fh:  # перечитываем с диска, не из памяти
            problems = verify_archive(fh.read())
    except OSError as exc:
        problems = [f"не удалось записать бэкап: {exc}"]
    if problems:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return path, problems
    os.replace(tmp, path)
    return path, problems


async def backup_loop(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    if settings.backup_interval_hours <= 0:
        log.info("авто-бэкап выключен (backup_interval_hours=0)")
        return
    await asyncio.sleep(30)  # не блокируем старт
    global _last_backup_ok
    while True:
        problems: list[str] = []
        exc: Exception | None = None
        try:
            path, problems = await write_backup(session_factory, settings)
        except Exception as e:  # noqa: BLE001 — цикл не должен падать
            exc = e
            log.exception("ошибка авто-бэкапа")
        ok = exc is None and not problems
        if ok:
            log.info("авто-бэкап записан, self-тест пройден: %s", path)
            if not _last_backup_ok:
                _last_backup_ok = True
                await alerts.maybe_alert(
                    session_factory, settings,
                    alerts.Card("ok", "🗄", alerts.t("Авто-бэкап снова проходит"), alerts.t("самопроверка ок")),
                )
        elif _last_backup_ok:  # переход ok → проблема: алертим один раз
            _last_backup_ok = False
            if exc is not None:
                card = alerts.Card(
                    "crit", "🗄", alerts.t("Авто-бэкап не создан"),
                    alerts.t("{err}. Проверьте место на диске и логи backend",
                             err=f"{type(exc).__name__}: {exc}"),
                )
            else:
                card = alerts.Card(
                    "warn", "🗄", alerts.t("Бэкап не прошел самопроверку"),
                    alerts.t("{problems}. Восстановиться из него может не выйти",
                             problems="; ".join(problems)),
                )
            log.error("проблема с бэкапом: %s", card.render()[0])
            await alerts.maybe_alert(session_factory, settings, card)
        await asyncio.sleep(settings.backup_interval_hours * 3600)
