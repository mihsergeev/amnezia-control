"""Удаление протокола с ноды целиком: контейнер вместе со всеми клиентами.

Перед удалением снимается снимок конфига (как перед пересборкой), а каталоги
конфига на хосте не стираются, а переименовываются в <каталог>.removed-<время>:
иначе повторное развертывание протокола подхватило бы старый конфиг, и
удаленные клиенты снова получили бы доступ."""

from dataclasses import dataclass, field

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app import awg, deploy, openvpn, xray
from app.models import (
    AwgConfig,
    AwgNote,
    ClientLimit,
    ClientName,
    OvpnConfig,
    PausedClient,
)

PROTOCOLS = ("awg", "awglegacy", "awg3", "openvpn", "xray")

# под каким тегом снимков хранится конфиг протокола (см. deploy._SNAP_SPECS)
_SNAP_TAG = {
    "awg": "awg", "awglegacy": "awg", "awg3": "awg3",
    "openvpn": "openvpn", "xray": "xray",
}

# каталоги хоста, которые можно переименовать: только конфиги Amnezia и панели,
# не системные маунты вроде /lib/modules
_REMOVE_SCRIPT = (
    'C={cont}; '
    'sudo docker inspect "$C" >/dev/null 2>&1 || {{ echo NO_CONT; exit 0; }}; '
    "IMG=$(sudo docker inspect -f '{{{{.Config.Image}}}}' \"$C\"); "
    "MNT=$(sudo docker inspect -f '{{{{range .Mounts}}}}{{{{if eq .Type \"bind\"}}}}"
    "{{{{println .Source}}}}{{{{end}}}}{{{{end}}}}' \"$C\"); "
    'sudo docker rm -f "$C" >/dev/null || {{ echo RM_FAIL; exit 1; }}; '
    'echo REMOVED; TS=$(date +%Y%m%d-%H%M%S); '
    'for d in $MNT; do case "$d" in /opt/amnezia/*|/opt/acontrol/*) '
    '[ -d "$d" ] && sudo mv "$d" "$d.removed-$TS" && echo "MOVED $d.removed-$TS" ;; esac; done; '
    'sudo docker image rm "$IMG" >/dev/null 2>&1 && echo "IMAGE $IMG"; true'
)


class RemoveError(Exception):
    pass


@dataclass
class RemoveResult:
    container: str
    kind: str  # протокол, под которым панель хранит клиентов этого контейнера
    snapshot: str
    moved: list[str] = field(default_factory=list)
    image: str = ""


async def find_container(conn, protocol: str) -> tuple[str, str] | None:
    """(контейнер, протокол его клиентов в панели) или None, если его нет."""
    if protocol in ("awg", "awglegacy"):
        found = await awg.detect_awg_containers(conn)
        if protocol == "awglegacy":
            return (found["legacy"], "awglegacy") if found["legacy"] else None
        if found["new"]:
            return found["new"], "awg"
        # одиночный старый контейнер панель показывает вкладкой AmneziaWG
        return (found["legacy"], "awglegacy") if found["legacy"] else None
    if protocol == "awg3":
        names = await deploy.awg3_containers(conn)
        return (names[0], "awg3") if names else None
    try:
        if protocol == "openvpn":
            return await openvpn.detect_container(conn), "openvpn"
        if protocol == "xray":
            return await xray.detect_container(conn), "xray"
    except (openvpn.OpenVpnError, xray.XrayError):
        return None
    return None


async def remove(conn, protocol: str) -> RemoveResult:
    found = await find_container(conn, protocol)
    if found is None:
        raise LookupError("Протокол на сервере не найден")
    container, kind = found
    if not deploy._CONT_NAME_RE.match(container):
        raise RemoveError(f"Странное имя контейнера: {container}")
    snap = await deploy.snapshot_config(conn, _SNAP_TAG[protocol], container=container)
    if not snap:
        raise RemoveError(
            "Не удалось снять снимок конфига, удаление отменено: без него "
            "клиентов было бы не вернуть"
        )
    out = await conn.run(_REMOVE_SCRIPT.format(cont=container), check=False)
    lines = (out.stdout or "").splitlines()
    if "REMOVED" not in lines:
        raise RemoveError(f"Контейнер {container} не удалился: {(out.stderr or '').strip()}")
    res = RemoveResult(container=container, kind=kind, snapshot=snap)
    for line in lines:
        if line.startswith("MOVED "):
            res.moved.append(line.removeprefix("MOVED "))
        elif line.startswith("IMAGE "):
            res.image = line.removeprefix("IMAGE ")
    return res


async def cleanup_db(session: AsyncSession, server_id: int, protocols: set[str]) -> None:
    """Стирает в панели все следы клиентов этих протоколов на сервере."""
    for proto in protocols:
        if proto in ("awg", "awg3", "awglegacy"):
            await session.execute(delete(AwgConfig).where(
                AwgConfig.server_id == server_id, AwgConfig.protocol == proto))
        if proto == "openvpn":
            await session.execute(delete(OvpnConfig).where(OvpnConfig.server_id == server_id))
        for model in (AwgNote, ClientLimit, ClientName, PausedClient):
            await session.execute(delete(model).where(
                model.server_id == server_id, model.protocol == proto))
