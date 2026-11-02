"""Удаление протокола с ноды целиком: контейнер вместе со всеми клиентами.
Здесь же переименование клиента: ему нужен тот же поиск контейнера протокола.

Перед удалением снимается снимок конфига (как перед пересборкой), а каталоги
конфига на хосте не стираются, а переименовываются в <каталог>.removed-<время>:
иначе повторное развертывание протокола подхватило бы старый конфиг, и
удаленные клиенты снова получили бы доступ."""

import shlex
from dataclasses import dataclass, field

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import awg, deploy, native_vpn, openvpn, xray
from app.models import (
    AwgConfig,
    AwgNote,
    ClientLimit,
    ClientName,
    OvpnConfig,
    NativeVpnConfig,
    PausedClient,
    TorrentHit,
)

PROTOCOLS = ("awg", "awglegacy", "awg3", "openvpn", "xray", *native_vpn.PROTOCOLS)

# под каким тегом снимков хранится конфиг протокола (см. deploy._SNAP_SPECS)
_SNAP_TAG = {
    "awg": "awg", "awglegacy": "awg", "awg3": "awg3",
    "openvpn": "openvpn", "xray": "xray",
    "wireguard": "wireguard", "openvpn-native": "openvpn-native",
}

# каталоги хоста, которые можно переименовать: только конфиги Amnezia и панели,
# не системные маунты вроде /lib/modules. OpenVPN монтирует /opt/amnezia
# целиком - тогда переименовываются только каталоги протокола (SUB), иначе
# повторная установка подхватила бы старый конфиг вместе с клиентами.
# Юнит подъема (awg-up, awg3-up) этого контейнера снимается: иначе он на
# каждой загрузке падает на docker exec в несуществующий контейнер.
_REMOVE_SCRIPT = (
    'C={cont}; SUB={sub}; '
    'sudo docker inspect "$C" >/dev/null 2>&1 || {{ echo NO_CONT; exit 0; }}; '
    "IMG=$(sudo docker inspect -f '{{{{.Config.Image}}}}' \"$C\"); "
    "MNT=$(sudo docker inspect -f '{{{{range .Mounts}}}}{{{{if eq .Type \"bind\"}}}}"
    "{{{{println .Source}}}}{{{{end}}}}{{{{end}}}}' \"$C\"); "
    # Keep the running container until all config directories have moved.
    # A failed mv used to leave the old config behind after reporting success;
    # reinstall then brought revoked clients back. Bind mounts keep their inode
    # while directories are staged, so the container can keep serving traffic.
    'TS=$(date +%Y%m%d-%H%M%S)-$$; MOVED=""; '
    'rollback() {{ for d in $MOVED; do sudo mv "$d.removed-$TS" "$d" || echo ROLLBACK_FAIL; done; }}; '
    'stage() {{ [ -d "$1" ] || return 0; '
    'sudo mv "$1" "$1.removed-$TS" || {{ rollback; echo MOVE_FAIL; exit 1; }}; '
    'MOVED="$1 $MOVED"; }}; '
    'for d in $MNT; do case "$d" in /opt/amnezia) for s in $SUB; do stage "$s"; done ;; '
    '/opt/amnezia/*|/opt/acontrol/*) stage "$d" ;; esac; done; '
    'sudo docker rm -f "$C" >/dev/null || {{ rollback; echo RM_FAIL; exit 1; }}; '
    'echo REMOVED; for d in $MOVED; do echo "MOVED $d.removed-$TS"; done; '
    'for u in /etc/systemd/system/awg-up.service /etc/systemd/system/awg3-up.service; do '
    '[ -f "$u" ] && grep -qw -- "$C" "$u" && {{ sudo systemctl disable --now "${{u##*/}}" >/dev/null 2>&1; '
    'sudo rm -f "$u"; sudo systemctl daemon-reload; echo "UNIT ${{u##*/}}"; }}; done; '
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
    if protocol in native_vpn.PROTOCOLS:
        try:
            return await native_vpn.detect(conn, protocol, running=False), protocol
        except native_vpn.NativeNotDeployed:
            return None
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
    sub = deploy._SNAP_SPECS["openvpn"]["paths"] if protocol == "openvpn" else ""
    out = await conn.run(
        _REMOVE_SCRIPT.format(cont=shlex.quote(container), sub=shlex.quote(sub)),
        check=False,
    )
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
        if proto in native_vpn.PROTOCOLS:
            await session.execute(delete(NativeVpnConfig).where(
                NativeVpnConfig.server_id == server_id, NativeVpnConfig.protocol == proto))
        if proto in ("awg", "awg3", "awglegacy"):
            await session.execute(delete(AwgConfig).where(
                AwgConfig.server_id == server_id, AwgConfig.protocol == proto))
        if proto == "openvpn":
            await session.execute(delete(OvpnConfig).where(OvpnConfig.server_id == server_id))
        for model in (AwgNote, ClientLimit, ClientName, PausedClient, TorrentHit):
            await session.execute(delete(model).where(
                model.server_id == server_id, model.protocol == proto))


async def rename_on_node(
    conn, protocol: str, client_id: str, name: str
) -> tuple[bool, str]:
    """Меняет имя клиента в clientsTable контейнера протокола. Возвращает
    (нашелся ли клиент в таблице, протокол его клиентов в панели). Клиента на
    паузе в таблице нет: он снят с ноды."""
    if protocol in native_vpn.PROTOCOLS:
        return await native_vpn.rename(conn, protocol, client_id, name), protocol
    found = await find_container(conn, protocol)
    if found is None:
        raise LookupError("Протокол на сервере не найден")
    container, kind = found
    mod = {"openvpn": openvpn, "xray": xray}.get(protocol, awg)
    data = await mod._read_table(conn, container)
    entry = next(
        (e for e in data if isinstance(e, dict) and e.get("clientId") == client_id), None
    )
    if entry is None:
        # пустая или нечитаемая таблица тоже сюда: записать ее обратно значило бы
        # стереть всех клиентов
        return False, kind
    user_data = entry.get("userData")
    if not isinstance(user_data, dict):
        user_data = entry["userData"] = {}
    user_data["clientName"] = name
    await mod._write_table(conn, container, data)
    return True, kind


async def rename_in_db(
    session: AsyncSession, server_id: int, protocols: set[str], client_id: str, name: str
) -> bool:
    """Меняет имя клиента во всех таблицах панели. True, если что-то нашлось."""
    found = False
    rows = []
    if protocols & {"awg", "awg3", "awglegacy"}:
        rows += list(await session.scalars(select(AwgConfig).where(
            AwgConfig.server_id == server_id, AwgConfig.public_key == client_id,
            AwgConfig.protocol.in_(protocols))))
    if "openvpn" in protocols:
        rows += list(await session.scalars(select(OvpnConfig).where(
            OvpnConfig.server_id == server_id, OvpnConfig.client_id == client_id)))
    if protocols & set(native_vpn.PROTOCOLS):
        rows += list(await session.scalars(select(NativeVpnConfig).where(
            NativeVpnConfig.server_id == server_id, NativeVpnConfig.client_id == client_id,
            NativeVpnConfig.protocol.in_(protocols))))
    for model in (ClientName, ClientLimit, PausedClient):
        rows += list(await session.scalars(select(model).where(
            model.server_id == server_id, model.protocol.in_(protocols),
            model.client_id == client_id)))
    for row in rows:
        found = found or isinstance(row, PausedClient)
        row.name = name
    return found
