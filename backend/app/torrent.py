"""Блокировка торрентов на сервере (настройка сервера torrent_block).

Правила iptables ставятся внутри контейнеров AWG и OpenVPN: там у пакета еще
адрес клиента в туннеле, до NAT. Пакет клиента с сигнатурой BitTorrent
(рукопожатие пиров, DHT, HTTP- и UDP-трекеры) отбрасывается, а адрес клиента
запоминает модуль recent. Коллектор каждый цикл забирает этот список, очищает
его и по адресу находит клиента: так видно, кто качает, без логов на ноде.

Ловятся только открытые сигнатуры: шифрованное рукопожатие (MSE/PE) и трекеры
по HTTPS проходят, но DHT и большинство трекеров клиент шлет открыто, и без них
раздачу не найти. XRay не охвачен: там все клиенты в одном процессе, адреса
клиента у пакета нет.

Смотрим только начало соединения (connbytes): торрент виден по первым пакетам,
а поиск строки по всему трафику нагрузил бы ноду.
"""

import asyncio
import logging
import re
import shlex
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from app import alerts, audit, awg, deploy, nodelock, openvpn, pausestore, settings_store, sshops
from app.config import Settings
from app.models import Server, TorrentHit
from app.sshkeys import ensure_panel_key, key_paths

log = logging.getLogger("acontrol.torrent")

CHAIN = "ACTORRENT"
RECENT = "actorrent"
# столько попаданий за цикл сбора считаем торрентом, а не случайным совпадением
# строки: торрент-клиент шлет DHT и трекерам десятки пакетов в минуту
MIN_HITS = 3
# повтор алерта о том же клиенте не чаще
ALERT_EVERY = timedelta(hours=24)
# записи о клиентах, которых давно не ловили, чистим
KEEP_DAYS = 30

# первые байты соединения от клиента
_HEAD = "-m connbytes --connbytes 0:8192 --connbytes-dir original --connbytes-mode bytes"
SIGNATURES = (
    # рукопожатие пиров, в том числе внутри uTP
    '-m string --algo bm --string "BitTorrent protocol"',
    # запрос и ответ DHT (bencode со своим id узла)
    '-m string --algo bm --string "d1:ad2:id20:"',
    '-m string --algo bm --string "d1:rd2:id20:"',
    # анонс HTTP-трекеру
    '-m string --algo bm --string "info_hash="',
    # connect к UDP-трекеру: магическое число протокола
    '-p udp -m string --algo bm --hex-string "|0000041727101980|"',
)

# eth0 - сеть docker, все остальные интерфейсы контейнера - туннели клиентов
_JUMP = f"FORWARD ! -i eth0 -j {CHAIN}"


def enable_script() -> str:
    """Ставит правила, если их нет или набор устарел, и отдает накопленные
    адреса из recent (и очищает их). Повтор безопасен: так же правила
    возвращаются после рестарта контейнера."""
    rules = "\n".join(
        f"  iptables -A {CHAIN} {_HEAD} {sig} "
        f"-m recent --name {RECENT} --rsource --set -j DROP || ok=0"
        for sig in SIGNATURES
    )
    return f"""ok=1
iptables -N {CHAIN} 2>/dev/null
if [ "$(iptables -S {CHAIN} 2>/dev/null | grep -c -- '-j DROP')" != "{len(SIGNATURES)}" ]; then
  iptables -F {CHAIN} || ok=0
{rules}
fi
iptables -C {_JUMP} 2>/dev/null || iptables -I {_JUMP.replace("FORWARD", "FORWARD 1", 1)} || ok=0
echo "{CHAIN} ok=$ok"
f=/proc/net/xt_recent/{RECENT}
if [ -r $f ]; then cat $f; echo / > $f; fi
"""


def disable_script() -> str:
    return f"""while iptables -D {_JUMP} 2>/dev/null; do :; done
iptables -F {CHAIN} 2>/dev/null
iptables -X {CHAIN} 2>/dev/null
echo "{CHAIN} off"
"""


_RECENT_RE = re.compile(r"^src=(\S+)\s.*?oldest_pkt:\s*\d+(.*)$")


def parse_recent(text: str) -> dict[str, int]:
    """/proc/net/xt_recent/<имя> -> {адрес: попаданий}. Строка ядра:
    `src=10.8.1.2 ttl: 64 last_seen: 4295 oldest_pkt: 2 4290, 4293, 4295` -
    после номера самой старой метки идут метки пакетов (не больше 20)."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        m = _RECENT_RE.match(line.strip())
        if not m:
            continue
        stamps = [s for s in m.group(2).replace(",", " ").split() if s.isdigit()]
        out[m.group(1)] = max(len(stamps), 1)
    return out


def parse_output(text: str) -> tuple[bool | None, dict[str, int]]:
    """Вывод enable_script -> (правила стоят?, {адрес: попаданий}).
    None - маркера нет (скрипт не дошел до конца)."""
    ok: bool | None = None
    for line in text.splitlines():
        if line.startswith(f"{CHAIN} ok="):
            ok = line.strip().endswith("=1")
    return ok, parse_recent(text)


def parse_ovpn_routes(text: str) -> dict[str, str]:
    """ROUTING TABLE из openvpn-status.log (v1) -> {адрес в туннеле: clientId}."""
    out: dict[str, str] = {}
    in_table = False
    for line in text.splitlines():
        if line.startswith("ROUTING TABLE"):
            in_table = True
            continue
        if line.startswith(("GLOBAL STATS", "END", "OpenVPN CLIENT LIST")):
            in_table = False
        if not in_table or line.startswith("Virtual Address"):
            continue
        parts = line.split(",")
        if len(parts) >= 2 and parts[0] and parts[1]:
            # адрес может быть с маской или суффиксом C (кэш), берем сам адрес
            out[parts[0].split("/")[0].rstrip("C")] = parts[1]
    return out


def awg_ipmap(clients) -> dict[str, tuple[str, str]]:
    """Клиенты AWG -> {адрес в туннеле: (публичный ключ, имя)}."""
    out: dict[str, tuple[str, str]] = {}
    for c in clients:
        for addr in (c.address or "").split(","):
            ip = addr.strip().split("/")[0]
            if ip:
                out[ip] = (c.public_key, c.name)
    return out


def _exec(container: str, script: str) -> str:
    return awg._DOCKER + f"$DOCKER exec {shlex.quote(container)} sh -c {shlex.quote(script)}"


async def sync_container(conn, container: str, enabled: bool) -> tuple[bool | None, dict[str, int]]:
    """Приводит правила контейнера к настройке. Включено - (стоят?, попадания)."""
    if not enabled:
        result = await conn.run(_exec(container, disable_script()), check=False)
        return f"{CHAIN} off" in (result.stdout or ""), {}
    result = await conn.run(_exec(container, enable_script()), check=False)
    return parse_output(result.stdout or "")


# по каким серверам правила точно сняты с начала работы панели: выключенную
# блокировку проверяем на ноде один раз, а не каждый цикл
_cleared: set[int] = set()
# последнее состояние правил по серверу для карточки: {"ok", "at", "error"}
_status: dict[int, dict] = {}


def status(server_id: int) -> dict | None:
    return _status.get(server_id)


async def sample(conn, server: Server, nets: list[dict]) -> list[dict]:
    """Шаг коллектора. nets - контейнеры с клиентами:
    [{"container", "protocol", "ips": {адрес: (client_id, имя)}}].
    Возвращает попадания по клиентам [{protocol, client_id, name, hits}]."""
    if not nets:
        return []
    if not server.torrent_block:
        if server.id in _cleared:
            return []
        done = True
        for net in nets:
            try:
                off, _ = await sync_container(conn, net["container"], False)
            except Exception:  # noqa: BLE001 - снимем в следующий цикл
                off = False
            done = done and off
        if done:
            _cleared.add(server.id)
            _status.pop(server.id, None)
        return []
    _cleared.discard(server.id)
    found: list[dict] = []
    failed: list[str] = []
    for net in nets:
        try:
            ok, hits = await sync_container(conn, net["container"], True)
        except Exception as exc:  # noqa: BLE001 - один контейнер не роняет сбор
            failed.append(f"{net['container']}: {exc}")
            continue
        if not ok:
            failed.append(net["container"])
        for ip, n in hits.items():
            who = net["ips"].get(ip)
            if who:
                found.append({"protocol": net["protocol"], "client_id": who[0],
                              "name": who[1], "hits": n})
    _status[server.id] = {
        "ok": not failed,
        "at": datetime.now(timezone.utc).isoformat(),
        "error": "; ".join(failed),
    }
    if failed:
        log.warning("правила торрентов на %s не встали: %s", server.name, "; ".join(failed))
    return found


async def node_nets(conn, host: str) -> list[dict]:
    """Контейнеры AWG и OpenVPN ноды с адресами клиентов (для включения из
    настроек сервера, вне цикла коллектора)."""
    nets: list[dict] = []
    conts = await awg.detect_awg_containers(conn)
    targets = [(conts["new"], "awg"), (conts["legacy"], "awglegacy")]
    targets += [(name, "awg3") for name in await deploy.awg3_containers(conn)]
    for container, proto in targets:
        if not container:
            continue
        try:
            state = await awg.read_state(conn, host, container=container)
        except Exception:  # noqa: BLE001
            continue
        nets.append({"container": container, "protocol": proto,
                     "ips": awg_ipmap(state.clients)})
    try:
        container = await openvpn.detect_container(conn)
    except Exception:  # noqa: BLE001 - OpenVPN на ноде нет
        container = None
    if container:
        nets.append({"container": container, "protocol": "openvpn", "ips": {}})
    return nets


async def apply_now(server: Server, settings: Settings) -> None:
    """Сразу применяет настройку на ноде после ее смены (не ждать цикл
    коллектора). Best-effort: нода недоступна - применит коллектор."""
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    timeout = settings.ssh_connect_timeout
    try:
        async with asyncio.timeout(max(timeout * 4, 30)):
            async with sshops.connect(
                server.host, server.ssh_port, server.ssh_user, key_path, timeout
            ) as conn:
                _cleared.discard(server.id)
                await sample(conn, server, await node_nets(conn, server.host))
    except Exception:  # noqa: BLE001
        log.warning("блокировка торрентов на %s не применилась сразу", server.name,
                    exc_info=True)


_tasks: set[asyncio.Task] = set()


def spawn_apply(server: Server, settings: Settings) -> None:
    task = asyncio.create_task(apply_now(server, settings))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def _pause(server: Server, settings: Settings, protocol: str, client_id: str) -> dict:
    """Пауза клиента, как кнопкой в панели: под блокировкой ноды."""
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    timeout = settings.ssh_connect_timeout
    async with asyncio.timeout(max(timeout * 4, 30)):
        async with nodelock.connect(protocol, server.id, sshops.connect(
            server.host, server.ssh_port, server.ssh_user, key_path, timeout
        )) as conn:
            if protocol == "openvpn":
                container = await openvpn.detect_container(conn)
                await openvpn.pause_client(conn, container, client_id)
                return {}
            if protocol == "awg3":
                names = await deploy.awg3_containers(conn)
                container = names[0] if names else None
            else:
                conts = await awg.detect_awg_containers(conn)
                container = conts["legacy" if protocol == "awglegacy" else "new"]
            if not container:
                raise RuntimeError("контейнер протокола не запущен")
            state = await awg.read_state(conn, server.host, container=container)
            return await awg.pause_client(conn, state, client_id)


async def record(session_factory, settings: Settings, samples: list[dict],
                 servers: dict[int, Server]) -> None:
    """Пишет попадания в torrent_hits, ставит на паузу (если включено) и шлет
    алерт о клиенте не чаще раза в сутки."""
    now = datetime.now(timezone.utc)
    to_alert: list[tuple[Server, dict, str]] = []
    async with session_factory() as session:
        for s in samples:
            server = servers.get(s["server_id"])
            hits = s.get("torrent") or []
            if server is None or not hits:
                continue
            for h in hits:
                row = await session.scalar(select(TorrentHit).where(
                    TorrentHit.server_id == server.id,
                    TorrentHit.protocol == h["protocol"],
                    TorrentHit.client_id == h["client_id"],
                ))
                if row is None:
                    row = TorrentHit(server_id=server.id, protocol=h["protocol"],
                                     client_id=h["client_id"], hits=0, first_seen=now)
                    session.add(row)
                row.hits = (row.hits or 0) + h["hits"]
                row.last_seen = now
                if h.get("name"):
                    row.name = h["name"][:128]
                if h["hits"] < MIN_HITS:
                    continue
                paused = ""
                if server.torrent_autopause:
                    paused = await _autopause(session, settings, server, h)
                fresh = row.alerted_at is None or now - alerts._aware(row.alerted_at) >= ALERT_EVERY
                if fresh or paused == "ok":
                    row.alerted_at = now
                    to_alert.append((server, h, paused))
        await session.commit()
        cfg = await settings_store.get_alert_config(session, settings) if to_alert else {}
    if not to_alert or not alerts.alerts_enabled(cfg):
        return
    for server, h, paused in to_alert:
        detail = alerts.t(
            "{name}, {proto}: {hits} попыток за {mins} мин, торренты на сервере блокируются",
            name=h.get("name") or h["client_id"][:16], proto=h["protocol"],
            hits=h["hits"], mins=max(settings.stats_interval // 60, 1),
        )
        if paused == "ok":
            detail = alerts.t("{detail}. Клиент поставлен на паузу", detail=detail)
        elif paused:
            detail = alerts.t("{detail}. Паузу поставить не вышло: {err}",
                              detail=detail, err=paused)
        card = alerts.Card("warn", "🧲", alerts.t("Клиент качает торренты"), detail,
                           subject=server.name)
        try:
            await alerts.send_card(cfg, settings, card)
        except Exception:  # noqa: BLE001
            log.warning("алерт о торрентах не отправлен", exc_info=True)


async def _autopause(session, settings: Settings, server: Server, h: dict) -> str:
    """"ok" - клиент на паузе, иначе текст ошибки."""
    try:
        data = await _pause(server, settings, h["protocol"], h["client_id"])
    except Exception as exc:  # noqa: BLE001
        log.warning("автопауза %s на %s не удалась", h["client_id"], server.name,
                    exc_info=True)
        return str(exc) or exc.__class__.__name__
    await pausestore.add(session, server.id, h["protocol"], h["client_id"],
                         h.get("name") or "", data or {})
    await audit.record(session, "система", f"{h['protocol']}_torrent_pause", server.name,
                       h.get("name") or h["client_id"])
    return "ok"


async def prune(session) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)
    await session.execute(delete(TorrentHit).where(TorrentHit.last_seen < cutoff))
