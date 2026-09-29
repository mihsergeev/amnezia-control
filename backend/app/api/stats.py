from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from app import protolabel, stats_calc
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import (
    AwgConfig,
    AwgNote,
    ClientName,
    ClientTrafficSample,
    NodeMetric,
    OvpnConfig,
    Server,
    TrafficSample,
)
from app.schemas import (
    ClientHistoryOut,
    HistoryOut,
    NodeMetricOut,
    OverviewOut,
    TopClientOut,
)

router = APIRouter(prefix="/stats", tags=["stats"])

# Фильтр "Обзора" по серверам: ?server_id=1&server_id=3. Не задан - весь парк.
# Annotated, а не `= Query(None)`: у функции остается настоящий None по
# умолчанию, и её можно звать напрямую (так делают тесты), не получая вместо
# фильтра объект Query.
ServerFilter = Annotated[list[int] | None, Query()]


@router.get("/top-clients", response_model=list[TopClientOut])
async def top_clients(
    _: CurrentUser,
    session: SessionDep,
    limit: int = Query(default=10, ge=1, le=50),
    server_id: ServerFilter = None,
) -> list[TopClientOut]:
    settings = get_settings()
    # свежие снимки (последний цикл) → последний по каждому клиенту
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=max(settings.stats_interval, 60) * 3
    )
    query = select(ClientTrafficSample).where(ClientTrafficSample.ts >= cutoff)
    if server_id:
        query = query.where(ClientTrafficSample.server_id.in_(server_id))
    samples = await session.scalars(query)
    latest: dict[tuple[int, str, str], ClientTrafficSample] = {}
    for s in samples:
        key = (s.server_id, s.protocol, s.client_id)
        cur = latest.get(key)
        if cur is None or s.ts > cur.ts:
            latest[key] = s
    ranked = sorted(
        (s for s in latest.values() if s.rx + s.tx > 0),
        key=lambda s: s.rx + s.tx,
        reverse=True,
    )[:limit]
    if not ranked:
        return []

    servers = {s.id: s for s in await session.scalars(select(Server))}
    awg_names = {
        (sid, pk): n
        for sid, pk, n in (
            await session.execute(
                select(AwgConfig.server_id, AwgConfig.public_key, AwgConfig.name)
            )
        ).all()
    }
    awg_notes = {
        (sid, pk): note
        for sid, pk, note in (
            await session.execute(
                select(AwgNote.server_id, AwgNote.public_key, AwgNote.note)
            )
        ).all()
    }
    ovpn_names = {
        (sid, cid): n
        for sid, cid, n in (
            await session.execute(
                select(OvpnConfig.server_id, OvpnConfig.client_id, OvpnConfig.name)
            )
        ).all()
    }
    # кэш имён с ноды (clientsTable) — покрывает клиентов, созданных не через панель
    cached_names = {
        (sid, proto, cid): n
        for sid, proto, cid, n in (
            await session.execute(
                select(
                    ClientName.server_id, ClientName.protocol,
                    ClientName.client_id, ClientName.name,
                )
            )
        ).all()
    }

    def resolve_name(s: ClientTrafficSample) -> str:
        key = (s.server_id, s.client_id)
        cached = cached_names.get((s.server_id, s.protocol, s.client_id))
        if cached:
            return cached
        if s.protocol == "awg":
            return awg_names.get(key) or awg_notes.get(key) or s.client_id[:12]
        if s.protocol == "openvpn":
            return ovpn_names.get(key) or s.client_id[:12]
        return s.client_id[:12]

    return [
        TopClientOut(
            server_id=s.server_id,
            server_name=servers[s.server_id].name if s.server_id in servers else "",
            protocol=s.protocol,
            protocol_label=protolabel.protocol_label(servers.get(s.server_id), s.protocol),
            client_id=s.client_id,
            name=resolve_name(s),
            rx=s.rx,
            tx=s.tx,
            total=s.rx + s.tx,
        )
        for s in ranked
    ]


@router.get("/nodes", response_model=list[NodeMetricOut])
async def node_metrics(_: CurrentUser, session: SessionDep) -> list[NodeMetric]:
    return list(
        await session.scalars(select(NodeMetric).order_by(NodeMetric.server_id))
    )


@router.get("/client", response_model=ClientHistoryOut)
async def client_history(
    _: CurrentUser,
    session: SessionDep,
    server_id: int,
    protocol: str,
    client_id: str,
    hours: int = Query(default=24, ge=1, le=720),
) -> ClientHistoryOut:
    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    samples = list(
        await session.scalars(
            select(ClientTrafficSample)
            .where(
                ClientTrafficSample.server_id == server_id,
                ClientTrafficSample.protocol == protocol,
                ClientTrafficSample.client_id == client_id,
                ClientTrafficSample.ts >= cutoff,
            )
            .order_by(ClientTrafficSample.ts)
        )
    )
    points = stats_calc.aggregate_client_history(samples, settings.stats_interval)
    last = samples[-1] if samples else None
    return ClientHistoryOut(
        interval_seconds=settings.stats_interval,
        current_rx=last.rx if last else 0,
        current_tx=last.tx if last else 0,
        points=points,
    )


@router.get("/overview", response_model=OverviewOut)
async def overview(
    _: CurrentUser, session: SessionDep, server_id: ServerFilter = None
) -> OverviewOut:
    settings = get_settings()
    srv_query = select(Server).order_by(Server.id)
    if server_id:
        # карточки сверху считаются по выбранным серверам: "серверов онлайн 2 / 3"
        # должно означать три выбранных, а не весь парк
        srv_query = srv_query.where(Server.id.in_(server_id))
    servers = [(s.id, s.name) for s in await session.scalars(srv_query)]
    # свежими считаем снимки не старше 3 интервалов
    staleness = timedelta(seconds=max(settings.stats_interval, 60) * 3)
    cutoff = datetime.now(timezone.utc) - staleness
    smp_query = (
        select(TrafficSample)
        .where(TrafficSample.ts >= cutoff)
        .order_by(TrafficSample.ts)
    )
    if server_id:
        smp_query = smp_query.where(TrafficSample.server_id.in_(server_id))
    recent = await session.scalars(smp_query)
    latest_by_id: dict[int, TrafficSample] = {}
    for smp in recent:
        latest_by_id[smp.server_id] = smp  # порядок asc → последний свежайший

    return OverviewOut(**stats_calc.build_overview(servers, latest_by_id))


@router.get("/history", response_model=HistoryOut)
async def history(
    _: CurrentUser,
    session: SessionDep,
    server_id: ServerFilter = None,
    hours: int = Query(default=24, ge=1, le=2160),  # до 90 дней
    from_ms: int | None = Query(default=None),  # произвольное окно (drag-zoom)
    to_ms: int | None = Query(default=None),
    by_server: bool = False,
) -> HistoryOut:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    if from_ms is not None and to_ms is not None and to_ms > from_ms:
        start = datetime.fromtimestamp(from_ms / 1000, timezone.utc)
        end = datetime.fromtimestamp(to_ms / 1000, timezone.utc)
    else:
        end = now
        start = now - timedelta(hours=hours)
    range_seconds = max((end - start).total_seconds(), 1)
    # шаг бакета подбираем под ширину окна, чтобы точек было ~несколько сотен
    step = stats_calc.pick_bucket_seconds(range_seconds, settings.stats_interval)
    query = (
        select(TrafficSample)
        .where(TrafficSample.ts >= start, TrafficSample.ts <= end)
        .order_by(TrafficSample.ts)
    )
    if server_id:
        query = query.where(TrafficSample.server_id.in_(server_id))
    samples = list(await session.scalars(query))
    points = stats_calc.aggregate_history(samples, step)
    servers = []
    if by_server:
        names = dict((await session.execute(select(Server.id, Server.name))).all())
        per = stats_calc.clients_by_server(samples, step)
        # удаленный сервер мог оставить снимки в истории - его в разбивку не берем
        servers = [
            {"server_id": sid, "name": names[sid], "clients_online": vals}
            for sid, vals in per.items()
            if sid in names
        ]
    return HistoryOut(interval_seconds=step, points=points, servers=servers)
