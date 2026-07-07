from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app import amnezia_import, server_ops
from app.amnezia_import import ImportParseError, ServerSpec
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import Server
from app.schemas import (
    ImportAmneziaRequest,
    ImportBulkRequest,
    ImportLinkRequest,
    ImportPreview,
    ImportResponse,
    ImportResult,
)

router = APIRouter(prefix="/import", tags=["import"])


async def _import_spec(session: SessionDep, spec: ServerSpec) -> ImportResult:
    settings = get_settings()
    # не заводим дубль по (host, ssh_port)
    existing = await session.scalar(
        select(Server).where(
            Server.host == spec.host, Server.ssh_port == spec.ssh_port
        )
    )
    if existing is not None:
        return ImportResult(
            name=spec.name, host=spec.host, ok=False,
            server_id=existing.id, message="уже есть в панели",
        )

    server = Server(
        name=spec.name,
        host=spec.host,
        ssh_port=spec.ssh_port,
        ssh_user=spec.ssh_user,
        note=("протоколы: " + ", ".join(spec.protocols)) if spec.protocols else "",
    )
    session.add(server)
    await session.commit()
    await session.refresh(server)

    if not spec.password:
        return ImportResult(
            name=spec.name, host=spec.host, ok=True, server_id=server.id,
            bootstrapped=False,
            message="добавлен; нет пароля для автонастройки — запустите «Скрипт»",
        )

    try:
        ok, error = await server_ops.bootstrap_and_check(
            session, server, spec.password, settings
        )
    except Exception as exc:  # noqa: BLE001
        ok, error = False, str(exc)

    if ok:
        return ImportResult(
            name=spec.name, host=spec.host, ok=True, server_id=server.id,
            bootstrapped=True, message="добавлен и настроен",
        )
    return ImportResult(
        name=spec.name, host=spec.host, ok=True, server_id=server.id,
        bootstrapped=False,
        message=f"добавлен, но автонастройка не удалась: {error}",
    )


@router.post("/amnezia/preview", response_model=ImportPreview)
async def preview_amnezia(
    body: ImportLinkRequest, _: CurrentUser
) -> ImportPreview:
    try:
        spec = amnezia_import.parse_amnezia_link(body.link)
    except ImportParseError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return ImportPreview(
        name=spec.name,
        host=spec.host,
        ssh_port=spec.ssh_port,
        ssh_user=spec.ssh_user,
        protocols=spec.protocols,
        has_password=spec.password is not None,
    )


@router.post("/amnezia", response_model=ImportResponse)
async def import_amnezia(
    body: ImportAmneziaRequest, _: CurrentUser, session: SessionDep
) -> ImportResponse:
    results: list[ImportResult] = []
    for link in body.links:
        link = link.strip()
        if not link:
            continue
        try:
            spec = amnezia_import.parse_amnezia_link(link)
        except ImportParseError as exc:
            results.append(
                ImportResult(name=link[:24] + "…", host="?", ok=False, message=str(exc))
            )
            continue
        results.append(await _import_spec(session, spec))
    return ImportResponse(results=results)


@router.post("/bulk", response_model=ImportResponse)
async def import_bulk(
    body: ImportBulkRequest, _: CurrentUser, session: SessionDep
) -> ImportResponse:
    try:
        specs = amnezia_import.parse_bulk(
            body.text, default_user=get_settings().default_ssh_user
        )
    except ImportParseError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    results = [await _import_spec(session, spec) for spec in specs]
    return ImportResponse(results=results)
