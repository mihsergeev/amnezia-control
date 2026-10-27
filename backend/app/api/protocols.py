import json

import asyncssh
from fastapi import APIRouter, HTTPException, Request, status

from app import audit, nodelock, protoremove, sshops, stepup
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import Server
from app.schemas import ProtocolRemoveOut, StepUpRequest
from app.sshkeys import ensure_panel_key, key_paths

router = APIRouter(prefix="/servers/{server_id}/protocols", tags=["protocols"])


@router.post("/{protocol}/remove", response_model=ProtocolRemoveOut)
async def remove_protocol(
    server_id: int,
    protocol: str,
    body: StepUpRequest,
    user: CurrentUser,
    session: SessionDep,
    request: Request,
) -> ProtocolRemoveOut:
    """Удаляет протокол с ноды вместе со всеми его клиентами. Необратимо для
    клиентов (снимок конфига остается на ноде), поэтому требует пароль."""
    if protocol not in protoremove.PROTOCOLS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неизвестный протокол")
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    try:
        await stepup.verify(user, body.password, request)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_403_FORBIDDEN:
            await audit.record(
                session, user.username, "protocol_remove_denied", server.name,
                f"{protocol}: неверный пароль",
            )
        raise

    settings = get_settings()
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    try:
        async with nodelock.connect(protocol, server.id, sshops.connect(
            server.host, server.ssh_port, server.ssh_user, key_path,
            settings.ssh_connect_timeout,
        )) as conn:
            res = await protoremove.remove(conn, protocol)
            # список протоколов на карточке обновляем сразу, не дожидаясь сбора
            check = await sshops.probe_containers(conn)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except protoremove.RemoveError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    except (asyncssh.Error, OSError) as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Ошибка SSH: {exc or type(exc).__name__}"
        ) from exc

    # вкладка AmneziaWG могла показывать одиночный Legacy-контейнер: тогда
    # клиенты в панели записаны под обоими ключами
    await protoremove.cleanup_db(session, server.id, {protocol, res.kind})
    if check is not None and check.docker:
        server.last_check_info = json.dumps(check.as_dict(), ensure_ascii=False)
    await session.commit()
    await audit.record(
        session, user.username, "protocol_remove", server.name,
        f"{protocol}: контейнер {res.container}, снимок {res.snapshot}",
    )
    return ProtocolRemoveOut(
        container=res.container, snapshot=res.snapshot, moved=res.moved, image=res.image
    )
