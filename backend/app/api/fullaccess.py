import asyncssh
from fastapi import APIRouter, HTTPException, status

from app import audit, awg, fullaccess, sshops
from app.config import get_settings
from app.deps import CurrentUser, SessionDep
from app.models import Server
from app.schemas import FullAccessOut
from app.sshkeys import ensure_panel_key, key_paths

router = APIRouter(prefix="/servers/{server_id}/fullaccess", tags=["fullaccess"])


async def _get_or_404(server_id: int, session: SessionDep) -> Server:
    server = await session.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Сервер не найден")
    return server


def _connect(server: Server):
    settings = get_settings()
    ensure_panel_key(settings.data_dir)
    key_path, _pub = key_paths(settings.data_dir)
    return sshops.connect(
        server.host, server.ssh_port, server.ssh_user, key_path,
        settings.ssh_connect_timeout,
    )


@router.post("", response_model=FullAccessOut)
async def export_full_access(
    server_id: int, user: CurrentUser, session: SessionDep
) -> FullAccessOut:
    """Генерит full-access vpn:// для десктоп-клиента: ставит выделенный
    SSH-ключ на ноду и вкладывает его приватную часть в конфиг."""
    server = await _get_or_404(server_id, session)
    dns1, dns2 = awg.dns_pair(get_settings().awg_client_dns)
    private_key, pubkey = fullaccess.generate_keypair()
    try:
        async with _connect(server) as conn:
            containers = await fullaccess.detect_containers(conn)
            await fullaccess.install_desktop_key(conn, pubkey)
    except fullaccess.FullAccessError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    except (asyncssh.Error, OSError) as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Ошибка SSH: {exc or type(exc).__name__}"
        ) from exc
    link = fullaccess.build_full_access_link(
        host=server.host, ssh_user=server.ssh_user, ssh_port=server.ssh_port,
        private_key=private_key, description=server.name, dns1=dns1, dns2=dns2,
        container_names=containers,
    )
    await audit.record(session, user.username, "fullaccess_export", server.name)
    return FullAccessOut(config=link, ssh_user=server.ssh_user)
