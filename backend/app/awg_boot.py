"""Update the panel's legacy AWG 3 boot unit without restarting the VPN."""

import asyncio
import logging
import shlex

from sqlalchemy import select

from app import cascadejob, deploy, nodelock
from app.models import Server


log = logging.getLogger("acontrol.awg_boot")
UNIT_PATH = "/etc/systemd/system/awg3-up.service"
CHECK_EVERY = 900


def upgrade_command() -> str:
    script = f"""
import fcntl,json,os,stat,subprocess,sys,tempfile
from pathlib import Path

path=Path({UNIT_PATH!r})
old={deploy._systemd_unit_v3(legacy=True).encode()!r}
new={deploy._systemd_unit_v3().encode()!r}
container={deploy.CONTAINER_V3!r}
mount_source={deploy.HOST_DIR_V3!r}

def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=6)

def properties():
    reply=run('systemctl','show',path.name,'-p','FragmentPath','-p','DropInPaths',
              '-p','ActiveState','-p','LoadState','-p','NeedDaemonReload')
    if reply.returncode:
        return {{}}
    return dict(line.split('=',1) for line in reply.stdout.splitlines() if '=' in line)

def eligible(props):
    return (props.get('FragmentPath')==str(path) and not props.get('DropInPaths')
            and props.get('LoadState')=='loaded'
            and props.get('ActiveState') not in ('activating','deactivating','reloading'))

def replace(content,mode):
    fd,name=tempfile.mkstemp(prefix='.awg3-up-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as file:
            os.fchmod(file.fileno(),mode)
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name,path)
    finally:
        Path(name).unlink(missing_ok=True)

def read_unit():
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except OSError:
        return None
    with os.fdopen(fd,'rb') as file:
        meta=os.fstat(file.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid or meta.st_mode & 0o022 or meta.st_size>8192:
            return None
        return file.read(8193),stat.S_IMODE(meta.st_mode)

lock=os.open('/run/acontrol-awg3-boot.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
try:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(0)
saved=read_unit()
if not saved or saved[0]!=old or not eligible(properties()):
    sys.exit(0)
reply=run('docker','container','inspect','--format','{{{{.State.Running}}}}\t{{{{json .Mounts}}}}',container)
if reply.returncode:
    sys.exit(0)
running,_,mounts=reply.stdout.strip().partition('\t')
if running!='true' or not any(m.get('Type')=='bind' and m.get('Source')==mount_source
                              and m.get('Destination')=='/opt/amnezia/awg' for m in json.loads(mounts)):
    sys.exit(0)
if read_unit()!=saved:
    sys.exit(0)
replace(new,saved[1])
try:
    result=run('systemctl','daemon-reload')
    props=properties()
    if result.returncode or not eligible(props) or props.get('NeedDaemonReload')!='no':
        raise RuntimeError('boot unit was not reloaded')
except Exception:
    replace(old,saved[1])
    run('systemctl','daemon-reload')
    sys.exit(1)
print('ACONTROL_AWG3_BOOT_UPDATED',flush=True)
"""
    return "sudo -n python3 -c " + shlex.quote(script)


async def upgrade_node(server: Server, settings) -> None:
    async with asyncio.timeout(55):
        async with nodelock.hold("awg3", server.id, wait=1):
            async with cascadejob.connect(server, settings) as conn:
                if deploy.CONTAINER_V3 not in await deploy.awg3_containers(conn):
                    return
                await deploy.ensure_idle(conn, tag="awg3")
                result = await conn.run(upgrade_command(), check=True, timeout=45)
                if "ACONTROL_AWG3_BOOT_UPDATED" in (result.stdout or ""):
                    log.info("AWG 3 boot unit updated on node %s", server.id)


async def watch_loop(session_factory, settings) -> None:
    await asyncio.sleep(30)
    while True:
        try:
            async with session_factory() as session:
                known = select(Server).where(Server.last_check_info.contains(deploy.CONTAINER_V3))
                servers = list(await session.scalars(known))
            for server in servers:
                try:
                    await upgrade_node(server, settings)
                except Exception as exc:  # noqa: BLE001 - retry without affecting VPN or monitoring
                    log.info("AWG 3 boot unit on node %s: %s", server.id, type(exc).__name__)
        except Exception:  # noqa: BLE001
            log.exception("AWG boot maintenance failed")
        await asyncio.sleep(CHECK_EVERY)
