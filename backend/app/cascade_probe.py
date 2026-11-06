"""Bounded, isolated transport measurements; never install or adopt a cascade."""

import asyncio
import ipaddress
import json
import secrets
import shlex
import uuid

from app import cascade, cascade_awg, deploy

PAYLOAD_BYTES = 20 * 1024 * 1024
LEASE_SECONDS = 100
PREPARE_SECONDS = 180
LABEL = "org.amnezia.control.probe"
AWG_PROBE_IMAGE = f"acontrol-cascade-probe-awg3:{deploy.AWG3_GO_TAG}-{deploy.AWG3_TOOLS_TAG}"
LOCAL_IMAGE_MISSING = "local_image_missing"


class PrerequisiteError(Exception):
    pass


class CleanupError(Exception):
    pass


REASONS = {
    "lease already exists": "Временный ресурс проверки уже занят",
    "resource operation failed": "Не удалось подготовить временный ресурс проверки",
    "resource operation timed out": "Превышено время подготовки временного ресурса",
    "temporary interface name is occupied": "Имя временного интерфейса занято",
    LOCAL_IMAGE_MISSING: "На сервере нет нужного локального образа",
    "temporary container name is occupied": "Имя временного контейнера занято",
    "temporary subnet overlaps an existing interface": "Временная подсеть пересекается с сетью сервера",
    "temporary subnet overlaps an existing route": "Временная подсеть пересекается с маршрутом сервера",
    "no source route to peer": "На сервере нет маршрута до соседа",
    "an existing unkeyed GRE tunnel already uses this peer": "Между серверами уже существует GRE-туннель",
    "temporary XRay failed to start": "Временный XRay не запустился",
    "temporary XRay listener not ready": "Временный XRay не открыл порт",
    "probe stopped or transfer failed": "Проверка остановлена или передача прервалась",
    "missing docker": "На сервере нет Docker",
    "missing ip": "На сервере нет утилиты ip",
    "missing iptables": "На сервере нет утилиты iptables",
    "missing ss": "На сервере нет утилиты ss",
}

IMAGE_SELECTION = r'''
class Unavailable(Exception): pass

def local_image(images, xray_version, command, check_legacy_xray):
    for candidate in images:
        inspected=command(['docker','image','inspect',candidate])
        if inspected.returncode:
            if inspected.returncode==124:
                raise Unavailable('resource operation timed out')
            if b'No such image' in inspected.stderr or b'No such object' in inspected.stderr:
                continue
            raise Unavailable('resource operation failed')
        selected=json.loads(inspected.stdout)[0]['Id']
        if candidate=='amnezia-xray':
            version=check_legacy_xray(selected)
            if version.returncode==124:
                raise Unavailable('resource operation timed out')
            if version.returncode or ('Xray '+xray_version+' ').encode() not in version.stdout:
                continue
            return selected, '/usr/bin/xray'
        return selected, None
    return None, None
'''

# The worker and its detached watchdog share only a private, random lease.
# Configuration/keys travel through SSH stdin, never argv or command output.
WORKER = r'''
import hashlib,ipaddress,json,os,shutil,signal,socket,subprocess,sys,time
from pathlib import Path
''' + IMAGE_SELECTION + r'''

class WorkerStopped(BaseException): pass
uncertain=[False]
def emit(**value): print(json.dumps(value),flush=True)
def command(args,required=True):
    try: p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
    except (subprocess.TimeoutExpired,OSError):
        if required: uncertain[0]=True
        if required: raise Unavailable('resource operation timed out')
        return subprocess.CompletedProcess(args,124,b'',b'')
    if required and p.returncode: raise Unavailable('resource operation failed')
    return p
def output(args): return command(args).stdout.decode().strip()
def exact(sock,size):
    result=b''
    while len(result)<size:
        part=sock.recv(size-len(result))
        if not part: raise OSError('incomplete acknowledgement')
        result+=part
    return result
def gre_key(value):
    try:
        return int(value) if isinstance(value,int) or str(value).isdigit() else int(ipaddress.IPv4Address(value))
    except (ValueError,TypeError): return -1
def bind_receiver(config,port):
    config['routing']['rules'][0]['port']=str(port)
    config['outbounds'][1]['settings']['finalRules'][0]['port']=str(port)
def receive(listener,token,total):
    listener.settimeout(25)
    conn,_=listener.accept()
    with conn:
        conn.settimeout(15)
        if exact(conn,len(token))!=token: raise OSError('invalid measurement token')
        conn.sendall(b'READY')
        begin=time.monotonic_ns(); count=0; digest=hashlib.sha256()
        try:
            while count<total and time.monotonic_ns()-begin<15_000_000_000:
                part=conn.recv(min(262144,total-count))
                if not part: break
                count+=len(part)
                digest.update(part)
        except OSError: pass
        record={'bytes':count,'receiver_secs':(time.monotonic_ns()-begin)/1e9,'sha256':digest.hexdigest()}
        try: conn.sendall(json.dumps(record).encode()+b'\n')
        except OSError: pass
        return record
def send(host,port,token,total,interface=None,own=None):
    count=0; received=0; start=None; error=''; digest=hashlib.sha256(); matched=False
    try:
        with socket.socket() as conn:
            conn.settimeout(8)
            if interface:
                conn.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
                conn.bind((own,0))
            conn.connect((host,port))
            conn.settimeout(15)
            conn.sendall(token)
            if exact(conn,5)!=b'READY': raise OSError('receiver not ready')
            block=os.urandom(65536)
            start=time.monotonic_ns()
            while count<total and time.monotonic_ns()-start<15_000_000_000:
                part=block[:min(len(block),total-count)]
                size=conn.send(part)
                if not size: raise OSError('short send')
                count+=size; digest.update(part[:size])
            conn.shutdown(socket.SHUT_WR)
            data=b''
            while b'\n' not in data and len(data)<2048:
                part=conn.recv(2048-len(data))
                if not part: break
                data+=part
            record=json.loads(data)
            received=int(record['bytes'])
            matched=record.get('sha256')==digest.hexdigest()
    except (OSError,ValueError,KeyError): error='transfer incomplete or timed out'
    return {'bytes':received,'sent':count,'secs':(time.monotonic_ns()-start)/1e9 if start else None,'digest_matches':matched,'error':error}

def main():
    os.umask(0o077)
    cfg=json.loads(sys.stdin.readline())
    tag=cfg['tag']; iface=cfg['interface']; name=cfg['container']
    label='org.amnezia.control.probe'
    directory=Path('/run')/('acontrol-probe-'+tag)
    if directory.exists(): raise Unavailable('lease already exists')
    directory.mkdir(mode=0o700)
    rules=[]; interface_created=False; container_attempted=False
    def save_owner(record):
        temporary=directory/'link-owner.json.tmp'
        with temporary.open('x',encoding='utf-8') as stream:
            json.dump(record,stream)
        temporary.chmod(0o600)
        temporary.replace(directory/'link-owner.json')
    def rule(parts,target='ACCEPT'):
        spec=['INPUT',*parts,'-m','comment','--comment',tag,'-j',target]
        rules.append(spec)
        command(['iptables','-w','3','-I',*spec])
    def cleanup():
        good=True
        if container_attempted:
            item=command(['docker','inspect',name],False)
            if item.returncode==124: good=False
            if item.returncode==0:
                try:
                    owned=json.loads(item.stdout)[0]['Config']['Labels'].get(label)==tag
                except (ValueError,KeyError,TypeError): owned=False
                if owned:
                    good=command(['docker','rm','-f',name],False).returncode==0 and good
                else: good=False
        if interface_created:
            item=command(['ip','-j','-d','link','show','dev',iface],False)
            if item.returncode==124: good=False
            if item.returncode==0:
                try:
                    link=json.loads(item.stdout)[0]
                    alias=link.get('ifalias','')
                    owned=alias==tag
                    # GRE creation can ignore an inline alias. A random GRE key
                    # is part of the atomic kernel creation and proves this
                    # lease's ownership even if set-alias is interrupted.
                    owner_path=directory/'link-owner.json'
                    if not owned and not alias and cfg['transport']=='gre' and owner_path.is_file() and not owner_path.is_symlink():
                        record=json.loads(owner_path.read_text())
                        info=link.get('linkinfo',{})
                        data=info.get('info_data',{})
                        owned=(info.get('info_kind')=='gre' and data.get('local')==record['local']
                            and data.get('remote')==cfg['peer_ip']
                            and gre_key(data.get('ikey'))==cfg['gre_key']
                            and gre_key(data.get('okey'))==cfg['gre_key']
                            and (not record.get('ifindex') or record['ifindex']==link.get('ifindex')))
                except (OSError,ValueError,KeyError,IndexError): owned=False
                if owned: good=command(['ip','link','del',iface],False).returncode==0 and good
                else: good=False
        for spec in reversed(rules):
            check=command(['iptables','-w','3','-C',*spec],False)
            if check.returncode==124: good=False
            if check.returncode==0:
                good=command(['iptables','-w','3','-D',*spec],False).returncode==0 and good
        # Keep the private ownership record/config for the watchdog if an
        # earlier deletion could not be confirmed.
        if not good or uncertain[0]: return False
        # Never recursively remove an arbitrary path, symlink, or extra file.
        try:
            for path in directory.iterdir():
                if path.name not in ('link.conf','config.json','link-owner.json','link-owner.json.tmp') or not path.is_file() or path.is_symlink():
                    good=False; continue
                path.unlink()
            directory.rmdir()
        except OSError: good=False
        return good and not uncertain[0]
    # Fork before the first mutation. If the panel, SSH channel, or worker dies,
    # the independent child still removes only this random lease's resources.
    watchdog=os.fork()
    if watchdog==0:
        signal.signal(signal.SIGTERM,signal.SIG_DFL)
        os.setsid()
        fd=os.open(os.devnull,os.O_RDWR)
        for number in (0,1,2): os.dup2(fd,number)
        time.sleep(cfg['lease'])
        # Mutated ownership lists live in the parent: reconstruct the exact
        # possible resources, always checking labels/aliases before removal.
        container_attempted=cfg['transport']!='gre'; interface_created=cfg['transport']!='vless'
        rules[:]=cfg['cleanup_rules']
        try: cleanup()
        finally: os._exit(0)
    def interrupted(*args): raise WorkerStopped()
    signal.signal(signal.SIGTERM,interrupted)
    signal.signal(signal.SIGALRM,interrupted)
    signal.alarm(cfg['lease']-10)
    listener=None
    try:
        transport=cfg['transport']; role=cfg['role']
        for tool in ('ip','iptables')+(() if transport=='gre' else ('docker',))+(('ss',) if transport=='vless' else ()):
            if not shutil.which(tool): raise Unavailable('missing '+tool)
        if command(['ip','link','show','dev',iface],False).returncode==0:
            raise Unavailable('temporary interface name is occupied')
        if transport!='gre':
            if command(['docker','inspect',name],False).returncode==0:
                raise Unavailable('temporary container name is occupied')
            def check_legacy_xray(selected):
                nonlocal container_attempted
                container_attempted=True
                version=command(['docker','run','--rm','--pull=never','--name',name,
                    '--label',label+'='+tag,'--network','none',
                    '--read-only','--cap-drop','ALL','--entrypoint','/usr/bin/xray',selected,'version'],False)
                if version.returncode==124: uncertain[0]=True
                return version
            image,executable=local_image(cfg['images'],cfg['xray_version'],
                lambda args: command(args,False),check_legacy_xray)
            if not image:
                raise Unavailable('local_image_missing')
        own=cfg['inner']; peer=cfg['peer_inner']
        if transport!='vless':
            network=ipaddress.ip_network(cfg['network'])
            for item in json.loads(output(['ip','-j','-4','address','show'])):
                for address in item.get('addr_info',[]):
                    if network.overlaps(ipaddress.ip_network(address['local']+'/'+str(address['prefixlen']),strict=False)):
                        raise Unavailable('temporary subnet overlaps an existing interface')
            routes=json.loads(output(['ip','-j','-4','route','show','table','all']))
            for route in routes:
                destination=route.get('dst','default')
                if destination!='default' and network.overlaps(ipaddress.ip_network(destination,strict=False)):
                    raise Unavailable('temporary subnet overlaps an existing route')
        if transport=='gre':
            local=json.loads(output(['ip','-j','-4','route','get',cfg['peer_ip']]))[0].get('prefsrc')
            if not local: raise Unavailable('no source route to peer')
            for existing in json.loads(output(['ip','-j','-d','link','show','type','gre'])):
                data=existing.get('linkinfo',{}).get('info_data',{})
                if data.get('remote')==cfg['peer_ip'] and data.get('local')==local and gre_key(data.get('ikey',0))==0:
                    raise Unavailable('an existing unkeyed GRE tunnel already uses this peer')
            record={'local':local,'remote':cfg['peer_ip'],'key':cfg['gre_key']}
            save_owner(record)
            interface_created=True
            command(['ip','link','add',iface,'type','gre','local',local,'remote',cfg['peer_ip'],
                'key',str(cfg['gre_key']),'ttl','64'])
            record['ifindex']=json.loads(output(['ip','-j','link','show','dev',iface]))[0]['ifindex']
            save_owner(record)
            command(['ip','link','set','dev',iface,'alias',tag])
            rule(['-p','gre','-s',cfg['peer_source']])
        if transport=='awg':
            path=directory/'link.conf'; path.write_text(cfg['awg_config']); path.chmod(0o600)
            container_attempted=True
            command(['docker','run','--pull=never','-d','--name',name,'--label',label+'='+tag,
                '--network','host','--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_BIND_SERVICE','--device','/dev/net/tun',
                '--read-only','--tmpfs','/run','--tmpfs','/tmp','--security-opt','no-new-privileges:true',
                '-v',str(directory)+':/probe:ro','--entrypoint','/usr/bin/amneziawg-go',image,'-f',iface])
            for attempt in range(30):
                if command(['ip','link','show',iface],False).returncode==0: break
                time.sleep(0.1)
            command(['ip','link','set','dev',iface,'alias',tag]); interface_created=True
            command(['docker','exec',name,'awg','setconf',iface,'/probe/link.conf'])
            rule(['-p','udp','-s',cfg['peer_source'],'--dport',str(cfg['port'])])
            rule(['-p','udp','!','-s',cfg['peer_source'],'--dport',str(cfg['port'])],'DROP')
        if transport!='vless':
            command(['ip','address','add',own+'/32','dev',iface])
            command(['ip','link','set',iface,'mtu',str(1280 if transport=='awg' else 1472),'up'])
            command(['ip','route','add',peer+'/32','dev',iface,'src',own])
            command(['sysctl','-qw','net.ipv4.conf.'+iface+'.rp_filter=2'])
            rule(['-i',iface,'-s',peer+'/32','-d',own+'/32','-p','tcp'])
        if role=='exit':
            listener=socket.socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(('127.0.0.1' if transport=='vless' else own,0)); listener.listen(1)
            receiver_port=listener.getsockname()[1]
        else: receiver_port=cfg['receiver_port']
        if transport=='vless':
            config=cfg['xray_config']
            if role=='exit':
                bind_receiver(config,receiver_port)
                rule(['-p','tcp','-s',cfg['peer_source'],'--dport',str(cfg['port'])])
                rule(['-p','tcp','!','-s',cfg['peer_source'],'--dport',str(cfg['port'])],'DROP')
            else:
                config['inbounds'][0]['settings']['port']=receiver_port
            path=directory/'config.json'; path.write_text(json.dumps(config)); path.chmod(0o600)
            container_attempted=True
            launch=['docker','run','--pull=never','-d','--name',name,'--label',label+'='+tag,
                '--network','host','--user','0:0','--read-only','--cap-drop','ALL','--cap-add','NET_BIND_SERVICE',
                '--security-opt','no-new-privileges:true','-e','GODEBUG=multipathtcp=0',
                '-v',str(directory)+':/usr/local/etc/xray:ro']
            if executable: launch+=['--entrypoint',executable]
            launch+=[image]
            if executable: launch+=['run','-c','/usr/local/etc/xray/config.json']
            command(launch)
            listen_port=cfg['port']
            for attempt in range(40):
                if command(['docker','inspect','-f','{{.State.Running}}',name]).stdout.strip()!=b'true':
                    raise Unavailable('temporary XRay failed to start')
                # Inspect the listener without opening a connection: a readiness
                # connection would consume the single authenticated receiver.
                if output(['ss','-lntH','sport = :'+str(listen_port)]): break
                time.sleep(0.1)
            else: raise Unavailable('temporary XRay listener not ready')
        prerequisite=None
        if transport=='vless' and role=='entry':
            try:
                with socket.create_connection((cfg['peer_ip'],cfg['peer_port']),timeout=5): pass
                prerequisite={'ok':True,'error':''}
            except OSError: prerequisite={'ok':False,'error':'TCP connection to the Reality listener failed'}
        emit(event='ready',receiver_port=receiver_port,prerequisite_tcp=prerequisite)
        if role=='entry':
            if sys.stdin.readline().strip()!='go': raise TimeoutError()
            host='127.0.0.1' if transport=='vless' else peer
            port=cfg['port'] if transport=='vless' else receiver_port
            result=send(host,port,cfg['token'].encode(),cfg['total'],iface if transport!='vless' else None,own)
        else: result=receive(listener,cfg['token'].encode(),cfg['total'])
        emit(event='result',**result)
        sys.stdin.readline()
    except Unavailable as exc: emit(event='unavailable',error=str(exc))
    except BaseException:
        emit(event='failed',error='probe stopped or transfer failed')
    finally:
        signal.alarm(0)
        emit(event='cleaning')
        if listener: listener.close()
        try: good=cleanup()
        except Exception: good=False
        emit(event='cleanup',ok=good)
        if good:
            try: os.kill(watchdog,signal.SIGTERM)
            except ProcessLookupError: pass
            os.waitpid(watchdog,0)
        # A failed explicit cleanup leaves the watchdog alive for one retry.
if __name__=='__main__': main()
'''

# SSH keeps stdin open while preparation is wanted. EOF also reaches the
# worker when the panel dies, so no detached build waits on an absent caller.
PREPARE_WORKER = r'''
import fcntl,json,os,select,shutil,signal,subprocess,sys,tempfile,time,uuid
from pathlib import Path
''' + IMAGE_SELECTION + r'''

class Stopped(Exception): pass

def stop(*args):
    raise Stopped()

def prepare(config):
    if not shutil.which('docker'):
        return 6
    os.umask(0o077)
    with open('/run/acontrol-probe-image.lock','a') as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            return 5
        return locked_prepare(config)

def locked_prepare(config):
    deadline=time.monotonic()+config['seconds']
    name='acontrol-probe-build-'+uuid.uuid4().hex
    label='org.amnezia.control.probe-builder='+name
    builder_used=False
    build=None

    def command(args,capture=True,env=None):
        if select.select([sys.stdin],[],[],0)[0]:
            raise Stopped()
        output=subprocess.PIPE if capture else subprocess.DEVNULL
        with subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=output,stderr=output,
                              start_new_session=True,env=env) as process:
            try:
                while True:
                    if select.select([sys.stdin],[],[],0)[0]:
                        raise Stopped()
                    remaining=deadline-time.monotonic()
                    if remaining<=0:
                        raise TimeoutError()
                    try:
                        stdout,stderr=process.communicate(timeout=min(0.2,remaining))
                    except subprocess.TimeoutExpired:
                        continue
                    return subprocess.CompletedProcess(args,process.returncode,stdout,stderr)
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def check_legacy_xray(image):
        nonlocal builder_used
        builder_used=True
        return command(['docker','run','--rm','--pull=never','--name',name,'--label',label,
                        '--network','none','--read-only','--cap-drop','ALL',
                        '--entrypoint','/usr/bin/xray',image,'version'])

    status=0
    try:
        image,_=local_image(config['images'],config['xray_version'],command,check_legacy_xray)
        if image is None:
            status=2
            if config['build_script']:
                build=tempfile.TemporaryDirectory(prefix='acontrol-probe-build-',dir='/run')
                builder_used=True
                env=dict(os.environ,BUILD=build.name,BUILDER=name,BUILDER_LABEL=label)
                status=2 if command(['bash','-c',config['build_script']],False,env).returncode else 0
            else:
                status=2 if command(['docker','pull',config['images'][0]],False).returncode else 0
    except Stopped:
        status=7
    except TimeoutError:
        status=3
    except (Unavailable,OSError,ValueError,KeyError,IndexError):
        status=6
    finally:
        if builder_used:
            # A killed Docker client can leave a daemon-side build container.
            # Only containers carrying this invocation's random label are ours.
            try:
                containers=subprocess.run(['docker','ps','-aq','--filter','label='+label],
                                          capture_output=True,check=True,timeout=5).stdout.split()
                if containers:
                    subprocess.run(['docker','rm','-f',*(item.decode() for item in containers)],
                                   capture_output=True,check=True,timeout=5)
            except (subprocess.SubprocessError,OSError):
                status=4
        if build:
            try:
                build.cleanup()
            except OSError:
                status=4
    return status

if __name__=='__main__':
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGHUP,stop)
    try:
        sys.exit(prepare(json.loads(sys.argv[1])))
    except (Stopped,OSError):
        sys.exit(6)
'''

PREPARE_ERRORS = {
    2: ("Не удалось подготовить образ для проверки", LOCAL_IMAGE_MISSING),
    3: ("Превышено время подготовки образа для проверки", LOCAL_IMAGE_MISSING),
    4: ("Не подтверждена очистка временной подготовки образа", None),
    5: ("На сервере уже идет подготовка образа для проверки", None),
    6: ("Не удалось запустить подготовку образа для проверки", None),
}


def _prepare_config(transport: str, images: list[str], xray_version: str) -> dict:
    script = ""
    if transport == "awg":
        script = "\n".join([
            "set -euo pipefail",
            'cd "$BUILD"',
            f"IMG={shlex.quote(AWG_PROBE_IMAGE)}",
            "log() { :; }",
            f'printf %s {shlex.quote(deploy._dockerfile_v3())} > Dockerfile',
            "printf '#!/bin/sh\\nexit 1\\n' > start.sh",
            *deploy._v3_build_lines(8, probe=True),
        ])
    return {"images": images, "xray_version": xray_version, "build_script": script,
            "seconds": PREPARE_SECONDS}


async def _stop_preparation(process) -> None:
    try:
        process.stdin.write_eof()
        await asyncio.wait_for(process.wait_closed(), timeout=15)
    except (OSError, RuntimeError, TimeoutError):
        process.close()


async def _prepare(conn, config: dict) -> int:
    command = "sudo -n python3 -c " + shlex.quote(PREPARE_WORKER) + " " + shlex.quote(json.dumps(config))
    opening = asyncio.ensure_future(asyncio.wait_for(conn.create_process(command), timeout=10))
    try:
        process = await asyncio.shield(opening)
    except asyncio.CancelledError:
        try:
            process = await opening
        except Exception:
            pass
        else:
            await _stop_preparation(process)
        raise
    try:
        await asyncio.wait_for(process.wait_closed(), timeout=PREPARE_SECONDS + 15)
    except (asyncio.CancelledError, TimeoutError):
        await _stop_preparation(process)
        raise
    return process.exit_status


def verdict(sent: dict, received: dict) -> dict:
    """Only receiver-confirmed full delivery is success; never use socket-buffer bytes."""
    count = min(max(int(received.get("bytes", 0)), 0), PAYLOAD_BYTES)
    secs = sent.get("secs")
    secs = float(secs) if isinstance(secs, (int, float)) and secs > 0 else None
    ok = (count == PAYLOAD_BYTES and sent.get("bytes") == count
          and sent.get("sent") == count and sent.get("digest_matches") is True
          and not sent.get("error"))
    return {"status": "ok" if ok else "failed", "ok": ok, "bytes": count, "secs": secs,
            "mbps": count * 8 / secs / 1e6 if secs else None,
            "error": "" if ok else "Передача прервалась или приняты не все данные"}


def xray_configs(params: dict, peer_ip: str, exit_port: int, entry_port: int) -> tuple[dict, dict]:
    params = params | {"port": exit_port}
    exit_config = json.loads(cascade.exit_vless_config(params))
    exit_config["log"] = {"loglevel": "none", "access": "none"}
    exit_config["inbounds"][0].pop("sniffing", None)
    exit_config["outbounds"] = [{"tag": "block", "protocol": "blackhole"},
                                {"tag": "receiver", "protocol": "freedom", "settings": {
                                    "finalRules": [{"action": "allow", "network": "tcp",
                                                    "ip": ["127.0.0.1/32"], "port": "1"}]}}]
    exit_config["routing"] = {"rules": [{"inboundTag": ["from-entry"], "ip": ["127.0.0.1/32"],
                                         "port": "1", "outboundTag": "receiver"}]}
    outbound = json.loads(cascade.entry_gateway_config("vless", peer_ip, params, bootstrap=True))["outbounds"][0]
    entry_config = {"log": {"loglevel": "none", "access": "none"}, "inbounds": [{
        "listen": "127.0.0.1", "port": entry_port, "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1", "port": 1, "network": "tcp"}}],
        "outbounds": [outbound]}
    return entry_config, exit_config


async def _port(conn, requested: int | None, protocol: str, candidates=()) -> int:
    choices = (requested,) if requested is not None else candidates or tuple(
        secrets.randbelow(20000) + 30000 for _ in range(12)
    )
    for port in choices:
        if await deploy.port_owner(conn, port, protocol) is None:
            return port
    raise PrerequisiteError("Для проверки нет свободного порта")


async def _event(process) -> dict:
    line = await asyncio.wait_for(process.stdout.readline(), timeout=45)
    try:
        value = json.loads(line)
        if isinstance(value, dict):
            return value
    except (ValueError, TypeError):
        pass
    raise RuntimeError("Временная проверка не ответила")


async def _start(conn, config: dict):
    python = await conn.run("command -v python3", check=False, timeout=10)
    if python.exit_status != 0:
        raise PrerequisiteError("На сервере нет python3")
    process = await conn.create_process("sudo -n python3 -u -c " + shlex.quote(WORKER))
    try:
        process.stdin.write(json.dumps(config) + "\n")
    except Exception as exc:
        # Retain responsibility before the caller can register this process.
        if not await _close(process):
            raise CleanupError() from exc
        raise PrerequisiteError("Не удалось передать параметры временной проверки") from exc
    return process


async def _close(process) -> bool:
    try:
        process.stdin.write("close\n")
        process.stdin.write_eof()
    except Exception:  # An exited worker can still have a buffered cleanup event.
        pass
    try:
        cleaning, terminated = False, False
        async with asyncio.timeout(45):
            for _ in range(8):
                try:
                    item = await asyncio.wait_for(_event(process), timeout=40 if cleaning else 3)
                except TimeoutError:
                    if cleaning or terminated:
                        return False
                    # EOF cannot interrupt a socket accept/receive. TERM reaches
                    # the worker's handler and enters its finally/cleanup path.
                    process.terminate()
                    terminated = True
                    continue
                if item.get("event") == "cleaning":
                    cleaning = True
                if item.get("event") == "cleanup":
                    return item.get("ok") is True
    except (Exception, asyncio.CancelledError):
        pass
    return False


async def run(exit_conn, entry_conn, entry_ip: str, exit_ip: str, transport: str,
              entry_port: int | None = None, exit_port: int | None = None,
              entry_source_ip: str | None = None, *, prepare_missing_image: bool = False) -> dict:
    """One measurement with two independently expiring remote leases."""
    if transport not in {"awg", "vless", "gre"}:
        raise ValueError("Unknown transport")
    if prepare_missing_image and transport == "gre":
        raise ValueError("GRE does not use a Docker image")
    entry_ip, exit_ip = str(ipaddress.IPv4Address(entry_ip)), str(ipaddress.IPv4Address(exit_ip))
    if entry_ip == exit_ip:
        raise ValueError("Entry and exit must be different hosts")
    source_ip = str(ipaddress.IPv4Address(entry_source_ip or entry_ip))
    run_id = uuid.uuid4().hex
    subnet = ipaddress.ip_network(f"198.18.{secrets.randbelow(256)}.{secrets.randbelow(64) * 4}/30")
    entry_inner, exit_inner = str(subnet[1]), str(subnet[2])
    images = [cascade_awg.IMAGE, deploy.IMAGE_V3, AWG_PROBE_IMAGE] if transport == "awg" else [cascade.XRAY_IMAGE, "amnezia-xray"]
    xray_version = cascade.XRAY_IMAGE.rsplit(":", 1)[1]
    base = {"tag": run_id, "transport": transport, "token": secrets.token_hex(24),
            "total": PAYLOAD_BYTES, "lease": LEASE_SECONDS, "images": images, "network": str(subnet),
            "gre_key": int(run_id[:8], 16) or 1, "xray_version": xray_version}
    configs = []
    processes = []
    result = {"transport": transport, "measurement": transport, "run_id": run_id,
              "requested_bytes": PAYLOAD_BYTES, "status": "unavailable", "ok": None,
              "bytes": 0, "secs": None, "mbps": None, "error": "Проверка не запущена"}
    cleanup_ok = True
    try:
        if transport != "gre":
            protocol = "udp" if transport == "awg" else "tcp"
            entry_port = await _port(entry_conn, entry_port if transport == "awg" else None, protocol,
                                     cascade_awg.PORTS if transport == "awg" else ())
            exit_port = await _port(exit_conn, exit_port if transport == "awg" else None, protocol,
                                    cascade.VLESS_PORTS if transport == "vless" else cascade_awg.PORTS)
        if prepare_missing_image:
            prepare_config = _prepare_config(transport, images, xray_version)
            statuses = await asyncio.gather(_prepare(exit_conn, prepare_config), _prepare(entry_conn, prepare_config),
                                            return_exceptions=True)
            codes = [status if isinstance(status, int) else 3 if isinstance(status, TimeoutError) else 6
                     for status in statuses]
            code = 4 if 4 in codes else next((code for code in codes if code != 0), 0)
            if code != 0:
                result["error"], result["reason"] = PREPARE_ERRORS.get(code, PREPARE_ERRORS[6])
                if code == 4:
                    result.update(status="failed", ok=False)
                return result
        if transport == "awg":
            params = cascade_awg.new_params() | {"entry_ip": entry_ip, "exit_ip": exit_ip,
                "entry_port": entry_port, "exit_port": exit_port, "entry_inner": entry_inner,
                "exit_inner": exit_inner}
        elif transport == "vless":
            entry_config, exit_config = xray_configs(cascade.new_vless_params(), exit_ip, exit_port, entry_port)
        for role, own_ip, peer_ip, own_inner, peer_inner, port in (
            ("exit", exit_ip, entry_ip, exit_inner, entry_inner, exit_port),
            ("entry", entry_ip, exit_ip, entry_inner, exit_inner, entry_port),
        ):
            tag = run_id + ("x" if role == "exit" else "e")
            cfg = base | {"role": role, "tag": tag, "interface": "acp" + run_id[:10],
                "container": "acontrol-probe-" + tag, "own_ip": own_ip, "peer_ip": peer_ip,
                "inner": own_inner, "peer_inner": peer_inner, "port": port}
            peer_source = source_ip if role == "exit" else exit_ip
            cfg["peer_source"] = peer_source
            rule_parts = []
            if transport == "gre": rule_parts.append(["-p", "gre", "-s", peer_source])
            if transport == "awg": rule_parts.append(["-p", "udp", "-s", peer_source, "--dport", str(port)])
            if transport == "vless" and role == "exit": rule_parts.append(["-p", "tcp", "-s", peer_source, "--dport", str(port)])
            if transport != "vless": rule_parts.append(["-i", cfg["interface"], "-s", peer_inner + "/32", "-d", own_inner + "/32", "-p", "tcp"])
            cfg["cleanup_rules"] = [["INPUT", *parts, "-m", "comment", "--comment", tag, "-j", "ACCEPT"] for parts in rule_parts]
            if transport == "awg" or (transport == "vless" and role == "exit"):
                protocol = "udp" if transport == "awg" else "tcp"
                cfg["cleanup_rules"].append(["INPUT", "-p", protocol, "!", "-s", peer_source,
                    "--dport", str(port), "-m", "comment", "--comment", tag, "-j", "DROP"])
            if transport == "awg":
                cfg["awg_config"] = cascade_awg.config(role, params).replace("FwMark = 1024", "FwMark = 0").replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = " + peer_inner + "/32")
            if transport == "vless":
                cfg["xray_config"] = exit_config if role == "exit" else entry_config
                cfg["peer_port"] = exit_port if role == "entry" else entry_port
            configs.append(cfg)
        exit_process = await _start(exit_conn, configs[0]); processes.append(exit_process)
        ready = await _event(exit_process)
        if ready.get("event") != "ready":
            result["error"] = REASONS.get(ready.get("error"), "Выход не готов к проверке")
            if ready.get("error") == LOCAL_IMAGE_MISSING:
                result["reason"] = LOCAL_IMAGE_MISSING
            return result
        configs[1]["receiver_port"] = ready["receiver_port"]
        entry_process = await _start(entry_conn, configs[1]); processes.append(entry_process)
        ready = await _event(entry_process)
        if ready.get("event") != "ready":
            result["error"] = REASONS.get(ready.get("error"), "Вход не готов к проверке")
            if ready.get("error") == LOCAL_IMAGE_MISSING:
                result["reason"] = LOCAL_IMAGE_MISSING
            return result
        if transport == "vless": result["prerequisite_tcp"] = ready.get("prerequisite_tcp")
        if result.get("prerequisite_tcp") and result["prerequisite_tcp"].get("error"):
            result["prerequisite_tcp"]["error"] = "Не удалось подключиться к TCP-порту VLESS"
        entry_process.stdin.write("go\n")
        sent, received = await asyncio.gather(_event(entry_process), _event(exit_process))
        result.update(verdict(sent, received))
        if transport != "gre": result.update(entry_port=entry_port, exit_port=exit_port)
    except CleanupError:
        result.update(status="failed", ok=False, error="Не подтверждена полная очистка временной проверки")
    except PrerequisiteError as exc:
        result["error"] = str(exc)
    except (OSError, ValueError, RuntimeError, TimeoutError):
        result["error"] = "Не удалось подготовить или завершить временную проверку"
    finally:
        if processes:
            cleanup = asyncio.ensure_future(asyncio.gather(*(_close(process) for process in processes)))
            try:
                cleanup_ok = all(await asyncio.shield(cleanup))
            except asyncio.CancelledError:
                await cleanup
                raise
        if not cleanup_ok:
            result.update(status="failed", ok=False, reason=None,
                          error="Не подтверждена полная очистка временной проверки")
    return result
