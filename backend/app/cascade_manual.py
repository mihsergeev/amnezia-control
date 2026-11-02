"""Bounded, read-only discovery of an existing manual XRay cascade.

Only a running known carrier and its actual mounted configuration qualify.
Routing tags, TLS SNI and geography are never treated as an exit hostname.
The remote program emits route metadata only, never credentials or full JSON.
"""

import ipaddress
import json
import re
import shlex


NETWORKS = frozenset({"tcp", "raw", "xhttp", "ws", "grpc", "http", "h2", "httpupgrade"})
SECURITIES = frozenset({"none", "tls", "reality"})


def _host(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253 or value != value.strip() or "%" in value:
        raise ValueError("invalid_host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        value = value.rstrip(".").lower()
        if not value or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
            raise ValueError("invalid_host") from None
        return value


def parse_probe(text: str) -> dict:
    """Whitelist the small discovery result; omit unverified exit names."""
    try:
        if len(text) > 4096:
            return {}
        value = json.loads(text)
        if not isinstance(value, dict) or value.get("transport") != "vless":
            return {}
        security, network = value["security"], value["network"]
        if security not in SECURITIES or network not in NETWORKS:
            return {}
        port = value["exit_port"]
        if type(port) is not int or not 1 <= port <= 65535:
            return {}
        return {"transport": "vless", "security": security, "network": network,
                "exit_host": _host(value["exit_host"]), "exit_port": port}
    except (KeyError, TypeError, ValueError):
        return {}


PROBE_PY = r'''
import ipaddress,json,os,posixpath,re,stat,subprocess,time
from pathlib import Path

APPROVED = '/app/cascade/config'
DEADLINE=time.monotonic()+2.5

def run(args):
    remaining=DEADLINE-time.monotonic()
    if remaining<=0: raise ValueError('budget')
    p=subprocess.run(args,capture_output=True,text=True,timeout=min(1.25,remaining))
    if p.returncode: raise ValueError('unavailable')
    return p.stdout

def host(value):
    if not isinstance(value,str) or not value or len(value)>253 or value!=value.strip() or '%' in value:
        raise ValueError('host')
    try: return str(ipaddress.ip_address(value))
    except ValueError:
        value=value.rstrip('.').lower()
        if not value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in value.split('.')):
            raise ValueError('host')
        return value

def public_route(config):
    if not isinstance(config,dict): return {}
    outbounds=config.get('outbounds')
    # The first outbound is XRay's default. A selective secondary VLESS route
    # does not establish that this node uses a manual cascade by default.
    if not isinstance(outbounds,list) or not outbounds or not isinstance(outbounds[0],dict): return {}
    first=outbounds[0]
    if first.get('protocol')!='vless': return {}
    stream=first.get('streamSettings') or {}
    network=stream.get('network','tcp');security=stream.get('security','none')
    if network not in ('tcp','raw','xhttp','ws','grpc','http','h2','httpupgrade') or security not in ('none','tls','reality'): return {}
    peers=(first.get('settings') or {}).get('vnext')
    if not isinstance(peers,list) or len(peers)!=1 or not isinstance(peers[0],dict): return {}
    peer=peers[0];port=peer.get('port')
    if type(port) is not int or not 1<=port<=65535: return {}
    return {'transport':'vless','security':security,'network':network,
            'exit_host':host(peer.get('address')),'exit_port':port}

def config_option(cmd):
    if not isinstance(cmd,list) or any(not isinstance(x,str) for x in cmd): return None
    options=[]
    for i,arg in enumerate(cmd):
        if arg in ('-confdir','--confdir','-config','--config','-c'):
            if i+1>=len(cmd): return None
            options.append(('dir' if 'confdir' in arg else 'file',cmd[i+1]))
        elif any(arg.startswith(k+'=') for k in ('-confdir','--confdir','-config','--config','-c')):
            k,v=arg.split('=',1);options.append(('dir' if 'confdir' in k else 'file',v))
    if len(options)!=1 or not options[0][1].startswith('/'): return None
    return options[0][0],posixpath.normpath(options[0][1])

def mounted_config(mounts,option):
    if not isinstance(mounts,list) or option is None: return None
    kind,target=option;approved=Path(APPROVED).resolve();candidates=[]
    for mount in mounts:
        if not isinstance(mount,dict) or mount.get('Type')!='bind': continue
        source=Path(mount.get('Source',''));destination=mount.get('Destination')
        if not isinstance(destination,str) or not destination.startswith('/'): continue
        destination=posixpath.normpath(destination)
        if kind=='dir' and destination==target and source.resolve()==approved:
            # Multiple JSON fragments may alter the effective default outbound.
            configs=list(source.glob('*.json'))
            if len(configs)==1 and configs[0].name=='config.json': candidates.append(configs[0])
        elif kind=='file' and source.resolve()==approved/'config.json' and destination==target:
            candidates.append(source)
        elif kind=='file' and source.resolve()==approved and target==destination+'/config.json':
            candidates.append(source/'config.json')
    if len(candidates)!=1: return None
    return candidates[0]

def read_config(path):
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
    fd=os.open(path,flags)
    with os.fdopen(fd,'rb') as f:
        meta=os.fstat(f.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_size>131072: raise ValueError('file')
        raw=f.read(131073)
    if len(raw)>131072: raise ValueError('size')
    return json.loads(raw)

def probe():
    fmt='{{json .State.Running}}\n{{json .Config.Entrypoint}}\n{{json .Config.Cmd}}\n{{json .Mounts}}'
    rows=run(['docker','inspect','--format',fmt,'xray-cascade']).splitlines()
    if len(rows)!=4: return {}
    running,entrypoint,cmd,mounts=map(json.loads,rows)
    if running is not True or entrypoint not in (['/usr/local/bin/xray'],['xray']): return {}
    path=mounted_config(mounts,config_option(cmd))
    if path is None or time.monotonic()>DEADLINE: return {}
    return public_route(read_config(path))

try:
    result=probe()
except Exception:
    result={}
print('MANUAL_CASCADE='+json.dumps(result,separators=(',',':')))
'''


# A fixed program; discovered paths are read as data and never executed. The
# outer root-owned timeout also bounds an unexpectedly blocked filesystem read.
PROBE_COMMAND = "sudo -n timeout 3 python3 -c " + shlex.quote(PROBE_PY) + " 2>/dev/null; "
