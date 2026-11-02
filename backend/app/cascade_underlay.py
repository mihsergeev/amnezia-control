"""Read-only discovery of an existing GRE-over-AWG link.

An installed file or an interface name is not encryption evidence. Only report
encryption when the live GRE binding, authenticated peer and peer route agree.
Never read a private configuration or use ``awg show ... dump`` here.
"""

import ipaddress
import json
import shlex


PROBE_PY = r'''
import ipaddress,json,subprocess,time

def run(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=3)
    if p.returncode: raise ValueError('unavailable')
    return p.stdout

def peer_rows(field):
    lines=run(['docker','exec','acontrol-awg-link','awg','show','acawg',field]).splitlines()
    if len(lines)!=1: raise ValueError('peer_count')
    parts=lines[0].split(None,1)
    if len(parts)!=2: raise ValueError('invalid_peer')
    return parts

def probe():
    info=json.loads(run(['docker','inspect','acontrol-awg-link']))[0]
    labels=info.get('Config',{}).get('Labels') or {}
    if 'acontrol-awg-link-v1' not in labels or info.get('State',{}).get('Running') is not True:
        return {}
    gre=json.loads(run(['ip','-j','-d','link','show','acgre']))[0]
    data=gre.get('linkinfo',{}).get('info_data',{})
    if gre.get('linkinfo',{}).get('info_kind')!='gre': return {}
    remote=ipaddress.IPv4Address(data['remote'])
    local=ipaddress.IPv4Address(data['local'])
    awg=json.loads(run(['ip','-j','addr','show','acawg']))[0]
    bound=data.get('link')=='acawg' or gre.get('link')=='acawg' or data.get('link')==awg.get('ifindex')
    local_ok=any(a.get('local')==str(local) for a in awg.get('addr_info',[]))
    hs_peer,hs=peer_rows('latest-handshakes')
    allowed_peer,allowed=peer_rows('allowed-ips')
    endpoint_peer,endpoint=peer_rows('endpoints')
    if len({hs_peer,allowed_peer,endpoint_peer})!=1: return {}
    # This helper owns a single point-to-point peer, never a default-route peer.
    allowed_ok=allowed.strip()==str(remote)+'/32'
    public,sep,port=endpoint.rpartition(':')
    if not sep or not 1<=int(port)<=65535: return {}
    public=str(ipaddress.IPv4Address(public))
    # Some iproute2 versions reject `route get ... ipproto gre`. Inspect the
    # actual GRE-only policy and its table instead, without generating traffic.
    routes=json.loads(run(['ip','-j','route','show','table','243']))
    route_ok=any(r.get('dst') in (str(remote),str(remote)+'/32') and r.get('dev')=='acawg' for r in routes)
    rules=json.loads(run(['ip','-j','rule','show']))
    policy_ok=any(r.get('priority')==1006 and r.get('dst') in (str(remote),str(remote)+'/32') and str(r.get('ipproto')) in ('gre','47') and str(r.get('table'))=='243' for r in rules)
    age=int(time.time())-int(hs)
    up='UP' in gre.get('flags',[]) and 'UP' in awg.get('flags',[])
    encrypted=bound and local_ok and allowed_ok and route_ok and policy_ok and up and age>=0 and int(hs)>0
    return {'transport':'awg','encrypted':bool(encrypted),'tunnel':'acgre',
            'public_remote':public,'handshake_age':age if int(hs)>0 else None,
            'healthy':bool(encrypted and age<180)}

try:
    result=probe()
except Exception:
    result={}
print('AWGUNDERLAY='+json.dumps(result,separators=(',',':')))
'''

# The entire program is a literal; no user-controlled value enters a shell.
PROBE_COMMAND = "sudo -n timeout 5 python3 -c " + shlex.quote(PROBE_PY) + " 2>/dev/null; "

# Cascade checks use their existing key/value protocol. Emit nothing for an
# unrelated node, so a native AWG or REALITY check retains its own evidence.
_CASCADE_PY = PROBE_PY.replace(
    "print('AWGUNDERLAY='+json.dumps(result,separators=(',',':')))",
    "if result:\n"
    "    print('CASCADE_ENCRYPTION=awg')\n"
    "    print('CASCADE_ENCRYPTED='+('yes' if result['encrypted'] else 'unknown'))\n"
    "    print('CASCADE_HANDSHAKE='+str(result.get('handshake_age','')))\n"
    "    print('CASCADE_LINKHEALTH='+('yes' if result['healthy'] else 'no'))",
)
CASCADE_PROBE_COMMAND = "sudo -n timeout 5 python3 -c " + shlex.quote(_CASCADE_PY) + " 2>/dev/null; "


def parse_probe(text: str) -> dict:
    """Accept only this probe's small public result, never arbitrary JSON keys."""
    try:
        value = json.loads(text)
        if not isinstance(value, dict) or not value:
            return {}
        if value.get("transport") != "awg" or value.get("tunnel") != "acgre":
            return {}
        if type(value.get("encrypted")) is not bool:
            return {}
        remote = str(ipaddress.IPv4Address(value["public_remote"]))
        age = value.get("handshake_age")
        if age is not None and (type(age) is not int or age < 0):
            return {}
        if value["encrypted"] and age is None:
            return {}
        return {"transport": "awg", "encrypted": value["encrypted"],
                "tunnel": "acgre", "public_remote": remote, "handshake_age": age,
                # Transport protection and current connectivity are distinct.
                "healthy": value["encrypted"] and age is not None and age < 180}
    except (KeyError, TypeError, ValueError):
        return {}
