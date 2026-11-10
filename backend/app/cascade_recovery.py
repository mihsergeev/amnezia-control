"""Read the entry's ownership marker without reading or exporting VPN secrets."""

import json
import shlex

from app import cascade, cascade_awg, cascade_exit

_INSPECT = r'''
import ipaddress,json,pathlib,re,stat,sys
def read(path, limit):
 path=pathlib.Path(path)
 try: meta=path.lstat()
 except FileNotFoundError:return None
 if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode & 0o022 or meta.st_size>limit:sys.exit(73)
 return path.read_text()
def directory(path):
 try: meta=path.lstat()
 except FileNotFoundError:return False
 if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode & 0o022:sys.exit(73)
 return True
base=pathlib.Path('/opt/acontrol/cascade')
awg=base.with_name('cascade-awg')
awg_script=pathlib.Path('/lib65/scripts/acontrol-cascade-awg.sh')
for path in (base.parent,base):
 directory(path)
raw=read(base/'owner.json',1024)
awg_present=directory(awg) or awg_script.exists() or awg_script.is_symlink()
if raw is None:
 if base.exists() or awg_present:sys.exit(73)
 for path in ('/etc/default/acontrol-gre','/etc/systemd/system/acontrol-cascade-tproxy.service.d/awg.conf'):
  if pathlib.Path(path).exists() or pathlib.Path(path).is_symlink():sys.exit(73)
 print('null');sys.exit(0)
owner=json.loads(raw)
if (not isinstance(owner,dict) or set(owner)!={'cascade_id','transport','owner','layout'} or owner['layout']!=2
 or type(owner['cascade_id']) is not int or not 0<owner['cascade_id']<=2147483647
 or owner['transport'] not in ('awg','vless','gre') or not isinstance(owner['owner'],str)
 or not re.fullmatch('[0-9a-f]{32}',owner['owner'])):sys.exit(73)
if awg_present:
 if owner['transport']!='awg':sys.exit(73)
 env=read(awg/'node.env',4096)
 if env is not None:
  if re.findall(r'^CID=(.*)$',env,re.M)!=[str(owner['cascade_id'])] or re.findall(r'^ROLE=(.*)$',env,re.M)!=['entry']:sys.exit(73)
 read(awg_script,32768)
gre=read('/etc/default/acontrol-gre',4096)
if gre is not None:
 if owner['transport']!='gre' or 'ROLE=entry' not in gre.splitlines():sys.exit(73)
 key=re.findall(r'^KEY=([0-9]{1,10})$',gre,re.M)
 peer=re.findall(r'^REMOTE=([0-9.]+)$',gre,re.M)
 if len(key)!=1 or not 0<int(key[0])<=4294967295 or len(peer)!=1:sys.exit(73)
 owner.update(gre_key=int(key[0]),exit_ip=str(ipaddress.IPv4Address(peer[0])))
print(json.dumps(owner,sort_keys=True,separators=(',',':')))
'''

INSPECT = cascade_awg.foreign_guard() + "sudo -n python3 -c " + shlex.quote(_INSPECT)


def params(marker: dict) -> dict:
    return {"runtime_layout": 2, "runtime_owner": marker["owner"],
            "gre_key": marker.get("gre_key", 0), "exit_ip": marker.get("exit_ip", "")}


def guard(runtime: dict | None, cid: int, transport: str, options: dict) -> str:
    # Check the snapshot again with the remote operation lock held. A detached
    # installer can have changed the entry between the HTTP preview and apply.
    expected = json.dumps(runtime, sort_keys=True, separators=(",", ":"))
    checks = ("ACTUAL=$(\n" + INSPECT + "\n) || exit 73\n"
            + f'[ "$ACTUAL" = {shlex.quote(expected)} ] || exit 73\n'
            + cascade_exit.entry_preflight(cid, transport, options)
            + (cascade_awg.preflight_command(cid) if runtime and transport == "awg" else ""))
    if runtime is None:
        checks += cascade.verify_no_entry_gateway()
    return checks


def creation_guard(transport: str, options: dict) -> str:
    # Check before installing on the new exit, even for transports without
    # an entry-side AWG preflight. The detached installer checks again.
    return ("ACTUAL=$(\n" + INSPECT + "\n) || exit 73\n"
            + 'if [ "$ACTUAL" != null ]; then echo CASCADE_ENTRY_RECOVERY_REQUIRED; exit 73; fi\n'
            + cascade_exit.entry_preflight(1, transport, options)
            + cascade.verify_no_entry_gateway())


def cleanup(runtime: dict | None, cid: int, transport: str, options: dict) -> str:
    if runtime is None:
        return "echo CASCADE_REMOVED=yes\n"
    return ("echo CASCADE_RECOVERY_CLEANUP_STARTED\n"
            + cascade.build_remove_entry(transport, cid, options, recover=True)
            + (cascade.ufw_cleanup(options.get("exit_ip", ""), None) if transport == "gre" else ""))
