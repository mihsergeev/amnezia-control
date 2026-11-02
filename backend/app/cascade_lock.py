"""A detached cascade installer outlives the panel's in-memory node locks."""

import shlex

BASE = "/lib65/scripts/acontrol-cascade-operation-locks"


def _program(cascade_id: int, *, mode: str = "check", owner: str = "",
             generation: str = "", base: str = BASE) -> str:
    if not 0 < cascade_id <= 2147483647:
        raise ValueError("Invalid cascade id")
    if mode not in ("check", "arm", "run", "remove"):
        raise ValueError("Invalid cascade operation")
    for value in (owner, generation):
        if value and (len(value) != 32 or any(c not in "0123456789abcdef" for c in value)):
            raise ValueError("Invalid cascade operation owner")
    if mode != "check" and not owner or mode in ("arm", "run") and not generation:
        raise ValueError("Cascade operation is not armed")
    return f'''
import fcntl,json,os,pathlib,stat,sys
directory=pathlib.Path({base!r})
if directory.is_symlink():sys.exit(73)
directory.mkdir(mode=0o700,parents=True,exist_ok=True)
meta=directory.stat()
if meta.st_uid!=os.geteuid() or meta.st_mode & 0o077:sys.exit(73)
fd=os.open(directory/{str(cascade_id)!r},os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
meta=os.fstat(fd)
if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.geteuid() or meta.st_mode & 0o077:sys.exit(73)
try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:
 print('CASCADE_OPERATION_BUSY',flush=True);sys.exit(75)
mode={mode!r};owner={owner!r};generation={generation!r}
path=directory/{str(cascade_id) + '.json'!r};state=None
if path.exists() or path.is_symlink():
 if path.is_symlink():sys.exit(73)
 meta=path.stat()
 if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.geteuid() or meta.st_mode & 0o077 or meta.st_size>4096:sys.exit(73)
 state=json.loads(path.read_text())
 if owner and state.get('owner')!=owner and not (mode=='arm' and state.get('revoked') is True):sys.exit(73)
def save(value):
 temporary=path.with_suffix('.tmp')
 out=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
 with os.fdopen(out,'w') as stream:json.dump(value,stream)
 os.replace(temporary,path)
if mode=='check':
 print('CASCADE_OPERATION_FREE',flush=True)
elif mode=='arm':
 save({{'owner':owner,'generation':generation,'revoked':False}})
 print('CASCADE_OPERATION_ARMED',flush=True)
else:
 if mode=='remove':save({{'owner':owner,'generation':None,'revoked':True}})
 elif not state or state.get('revoked') is not False or state.get('owner')!=owner or state.get('generation')!=generation:
  print('CASCADE_OPERATION_SUPERSEDED',flush=True);sys.exit(73)
 # Preserve the same locked inode across exec and all resource-writing children.
 os.set_inheritable(fd,True)
 os.execvp('bash',['bash','-s'])
'''


def check_command(cascade_id: int, owner: str) -> str:
    return "sudo -n python3 -c " + shlex.quote(_program(cascade_id, owner=owner))


def arm_command(cascade_id: int, owner: str, generation: str) -> str:
    return "sudo -n python3 -c " + shlex.quote(_program(cascade_id, mode="arm", owner=owner, generation=generation))


def wrap(cascade_id: int, script: str, owner: str, *, generation: str = "", remove: bool = False) -> str:
    delimiter = "AC_CASCADE_OPERATION_PAYLOAD"
    while delimiter in script:
        delimiter += "_"
    # The generated configuration travels through stdin, never Python argv.
    program = _program(cascade_id, mode="remove" if remove else "run", owner=owner, generation=generation)
    return ("sudo -n python3 -c " + shlex.quote(program) + " <<'" + delimiter + "'\n"
            + script + "\n" + delimiter + "\n"
            "CASCADE_RC=$?\n"
            'if [ "$CASCADE_RC" -eq 75 ]; then echo CASCADE_OPERATION_BUSY; '
            'echo "DEPLOY_ERROR: cascade operation is still running on the node"; '
            'elif [ "$CASCADE_RC" -ne 0 ]; then echo "DEPLOY_ERROR: cascade operation failed"; fi\n'
            'exit "$CASCADE_RC"\n')
