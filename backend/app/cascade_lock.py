"""A detached cascade installer outlives the panel's in-memory node locks."""

import shlex

BASE = "/lib65/scripts/acontrol-cascade-operation-locks"
OPERATION_FAILED = "cascade operation failed"


def _program(cascade_id: int, *, mode: str = "check", owner: str = "",
             generation: str = "", base: str = BASE,
             recovery_row: tuple[int, str] | None = None, guard: str = "") -> str:
    if not 0 < cascade_id <= 2147483647 or recovery_row and not 0 < recovery_row[0] <= 2147483647:
        raise ValueError("Invalid cascade id")
    if mode not in ("check", "arm", "run", "remove", "edit", "recover"):
        raise ValueError("Invalid cascade operation")
    for value in (owner, generation, recovery_row[1] if recovery_row else ""):
        if value and (len(value) != 32 or any(c not in "0123456789abcdef" for c in value)):
            raise ValueError("Invalid cascade operation owner")
    if mode not in ("check", "edit") and not owner or mode in ("arm", "run") and not generation:
        raise ValueError("Cascade operation is not armed")
    return f'''
import fcntl,json,os,pathlib,stat,subprocess,sys
directory=pathlib.Path({base!r})
if directory.is_symlink():sys.exit(73)
directory.mkdir(mode=0o700,parents=True,exist_ok=True)
meta=directory.stat()
if meta.st_uid!=os.geteuid() or meta.st_mode & 0o077:sys.exit(73)
def locked(identifier):
 fd=os.open(directory/str(identifier),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 meta=os.fstat(fd)
 if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.geteuid() or meta.st_mode & 0o077:sys.exit(73)
 try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:
  print('CASCADE_OPERATION_BUSY',flush=True);sys.exit(75)
 path=directory/(str(identifier)+'.json');state=None
 if path.exists() or path.is_symlink():
  if path.is_symlink():sys.exit(73)
  meta=path.stat()
  if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.geteuid() or meta.st_mode & 0o077 or meta.st_size>4096:sys.exit(73)
  state=json.loads(path.read_text())
  if not isinstance(state,dict) or not state.get('owner'):sys.exit(73)
 return fd,path,state
mode={mode!r};owner={owner!r};generation={generation!r}
cid={cascade_id};row={recovery_row!r}
fd,path,state=locked(cid)
if mode!='recover' and state and owner and state.get('owner')!=owner:
  if state.get('revoked') is not True:sys.exit(73)
  # SQLite can reuse an ID. A different owner has not armed this node yet.
  # Leave the old tombstone and any foreign runtime alone on removal.
  if mode=='remove':
   print('CASCADE_REMOVED=yes',flush=True);sys.exit(0)
  if mode not in ('check','arm'):sys.exit(73)
def save(path,value):
 temporary=path.with_suffix('.tmp')
 out=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
 with os.fdopen(out,'w') as stream:json.dump(value,stream)
 os.replace(temporary,path)
if mode=='check':
 print('CASCADE_OPERATION_FREE',flush=True)
elif mode=='arm':
 save(path,{{'owner':owner,'generation':generation,'revoked':False}})
 print('CASCADE_OPERATION_ARMED',flush=True)
else:
 if mode=='recover':
  allowed={{owner}}
  if row and row[0]==cid:allowed.add(row[1])
  if state and state.get('owner') not in allowed and state.get('revoked') is not True:sys.exit(73)
  if row and row[0]!=cid:
   other_fd,other_path,other_state=locked(row[0])
   if other_state and other_state.get('owner')!=row[1] and other_state.get('revoked') is not True:sys.exit(73)
  verified=subprocess.run(['bash','-c',{guard!r}],stdin=subprocess.DEVNULL,timeout=45)
  if verified.returncode:sys.exit(verified.returncode)
  if row and row[0]!=cid:
   save(other_path,{{'owner':row[1],'generation':None,'revoked':True}})
   os.set_inheritable(other_fd,True)
  save(path,{{'owner':owner,'generation':None,'revoked':True}})
 elif mode=='remove':save(path,{{'owner':owner,'generation':None,'revoked':True}})
 elif mode=='edit':
  if owner and (not state or state.get('revoked') is not False):sys.exit(73)
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


def wrap(cascade_id: int, script: str, owner: str, *, generation: str = "", remove: bool = False, edit: bool = False) -> str:
    program = _program(cascade_id, mode="edit" if edit else "remove" if remove else "run", owner=owner, generation=generation)
    return _wrap(program, script)


def recover(cascade_id: int, script: str, owner: str, guard: str,
            row: tuple[int, str] | None = None) -> str:
    return _wrap(_program(cascade_id, mode="recover", owner=owner, recovery_row=row, guard=guard), script)


def _wrap(program: str, script: str) -> str:
    delimiter = "AC_CASCADE_OPERATION_PAYLOAD"
    while delimiter in script:
        delimiter += "_"
    # The generated configuration travels through stdin, never Python argv.
    return ("sudo -n python3 -c " + shlex.quote(program) + " <<'" + delimiter + "'\n"
            + script + "\n" + delimiter + "\n"
            "CASCADE_RC=$?\n"
            'if [ "$CASCADE_RC" -eq 75 ]; then echo CASCADE_OPERATION_BUSY; '
            'echo "DEPLOY_ERROR: cascade operation is still running on the node"; '
            f'elif [ "$CASCADE_RC" -ne 0 ]; then echo "DEPLOY_ERROR: {OPERATION_FAILED}"; fi\n'
            'exit "$CASCADE_RC"\n')
