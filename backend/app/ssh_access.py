"""Explicit, scoped SSH preparation with a durable journal and a second connection."""
import asyncio
import ipaddress
import json
import hashlib
import re
import time
import uuid
from contextlib import asynccontextmanager
from functools import wraps

import asyncssh
from fastapi import HTTPException
from sqlalchemy import select

from app import audit, bulk_issue_state, nodelock, ssh_firewall, ssh_policy, sshops
from app.models import Server, SshAccessChange
from app.sshkeys import ensure_jump_key, ensure_panel_key, jump_key_path, jump_username, key_paths

ACCESS_FIELDS = ("ssh_jump_server_id", "ssh_source_mode", "ssh_source_ips", "ssh_firewall_mode")
ACTIVE = ("applying", "finalizing")
# "abandoned": the owner closed a journal whose node can no longer be reached.
TERMINAL = ("preview", "done", "rolledback", "abandoned")
FIREWALL_LEFT = ("Разрешения firewall для новых источников SSH остались на сервере, "
                 "хотя настройка доступа отменена: {sources}. Уберите их вручную, если они не нужны")


class _RemoteRolledBack(Exception):
    pass


def serialized(handler):
    @wraps(handler)
    async def wrapped(*args, **kwargs):
        async with nodelock.hold("ssh-access", 0):
            return await handler(*args, **kwargs)
    return wrapped


async def require_idle(session, server_id, *, deleting=False):
    # Deleting a node may drop its own unconfirmed stage. In "applying" the
    # saved policy is still the old one and the node-side watchdog undoes the
    # stage, so a node destroyed mid-change cannot block the panel forever.
    own = ("finalizing",) if deleting else ACTIVE
    if await session.scalar(select(SshAccessChange.id).where(SshAccessChange.server_id == server_id, SshAccessChange.phase.in_(own)).limit(1)):
        raise HTTPException(409, "Сначала завершите восстановление незавершенной настройки SSH")
    for row in await session.scalars(select(SshAccessChange).where(SshAccessChange.phase.in_(ACTIVE))):
        if any(row.payload.get(part, {}).get('ssh_jump_server_id') == server_id for part in ('old', 'proposed')):
            raise HTTPException(409, "Сервер участвует в незавершенной настройке промежуточного SSH-доступа")


def snapshot(server):
    return {**ssh_policy.values(server), "id": server.id}


async def candidate(session, server, fields):
    node = Server(**{**snapshot(server), **fields})
    if node.ssh_jump_server_id:
        jump = await session.get(Server, node.ssh_jump_server_id)
        if jump is None or jump.id == node.id or jump.ssh_jump_server_id:
            raise HTTPException(409, "Промежуточная SSH-нода должна существовать и подключаться напрямую")
        if node.id is not None and await session.scalar(select(Server.id).where(Server.ssh_jump_server_id == node.id).limit(1)):
            raise HTTPException(409, "Этот сервер уже служит промежуточной нодой. Цепочки SSH не поддерживаются")
        node.ssh_jump_server = jump
    if node.ssh_source_mode == "custom" and not node.ssh_source_ips:
        raise HTTPException(422, "Укажите разрешенные источники SSH")
    return node


def options(addresses):
    return ('from="' + ','.join(addresses) + '",' if addresses else '') + "restrict"


def _identity(public_key):
    parts = public_key.split()
    if len(parts) < 2 or not parts[0].startswith("ssh-") or not re.fullmatch(r"[A-Za-z0-9+/=]+", parts[1]):
        raise ValueError("Некорректный SSH-ключ")
    return parts[1]


def write_key(public_key, key_options, *, transaction=None, operation="set"):
    """Only our key identity changes; unrelated lines survive set and rollback.

    A staged key retains the original authorization until a second connection
    succeeds. A detached watchdog rolls back even if the panel process dies.
    Backups and state are private data, never executable server-side files.
    """
    blob = _identity(public_key)
    line = key_options + " " + public_key
    if transaction is not None and not re.fullmatch(r"[a-f0-9]{32}", transaction):
        raise ValueError("Некорректный идентификатор SSH-операции")
    token = transaction or "setup"
    # Parse the actual key field, respecting spaces in quoted options. A key
    # blob mentioned in another administrator's comment is not our identity.
    selector = r'''function identity(line, i,c,q,esc,stop,first,rest,a) {
      sub(/^[ \t]+/, "", line); if(line ~ /^#/ || line == "") return ""
      q=0; esc=0; stop=length(line)+1
      for(i=1;i<=length(line);i++) {
        c=substr(line,i,1)
        if(esc) { esc=0; continue }
        if(c=="\\") { esc=1; continue }
        if(c=="\"") { q=!q; continue }
        if(!q && c ~ /[ \t]/) { stop=i; break }
      }
      first=substr(line,1,stop-1); rest=substr(line,stop+1); sub(/^[ \t]+/,"",rest)
      split(rest,a,/[ \t]+/)
      if(first ~ /^(ssh-|ecdsa-|sk-)/) return first ":" a[1]
      return a[1] ":" a[2]
    }
    { mine=(identity($0)==want); if(mine==selected) print }'''
    awk = f"awk -v want={sshops._sh_quote(public_key.split()[0] + ':' + blob)} "
    strip = awk + '-v selected=0 ' + sshops._sh_quote(selector)
    own = awk + '-v selected=1 ' + sshops._sh_quote(selector)
    lock = '''exec 9>"$LOCK"
flock -w 5 9 || { echo 'Другая операция меняет SSH-ключ'; exit 1; }
'''
    rollback = lock + f'''
[ -f "$BACKUP" ] || exit 1
[ "$(cat "$DIR/.acontrol-current" 2>/dev/null)" = '{token}' ] || exit 1
[ ! -e "$STATE.rolledback" ] || {{ echo ACONTROL_KEY_ROLLEDBACK; exit 0; }}
[ ! -e "$STATE.commit" ] || exit 0
T=$(mktemp "$DIR/.acontrol-key.XXXXXX") || exit 1
{{ {strip} "$AK"; {own} "$BACKUP"; }} > "$T" && chmod 600 "$T" && mv -f "$T" "$AK" || exit 1
touch "$STATE.rolledback"
'''
    header = f'''set -eu
umask 077
command -v flock >/dev/null 2>&1 || {{ echo 'Требуется flock для безопасного изменения SSH'; exit 1; }}
DIR="$HOME/.ssh"
[ ! -L "$DIR" ] || {{ echo 'Символические ссылки SSH не поддерживаются'; exit 1; }}
if [ -e "$DIR" ]; then [ -d "$DIR" ] && [ "$(stat -c %u "$DIR")" = "$(id -u)" ] || exit 1; fi
mkdir -p "$DIR" && chmod 700 "$DIR"
AK="$DIR/authorized_keys"
[ ! -L "$AK" ] || exit 1
if [ -e "$AK" ]; then [ -f "$AK" ] && [ "$(stat -c %u "$AK")" = "$(id -u)" ] && [ "$(stat -c %h "$AK")" = 1 ] || exit 1; fi
touch "$AK" && chmod 600 "$AK"
BLOB={sshops._sh_quote(blob)}
LINE={sshops._sh_quote(line)}
STATE="$DIR/.acontrol-{token}"
BACKUP="$STATE.backup"
[ ! -L "$BACKUP" ] && [ ! -L "$DIR/.acontrol-current" ] || exit 1
LOCK="$DIR/.acontrol-key.lock"
[ ! -L "$LOCK" ] || exit 1
if [ -e "$LOCK" ]; then [ -f "$LOCK" ] && [ "$(stat -c %u "$LOCK")" = "$(id -u)" ] && [ "$(stat -c %h "$LOCK")" = 1 ] || exit 1; fi
'''
    if operation == "rollback":
        # A stage that never made its backup never changed authorized_keys,
        # whatever stopped it (no flock, unsafe layout, lost connection).
        # Report that before the layout checks, or the journal can never be
        # closed. A stage still running right now arms its own watchdog.
        untouched = f'''set -eu
S="$HOME/.ssh/.acontrol-{token}"
[ -e "$S.backup" ] || [ -e "$S.commit" ] || [ -e "$S.rolledback" ] || {{ echo ACONTROL_KEY_ROLLEDBACK; exit 0; }}
'''
        return untouched + header + rollback.replace('[ ! -e "$STATE.commit" ] || exit 0\n', '') + 'echo ACONTROL_KEY_ROLLEDBACK\n'
    if operation == "watchdog":
        return header + rollback
    if operation == "status":
        return header + lock + f'''[ "$(cat "$DIR/.acontrol-current" 2>/dev/null)" = '{token}' ] || exit 1
if [ -e "$STATE.rolledback" ]; then echo ACONTROL_KEY_STATE_ROLLEDBACK
elif [ -e "$STATE.commit" ]; then echo ACONTROL_KEY_STATE_COMMITTED
elif [ -f "$BACKUP" ]; then echo ACONTROL_KEY_STATE_STAGED
else exit 1; fi
'''
    if operation == "commit":
        return header + lock + f'''[ -f "$BACKUP" ] && [ ! -e "$STATE.rolledback" ] || exit 1
[ "$(cat "$DIR/.acontrol-current" 2>/dev/null)" = '{token}' ] || exit 1
T=$(mktemp "$DIR/.acontrol-key.XXXXXX")
{{ {strip} "$AK"; printf '%s\\n' "$LINE"; }} > "$T"
chmod 600 "$T" && mv -f "$T" "$AK"
touch "$STATE.commit"
echo ACONTROL_KEY_COMMITTED
'''
    if operation == "revoke":
        return header + lock + f'''BEFORE=$(sha256sum "$AK" | cut -d' ' -f1)
T=$(mktemp "$DIR/.acontrol-key.XXXXXX")
{strip} "$AK" > "$T"
[ "$(sha256sum "$AK" | cut -d' ' -f1)" = "$BEFORE" ] || {{ rm -f "$T"; exit 1; }}
chmod 600 "$T" && mv -f "$T" "$AK"
echo ACONTROL_JUMP_REVOKED
'''
    script = header + lock
    script += f'''printf '%s\\n' '{token}' > "$DIR/.acontrol-current"
'''
    if transaction:
        # A retry must not replace the only copy of the original authorization.
        guard = header + f'''i=0
while [ "$i" -lt 120 ]; do
  [ ! -e "$STATE.commit" ] && [ ! -e "$STATE.rolledback" ] || exit 0
  [ "$(cat "$DIR/.acontrol-current" 2>/dev/null)" = '{token}' ] || exit 0
  sleep 1; i=$((i + 1))
done
''' + rollback
        script += f'''[ ! -e "$BACKUP" ] && [ ! -e "$STATE.rolledback" ] || exit 1
cp -p "$AK" "$BACKUP" && chmod 600 "$BACKUP"
nohup sh -c {sshops._sh_quote(guard)} 9>&- </dev/null >/dev/null 2>&1 &
'''
    script += '''T=$(mktemp "$DIR/.acontrol-key.XXXXXX")
'''
    script += ('''awk '{print}' "$AK" > "$T"\n''' if transaction else f'{strip} "$AK" > "$T"\n')
    script += '''printf '%s\n' "$LINE" >> "$T"
chmod 600 "$T" && mv -f "$T" "$AK"
echo ACONTROL_KEY_READY
'''
    return script


async def _run(conn, command, marker):
    result = await conn.run(command, check=False, timeout=30)
    if result.exit_status != 0 or marker not in (result.stdout or ""):
        raise RuntimeError("SSH-подготовка не подтверждена: " + (result.stderr or result.stdout or "нет ответа")[:600])
    return result


def jump_script(public_key, server, addresses, user):
    # A dedicated no-sudo account and separate key for a single destination.
    host = server.host
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", host) or host.startswith("-"):
        raise ValueError("Адрес цели SSH должен быть IP или DNS-именем")
    destination = f"[{host}]:{server.ssh_port}" if ":" in host else f"{host}:{server.ssh_port}"
    owner = hashlib.sha256(public_key.split()[1].encode()).hexdigest()
    if not re.fullmatch(r"acj[a-f0-9]{24}", user):
        raise ValueError("Некорректный пользователь SSH-перехода")
    keyopts = options(addresses) + f',port-forwarding,permitopen="{destination}",command="/bin/false"'
    writer = write_key(public_key, keyopts)
    config = f'''# acontrol-jump-owner {owner}
Match User {user}
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding local
    AllowStreamLocalForwarding no
    PermitOpen {destination}
    PermitListen none
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
Match all
'''
    probe_address = addresses[0].split('/')[0] if addresses else "127.0.0.1"
    # Only a known managed Include and a reloadable systemd SSH service are
    # supported. Never bypass a pre-existing ban on TCP forwarding.
    config_setup = f'''command -v sshd >/dev/null 2>&1 || exit 1
grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\\*\\.conf([[:space:]]|$)' /etc/ssh/sshd_config || {{ echo 'SSH Include не поддерживается'; exit 1; }}
sshd -t
SERVICE=""
for s in ssh sshd; do
  if systemctl is-active --quiet "$s" && [ "$(systemctl show "$s" -p CanReload --value)" = yes ]; then SERVICE="$s"; break; fi
done
[ -n "$SERVICE" ] || {{ echo 'SSH reload не поддерживается'; exit 1; }}
CONF='/etc/ssh/sshd_config.d/00-{user}.conf'
[ ! -L "$CONF" ] || exit 1
if [ ! -e "$CONF" ]; then
  BEFORE=$(sshd -T -C 'user={user},addr={probe_address},host=localhost')
  printf '%s\\n' "$BEFORE" | grep -qx 'disableforwarding no' || {{ echo 'DisableForwarding запрещает переход'; exit 1; }}
  printf '%s\\n' "$BEFORE" | grep -Eq '^allowtcpforwarding (yes|all|local)$' || {{ echo 'AllowTcpForwarding запрещает переход'; exit 1; }}
fi
'''
    config_apply = f'''EXPECTED={sshops._sh_quote(config)}
NEW_HASH=$(printf '%s' "$EXPECTED" | sha256sum | cut -d' ' -f1)
HASH_FILE="$STATE_DIR/sshd-sha"
OLD_EXISTS=0
if [ -e "$CONF" ]; then
  [ -f "$HASH_FILE" ] && [ "$(sha256sum "$CONF" | cut -d' ' -f1)" = "$(cat "$HASH_FILE")" ] || {{ echo 'SSH drop-in изменен вне панели'; exit 1; }}
  OLD_EXISTS=1
  cp -p "$CONF" "$STATE_DIR/sshd.backup"
fi
rollback_config() {{
  if [ -e "$CONF" ] && [ "$(sha256sum "$CONF" | cut -d' ' -f1)" = "$NEW_HASH" ]; then
    if [ "$OLD_EXISTS" = 1 ]; then cp -p "$STATE_DIR/sshd.backup" "$CONF"; else rm -f "$CONF"; fi
    sshd -t && systemctl reload "$SERVICE"
  fi
}}
trap rollback_config EXIT HUP INT TERM
T=$(mktemp /etc/ssh/sshd_config.d/.acontrol.XXXXXX)
printf '%s' "$EXPECTED" > "$T"
chmod 600 "$T" && mv -f "$T" "$CONF"
sshd -t
EFFECTIVE=$(sshd -T -C 'user={user},addr={probe_address},host=localhost')
for expected in 'disableforwarding no' 'allowtcpforwarding local' 'allowstreamlocalforwarding no' 'permitlisten none' 'allowagentforwarding no' 'x11forwarding no' 'permittty no' 'authenticationmethods publickey' 'passwordauthentication no'; do
  printf '%s\\n' "$EFFECTIVE" | grep -qx "$expected" || {{ echo "Неподдерживаемая SSH-политика: $expected"; exit 1; }}
done
printf '%s\\n' "$EFFECTIVE" | grep -Fqx 'permitopen {destination}' || exit 1
systemctl reload "$SERVICE"
printf '%s\\n' "$NEW_HASH" > "$HASH_FILE"
chmod 600 "$HASH_FILE"
trap - EXIT HUP INT TERM
'''
    return f'''set -eu
if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO="sudo -n"; fi
$SUDO sh -c {sshops._sh_quote(f'''set -eu
{config_setup}
for path in /lib65 /lib65/acontrol-ssh; do
  [ ! -L "$path" ] || exit 1
  if [ -e "$path" ]; then [ -d "$path" ] && [ "$(stat -c %u "$path")" = 0 ] || exit 1; else mkdir "$path"; fi
done
chmod 700 /lib65/acontrol-ssh
STATE_DIR='/lib65/acontrol-ssh/{user}'
[ ! -L "$STATE_DIR" ] || exit 1
if [ -e "$STATE_DIR" ]; then [ -d "$STATE_DIR" ] && [ "$(stat -c %u "$STATE_DIR")" = 0 ] || exit 1; else mkdir -m 700 "$STATE_DIR"; fi
if ! id '{user}' >/dev/null 2>&1; then
  printf '%s\\n' '{owner}' > "$STATE_DIR/owner"
  chmod 600 "$STATE_DIR/owner"
  useradd -m -s /bin/sh '{user}'
  # Unlock public-key login without setting a usable password.
  usermod -p '*' '{user}'
fi
[ "$(id -u '{user}')" -ne 0 ] || exit 1
[ ! -f '/etc/sudoers.d/{user}' ] || exit 1
HOME_DIR=$(getent passwd '{user}' | cut -d: -f6)
[ ! -L "$HOME_DIR" ] && [ -d "$HOME_DIR" ] && [ "$(stat -c %u "$HOME_DIR")" = "$(id -u '{user}')" ] || exit 1
[ ! -L "$STATE_DIR/owner" ] && [ "$(stat -c %u "$STATE_DIR/owner")" = 0 ] || exit 1
[ "$(cat "$STATE_DIR/owner" 2>/dev/null)" = '{owner}' ] || exit 1
[ "$(id -nG '{user}')" = '{user}' ] || exit 1
{config_apply}
su -s /bin/sh '{user}' -c {sshops._sh_quote(writer)}
''')}
echo ACONTROL_JUMP_READY
'''


async def prepare_jump(session, node, settings):
    if not node.ssh_jump_server_id:
        return
    jump = node.ssh_jump_server
    key, _ = key_paths(settings.data_dir)
    public = ensure_jump_key(key, node.id)
    async with sshops.connect(jump.host, jump.ssh_port, jump.ssh_user, key, settings.ssh_connect_timeout) as conn:
        observed = await conn.run("printf '%s\\n' \"${SSH_CONNECTION%% *}\"", check=True, timeout=10)
        # The forwarding key is narrower than the management key policy, even
        # when the jump card explicitly permits management from any source.
        addresses = [str(ipaddress.ip_address(observed.stdout.strip()))]
        await _run(conn, jump_script(public, node, addresses, jump_username(key, node.id)), "ACONTROL_JUMP_READY")


def revoke_jump_script(public, user):
    """Remove only this panel's exact identity from an unchanged owned role."""
    owner = hashlib.sha256(_identity(public).encode()).hexdigest()
    if not re.fullmatch(r"acj[a-f0-9]{24}", user):
        raise ValueError("Некорректный пользователь SSH-перехода")
    writer = write_key(public, "restrict", operation="revoke")
    return f'''set -eu
if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO="sudo -n"; fi
$SUDO sh -c {sshops._sh_quote(f'''set -eu
for path in /lib65 /lib65/acontrol-ssh /lib65/acontrol-ssh/{user}; do
  [ ! -L "$path" ] && [ -d "$path" ] && [ "$(stat -c %u "$path")" = 0 ] || exit 1
done
STATE_DIR='/lib65/acontrol-ssh/{user}'
[ "$(stat -c %a /lib65/acontrol-ssh)" = 700 ] && [ "$(stat -c %a "$STATE_DIR")" = 700 ] || exit 1
for path in "$STATE_DIR/owner" "$STATE_DIR/sshd-sha"; do
  [ ! -L "$path" ] && [ -f "$path" ] && [ "$(stat -c %u "$path")" = 0 ] && [ "$(stat -c %h "$path")" = 1 ] || exit 1
done
[ "$(cat "$STATE_DIR/owner")" = '{owner}' ] || exit 1
CONF='/etc/ssh/sshd_config.d/00-{user}.conf'
[ ! -L "$CONF" ] && [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] || exit 1
[ "$(sha256sum "$CONF" | cut -d' ' -f1)" = "$(cat "$STATE_DIR/sshd-sha")" ] || exit 1
HOME_DIR=$(getent passwd '{user}' | cut -d: -f6)
[ "$(id -u '{user}')" -ne 0 ] && [ "$(id -nG '{user}')" = '{user}' ] || exit 1
[ ! -L "$HOME_DIR" ] && [ -d "$HOME_DIR" ] && [ "$(stat -c %u "$HOME_DIR")" = "$(id -u '{user}')" ] || exit 1
su -s /bin/sh '{user}' -c {sshops._sh_quote(writer)}
''')}
'''


async def retire_jump(node, settings):
    """Best effort: a failed retirement must not undo a working replacement."""
    if not node.ssh_jump_server_id:
        return ""
    key, _ = key_paths(settings.data_dir)
    path = jump_key_path(key, node.id)
    if not path.exists():
        return "Старый промежуточный доступ не отозван: локальный ключ отсутствует, прежняя идентичность неизвестна"
    try:
        public = asyncssh.read_private_key(path).export_public_key().decode().strip()
        jump = node.ssh_jump_server
        if jump is None:
            raise RuntimeError("промежуточная нода отсутствует")
        async with sshops.connect(jump.host, jump.ssh_port, jump.ssh_user, key, settings.ssh_connect_timeout) as conn:
            await _run(conn, revoke_jump_script(public, jump_username(key, node.id)), "ACONTROL_JUMP_REVOKED")
    except Exception as exc:
        return f"Старый промежуточный доступ не отозван: {str(exc)[:600] or type(exc).__name__}"
    return ""


async def retire_previous(session, server, change, settings):
    old_id = change.payload["old"]["ssh_jump_server_id"]
    if not old_id or old_id == server.ssh_jump_server_id:
        return
    try:
        old = await candidate(session, server, {f: change.payload["old"][f] for f in ACCESS_FIELDS})
        warning = await retire_jump(old, settings)
    except Exception as exc:
        warning = f"Старый промежуточный доступ не отозван: {str(exc)[:600] or type(exc).__name__}"
    change.payload = {**change.payload, "retired_jump": "warning" if warning else "revoked", "retired_jump_warning": warning}
    if warning:
        try:
            info = json.loads(server.last_check_info or "{}")
        except (ValueError, TypeError):
            info = {}
        if not isinstance(info, dict):
            info = {}
        server.last_check_info = json.dumps({**info, "ssh_access_warning": warning}, ensure_ascii=False)
    await audit.record(session, "", "ssh_jump_retire", server.name, warning or "Старый промежуточный ключ отозван")


def keyopts_sources(node, settings) -> list[str]:
    try:
        return ssh_policy.sources(node, settings.panel_ip)
    except ValueError:
        return []


def _warn(server, warning: str) -> None:
    try:
        info = json.loads(server.last_check_info or "{}")
    except (ValueError, TypeError):
        info = {}
    if not isinstance(info, dict):
        info = {}
    server.last_check_info = json.dumps({**info, "ssh_access_warning": warning}, ensure_ascii=False)


@asynccontextmanager
async def connection(node, settings, **extra):
    key, _ = key_paths(settings.data_dir)
    async with sshops.connect(node.host, node.ssh_port, node.ssh_user, key,
                              settings.ssh_connect_timeout, **sshops.route_options(node), **extra) as conn:
        yield conn


async def verify(node, settings):
    async with connection(node, settings) as conn:
        result = await conn.run("printf 'SOURCE=%s\\n' \"${SSH_CONNECTION%% *}\"", check=True, timeout=10)
        source = result.stdout.strip().removeprefix("SOURCE=")
        actual = ipaddress.ip_address(source)
        allowed = ssh_policy.sources(node, settings.panel_ip)
        if allowed and not any(actual in ipaddress.ip_network(item, strict=False) for item in allowed):
            raise RuntimeError(f"Цель видит источник SSH {source}, ожидается {', '.join(allowed)}. Укажите его в расширенных настройках")
        return source


@bulk_issue_state.guard()
@serialized
async def preview(session, server, fields, settings):
    await require_idle(session, server.id)
    proposed = await candidate(session, server, fields)
    try:
        addresses = ssh_policy.sources(proposed, settings.panel_ip)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    change = SshAccessChange(id=uuid.uuid4().hex, server_id=server.id, phase="preview", payload={
        "old": snapshot(server), "proposed": snapshot(proposed), "created": time.time(),
        "jump_endpoint": snapshot(proposed.ssh_jump_server) if proposed.ssh_jump_server_id else None,
    })
    session.add(change)
    await session.commit()
    return {"token": change.id, "sources": addresses, "unrestricted": not addresses,
            "firewall": proposed.ssh_firewall_mode, "jump_server_id": proposed.ssh_jump_server_id,
            "actions": ["Резервная копия authorized_keys", "Изменение только ключа панели", "Проверка отдельным SSH-соединением", "Автооткат ключа через 120 секунд при сбое"],
            "jump_user": "Отдельный пользователь только для этой панели и цели" if proposed.ssh_jump_server_id else None}


@bulk_issue_state.guard()
async def apply(session, server, token, settings):
    async with nodelock.hold("ssh-access", 0):
        change = await session.get(SshAccessChange, token)
        if change is None or change.server_id != server.id:
            raise HTTPException(404, "Предпросмотр SSH не найден")
        if change.phase == "done":
            return server  # Successful requests are safe to retry.
        await require_idle(session, server.id)
        if change.phase != "preview" or time.time() - change.payload["created"] > 600:
            raise HTTPException(409, "Предпросмотр устарел. Создайте новый")
        if snapshot(server) != change.payload["old"]:
            raise HTTPException(409, "Настройки сервера изменились. Повторите предпросмотр")
        proposed = await candidate(session, server, {f: change.payload["proposed"][f] for f in ACCESS_FIELDS})
        if (snapshot(proposed.ssh_jump_server) if proposed.ssh_jump_server_id else None) != change.payload["jump_endpoint"]:
            raise HTTPException(409, "Промежуточная нода изменилась. Повторите предпросмотр")
        public = ensure_panel_key(settings.data_dir)
        keyopts = options(ssh_policy.sources(proposed, settings.panel_ip))
        change.phase = "applying"
        await session.commit()
        mutation_started = False
        rollback_confirmed = False
        try:
            async with connection(server, settings) as old_conn:
                await prepare_jump(session, proposed, settings)
                mutation_started = True
                try:
                    # A failed or unanswered stage is rolled back right away
                    # while the original connection still works.
                    await _run(old_conn, write_key(public, keyopts, transaction=token), "ACONTROL_KEY_READY")
                    # Add-only firewall changes cannot revoke existing SSH access.
                    if proposed.ssh_firewall_mode == "add":
                        await _run(old_conn, ssh_firewall.script(token, ssh_policy.sources(proposed, settings.panel_ip), proposed.ssh_port), "ACONTROL_FIREWALL_READY")
                    source = await verify(proposed, settings)
                    for field in ACCESS_FIELDS:
                        setattr(server, field, getattr(proposed, field))
                    change.phase = "finalizing"
                    change.payload = {**change.payload, "source": source}
                    await session.commit()
                    # The add-only allow is committed first: keeping it is
                    # harmless, while a committed key without its allow could
                    # lock the panel out once the firewall watchdog fires.
                    if proposed.ssh_firewall_mode == "add":
                        await _run(old_conn, ssh_firewall.script(token, [], proposed.ssh_port, "commit"), "ACONTROL_FIREWALL_COMMITTED")
                    await _run(old_conn, write_key(public, keyopts, transaction=token, operation="commit"), "ACONTROL_KEY_COMMITTED")
                    # Keep the durable finalizing phase until the best-effort
                    # retirement is recorded; restart recovery can finish it.
                except BaseException:
                    if change.phase != "finalizing":
                        await _run(old_conn, write_key(public, keyopts, transaction=token, operation="rollback"), "ACONTROL_KEY_ROLLEDBACK")
                        if proposed.ssh_firewall_mode == "add":
                            await _run(old_conn, ssh_firewall.script(token, [], proposed.ssh_port, "rollback"), "ACONTROL_FIREWALL_ROLLEDBACK")
                        rollback_confirmed = True
                    raise
        except BaseException as exc:
            await session.rollback()
            # refresh expired ORM state before reading the durable payload
            await session.refresh(change)
            await session.refresh(server)
            if change.phase != "finalizing":
                for field in ACCESS_FIELDS:
                    setattr(server, field, change.payload["old"][field])
            if rollback_confirmed or not mutation_started:
                change.phase = "rolledback"
            await session.commit()
            if isinstance(exc, asyncio.CancelledError):
                raise
            state = "откат ключа подтвержден" if locals().get("rollback_confirmed", False) else "откат не подтвержден, сохранен журнал восстановления"
            raise HTTPException(409, f"Настройка SSH не завершена ({state}): {exc}") from exc
        await retire_previous(session, server, change, settings)
        change.phase = "done"
        await session.commit()
        await session.refresh(server)
        return server


@bulk_issue_state.guard()
@serialized
async def recover(session, settings, server_id=None):
    """Run before background jobs: recover a process crash, never migrate nodes."""
    changes = list(await session.scalars(select(SshAccessChange).where(SshAccessChange.phase.in_(ACTIVE))))
    for change in changes:
        if server_id is not None and change.server_id != server_id:
            continue
        server = await session.get(Server, change.server_id)
        if server is None:
            continue
        try:
            old = await candidate(session, server, {f: change.payload["old"][f] for f in ACCESS_FIELDS})
            proposed = await candidate(session, server, {f: change.payload["proposed"][f] for f in ACCESS_FIELDS})
        except (HTTPException, ValueError, KeyError):
            continue
        public = ensure_panel_key(settings.data_dir)
        keyopts = options(ssh_policy.sources(proposed, settings.panel_ip))
        # In finalizing, either the staged or original key can still connect.
        restored = False
        for target in (old, proposed):
            firewall_kept = False
            try:
                async with connection(target, settings) as conn:
                    if change.phase == "finalizing":
                        try:
                            key_state = (await _run(conn, write_key(public, keyopts, transaction=change.id, operation="status"), "ACONTROL_KEY_STATE_")).stdout.strip()
                            firewall_state = ""
                            if proposed.ssh_firewall_mode == "add":
                                firewall_state = (await _run(conn, ssh_firewall.script(change.id, [], proposed.ssh_port, "status"), "ACONTROL_FIREWALL_STATE_")).stdout.strip()
                            if (
                                "ROLLEDBACK" in key_state
                                or "ROLLEDBACK" in firewall_state
                                or "ROLLINGBACK" in firewall_state
                            ):
                                if "COMMITTED" in firewall_state:
                                    if "ROLLEDBACK" not in key_state:
                                        continue  # Conflicting proof: preserve the journal.
                                    # The allow is committed first and the key
                                    # watchdog undid the key: keep the add-only
                                    # allow, undo the rest and say so.
                                    firewall_kept = True
                                # A watchdog started rollback for this exact
                                # generation; complete it while it is current.
                                raise _RemoteRolledBack
                            await verify(proposed, settings)
                            if proposed.ssh_firewall_mode == "add":
                                await _run(conn, ssh_firewall.script(change.id, [], proposed.ssh_port, "commit"), "ACONTROL_FIREWALL_COMMITTED")
                            await _run(conn, write_key(public, keyopts, transaction=change.id, operation="commit"), "ACONTROL_KEY_COMMITTED")
                            for field in ACCESS_FIELDS:
                                setattr(server, field, getattr(proposed, field))
                            change.phase = "done"
                            restored = True
                            break
                        except _RemoteRolledBack:
                            pass
                        except Exception:
                            continue  # Lost replies are reconciled, never guessed.
                    await _run(conn, write_key(public, keyopts, transaction=change.id, operation="rollback"), "ACONTROL_KEY_ROLLEDBACK")
                    if proposed.ssh_firewall_mode == "add" and not firewall_kept:
                        await _run(conn, ssh_firewall.script(change.id, [], proposed.ssh_port, "rollback"), "ACONTROL_FIREWALL_ROLLEDBACK")
                    for field in ACCESS_FIELDS:
                        setattr(server, field, getattr(old, field))
                    change.phase = "rolledback"
                    if firewall_kept:
                        # The card's warning lasts until the next check; the
                        # audit log keeps the leftover allow on record.
                        left = ", ".join(keyopts_sources(proposed, settings)) or "-"
                        _warn(server, FIREWALL_LEFT.format(sources=left))
                        await audit.record(session, "", "ssh_access_firewall_left", server.name, left)
                    restored = True
                    break
            except Exception:
                continue
        if not restored:
            # Preserve the journal for an explicit retry; don't pretend recovery succeeded.
            continue
        if change.phase == "done":
            await retire_previous(session, server, change, settings)
        await session.commit()


ABANDONED = ("Незавершенная настройка SSH закрыта без связи с сервером. Состояние ключа панели "
             "и firewall на нем неизвестно: проверьте сервер или удалите его из панели")


async def abandon(session, settings, server, user):
    """Close a journal whose node is gone. Recovery is tried first and wins;
    only what it cannot reach is closed, with the saved policy kept as is."""
    await recover(session, settings, server.id)
    async with nodelock.hold("ssh-access", 0):
        changes = list(await session.scalars(select(SshAccessChange).where(
            SshAccessChange.server_id == server.id, SshAccessChange.phase.in_(ACTIVE))))
        if not changes:
            return False
        for change in changes:
            change.payload = {**change.payload, "abandoned_from": change.phase, "abandoned_at": time.time()}
            change.phase = "abandoned"
        _warn(server, ABANDONED)
        await session.commit()
    await audit.record(session, user, "ssh_access_abandon", server.name,
                       ", ".join(sorted({c.payload["abandoned_from"] for c in changes})))
    return True
