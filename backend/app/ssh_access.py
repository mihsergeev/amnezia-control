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

from app import bulk_issue_state, nodelock, ssh_firewall, ssh_policy, sshops
from app.models import Server, SshAccessChange
from app.sshkeys import ensure_jump_key, ensure_panel_key, jump_username, key_paths

ACCESS_FIELDS = ("ssh_jump_server_id", "ssh_source_mode", "ssh_source_ips", "ssh_firewall_mode")
ACTIVE = ("applying", "finalizing")


def serialized(handler):
    @wraps(handler)
    async def wrapped(*args, **kwargs):
        async with nodelock.hold("ssh-access", 0):
            return await handler(*args, **kwargs)
    return wrapped


async def require_idle(session, server_id):
    if await session.scalar(select(SshAccessChange.id).where(SshAccessChange.server_id == server_id, SshAccessChange.phase.in_(ACTIVE)).limit(1)):
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
    # All awk comparisons use complete key fields, not substring matches.
    strip = "awk -v k=\"$BLOB\" '{ own=0; for(i=1;i<=NF;i++) if($i==k) own=1; if(!own) print }'"
    own = "awk -v k=\"$BLOB\" '{ for(i=1;i<=NF;i++) if($i==k) { print; break } }'"
    rollback = f'''mkdir "$LOCK" 2>/dev/null || exit 1
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT
trap 'exit 1' HUP INT TERM
[ -f "$BACKUP" ] || exit 1
[ ! -e "$STATE.rolledback" ] || {{ echo ACONTROL_KEY_ROLLEDBACK; exit 0; }}
[ ! -e "$STATE.commit" ] || exit 0
[ "$(cat "$DIR/.acontrol-current" 2>/dev/null)" = '{token}' ] || exit 1
T=$(mktemp "$DIR/.acontrol-key.XXXXXX") || exit 1
{{ {strip} "$AK"; {own} "$BACKUP"; }} > "$T" && chmod 600 "$T" && mv -f "$T" "$AK" || exit 1
touch "$STATE.rolledback"
'''
    header = f'''set -eu
umask 077
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
LOCK="$DIR/.acontrol-key-lock"
'''
    if operation == "rollback":
        return header + rollback.replace('[ ! -e "$STATE.commit" ] || exit 0\n', '') + 'echo ACONTROL_KEY_ROLLEDBACK\n'
    if operation == "watchdog":
        return header + rollback
    lock = '''mkdir "$LOCK" 2>/dev/null || { echo 'Другая операция меняет SSH-ключ'; exit 1; }
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT
trap 'exit 1' HUP INT TERM
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
    script = header + lock
    script += f'''printf '%s\\n' '{token}' > "$DIR/.acontrol-current"
'''
    if transaction:
        # A retry must not replace the only copy of the original authorization.
        guard = header + 'sleep 120\n' + rollback
        script += f'''[ ! -e "$BACKUP" ] && [ ! -e "$STATE.rolledback" ] || exit 1
cp -p "$AK" "$BACKUP" && chmod 600 "$BACKUP"
nohup sh -c {sshops._sh_quote(guard)} </dev/null >/dev/null 2>&1 &
'''
    script += '''T=$(mktemp "$DIR/.acontrol-key.XXXXXX")
'''
    script += ('cat "$AK" > "$T"\n' if transaction else f'{strip} "$AK" > "$T"\n')
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
    # The panel->jump source policy is independent from jump->target policy.
    addresses = ssh_policy.sources(jump, settings.panel_ip)
    async with sshops.connect(jump.host, jump.ssh_port, jump.ssh_user, key, settings.ssh_connect_timeout) as conn:
        await _run(conn, jump_script(public, node, addresses, jump_username(key, node.id)), "ACONTROL_JUMP_READY")


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
                await _run(old_conn, write_key(public, keyopts, transaction=token), "ACONTROL_KEY_READY")
                try:
                    # Add-only firewall changes cannot revoke existing SSH access.
                    if proposed.ssh_firewall_mode == "add":
                        await _run(old_conn, ssh_firewall.script(token, ssh_policy.sources(proposed, settings.panel_ip), proposed.ssh_port), "ACONTROL_FIREWALL_READY")
                    source = await verify(proposed, settings)
                    for field in ACCESS_FIELDS:
                        setattr(server, field, getattr(proposed, field))
                    change.phase = "finalizing"
                    change.payload = {**change.payload, "source": source}
                    await session.commit()
                    await _run(old_conn, write_key(public, keyopts, transaction=token, operation="commit"), "ACONTROL_KEY_COMMITTED")
                    if proposed.ssh_firewall_mode == "add":
                        await _run(old_conn, ssh_firewall.script(token, [], proposed.ssh_port, "commit"), "ACONTROL_FIREWALL_COMMITTED")
                    change.phase = "done"
                    await session.commit()
                except BaseException:
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
            for field in ACCESS_FIELDS:
                setattr(server, field, change.payload["old"][field])
            if rollback_confirmed or not mutation_started:
                change.phase = "rolledback"
            await session.commit()
            if isinstance(exc, asyncio.CancelledError):
                raise
            state = "откат ключа подтвержден" if locals().get("rollback_confirmed", False) else "откат не подтвержден, сохранен журнал восстановления"
            raise HTTPException(409, f"Настройка SSH не завершена ({state}): {exc}") from exc
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
            try:
                async with connection(target, settings) as conn:
                    if change.phase == "finalizing":
                        try:
                            await verify(proposed, settings)
                            await _run(conn, write_key(public, keyopts, transaction=change.id, operation="commit"), "ACONTROL_KEY_COMMITTED")
                            if proposed.ssh_firewall_mode == "add":
                                await _run(conn, ssh_firewall.script(change.id, [], proposed.ssh_port, "commit"), "ACONTROL_FIREWALL_COMMITTED")
                            for field in ACCESS_FIELDS:
                                setattr(server, field, getattr(proposed, field))
                            change.phase = "done"
                            restored = True
                            break
                        except Exception:
                            pass
                    await _run(conn, write_key(public, keyopts, transaction=change.id, operation="rollback"), "ACONTROL_KEY_ROLLEDBACK")
                    if proposed.ssh_firewall_mode == "add":
                        await _run(conn, ssh_firewall.script(change.id, [], proposed.ssh_port, "rollback"), "ACONTROL_FIREWALL_ROLLEDBACK")
                    for field in ACCESS_FIELDS:
                        setattr(server, field, getattr(old, field))
                    change.phase = "rolledback"
                    restored = True
                    break
            except Exception:
                continue
        if not restored:
            # Preserve the journal for an explicit retry; don't pretend recovery succeeded.
            continue
        await session.commit()
