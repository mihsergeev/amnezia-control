import asyncio
import ipaddress
import os
import re
import socket
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

from app import cascade_manual, cascade_underlay
from app.sshkeys import jump_key_path, jump_username


@dataclass(frozen=True)
class Jump:
    host: str
    port: int
    target_id: int


class JumpAccessError(asyncssh.PermissionDenied):
    pass


def route_options(server) -> dict:
    """Keep direct call signatures stable; never infer a route from reachability."""
    if not getattr(server, "ssh_jump_server_id", None):
        return {}
    jump = server.ssh_jump_server
    if jump is None or jump.id == server.id or jump.ssh_jump_server_id:
        raise ValueError("Некорректный маршрут SSH: допускается одна прямая промежуточная нода")
    return {"jump": Jump(jump.host, jump.ssh_port, server.id)}

# hostname + список docker-контейнеров (с фолбэком на sudo без пароля)
# Определение РЕАЛЬНОГО протокола в каждом amnezia-контейнере — по содержимому
# его конфига, а не по имени. Имена у Amnezia версию не отражают: контейнер
# amnezia-awg2 может нести и legacy-конфиг, а панельный amnezia-awg3 внешне
# неотличим от него же. Признаки (сверены с исходниками апстрима и живыми нодами):
#   RandomTrailers/DisableCookies -> AmneziaWG 3.1 (добавлены в 3.1)
#   HeaderProtectionKey  -> AmneziaWG 3.0 (ключ появился в третьей версии)
#   I1 (в т.ч. «# I1»)   -> AmneziaWG 2.0 (CPS; у Amnezia хранится закомментированным)
#   ни того, ни другого  -> AmneziaWG 1.0 / legacy
_PROTO_PROBE = (
    "for c in $($D ps --format '{{.Names}}' 2>/dev/null | grep -i '^amnezia'); do "
    "k=other; "
    'case "$c" in '
    "*openvpn*) k=openvpn ;; "
    "*xray*) k=xray ;; "
    "*) "
    "f=$($D exec \"$c\" sh -c 'ls /opt/amnezia/awg/awg0.conf /opt/amnezia/awg/wg0.conf "
    "2>/dev/null | head -1' 2>/dev/null); "
    'if [ -n "$f" ]; then '
    "cfg=$($D exec \"$c\" cat \"$f\" 2>/dev/null); "
    # 3.1 отличается от 3.0 ровно двумя булевыми ключами (RandomTrailers /
    # DisableCookies) — по ним версии и различаем; всё остальное у них общее
    'if printf "%s" "$cfg" | grep -qiE "^(RandomTrailers|DisableCookies)"; then k=awg31; '
    'elif printf "%s" "$cfg" | grep -qi "^HeaderProtectionKey"; then k=awg3; '
    'elif printf "%s" "$cfg" | grep -qE "^#? *I1"; then k=awg2; '
    "else k=awg1; fi; fi ;; "
    "esac; "
    'echo "PROTO=$c|$k"; '
    "done"
)

_NATIVE_PROTO_PROBE = (
    "for pair in wireguard:acontrol-wireguard openvpn-native:acontrol-openvpn-native; do "
    'p=${pair%%:*}; c=${pair#*:}; '
    "owned=$($D container inspect -f '{{.State.Running}}|{{index .Config.Labels \"org.amnezia.control.native\"}}' \"$c\" 2>/dev/null); "
    '[ "$owned" = "true|$p" ] && echo "PROTO=$c|$p"; done; true'
)

# GRE-туннели ноды (каскад через GRE: ТСПУ не трогает proto 47). Сырые строки
# `ip -o -d link`, разбираем в _parse_tunnel; служебный gre0 (remote any) отсеиваем
_TUNNEL_PROBE = (
    "ip -o -d link show type gre 2>/dev/null | sed 's/^/GRELINK=/'; "
)

CHECK_COMMAND = (
    'echo "HOST=$(hostname)"; '
    # развертывание и изменения на ноде идут через sudo -n: без него проверка
    # проходила, а ошибка всплывала только при установке протокола
    'if [ "$(id -u)" = 0 ]; then echo SUDO=root; elif sudo -n true 2>/dev/null; then echo SUDO=yes; else echo SUDO=no; fi; '
    + _TUNNEL_PROBE + cascade_underlay.PROBE_COMMAND + cascade_manual.PROBE_COMMAND +
    "if docker ps --format '{{.Names}}' 2>/dev/null; then D=docker; "
    "elif sudo -n docker ps --format '{{.Names}}' 2>/dev/null; then D='sudo -n docker'; "
    "else echo DOCKER_UNAVAILABLE; D=''; fi; "
    '[ -n "$D" ] && { ' + _PROTO_PROBE + "; " + _NATIVE_PROTO_PROBE + "; } || true"
)


# Адрес, с которого трафик клиентов уходит в интернет. Спрашиваем изнутри
# amnezia-контейнера, а не с хоста: у каскадов (tproxy с docker0, GRE и т.п.)
# собственный трафик ноды идет напрямую, а клиентский - через другой выход.
# В alpine-контейнерах есть busybox wget, в xray еще и curl.
EGRESS_COMMAND = (
    "if [ -w /var/run/docker.sock ] || [ -w /run/docker.sock ]; then D=docker; "
    "elif sudo -n true 2>/dev/null; then D='sudo -n docker'; "
    "else exit 0; fi; "
    "c=$($D ps --format '{{.Names}}' 2>/dev/null | grep -i '^amnezia' | head -1); "
    'if [ -z "$c" ]; then for pair in wireguard:acontrol-wireguard openvpn-native:acontrol-openvpn-native; do '
    'p=${pair%%:*}; n=${pair#*:}; '
    "owned=$($D container inspect -f '{{.State.Running}}|{{index .Config.Labels \"org.amnezia.control.native\"}}' \"$n\" 2>/dev/null); "
    '[ "$owned" = "true|$p" ] && { c=$n; break; }; done; fi; '
    '[ -n "$c" ] || exit 0; '
    # busybox wget по https запускает помощника ssl_client и не дожидается его:
    # тот становится сиротой у PID 1 контейнера, а `tail -f /dev/null` детей не
    # собирает - по зомби в час. Поэтому curl по https, а wget только по http
    # (адрес выхода - справка на карточке, подмена в пути ничего не ломает)
    "for u in api.ipify.org ifconfig.me/ip; do "
    'ip=$($D exec "$c" sh -c "curl -fsS -m 6 https://$u 2>/dev/null || wget -qO- -T 6 http://$u 2>/dev/null" '
    "2>/dev/null); "
    'case "$ip" in *.*.*.*) echo "EGRESS=$ip"; exit 0 ;; esac; '
    "done"
)


def _parse_egress_output(output: str) -> str:
    """IPv4 из строки EGRESS=..., иначе '' (нет контейнеров / сервисы не ответили)."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("EGRESS="):
            try:
                addr = ipaddress.IPv4Address(line.removeprefix("EGRESS="))
            except ValueError:
                return ""
            return "" if addr.is_loopback or addr.is_unspecified else str(addr)
    return ""


async def probe_egress(conn: "asyncssh.SSHClientConnection") -> str | None:
    """Адрес выхода клиентов через уже открытое соединение.

    '' - ответа нет (контейнеров нет, сервисы недоступны), None - SSH-сбой.
    """
    try:
        run = await conn.run(EGRESS_COMMAND, check=False, timeout=30)
    except (OSError, asyncssh.Error):
        return None
    output = run.stdout if isinstance(run.stdout, str) else ""
    return _parse_egress_output(output)


# This observes the managed host, never the client container or cascade exit.
# URLs are fixed, proxies and redirects disabled, output and time are bounded.
HOST_EGRESS_COMMAND = (
    "for u in https://api.ipify.org https://ipv4.icanhazip.com; do "
    "ip=$(curl -q -4 -fsS --noproxy '*' --connect-timeout 3 --max-time 6 --max-filesize 64 \"$u\" 2>/dev/null) || continue; "
    'printf "EGRESS=%s\\n" "$ip"; break; done'
)


async def probe_host_egress(conn: "asyncssh.SSHClientConnection") -> str:
    try:
        result = await conn.run(HOST_EGRESS_COMMAND, check=False, timeout=15)
        value = _parse_egress_output(result.stdout if isinstance(result.stdout, str) else "")
        return value if value and ipaddress.ip_address(value).is_global else ""
    except (OSError, asyncssh.Error, TimeoutError):
        return ""


@dataclass
class CheckResult:
    ok: bool
    error: str = ""
    hostname: str = ""
    # root | yes (sudo -n работает) | no (нет sudo без пароля) | "" (не проверялось)
    sudo: str = ""
    docker: bool = False
    containers: list[str] = field(default_factory=list)
    amnezia_containers: list[str] = field(default_factory=list)
    # реальный протокол по каждому amnezia-контейнеру: {имя: awg1|awg2|awg3|
    # openvpn|xray|other} — определяется по конфигу ВНУТРИ контейнера, а не по имени
    protocols: dict[str, str] = field(default_factory=dict)
    # поднятые GRE-туннели: [{"kind": "gre", "name": "gre-fi", "remote": "203.0.113.9"}]
    tunnels: list[dict] = field(default_factory=list)
    # Public live evidence for a previously configured GRE-over-AWG underlay.
    cascade_link: dict = field(default_factory=dict)
    manual_cascade: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "error": self.error,
            "hostname": self.hostname,
            "sudo": self.sudo,
            "docker": self.docker,
            "containers": self.containers,
            "amnezia_containers": self.amnezia_containers,
            "protocols": self.protocols,
            "tunnels": self.tunnels,
            "cascade_link": self.cascade_link,
            "manual_cascade": self.manual_cascade,
        }


@dataclass
class BootstrapResult:
    ok: bool
    error: str = ""
    output: str = ""


_GRELINK_RE = re.compile(r"^\d+:\s+([^@:\s]+)[@:].*?<([^>]*)>.*\sgre remote (\S+)")


def _parse_tunnel(line: str) -> dict | None:
    """Строка `ip -o -d link show type gre` -> туннель, если он поднят и с адресом."""
    m = _GRELINK_RE.search(line)
    if not m:
        return None
    name, flags, remote = m.groups()
    if "UP" not in flags.split(",") or remote == "any":
        return None
    return {"kind": "gre", "name": name, "remote": remote}


def _parse_check_output(output: str) -> CheckResult:
    result = CheckResult(ok=True, docker=True)
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("HOST="):
            result.hostname = line.removeprefix("HOST=")
        elif line in ("SUDO=root", "SUDO=yes", "SUDO=no"):
            result.sudo = line.removeprefix("SUDO=")
        elif line == "DOCKER_UNAVAILABLE":
            result.docker = False
        elif line.startswith("GRELINK="):
            tun = _parse_tunnel(line.removeprefix("GRELINK="))
            if tun:
                result.tunnels.append(tun)
        elif line.startswith("AWGUNDERLAY="):
            result.cascade_link = cascade_underlay.parse_probe(line.removeprefix("AWGUNDERLAY="))
        elif line.startswith("MANUAL_CASCADE="):
            result.manual_cascade = cascade_manual.parse_probe(line.removeprefix("MANUAL_CASCADE="))
        elif line.startswith("PROTO="):
            name, _, kind = line.removeprefix("PROTO=").partition("|")
            if name and kind:
                result.protocols[name] = kind
        else:
            result.containers.append(line)
    result.amnezia_containers = [
        name for name in result.containers if name.startswith("amnezia")
        or result.protocols.get(name) in {"wireguard", "openvpn-native"}
    ]
    return result


def _firewall_snippet(panel_ip: str, ssh_port: int, sudo: str, *, strict: bool = False) -> str:
    """Add source-specific rules only; never reload/enable/reset a firewall."""
    if not panel_ip:
        return 'FW="(panel_ip не задан)"\n'
    network = ipaddress.ip_network(panel_ip, strict=False)
    address = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
    family = "ipv4" if network.version == 4 else "ipv6"
    rich = f"rule family={family} source address={address} port port={int(ssh_port)} protocol=tcp accept"
    failure = 'FAILED=1' if strict else ':'
    return (
        'FW=""; FAILED=0\n'
        'if command -v ufw >/dev/null 2>&1; then '
        f'{sudo} ufw allow from {address} to any port {int(ssh_port)} proto tcp '
        f'>/dev/null 2>&1 && FW="$FW ufw" || {failure}; fi\n'
        'if command -v firewall-cmd >/dev/null 2>&1 && '
        f'{sudo} firewall-cmd --state >/dev/null 2>&1; then '
        f'{sudo} firewall-cmd --permanent --add-rich-rule="{rich}" >/dev/null 2>&1 '
        f'&& {sudo} firewall-cmd --add-rich-rule="{rich}" >/dev/null 2>&1 '
        f'&& FW="$FW firewalld" || {failure}; fi\n'
        'if [ -f /etc/hosts.allow ]; then '
        f"""{sudo} sh -c "grep -qs 'sshd: {address}' /etc/hosts.allow """
        f"""|| echo 'sshd: {address}' >> /etc/hosts.allow" >/dev/null 2>&1 """
        f'&& FW="$FW hosts.allow" || {failure}; fi\n'
        '[ -n "$FW" ] || FW=" (не найден активный ufw/firewalld/hosts.allow)"\n'
        + ('[ "$FAILED" = 0 ] || { echo "Не удалось добавить разрешение firewall" >&2; exit 1; }\n' if strict else '')
    )


def _key_options(panel_ip: str) -> str:
    """Опции для строки authorized_keys панельного ключа.

    restrict отключает штатные PTY и SSH-форвардинги. Это не ограничивает
    команды пользователя и не заменяет изоляцию его sudo/docker-полномочий.
    from="<panel_ip>" — привязка к IP панели (ключ бесполезен с другого адреса).
    """
    ip = (panel_ip or "").strip()
    if ip and re.fullmatch(r"[0-9A-Fa-f:.,/ ]+", ip):
        return f'from="{ip}",restrict '
    return "restrict "


# Имя SSH-пользователя уходит в скрипт, который админ выполняет под root.
# Форма проверяла его, а импорт ссылки, файла переноса и бэкапа - нет, и чужая
# ссылка с userName вида x';curl ...|sh;' выполнялась бы под root на ноде.
SSH_USER_PATTERN = r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$"


def valid_ssh_user(name: object) -> bool:
    return isinstance(name, str) and re.fullmatch(SSH_USER_PATTERN, name) is not None


def build_setup_script(
    public_key: str, ssh_user: str, ssh_port: int, panel_ip: str,
    *, source_ips: list[str] | None = None, firewall_mode: str = "add",
) -> str:
    """Скрипт для ручного запуска админом под root на новой ноде."""
    if not valid_ssh_user(ssh_user):
        raise ValueError(f"недопустимое имя SSH-пользователя: {ssh_user!r}")
    from app.ssh_access import options, write_key
    addresses = source_ips if source_ips is not None else ([panel_ip] if panel_ip else [])
    firewall = ''.join(_firewall_snippet(address, ssh_port, sudo="", strict=True) for address in addresses) if firewall_mode == "add" else 'FW="не изменен"\n'
    firewall = firewall or 'FW="не изменен"\n'
    writer = write_key(public_key, options(addresses))
    return f"""#!/bin/sh
# Amnezia Control: подготовка сервера. Выполнить под root.
set -e
KEY='{public_key}'
# создаём пользователя панели, если его ещё нет (+ sudo NOPASSWD + docker)
if ! id '{ssh_user}' >/dev/null 2>&1; then
  useradd -m -s /bin/bash '{ssh_user}' 2>/dev/null || adduser -D '{ssh_user}' 2>/dev/null || true
fi
echo '{ssh_user} ALL=(ALL) NOPASSWD:ALL' > "/etc/sudoers.d/{ssh_user}" 2>/dev/null && chmod 440 "/etc/sudoers.d/{ssh_user}"
getent group docker >/dev/null 2>&1 && usermod -aG docker '{ssh_user}' 2>/dev/null || true
HOME_DIR=$(getent passwd '{ssh_user}' | cut -d: -f6)
[ -n "$HOME_DIR" ] || {{ echo "ACONTROL SETUP FAILED: не удалось создать пользователя {ssh_user}"; exit 1; }}
su -s /bin/sh '{ssh_user}' -c {_sh_quote(writer)}
set +e  # фаервол — best-effort, не должен ронять настройку
{firewall}echo "ACONTROL SETUP OK: $(hostname) [fw:$FW ]"
"""


def _build_bootstrap_script(public_key: str, ssh_port: int, panel_ip: str, *, source_ips=None, firewall_mode="add", transaction=None) -> str:
    """Скрипт, который панель выполняет сама, зайдя по SSH-паролю как ssh_user.

    Ключ ставится в домашний каталог текущего пользователя; для фаервола
    используется sudo -S (пароль подаётся на stdin), если мы не root.
    """
    from app.ssh_access import options, write_key
    addresses = source_ips if source_ips is not None else ([panel_ip] if panel_ip else [])
    firewall = ''.join(_firewall_snippet(address, ssh_port, sudo="$SUDO", strict=bool(transaction)) for address in addresses) if firewall_mode == "add" else 'FW="не изменен"\n'
    firewall = firewall or 'FW="не изменен"\n'
    writer = write_key(public_key, options(addresses), transaction=transaction)
    return f"""set -e
KEY='{public_key}'
{writer}
set +e
if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO="sudo -S"; fi
{firewall}echo "ACONTROL SETUP OK: $(hostname) [fw:$FW ]"
"""


async def remove_authorized_key(
    conn: asyncssh.SSHClientConnection, public_key: str
) -> None:
    """Убирает строку с публичным ключом панели из authorized_keys юзера."""
    quoted = _sh_quote(public_key)
    # Подменяем файл только при успешной записи: grep -v отдает 1, если строк не
    # осталось (это норма), а 2 - ошибка (полный диск). Иначе обрезанный до 0 байт
    # authorized_keys отнял бы вход у админа.
    cmd = (
        'f="$HOME/.ssh/authorized_keys"; t="$f.acontrol.tmp"; '
        f'if [ -f "$f" ]; then grep -vF {quoted} "$f" > "$t" 2>/dev/null; '
        'if [ $? -le 1 ] && chmod 600 "$t"; then mv -f "$t" "$f"; '
        'else rm -f "$t"; fi; fi'
    )
    await conn.run(cmd, check=False)


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


# --- TOFU-пиннинг host-ключей нод ---------------------------------------------
# Ключ ноды запоминается при первом подключении (в data/ssh/known_hosts, рядом с
# ключом панели), дальше сверяется. Несовпадение (MITM/подмена ноды) → ошибка.


class HostKeyChangedError(Exception):
    """Host-ключ ноды не совпал с запомненным (возможен MITM/подмена ноды)."""


def _kh_path(key_path: Path) -> Path:
    return Path(key_path).parent / "known_hosts"


def _kh_host(host: str, port: int) -> str:
    # OpenSSH-формат: для нестандартного порта — [host]:port
    return host if port == 22 else f"[{host}]:{port}"


def _host_known(kh: Path, host: str, port: int) -> bool:
    if not kh.exists():
        return False
    token = _kh_host(host, port)
    try:
        for line in kh.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if token in line.split()[0].split(","):
                return True
    except OSError:
        return False
    return False


def _record_host_key(kh: Path, host: str, port: int, conn) -> None:
    """Записывает host-ключ ноды в known_hosts (best-effort, не роняет коннект)."""
    try:
        if _host_known(kh, host, port):
            return
        key = conn.get_server_host_key()
        if key is None:
            return
        pub = key.export_public_key().decode().split()
        if len(pub) < 2:
            return
        kh.parent.mkdir(parents=True, exist_ok=True)
        with open(kh, "a", encoding="utf-8") as fh:
            fh.write(f"{_kh_host(host, port)} {pub[0]} {pub[1]}\n")
        try:
            os.chmod(kh, 0o600)
        except OSError:
            pass
    except Exception:  # noqa: BLE001 — запись ключа не критична для операции
        pass


async def _tofu_connect(
    host: str,
    port: int,
    username: str,
    key_path: Path,
    *,
    password: str | None = None,
    timeout: int = 10,
    tunnel=None,
    require_known: bool = False,
):
    kh = _kh_path(key_path)
    # keepalive: нода, пропавшая посреди операции (обрыв маршрута, зависший
    # ядром хост), иначе держала бы соединение и ручку бесконечно
    common = dict(
        host=host, port=port, username=username, connect_timeout=timeout,
        keepalive_interval=15, keepalive_count_max=3,
        config=None, agent_path=None,
    )
    if tunnel is not None:
        common["tunnel"] = tunnel
    if require_known and not _host_known(kh, host, port):
        raise HostKeyChangedError(f"{host}:{port}: host key не проверен")
    if password is not None:
        common["password"] = password
    else:
        common["client_keys"] = [str(key_path)]
    if _host_known(kh, host, port):
        # ключ ноды известен — строго проверяем (несовпадение = ошибка)
        try:
            return await asyncssh.connect(known_hosts=str(kh), **common)
        except asyncssh.HostKeyNotVerifiable as exc:
            raise HostKeyChangedError(f"{host}:{port}") from exc
    # первый контакт — принимаем и запоминаем (TOFU)
    conn = await asyncssh.connect(known_hosts=None, **common)
    _record_host_key(kh, host, port, conn)
    return conn


@asynccontextmanager
async def connect(
    host: str, port: int, username: str, key_path: Path, timeout: int = 10,
    *, jump: Jump | None = None, password: str | None = None, require_known: bool = False,
):
    """Подключение панельным ключом с TOFU-пиннингом (для async with)."""
    parent = None
    conn = None
    try:
        options = {}
        if password is not None:
            options["password"] = password
        if require_known:
            options["require_known"] = True
        if jump is not None:
            path = jump_key_path(key_path, jump.target_id)
            if not path.is_file():
                raise JumpAccessError("Сначала подготовьте SSH-доступ через промежуточную ноду")
            try:
                parent = await _tofu_connect(jump.host, jump.port, jump_username(key_path, jump.target_id), path,
                                            timeout=timeout, require_known=True)
            except asyncssh.PermissionDenied as exc:
                raise JumpAccessError("Промежуточный SSH-ключ не принят. При смене исходящего IP панели повторите подготовку промежуточной ноды") from exc
            options["tunnel"] = parent
        conn = await _tofu_connect(host, port, username, key_path, timeout=timeout, **options)
        yield conn
    finally:
        # The target must close before the forwarding connection, including failed auth.
        try:
            if conn is not None:
                conn.close()
                await conn.wait_closed()
        finally:
            if parent is not None:
                parent.close()
                await parent.wait_closed()


async def check_server(
    host: str, port: int, username: str, key_path: Path, timeout: int = 10,
    *, jump: Jump | None = None,
) -> CheckResult:
    try:
        async with asyncio.timeout(timeout * 2):
            async with connect(host, port, username, key_path, timeout, **({"jump": jump} if jump else {})) as conn:
                run = await conn.run(CHECK_COMMAND, check=False)
    except asyncio.TimeoutError:
        return CheckResult(ok=False, error="Таймаут подключения")
    except HostKeyChangedError:
        return CheckResult(
            ok=False,
            error="Host-ключ ноды ИЗМЕНИЛСЯ — возможна подмена/MITM. Если вы "
            "пересоздавали ноду, удалите её строку из data/ssh/known_hosts.",
        )
    except JumpAccessError as exc:
        return CheckResult(ok=False, error=str(exc))
    except asyncssh.PermissionDenied:
        return CheckResult(
            ok=False,
            error="SSH-ключ панели не авторизован (выполните настройку сервера)",
        )
    except socket.gaierror:
        return CheckResult(
            ok=False,
            error="Панель не нашла адрес сервера в DNS. Укажите IP или доступный панели домен.",
        )
    except (OSError, asyncssh.Error) as exc:
        return CheckResult(ok=False, error=str(exc) or type(exc).__name__)
    except ValueError as exc:
        return CheckResult(ok=False, error=str(exc))

    output = run.stdout if isinstance(run.stdout, str) else ""
    return _parse_check_output(output)


async def probe_containers(conn: "asyncssh.SSHClientConnection") -> CheckResult | None:
    """Список контейнеров через УЖЕ ОТКРЫТОЕ соединение (для фонового сбора).

    Возвращает CheckResult при успешном ответе docker (даже пустой список —
    это валидное «контейнеров нет»), либо None, если сама команда не выполнилась
    (SSH-сбой) — чтобы транзиентная ошибка не затирала список протоколов.
    """
    try:
        run = await conn.run(CHECK_COMMAND, check=False)
    except (OSError, asyncssh.Error):
        return None
    output = run.stdout if isinstance(run.stdout, str) else ""
    return _parse_check_output(output)


async def bootstrap_server(
    host: str,
    port: int,
    username: str,
    password: str,
    public_key: str,
    panel_ip: str,
    become_password: str | None = None,
    timeout: int = 10,
    *,
    key_path: Path,
    source_ips: list[str] | None = None,
    firewall_mode: str = "add",
    jump: Jump | None = None,
) -> BootstrapResult:
    """Заходит по паролю, ставит ключ панели и настраивает фаервол.
    Ключ хоста - как у остальных подключений (TOFU): у знакомой ноды
    проверяется строго, иначе пароли SSH и sudo ушли бы подменному хосту."""
    import uuid
    from app.ssh_access import options, write_key, _run
    token = uuid.uuid4().hex
    addresses = source_ips if source_ips is not None else ([panel_ip] if panel_ip else [])
    script = _build_bootstrap_script(public_key, port, panel_ip, source_ips=addresses, firewall_mode=firewall_mode, transaction=token)
    sudo_input = (become_password or password) + "\n"
    key_verified = False
    password_connected = False
    try:
        async with asyncio.timeout(timeout * 3):
            async with connect(host, port, username, key_path, timeout, password=password, **({"jump": jump} if jump else {})) as conn:
                password_connected = True
                run = await conn.run(script, input=sudo_input, check=False)
                if run.exit_status == 0 and "ACONTROL SETUP OK" in (run.stdout or ""):
                    try:
                        async with connect(host, port, username, key_path, timeout, **({"jump": jump} if jump else {})) as check:
                            verified = await check.run("printf 'SOURCE=%s\\n' \"${SSH_CONNECTION%% *}\"", check=True, timeout=10)
                            actual = ipaddress.ip_address(verified.stdout.strip().removeprefix("SOURCE="))
                            if addresses and not any(actual in ipaddress.ip_network(item, strict=False) for item in addresses):
                                raise ValueError(f"Фактический источник SSH {actual} не входит в разрешенный список: {', '.join(addresses)}")
                        await _run(conn, write_key(public_key, options(addresses), transaction=token, operation="commit"), "ACONTROL_KEY_COMMITTED")
                        key_verified = True
                    except BaseException:
                        await _run(conn, write_key(public_key, options(addresses), transaction=token, operation="rollback"), "ACONTROL_KEY_ROLLEDBACK")
                        raise
    except asyncio.TimeoutError:
        return BootstrapResult(ok=False, error="Таймаут подключения")
    except HostKeyChangedError:
        return BootstrapResult(
            ok=False,
            error="Host-ключ ноды ИЗМЕНИЛСЯ — возможна подмена/MITM. Если вы "
            "пересоздавали ноду, удалите её строку из data/ssh/known_hosts.",
        )
    except JumpAccessError as exc:
        return BootstrapResult(ok=False, error=str(exc))
    except asyncssh.PermissionDenied:
        return BootstrapResult(
            ok=False,
            error=("Ключ панели установлен, но повторный вход по ключу не принят" if password_connected else
                   "Неверный пароль или на сервере запрещён вход по паролю "
                   "(PasswordAuthentication no) — используйте ручной скрипт"),
        )
    except (OSError, asyncssh.Error) as exc:
        return BootstrapResult(ok=False, error=str(exc) or type(exc).__name__)
    except (ValueError, RuntimeError) as exc:
        return BootstrapResult(ok=False, error=str(exc))

    output = (run.stdout or "") + (run.stderr or "")
    if key_verified:
        return BootstrapResult(ok=True, output=output.strip())
    return BootstrapResult(
        ok=False,
        error="Скрипт настройки не подтвердил успех",
        output=output.strip(),
    )
