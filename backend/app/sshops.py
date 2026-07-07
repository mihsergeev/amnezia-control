import asyncio
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

# hostname + список docker-контейнеров (с фолбэком на sudo без пароля)
CHECK_COMMAND = (
    'echo "HOST=$(hostname)"; '
    "if docker ps --format '{{.Names}}' 2>/dev/null; then :; "
    "elif sudo -n docker ps --format '{{.Names}}' 2>/dev/null; then :; "
    "else echo DOCKER_UNAVAILABLE; fi"
)


@dataclass
class CheckResult:
    ok: bool
    error: str = ""
    hostname: str = ""
    docker: bool = False
    containers: list[str] = field(default_factory=list)
    amnezia_containers: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "error": self.error,
            "hostname": self.hostname,
            "docker": self.docker,
            "containers": self.containers,
            "amnezia_containers": self.amnezia_containers,
        }


@dataclass
class BootstrapResult:
    ok: bool
    error: str = ""
    output: str = ""


def _parse_check_output(output: str) -> CheckResult:
    result = CheckResult(ok=True, docker=True)
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("HOST="):
            result.hostname = line.removeprefix("HOST=")
        elif line == "DOCKER_UNAVAILABLE":
            result.docker = False
        else:
            result.containers.append(line)
    result.amnezia_containers = [
        name for name in result.containers if name.startswith("amnezia")
    ]
    return result


def _firewall_snippet(panel_ip: str, ssh_port: int, sudo: str) -> str:
    """Best-effort открытие порта для IP панели. Никогда не роняет скрипт.

    Каждая ветка проверяет наличие инструмента; hosts.allow трогаем только
    если файл уже существует (tcp-wrappers могут быть не установлены).
    """
    if not panel_ip:
        return 'FW="(panel_ip не задан)"\n'
    rich = (
        f'rule family=ipv4 source address={panel_ip} '
        f'port port={ssh_port} protocol=tcp accept'
    )
    return (
        'FW=""\n'
        "if command -v ufw >/dev/null 2>&1; then "
        f"{sudo} ufw allow from {panel_ip} to any port {ssh_port} proto tcp "
        '>/dev/null 2>&1 && FW="$FW ufw"; fi\n'
        "if command -v firewall-cmd >/dev/null 2>&1; then "
        f'{sudo} firewall-cmd --permanent --add-rich-rule="{rich}" >/dev/null 2>&1 '
        f'&& {sudo} firewall-cmd --reload >/dev/null 2>&1 && FW="$FW firewalld"; fi\n'
        "if [ -f /etc/hosts.allow ]; then "
        f"""{sudo} sh -c "grep -qs 'sshd: {panel_ip}' /etc/hosts.allow """
        f"""|| echo 'sshd: {panel_ip}' >> /etc/hosts.allow" >/dev/null 2>&1 """
        '&& FW="$FW hosts.allow"; fi\n'
        '[ -n "$FW" ] || FW=" (не найден ufw/firewalld/hosts.allow)"\n'
    )


def build_setup_script(
    public_key: str, ssh_user: str, ssh_port: int, panel_ip: str
) -> str:
    """Скрипт для ручного запуска админом под root на новой ноде."""
    firewall = _firewall_snippet(panel_ip, ssh_port, sudo="")
    return f"""#!/bin/sh
# Amnezia Control: подготовка сервера. Выполнить под root.
set -e
KEY='{public_key}'
# создаём пользователя панели, если его ещё нет (+ sudo NOPASSWD + docker)
if ! id '{ssh_user}' >/dev/null 2>&1; then
  useradd -m -s /bin/bash '{ssh_user}' 2>/dev/null || adduser -D '{ssh_user}' 2>/dev/null || true
fi
echo '{ssh_user} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{ssh_user} 2>/dev/null && chmod 440 /etc/sudoers.d/{ssh_user}
getent group docker >/dev/null 2>&1 && usermod -aG docker '{ssh_user}' 2>/dev/null || true
HOME_DIR=$(getent passwd '{ssh_user}' | cut -d: -f6)
[ -n "$HOME_DIR" ] || {{ echo "ACONTROL SETUP FAILED: не удалось создать пользователя {ssh_user}"; exit 1; }}
mkdir -p "$HOME_DIR/.ssh" && chmod 700 "$HOME_DIR/.ssh"
touch "$HOME_DIR/.ssh/authorized_keys"
grep -qF "$KEY" "$HOME_DIR/.ssh/authorized_keys" || printf '%s\\n' "$KEY" >> "$HOME_DIR/.ssh/authorized_keys"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"
chown -R '{ssh_user}:' "$HOME_DIR/.ssh"
set +e  # фаервол — best-effort, не должен ронять настройку
{firewall}echo "ACONTROL SETUP OK: $(hostname) [fw:$FW ]"
"""


def _build_bootstrap_script(public_key: str, ssh_port: int, panel_ip: str) -> str:
    """Скрипт, который панель выполняет сама, зайдя по SSH-паролю как ssh_user.

    Ключ ставится в домашний каталог текущего пользователя; для фаервола
    используется sudo -S (пароль подаётся на stdin), если мы не root.
    """
    firewall = _firewall_snippet(panel_ip, ssh_port, sudo="$SUDO")
    return f"""set -e
KEY='{public_key}'
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
grep -qF "$KEY" "$HOME/.ssh/authorized_keys" || printf '%s\\n' "$KEY" >> "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
set +e
if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO="sudo -S"; fi
{firewall}echo "ACONTROL SETUP OK: $(hostname) [fw:$FW ]"
"""


async def remove_authorized_key(
    conn: asyncssh.SSHClientConnection, public_key: str
) -> None:
    """Убирает строку с публичным ключом панели из authorized_keys юзера."""
    quoted = _sh_quote(public_key)
    cmd = (
        'f="$HOME/.ssh/authorized_keys"; '
        f'if [ -f "$f" ]; then grep -vF {quoted} "$f" > "$f.acontrol.tmp" 2>/dev/null; '
        'mv "$f.acontrol.tmp" "$f"; chmod 600 "$f"; fi'
    )
    await conn.run(cmd, check=False)


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def connect(
    host: str, port: int, username: str, key_path: Path, timeout: int = 10
):
    """asyncssh-подключение панельным ключом (для использования в async with)."""
    return asyncssh.connect(
        host,
        port=port,
        username=username,
        client_keys=[str(key_path)],
        known_hosts=None,
        connect_timeout=timeout,
    )


async def check_server(
    host: str, port: int, username: str, key_path: Path, timeout: int = 10
) -> CheckResult:
    try:
        async with asyncio.timeout(timeout * 2):
            conn = await asyncssh.connect(
                host,
                port=port,
                username=username,
                client_keys=[str(key_path)],
                known_hosts=None,
                connect_timeout=timeout,
            )
            async with conn:
                run = await conn.run(CHECK_COMMAND, check=False)
    except asyncio.TimeoutError:
        return CheckResult(ok=False, error="Таймаут подключения")
    except asyncssh.PermissionDenied:
        return CheckResult(
            ok=False,
            error="SSH-ключ панели не авторизован (выполните настройку сервера)",
        )
    except (OSError, asyncssh.Error) as exc:
        return CheckResult(ok=False, error=str(exc) or type(exc).__name__)

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
) -> BootstrapResult:
    """Заходит по паролю, ставит ключ панели и настраивает фаервол."""
    script = _build_bootstrap_script(public_key, port, panel_ip)
    sudo_input = (become_password or password) + "\n"
    try:
        async with asyncio.timeout(timeout * 3):
            conn = await asyncssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                known_hosts=None,
                connect_timeout=timeout,
            )
            async with conn:
                run = await conn.run(script, input=sudo_input, check=False)
    except asyncio.TimeoutError:
        return BootstrapResult(ok=False, error="Таймаут подключения")
    except asyncssh.PermissionDenied:
        return BootstrapResult(
            ok=False,
            error="Неверный пароль или на сервере запрещён вход по паролю "
            "(PasswordAuthentication no) — используйте ручной скрипт",
        )
    except (OSError, asyncssh.Error) as exc:
        return BootstrapResult(ok=False, error=str(exc) or type(exc).__name__)

    output = (run.stdout or "") + (run.stderr or "")
    if "ACONTROL SETUP OK" in output:
        return BootstrapResult(ok=True, output=output.strip())
    return BootstrapResult(
        ok=False,
        error="Скрипт настройки не подтвердил успех",
        output=output.strip(),
    )
