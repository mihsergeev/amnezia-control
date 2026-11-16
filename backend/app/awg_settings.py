"""Version-aware AWG settings, network preflight and reversible node changes.

Parameter syntax follows the pinned upstream amneziawg-go/device/uapi.go,
device/obf*.go and amneziawg-tools/src/config.c, not prospective versions.
"""

import base64
import hashlib
import ipaddress
import json
import re
import shlex
import uuid

from fastapi import HTTPException

from app import awg, deploy


def version(params: dict) -> str:
    if "RandomTrailers" in params and "DisableCookies" in params:
        return "3.1"
    if "HeaderProtectionKey" in params:
        return "3.0"
    return "2.0"


def keys(ver: str) -> list[str]:
    active = deploy._AWG_ACTIVE_ORDER.copy()
    if ver.startswith("3"):
        active += [k for k in deploy._AWG3_ACTIVE_ORDER if k not in active
                   and (ver == "3.1" or k not in ("RandomTrailers", "DisableCookies"))]
    return active + deploy._AWG_CPS_KEYS


def invalid(message: str):
    raise HTTPException(422, message)


def _range(value, key, maximum, minimum=0):
    value = str(value)
    if len(value) > 32 or not re.fullmatch(r"\d+(?:-\d+)?", value):
        invalid(f"{key}: ожидается число или диапазон min-max")
    parts = list(map(int, value.split("-")))
    lo, hi = parts[0], parts[-1]
    if not minimum <= lo <= hi <= maximum:
        invalid(f"{key}: допустимые границы {minimum}..{maximum}")
    return lo, hi


def validate_params(params: dict, ver: str) -> dict[str, str]:
    allowed = keys(ver)
    if set(params) - set(allowed):
        invalid("Параметр не поддерживается установленной версией AmneziaWG")
    missing = set(allowed) - set(deploy._AWG_CPS_KEYS) - set(params)
    if missing:
        invalid("Не заданы обязательные параметры AmneziaWG: " + ", ".join(sorted(missing)))
    result = {k: str(params.get(k, "")).strip() for k in allowed}
    if any(len(v) > 4096 for v in result.values()):
        invalid("Значение параметра AmneziaWG слишком длинное")
    if any("\n" in v or "\r" in v or "#" in v or ";" in v or "\x00" in v for v in result.values()):
        invalid("Параметры AmneziaWG должны занимать одну строку без комментариев")
    # Conservative working envelope: uint32 J*, uint16 S* in the engine;
    # cap packet allocations at 1280 bytes and handshake burst at 128.
    for key, high in (("Jc", 128), ("Jmin", 1280), ("Jmax", 1280),
                      *((f"S{i}", 1280) for i in range(1, 5))):
        lo, hi = _range(result[key], key, high)
        if lo != hi or "-" in result[key]:
            invalid(f"{key}: ожидается одно целое число")
    if int(result["Jmin"]) > int(result["Jmax"]) or (int(result["Jc"]) and int(result["Jmin"]) == int(result["Jmax"])):
        invalid("При Jc > 0 Jmin должен быть < Jmax")
    headers = [_range(result[f"H{i}"], f"H{i}", 2**32 - 1, 1) for i in range(1, 5)]
    for i, (lo, hi) in enumerate(headers):
        if any(lo <= other_hi and other_lo <= hi for other_lo, other_hi in headers[:i]):
            invalid("Диапазоны H1-H4 не должны пересекаться")
    for key in deploy._AWG_CPS_KEYS:
        value = result[key]
        if not value:
            continue
        tags = re.findall(r"<([^<>]+)>", value)
        if not tags or re.sub(r"<[^<>]+>", "", value).strip():
            invalid(f"{key}: ожидается CPS-цепочка <r 20><b 0x1234>")
        length = 0
        for tag in tags:
            parts = tag.split()
            if not parts:
                invalid(f"{key}: CPS-тег не может быть пустым")
            kind, arg = parts[0], parts[1] if len(parts) == 2 else ""
            if kind == "b" and re.fullmatch(r"(?:0x)?(?:[0-9a-fA-F]{2})+", arg):
                length += len(arg.removeprefix("0x")) // 2
            elif kind in ("r", "rc", "rd") and len(arg) <= 4 and arg.isdecimal() and 0 <= int(arg) <= 1280:
                length += int(arg)
            elif kind == "t" and len(parts) == 1:
                length += 4
            elif ver.startswith("3") and kind in ("d", "ds") and len(parts) == 1:
                pass  # CPS has an empty source payload.
            elif ver.startswith("3") and kind == "dz" and arg.isdecimal() and len(arg) <= 2 and 1 <= int(arg) <= 8:
                length += int(arg)
            else:
                invalid(f"{key}: поддерживаются CPS-теги b, r, rc, rd, t")
        if length > 1280:
            invalid(f"{key}: CPS-пакет должен быть <= 1280 байт")
    if ver.startswith("3"):
        try:
            valid_key = len(base64.b64decode(result["HeaderProtectionKey"], validate=True)) == 32
        except ValueError:
            valid_key = False
        if not valid_key:
            invalid("HeaderProtectionKey: ожидается 32-байтный ключ base64")
        if min(int(result[f"S{i}"]) for i in range(1, 5)) < 12:
            invalid("При защите заголовков S1-S4 должны быть >= 12")
        for key in ("ContentPaddingAddition", *deploy._AWG3_TIMING_DEFAULTS):
            _range(result[key], key, 128 if key == "ContentPaddingAddition" else 65535,
                   0 if key == "ContentPaddingAddition" else 1)
        if _range(result["RekeyAfterTime"], "RekeyAfterTime", 65535)[1] >= _range(result["RejectAfterTime"], "RejectAfterTime", 65535)[0]:
            invalid("RejectAfterTime должен полностью превышать RekeyAfterTime")
        if ver == "3.1":
            if any(result[k] not in ("on", "off") for k in ("RandomTrailers", "DisableCookies")):
                invalid("RandomTrailers и DisableCookies: on или off")
            if result["RandomTrailers"] == "on" and len({result[f"S{i}"] for i in range(1, 5)}) != 1:
                invalid("При RandomTrailers = on используйте одинаковые S1-S4 для надежной передачи данных")
    elif int(result["S1"]) + 148 == int(result["S2"]) + 92:
        invalid("S1 + 148 и S2 + 92 должны различаться")
    return result


def network(subnet: str, address: str | None = None, *, existing_address: str | None = None):
    try:
        net = ipaddress.IPv4Network(subnet, strict=True)
        ip = ipaddress.IPv4Address((address or str(net.network_address + 1)).split("/")[0])
        if address and "/" in address and ipaddress.IPv4Interface(address).network != net:
            invalid("Маска адреса интерфейса должна совпадать с подсетью")
    except ValueError:
        invalid("Укажите IPv4-подсеть CIDR и адрес интерфейса внутри нее")
    private = any(net.subnet_of(ipaddress.ip_network(block)) for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not private or not 16 <= net.prefixlen <= 29:
        invalid("Подсеть должна быть частной IPv4 с маской /16../29")
    retained_legacy = existing_address and ipaddress.ip_interface(existing_address) == ipaddress.ip_interface(f"{ip}/{net.prefixlen}")
    if ip not in net or ip == net.broadcast_address or (ip == net.network_address and not retained_legacy):
        invalid("Адрес интерфейса должен быть доступным адресом хоста внутри подсети")
    return net, f"{ip}/{net.prefixlen}"


# Explicit failure markers: absent ip/docker/permission must never mean free.
DISCOVER = r'''set -e
set -o pipefail
sudo -n ss -lnuH >/dev/null
ip -j -4 route show table all
echo ===ADDR===
ip -j -4 address show
echo ===CONTAINERS===
if command -v docker >/dev/null; then
  for n in $(sudo -n docker network ls -q); do
    sudo -n docker network inspect "$n" --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' | sed 's/^/NETWORK=/'
  done
  sudo -n docker ps --format '{{.Names}}' | while read -r c; do
    case "$c" in *awg*|*wireguard*|*openvpn*) :;; *) continue;; esac
    echo "CONTAINER=$c"
    sudo -n docker exec "$c" sh -c 'ip -j -4 route show table all' 2>/dev/null || echo DISCOVERY_ERROR
  done
fi
'''


def discovered_networks(output: str, own: str | None = None) -> list[ipaddress.IPv4Network]:
    nets = []
    section = "host"
    for line in output.splitlines():
        if line.startswith("NETWORK=") and line != "NETWORK=":
            try:
                nets.append(ipaddress.IPv4Network(line.removeprefix("NETWORK=")))
            except ValueError:
                pass  # IPv6 is outside the IPv4 subnet selector.
        if line == "DISCOVERY_ERROR":
            raise HTTPException(409, "Не удалось проверить сети одного из контейнеров")
        if line.startswith("CONTAINER="):
            section = line.removeprefix("CONTAINER=")
        if not line.startswith("[") or section == own:
            continue
        try:
            entries = json.loads(line)
        except ValueError:
            raise HTTPException(409, "Не удалось разобрать список сетей сервера")
        for item in entries:
            candidates = [item.get("dst", "")]
            candidates += [f"{a['local']}/{a['prefixlen']}" for a in item.get("addr_info", []) if a.get("family") == "inet"]
            for value in candidates:
                if value and value != "default":
                    try:
                        net = ipaddress.IPv4Network(value, strict=False)
                    except ValueError:
                        continue
                    if net.prefixlen:
                        nets.append(net)
    return nets


def generate_defaults(ver: str) -> dict:
    values = deploy.generate_awg3_params() if ver.startswith("3") else deploy.generate_awg_params()
    return validate_params({key: values[key] for key in keys(ver)}, ver)


async def choose(conn, body, ver: str, own: str | None = None, *, existing_address: str | None = None):
    result = await conn.run("bash -s", input=DISCOVER, check=False)
    if result.exit_status != 0:
        raise HTTPException(409, "Не удалось проверить сети сервера до изменения")
    occupied = discovered_networks(result.stdout or "", own)
    if body.subnet:
        net, address = network(body.subnet, body.server_address, existing_address=existing_address)
        if any(net.overlaps(n) for n in occupied):
            raise HTTPException(409, "Подсеть пересекается с сетью сервера или другого VPN")
    else:
        if body.server_address:
            invalid("Для ручного адреса интерфейса укажите подсеть")
        preferred = deploy.SUBNET_V3 if ver.startswith("3") else deploy.SUBNET
        choices = [preferred] + [f"10.{a}.{b}.0/24" for a in (8, 9, 73, 147, 231) for b in range(1, 255)]
        selected = next((v for v in choices if not any(ipaddress.ip_network(v).overlaps(n) for n in occupied)), None)
        if selected is None:
            raise HTTPException(409, "Не найдена свободная подсеть, укажите ее вручную")
        net, address = network(selected)
    default_port = 47300 if ver.startswith("3") else 47180
    candidates = [body.port] if body.port else range(default_port, default_port + 100)
    for port in candidates:
        owner = await deploy.port_owner(conn, port, "udp", own=own)
        if not owner:
            params = body.params
            if params is None:
                params = generate_defaults(ver)
            return port, str(net), address, validate_params(params, ver)
    raise HTTPException(409, deploy.port_busy_detail(body.port or default_port, "udp", owner, "AmneziaWG"))


def revision(conf: str) -> str:
    return hashlib.sha256(conf.encode()).hexdigest()


def replace_interface(conf: str, values: dict, *, server=True) -> str:
    """Replace selected interface fields; preserve peer sections/comments/hooks."""
    result, seen, inside = [], set(), False
    for line in conf.splitlines():
        header = awg._conf_header(line)
        if header.startswith("["):
            if inside:
                result += [f"{'# ' if server and k in deploy._AWG_CPS_KEYS else ''}{k} = {v}" for k, v in values.items() if k not in seen and (v or server)]
            inside = header == "[interface]"
        match = re.match(r"^\s*#?\s*([A-Za-z][A-Za-z0-9]*)\s*=", line)
        if match and line.lstrip().startswith("#") and match[1] not in deploy._AWG_CPS_KEYS:
            match = None  # Preserve commented examples and operator notes.
        if inside and match and match[1] in values:
            key = match[1]
            if key not in seen and (values[key] or server):
                result.append(f"{'# ' if server and key in deploy._AWG_CPS_KEYS else ''}{key} = {values[key]}")
            seen.add(key)
        else:
            result.append(line)
    if inside:
        result += [f"{'# ' if server and k in deploy._AWG_CPS_KEYS else ''}{k} = {v}" for k, v in values.items() if k not in seen and (v or server)]
    return "\n".join(result).rstrip() + "\n"


def remap_ip(value: str, old, new, server_ip):
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        invalid("Клиент имеет нестандартный адрес, изменение подсети отменено")
    if ip not in old:
        invalid("Клиент имеет адрес вне прежней подсети, изменение отменено")
    replacement = new.network_address + int(ip) - int(old.network_address)
    if replacement not in new or replacement in (new.network_address, new.broadcast_address, server_ip):
        invalid("В новой подсети не хватает адресов или адрес занят интерфейсом")
    return str(replacement)


def remap_peers(conf: str, old, new, server_ip):
    result = []
    for line in conf.splitlines():
        match = re.match(r"^\s*AllowedIPs\s*=\s*([^/ ]+)/32\s*$", line, re.I)
        if re.match(r"^\s*AllowedIPs\s*=", line, re.I):
            if not match:
                invalid("Клиент имеет нестандартные маршруты, изменение подсети отменено")
            line = f"AllowedIPs = {remap_ip(match[1], old, new, server_ip)}/32"
        result.append(line)
    return "\n".join(result) + "\n"


def refresh_profile(conf: str, params: dict, address: str, port: int, subnet: str):
    interface, peers = awg.parse_conf(conf)
    if not interface.get("PrivateKey") or len(peers) != 1:
        invalid("Сохраненный профиль имеет нестандартный формат, изменение отменено")
    endpoint = peers[0].get("Endpoint", "")
    host, _, _port = endpoint.rpartition(":")
    if not host:
        invalid("Сохраненный профиль не содержит endpoint")
    updated = replace_interface(conf, {**params, "Address": address}, server=False)
    updated = re.sub(r"(?im)^\s*Endpoint\s*=.*$", f"Endpoint = {host}:{port}", updated)
    updated = re.sub(r"(?m)^# ac-subnet = .*\n?", "", updated)
    return f"# ac-subnet = {subnet}\n" + updated


def transaction_id():
    return uuid.uuid4().hex


async def checked(conn, command, *, stdin=None):
    result = await conn.run(command, input=stdin, check=False)
    if result.exit_status != 0:
        # Never return raw engine stderr: it can include the key/config line.
        raise HTTPException(502, "Не удалось применить настройки AmneziaWG; проверьте состояние операции")
    return result.stdout or ""


def managed(info: dict, container: str, proto: str, image_info: dict | None = None, canonical_host: dict | None = None):
    """Only rebuild the exact deployment shape we know how to preserve."""
    expected = deploy.CONTAINER_V3 if proto == "awg3" else deploy.CONTAINER
    host_dir = deploy.HOST_DIR_V3 if proto == "awg3" else awg.AWG_DIR
    image = info.get("Config", {}).get("Image", "").split(":", 1)[0]
    mounts = info.get("Mounts", [])
    host = info.get("HostConfig", {})
    ports = host.get("PortBindings") or {}
    bindings = [b for values in ports.values() for b in values or []]
    networks = info.get("NetworkSettings", {}).get("Networks", {})
    valid = (
        container == expected and image in (deploy.IMAGE, deploy.IMAGE_V3)
        and host.get("NetworkMode") in ("default", "bridge") and set(networks) == {"bridge"}
        and len(mounts) == 1 and mounts[0].get("Type") == "bind"
        and mounts[0].get("Source") == host_dir and mounts[0].get("Destination") == awg.AWG_DIR
        and mounts[0].get("RW") is True and len(ports) == 1 and len(bindings) in (1, 2)
        and all(b.get("HostIp", "") in ("", "0.0.0.0", "::") for b in bindings)
        and host.get("Privileged") is True
        and not host.get("Binds", [host_dir + ":" + awg.AWG_DIR]) == []
        and info.get("Config", {}).get("Entrypoint") == ["/opt/amnezia/start.sh"]
        and host.get("RestartPolicy", {}).get("Name") == "always"
        and not any(host.get(k) for k in ("CapDrop", "Devices", "DeviceRequests", "Tmpfs", "ExtraHosts", "Dns", "DnsSearch", "DnsOptions", "VolumesFrom", "ReadonlyRootfs", "Memory", "NanoCpus", "CpusetCpus", "PidMode", "PortSpecs"))
        and not (set(host.get("SecurityOpt") or []) - {"label=disable"})
        and all(key.endswith("/udp") and all(str(b.get("HostPort")) == key.split("/")[0] for b in values or []) for key, values in ports.items())
    )
    if image_info is not None:
        config, original = info.get("Config", {}), image_info.get("Config", {})
        valid = valid and all((config.get(k) or None) == (original.get(k) or None) for k in (
            "Env", "Entrypoint", "Cmd", "User", "WorkingDir", "Labels", "Healthcheck", "StopSignal"))
    if canonical_host is not None:
        def normalize(value):
            # Port changes are intentional. Docker versions serialize the
            # default bridge mode and empty security options differently.
            value = dict(value)
            value.pop("PortBindings", None)
            if value.get("NetworkMode") == "default":
                value["NetworkMode"] = "bridge"
            for key in ("CapAdd", "SecurityOpt"):
                value[key] = sorted(value.get(key) or [])
            # Docker fills an unspecified OOM-killer default when starting.
            value["OomKillDisable"] = bool(value.get("OomKillDisable"))
            return value
        valid = valid and normalize(host) == normalize(canonical_host)
    if not valid:
        raise HTTPException(409, "Настройки доступны для стандартного контейнера панели без дополнительных сетей и монтирований")
    return host_dir


async def canonical_host(conn, info: dict, host_dir: str, port: int):
    """Inspect a never-started canonical container before touching the server.

    Comparing the complete HostConfig catches custom resource, logging,
    namespace, sysctl, capability and future Docker options we cannot preserve.
    """
    name = "acontrol-settings-shape-" + transaction_id()
    script = f'''set -eu
trap 'docker rm -f {name} >/dev/null 2>&1 || true' EXIT
docker create --name {name} --restart always --privileged \\
  --cap-add NET_ADMIN --cap-add SYS_MODULE \\
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \\
  -v {shlex.quote(host_dir)}:/opt/amnezia/awg -p {int(port)}:{int(port)}/udp \\
  {shlex.quote(info['Image'])} >/dev/null
docker inspect {name} --format '{{{{json .HostConfig}}}}'
'''
    return json.loads(await checked(conn, "sudo -n bash -s", stdin=script))


def runtime(token: str, container: str, host_dir: str, proto: str, port: int, address: str, *, torrent_block: bool = False) -> str:
    """Keep the original stopped container until DB commit; rollback restores it.

    A systemd watchdog handles disconnect/process death. Every action is
    idempotent; a missing result is an unknown outcome, never success.
    """
    if not re.fullmatch(r"[a-f0-9]{32}", token) or container not in (deploy.CONTAINER, deploy.CONTAINER_V3):
        raise ValueError("Invalid transaction")
    net = str(ipaddress.ip_interface(address).network)
    service = "awg3-up.service" if proto == "awg3" else "awg-up.service"
    unit = deploy._systemd_unit_v3() if proto == "awg3" else deploy._systemd_unit()
    start = deploy._start_sh(net)
    policy_readback = ""
    policy_restore_start = ""
    rollback_policy_readback = ""
    from app import torrent
    policy = ('# acontrol-settings-torrent-policy\n'
              'if [ -f /opt/amnezia/awg/.acontrol-torrent-block ]; then\n'
              + torrent.enable_script() + '\n[ "$ok" = 1 ] || exit 1\nfi\n')
    start = start.replace("awg-quick down", policy + "awg-quick down", 1)
    policy_flag = 'touch "$D/.acontrol-torrent-block"' if torrent_block else 'rm -f "$D/.acontrol-torrent-block"'
    if torrent_block:
        policy_readback = (
            f'  docker exec "$C" iptables -C {torrent._JUMP}\n'
            f'  [ "$(docker exec "$C" iptables -S {torrent.CHAIN} | grep -c -- "-j DROP")" = "{len(torrent.SIGNATURES)}" ]\n'
        )
        encoded_policy = base64.b64encode(policy.encode()).decode()
        policy_restore_start = f'''  if grep -q '^# acontrol-settings-torrent-policy$' "$T/original-start.sh"; then
    cp "$T/original-start.sh" "$T/rollback-start.sh" || return 1
  else
    printf %s {shlex.quote(encoded_policy)} | base64 -d > "$T/rollback-start.sh" || return 1
    cat "$T/original-start.sh" >> "$T/rollback-start.sh" || return 1
  fi
  chmod 755 "$T/rollback-start.sh" || return 1
  {policy_flag} || return 1
  docker cp "$T/rollback-start.sh" "$C:/opt/amnezia/start.sh" || return 1
'''
        rollback_policy_readback = policy_readback.replace('\n', ' || return 1\n')
    return f'''#!/bin/bash
set -eu
umask 077
T=/opt/acontrol/settings-backups/{token}
C={container}
OLD={container}-settings-{token}
D={host_dir}
UNIT={service}
WATCH=acontrol-awg-settings-{token}
SCRIPT=/lib65/scripts/acontrol-awg-settings-{token}.sh
exec 9>/run/lock/acontrol-awg-settings-{container}.lock
flock -x 9
state() {{ cat "$T/state" 2>/dev/null || echo missing; }}
mark() {{ printf '%s\\n' "$1" > "$T/state.next"; mv -f "$T/state.next" "$T/state"; }}
readback() {{
  [ "$(docker exec "$C" awg show awg0 listen-port)" = "$1" ] &&
  docker exec "$C" ip -4 address show dev awg0 | grep -Fq "inet $2 "
}}
rollback() {{
  case "$(state)" in rolledback|prepared) return 0;; committed) return 1;; esac
  if docker inspect "$OLD" >/dev/null 2>&1; then
    docker rm -f "$C" >/dev/null 2>&1 || true
    cp -a "$T/config/." "$D/" || return 1
    if [ -f "$T/unit" ]; then cp -a "$T/unit" "/etc/systemd/system/$UNIT" || return 1; fi
    systemctl daemon-reload || return 1
    docker rename "$OLD" "$C" || return 1
{policy_restore_start.rstrip()}
    docker start "$C" >/dev/null || return 1
  else
    # Failure before rename/stop must not remove the working container.
    docker inspect "$C" >/dev/null || return 1
    cp -a "$T/config/." "$D/" || return 1
{policy_restore_start.rstrip()}
    docker start "$C" >/dev/null || return 1
  fi
  sleep 2
  readback "$(cat "$T/old-port")" "$(cat "$T/old-address")" || return 1
{rollback_policy_readback.rstrip()}
  if [ -f "$T/ufw-added" ]; then ufw delete allow {port}/udp >/dev/null || return 1; fi
  if [ -f "$T/firewalld-added" ]; then
    firewall-cmd --permanent --remove-port={port}/udp >/dev/null || return 1
    firewall-cmd --reload >/dev/null || return 1
  fi
  mark rolledback
}}
case "$1" in
 status) state;;
 prepare)
  mkdir -p "$T"
  [ ! -f "$T/state" ] || exit 0
  cp -a "$D" "$T/config"
  docker cp "$C:/opt/amnezia/start.sh" "$T/original-start.sh"
  docker inspect "$C" --format '{{{{.Image}}}}' > "$T/image"
  docker inspect "$C" --format '{{{{.Config.Image}}}}' > "$T/image-ref"
  docker exec "$C" awg show awg0 listen-port > "$T/old-port"
  docker exec "$C" ip -4 -o addr show dev awg0 | awk '{{print $4; exit}}' > "$T/old-address"
  [ ! -f "/etc/systemd/system/$UNIT" ] || cp -a "/etc/systemd/system/$UNIT" "$T/unit"
  if command -v ufw >/dev/null && ufw show added | grep -Fqx 'ufw allow {port}/udp'; then touch "$T/ufw-existed"; fi
  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --query-port={port}/udp >/dev/null; then touch "$T/firewalld-existed"; fi
  mark prepared;;
 apply)
  case "$(state)" in applied|committed) readback {port} {address}; exit;; prepared) :;; *) exit 1;; esac
  # Validate in a separate network namespace before touching the live interface.
  # The probe uses the installed binaries and has no host publication.
  PROBE="$C-settings-probe-{token}"
  cleanup_probe() {{ docker rm -f "$PROBE" >/dev/null 2>&1 || true; }}
  trap cleanup_probe EXIT
  docker run -d --name "$PROBE" --network none --privileged \\
    --entrypoint /bin/sh "$(cat "$T/image")" -c 'sleep 120' >/dev/null
  docker cp "$T/candidate.conf" "$PROBE:/tmp/awg0.conf"
  docker exec "$PROBE" sh -c 'awg-quick up /tmp/awg0.conf >/dev/null 2>&1' >/dev/null 2>&1
  cleanup_probe
  trap - EXIT
  systemd-run --quiet --unit="$WATCH" --on-active=180s /bin/bash "$SCRIPT" rollback
  mark changing
  trap 'trap - ERR; rollback || mark rollback_failed; exit 1' ERR
  docker stop "$C" >/dev/null
  docker rename "$C" "$OLD"
  cp -f "$T/candidate.conf" "$D/awg0.conf"
  cp -f "$T/candidate.table" "$D/clientsTable"
  chmod 600 "$D/awg0.conf" "$D/clientsTable"
  {policy_flag}
  printf '%s' {shlex.quote(base64.b64encode(start.encode()).decode())} | base64 -d > "$T/start.sh"
  chmod 755 "$T/start.sh"
  [ "$(docker image inspect "$(cat "$T/image-ref")" --format '{{{{.Id}}}}')" = "$(cat "$T/image")" ]
  docker create --name "$C" --restart always --privileged \\
    --cap-add NET_ADMIN --cap-add SYS_MODULE \\
    --sysctl net.ipv4.conf.all.src_valid_mark=1 \\
    -v "$D":/opt/amnezia/awg -p {port}:{port}/udp "$(cat "$T/image-ref")" >/dev/null
  docker cp "$T/start.sh" "$C:/opt/amnezia/start.sh"
  docker start "$C" >/dev/null
  printf '%s' {shlex.quote(base64.b64encode(unit.encode()).decode())} | base64 -d > "/etc/systemd/system/$UNIT"
  systemctl daemon-reload
  sleep 2
  readback {port} {address}
{policy_readback.rstrip()}
  if command -v ufw >/dev/null; then
    [ -f "$T/ufw-existed" ] || touch "$T/ufw-added"
    ufw allow {port}/udp >/dev/null
  fi
  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    [ -f "$T/firewalld-existed" ] || touch "$T/firewalld-added"
    firewall-cmd --permanent --add-port={port}/udp >/dev/null
    firewall-cmd --reload >/dev/null
  fi
  mark applied;;
 rollback)
  rollback
  systemctl stop "$WATCH.timer" >/dev/null 2>&1 || true;;
 finalize)
  case "$(state)" in committed) exit 0;; applied) :;; *) exit 1;; esac
  readback {port} {address}
  mark committed
  systemctl stop "$WATCH.timer" >/dev/null 2>&1 || true
  docker rm "$OLD" >/dev/null 2>&1 || true;;
 *) exit 1;;
esac
'''


async def remote_action(conn, token: str, action: str):
    if not re.fullmatch(r"[a-f0-9]{32}", token) or action not in ("prepare", "apply", "rollback", "finalize", "status"):
        raise ValueError("Invalid transaction action")
    path = f"/lib65/scripts/acontrol-awg-settings-{token}.sh"
    command = f"sudo -n bash {path} {action}"
    if action == "status":
        command = f"if sudo -n test -f {path}; then {command}; else echo missing; fi"
    return (await checked(conn, command)).strip()
