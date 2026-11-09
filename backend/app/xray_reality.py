"""Inspect and change the TLS camouflage of a running VLESS inbound."""

import asyncio
import hashlib
import ipaddress
import json
import re
import shlex
import uuid
from dataclasses import dataclass

import asyncssh
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app import deploy, xray
from app.schemas import XrayDeployRequest


class RealityConflict(xray.XrayError):
    """The running configuration cannot be edited safely."""


class RealityValidation(xray.XrayError):
    """The proposed target did not pass validation."""


class RealityUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    inbound_index: int = Field(ge=0)
    site: str = Field(min_length=1, max_length=254)
    dest: str = Field(min_length=1, max_length=260)

    @field_validator("site", "dest")
    @classmethod
    def normalize(cls, value: str, info) -> str:
        normalizer = (
            XrayDeployRequest.normalize_site if info.field_name == "site"
            else XrayDeployRequest.normalize_dest
        )
        if normalized := normalizer(value):
            return normalized
        raise ValueError("Both SNI and Dest are required")


class RealityInbound(BaseModel):
    index: int
    tag: str
    port: int | None
    published_ports: list[int]
    server_names: list[str]
    destination: str | None
    destination_port: int | None
    destination_field: str | None
    public_key: str | None
    short_ids: list[str]
    editable: bool


class RealityState(BaseModel):
    revision: str
    inbounds: list[RealityInbound]


@dataclass
class _Document:
    container_id: str
    bindings: dict
    raw: str
    server: dict

    @property
    def revision(self) -> str:
        return hashlib.sha256(f"{self.container_id}:{self.raw}".encode()).hexdigest()


async def _remote(conn, command: str, *, payload: str | None = None):
    try:
        return await conn.run(command, input=payload, check=False)
    except (asyncssh.Error, OSError):
        # Neither SSH command diagnostics nor Xray validation output are safe to echo.
        raise xray.XrayError("Не удалось завершить операцию REALITY по SSH") from None


async def _read_document(conn, container: str) -> _Document:
    fmt = "{{.Id}}|{{json .HostConfig.PortBindings}}"
    meta = await _remote(
        conn,
        xray._DOCKER + f"$DOCKER inspect -f {shlex.quote(fmt)} {shlex.quote(container)}",
    )
    container_id, _, raw_bindings = (meta.stdout or "").strip().partition("|")
    if meta.exit_status != 0 or not re.fullmatch(r"[a-f0-9]{64}", container_id):
        raise xray.XrayError("Не удалось прочитать состояние контейнера Xray")
    result = await _remote(conn, xray._docker_exec(container_id, f"cat {xray.SERVER_JSON}"))
    try:
        bindings = json.loads(raw_bindings)
        raw = result.stdout or ""
        server = json.loads(raw)
    except ValueError:
        raise xray.XrayError("Не удалось прочитать конфигурацию REALITY") from None
    if (
        result.exit_status != 0 or not isinstance(server, dict)
        or (bindings is not None and not isinstance(bindings, dict))
    ):
        raise xray.XrayError("Не удалось прочитать конфигурацию REALITY")
    return _Document(container_id, bindings or {}, raw, server)


def _port(value: object) -> int | None:
    if re.fullmatch(r"[0-9]{1,5}", str(value)) and 1 <= int(value) <= 65535:
        return int(value)
    return None


def _listener(inbound: dict) -> str | None:
    port = _port(inbound.get("port"))
    listen = inbound.get("listen") or "0.0.0.0"
    if port is None or not isinstance(listen, str):
        return None
    try:
        address = ipaddress.ip_address(listen)
    except ValueError:
        return None
    if address.version == 4:
        return f"{address if not address.is_unspecified else '127.0.0.1'}:{port}"
    return f"[{address if not address.is_unspecified else '::1'}]:{port}"


def _settings(server: dict):
    inbounds = server.get("inbounds")
    if not isinstance(inbounds, list):
        return
    for index, inbound in enumerate(inbounds):
        if not isinstance(inbound, dict) or inbound.get("protocol") != "vless":
            continue
        stream = inbound.get("streamSettings")
        if not isinstance(stream, dict) or str(stream.get("security")).lower() != "reality":
            continue
        if isinstance(reality := stream.get("realitySettings"), dict):
            yield index, inbound, stream, reality


def _names_supported(names: list[str]) -> bool:
    if not names:
        return False
    try:
        return all(XrayDeployRequest.normalize_site(name) for name in names)
    except ValueError:
        return False


def _can_edit(
    inbound: dict, stream: dict, reality: dict, names: list[str], destination: str | None,
) -> bool:
    if (
        not destination or not _listener(inbound)
        or not _names_supported(names)
        or reality.get("xver") not in (None, 0)
        or reality.get("type") not in (None, "", "tcp")
        or (reality.get("target") is not None and reality.get("dest") is not None
            and reality["target"] != reality["dest"])
    ):
        return False
    try:
        if not XrayDeployRequest.normalize_dest(destination):
            return False
    except ValueError:
        return False
    method = str(stream.get("method") or stream.get("network") or "tcp").lower()
    if method not in {"tcp", "raw", "xhttp", "splithttp", "grpc"}:
        return False
    return not any(
        isinstance(options := stream.get(key), dict) and options.get("acceptProxyProtocol")
        for key in ("sockopt", "rawSettings", "tcpSettings", "xhttpSettings", "splithttpSettings")
    )


def _public_state(doc: _Document) -> RealityState:
    views = []
    for index, inbound, stream, reality in _settings(doc.server):
        port = _port(inbound.get("port"))
        entries = doc.bindings.get(f"{port}/tcp") or []
        published = {
            item_port for item in entries
            if isinstance(item, dict) and (item_port := _port(item.get("HostPort"))) is not None
        }
        field = "target" if reality.get("target") is not None else "dest"
        value = reality.get(field)
        destination = str(value) if type(value) in (str, int) else None
        dest_port = None
        if destination:
            dest_port = _port(destination) if ":" not in destination else _port(destination.rsplit(":", 1)[1])
        names = reality.get("serverNames")
        names = names if isinstance(names, list) and all(isinstance(n, str) for n in names) else []
        short_ids = reality.get("shortIds")
        short_ids = [
            sid for sid in short_ids if isinstance(sid, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", sid)
        ] if isinstance(short_ids, list) else []
        public_key = xray.reality_public_key(reality.get("privateKey"))
        views.append(RealityInbound(
            index=index,
            tag=inbound["tag"] if isinstance(inbound.get("tag"), str) else "",
            port=port,
            published_ports=sorted(published),
            server_names=names,
            destination=destination,
            destination_port=dest_port,
            destination_field=field if destination is not None else None,
            public_key=public_key,
            short_ids=short_ids,
            editable=bool(public_key and short_ids and _can_edit(inbound, stream, reality, names, destination)),
        ))
    return RealityState(revision=doc.revision, inbounds=views)


async def read(conn, container: str) -> RealityState:
    return _public_state(await _read_document(conn, container))


def _tls_check(address: str, name: str) -> str:
    return (
        'TLS_RESULT=$(LC_ALL=C timeout 8 openssl s_client -tls1_3 -alpn h2 '
        f'-connect {shlex.quote(address)} -servername {shlex.quote(name)} '
        f'-verify_hostname {shlex.quote(name)} -verify_return_error </dev/null 2>&1) '
        """&& printf '%s\n' "$TLS_RESULT" | grep -Fxq 'ALPN protocol: h2'"""
    )


async def _check_target(conn, container_id: str, dest: str, name: str) -> None:
    result = await _remote(conn, xray._docker_exec(container_id, _tls_check(dest, name)))
    if result.exit_status != 0:
        raise RealityValidation(f"Цель REALITY не прошла проверку TLS 1.3 и HTTP/2 для SNI {name}")


def _apply_script(
    container_id: str, old_hash: str, new_hash: str, listener: str,
    names: list[str], old_site: str,
) -> str:
    # A host-side copy remains accessible if a bad start stops the container.
    path = xray.SERVER_JSON
    directory, _, filename = path.rpartition("/")
    directory = directory or "."
    staged = f"{path}.acontrol-reality.{uuid.uuid4().hex}.json"
    backup = f"{staged}.previous"
    read_hash = f'ACTUAL=$(sha256sum {path}) && [ "${{ACTUAL%% *}}" ='
    running = (
        'for P in /proc/[0-9]*; do '
        '[ "$(cat "$P/comm" 2>/dev/null)" = xray ] || continue; '
        r"""ARGS=$(tr '\000' '\n' < "$P/cmdline" 2>/dev/null) || continue; """
        r"""[ "$(printf '%s\n' "$ARGS" | grep -Ec '^--?(c|config)(=|$)')" = 1 ] || continue; """
        r"""printf '%s\n' "$ARGS" | grep -Eq '^--?confdir(=|$)' && continue; """
        r"""printf '%s\n' "$ARGS" | """
        f"grep -Fxq -e {path} -e -config={path} -e -c={path} "
        f"-e --config={path} -e --c={path} && exit 0; done; exit 1"
    )
    stage = (
        f'[ ! -L {path} ] && {read_hash} {old_hash} ] '
        f'&& cp -p {path} {backup} && cp -p {path} {staged} '
        f'&& cat > {staged} && xray run -test -config {staged}'
    )
    install = f'{read_hash} {old_hash} ] && mv -f {staged} {path}'
    verify = f'{read_hash} {new_hash} ] && ({running}) && ' + " && ".join(
        _tls_check(listener, name) for name in names
    )
    restore = f'{read_hash} {new_hash} ] && mv -f {backup} {path}'
    verify_old = f'{read_hash} {old_hash} ] && ({running}) && ' + _tls_check(listener, old_site)
    return xray._DOCKER + f"""C={container_id}
exec 2>/dev/null
umask 077
WORK=$(mktemp -d) || {{ echo BACKUP_FAILED; exit 1; }}
hash_archive() {{
    # Extract only the bytes. The SSH user need not own the original root-only file.
    tar -xOf "$1" {filename} > "$WORK/contents" || return 1
    HASH=$(sha256sum "$WORK/contents") || return 1
    HASH=${{HASH%% *}}
    rm -f "$WORK/contents"
}}
read_current_hash() {{
    timeout 20 $DOCKER cp "$C:{path}" - > "$WORK/current.tar" || return 1
    hash_archive "$WORK/current.tar" || return 1
    CURRENT=$HASH
}}
restore_config() {{
    if timeout 20 $DOCKER exec "$C" sh -c {shlex.quote(restore)}; then return 0; fi
    read_current_hash || return 1
    [ "$CURRENT" = {old_hash} ] && return 0
    [ "$CURRENT" = {new_hash} ] &&
        [ "$(timeout 10 $DOCKER inspect -f '{{{{.State.Running}}}}' "$C")" = false ] &&
        timeout 20 $DOCKER cp -a - "$C:{directory}" < "$WORK/original.tar"
}}
cleanup() {{
    if [ "$INSTALL_STARTED" = 1 ]; then
        # Remove the source before checking the destination. A delayed rename can no longer apply it.
        if ! timeout 15 $DOCKER exec "$C" rm -f {staged} >/dev/null &&
            [ "$(timeout 10 $DOCKER inspect -f '{{{{.State.Running}}}}' "$C")" != false ]; then
            echo REVERT_FAILED
            return
        fi
        if ! read_current_hash; then
            echo REVERT_FAILED
            return
        fi
        if [ "$CURRENT" = {new_hash} ]; then
            if restore_config >/dev/null &&
                timeout 30 $DOCKER restart -t 5 "$C" >/dev/null &&
                sleep 1 &&
                timeout 15 $DOCKER exec "$C" sh -c {shlex.quote(verify_old)} >/dev/null; then
                echo REVERTED
            else
                echo REVERT_FAILED
                return
            fi
        elif [ "$CURRENT" != {old_hash} ]; then
            echo REVERT_FAILED
            return
        fi
    fi
    timeout 15 $DOCKER exec "$C" rm -f {staged} {backup} >/dev/null
    rm -f "$WORK/original.tar" "$WORK/current.tar" "$WORK/contents"
    rmdir "$WORK"
}}
INSTALL_STARTED=0
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
timeout 10 $DOCKER exec "$C" sh -c {shlex.quote(running)} >/dev/null ||
    {{ echo ACTIVE_CONFIG_UNSUPPORTED; exit 1; }}
timeout 20 $DOCKER cp "$C:{path}" - > "$WORK/original.tar" ||
    {{ echo BACKUP_FAILED; exit 1; }}
hash_archive "$WORK/original.tar" && [ "$HASH" = {old_hash} ] ||
    {{ echo BACKUP_FAILED; exit 1; }}
timeout 30 $DOCKER exec -i "$C" sh -c {shlex.quote(stage)} >/dev/null ||
    {{ echo VALIDATION_FAILED; exit 1; }}
INSTALL_STARTED=1
timeout 20 $DOCKER exec "$C" sh -c {shlex.quote(install)} >/dev/null ||
    {{ echo WRITE_FAILED; exit 1; }}
timeout 30 $DOCKER restart -t 5 "$C" >/dev/null || exit 1
sleep 1
timeout 45 $DOCKER exec "$C" sh -c {shlex.quote(verify)} >/dev/null || exit 1
INSTALL_STARTED=0
echo UPDATED
"""


async def update(conn, container: str, body: RealityUpdate, node_host: str) -> tuple[RealityState, bool]:
    await deploy.ensure_idle(conn, tag="xray")
    doc = await _read_document(conn, container)
    state = _public_state(doc)
    if body.revision != state.revision:
        raise RealityConflict("Конфигурация Xray изменилась. Откройте настройки REALITY заново.")
    selected = next((item for item in state.inbounds if item.index == body.inbound_index), None)
    if selected is None or not selected.editable:
        raise RealityConflict("Для этого входа доступен только просмотр настроек REALITY")
    inbound = doc.server["inbounds"][body.inbound_index]
    listener = _listener(inbound)
    reality = inbound["streamSettings"]["realitySettings"]
    names = [body.site, *(name for name in selected.server_names if name != body.site)]
    if names == selected.server_names and body.dest == selected.destination:
        return state, False
    host, _, port = body.dest.rpartition(":")
    local = {node_host.lower().rstrip("."), "localhost", listener.rsplit(":", 1)[0]}
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        address = getattr(address, "ipv4_mapped", None) or address
        if address.is_loopback or address.is_unspecified:
            local.add(host)
    except ValueError:
        pass
    if host in local and int(port) in {selected.port, *selected.published_ports}:
        raise RealityValidation("Цель REALITY совпадает с адресом самого входа Xray")
    results = await asyncio.gather(
        *(_check_target(conn, doc.container_id, body.dest, name) for name in dict.fromkeys(names)),
        return_exceptions=True,
    )
    for result in results:
        if isinstance(result, BaseException):
            raise result
    if not await deploy.snapshot_config(conn, "xray", container=container):
        raise xray.XrayError("Не удалось сохранить резервную копию Xray перед изменением REALITY")
    for field in ("target", "dest"):
        if reality.get(field) is not None:
            reality[field] = body.dest
    reality["serverNames"] = names
    payload = json.dumps(doc.server, ensure_ascii=False, indent=4) + "\n"
    command = _apply_script(
        doc.container_id, hashlib.sha256(doc.raw.encode()).hexdigest(),
        hashlib.sha256(payload.encode()).hexdigest(), listener,
        list(dict.fromkeys(names)), selected.server_names[0],
    )
    result = await _remote(conn, command, payload=payload)
    marker = (result.stdout or "").strip().splitlines()[-1:]
    if result.exit_status == 0 and marker == ["UPDATED"]:
        return await read(conn, container), True
    if marker == ["ACTIVE_CONFIG_UNSUPPORTED"]:
        raise RealityConflict("Запущенный Xray использует другую схему загрузки конфигурации")
    if marker == ["VALIDATION_FAILED"]:
        raise RealityValidation("Xray не принял новую конфигурацию REALITY. Настройки сохранены.")
    if marker in (["WRITE_FAILED"], ["BACKUP_FAILED"]):
        raise xray.XrayError("Не удалось подготовить запись настроек REALITY")
    if marker == ["REVERTED"]:
        raise xray.XrayError("Xray не прошел проверку после перезапуска. Прежняя конфигурация восстановлена.")
    raise xray.XrayError("Изменение REALITY прервано. Проверьте Xray и резервную копию конфигурации.")
