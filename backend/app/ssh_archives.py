"""Validate archived SSH policy without making network or node changes."""
import os
import posixpath
import re
import tempfile
from pathlib import Path

import asyncssh

from app import ssh_host
from app.schemas import SshAccessFields

POLICY_FIELDS = ("ssh_source_mode", "ssh_source_ips", "ssh_firewall_mode")
PRIVATE_JUMP = re.compile(r"jump_[1-9][0-9]*\Z")


def validate_path(root: Path, member_name: str) -> None:
    if "\\" in member_name:
        raise ValueError("В архиве неверный разделитель пути")
    canonical = posixpath.normpath(member_name)
    if not re.fullmatch(r"data/ssh/(?:id_ed25519(?:\.pub)?|known_hosts|jump_[1-9][0-9]*)", canonical):
        return
    if canonical != member_name:
        raise ValueError("В архиве неканонический путь файла доступа SSH")
    target = root / member_name.removeprefix("data/")
    for path in (target, *target.parents):
        if path == root:
            break
        if path.is_symlink():
            raise ValueError("Файлы доступа SSH нельзя восстанавливать через символическую ссылку")


def policy(row: dict) -> dict:
    candidate = {field: row[field] for field in POLICY_FIELDS if field in row}
    try:
        return SshAccessFields.model_validate(candidate, strict=True).model_dump(exclude={"ssh_jump_server_id"})
    except ValueError as exc:
        raise ValueError("Неверная политика доступа SSH в архиве") from exc


def validate_endpoint(row: dict) -> None:
    if not ssh_host.valid(row.get("host")):
        raise ValueError("В архиве неверный адрес сервера SSH")
    port = row.get("ssh_port", 22)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("В архиве неверный SSH-порт сервера")


def validate_servers(rows: list[dict]) -> None:
    """Reject dangling or chained hops before replacing any database rows."""
    by_id = {}
    for row in rows:
        validate_endpoint(row)
        sid = row.get("id")
        if type(sid) is not int or sid <= 0 or sid in by_id:
            raise ValueError("Неверные идентификаторы серверов в архиве")
        jump = row.get("ssh_jump_server_id")
        if jump is not None and (type(jump) is not int or jump <= 0):
            raise ValueError("Неверная промежуточная нода SSH в архиве")
        row.update(policy(row))
        by_id[sid] = row
    for sid, row in by_id.items():
        jump = row.get("ssh_jump_server_id")
        if jump is not None and (jump == sid or jump not in by_id or by_id[jump].get("ssh_jump_server_id") is not None):
            raise ValueError("Маршрут SSH в архиве должен содержать одну существующую прямую промежуточную ноду")


def validate_keys(tar, files: dict, data_dir: str, rows: list[dict]) -> list[int]:
    required = {"jump_" + str(row["id"]) for row in rows if row.get("ssh_jump_server_id") is not None}
    if not required:
        return []
    routes = {row["id"]: row for row in rows if row.get("ssh_jump_server_id") is not None}
    pending = set()
    unprepared = {sid for sid, row in routes.items() if row.get("last_check_ok") is not True}
    required.add("id_ed25519")
    root = Path(data_dir).resolve()
    parsed = {}
    for name in required:
        target = (root / "ssh" / name).resolve()
        member = files.get(target)
        if member is None and name.startswith("jump_") and int(name[5:]) in unprepared:
            pending.add(int(name[5:]))
            continue
        if member is None or member.name != "data/ssh/" + name or member.size > 32768:
            raise ValueError("В архиве нет ключей для сохраненного маршрута SSH")
        try:
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError()
            with stream:
                parsed[name] = asyncssh.import_private_key(stream.read())
        except (ValueError, asyncssh.KeyImportError) as exc:
            raise ValueError("В архиве поврежден ключ маршрута SSH") from exc
    try:
        pub = files[(root / "ssh/id_ed25519.pub").resolve()]
        if pub.name != "data/ssh/id_ed25519.pub" or pub.size > 32768:
            raise ValueError()
        with tar.extractfile(pub) as stream:
            public = asyncssh.import_public_key(stream.read()).export_public_key().strip()
        if public != parsed["id_ed25519"].export_public_key().strip():
            raise ValueError()
        known = files.get((root / "ssh/known_hosts").resolve())
        if known is None:
            lines = []
        else:
            if known.name != "data/ssh/known_hosts" or known.size > 1024 * 1024:
                raise ValueError()
            with tar.extractfile(known) as stream:
                lines = stream.read().decode("utf-8").splitlines()
        trusted = set()
        for line in lines:
            words = line.split()
            if not words or words[0].startswith("#"):
                continue
            if len(words) < 3:
                raise ValueError()
            asyncssh.import_public_key(" ".join(words[1:3]))
            trusted.update(words[0].split(","))
        by_id = {row["id"]: row for row in rows}
        for row in rows:
            if row.get("ssh_jump_server_id") is None:
                continue
            for node in (row, by_id[row["ssh_jump_server_id"]]):
                host, port = node["host"], node.get("ssh_port", 22)
                token = host if port == 22 else f"[{host}]:{port}"
                if token not in trusted:
                    if row["id"] not in unprepared:
                        raise ValueError()
                    pending.add(row["id"])
    except (KeyError, ValueError, TypeError, asyncssh.KeyImportError) as exc:
        raise ValueError("В архиве нет согласованной пары ключей и доверенных host-ключей для маршрута SSH") from exc
    return sorted(pending)


def missing_key_files(files: dict, data_dir: str) -> list[Path]:
    """Old panel-local identities must not attach to IDs from another archive."""
    root = Path(data_dir).resolve()
    ssh = root / "ssh"
    if not ssh.is_dir():
        return []
    stale = []
    for path in ssh.iterdir():
        if not (PRIVATE_JUMP.fullmatch(path.name) or path.name == "known_hosts"):
            continue
        validate_path(root, "data/ssh/" + path.name)
        if not path.is_file():
            raise ValueError("В каталоге SSH некорректный тип файла ключа или доверенных отпечатков")
        if path not in files:
            stale.append(path)
    return stale


def is_private_key(archive_path: str) -> bool:
    name = archive_path.removeprefix("data/ssh/")
    return name != archive_path and (name == "id_ed25519" or PRIVATE_JUMP.fullmatch(name) is not None)


def restore_file(dest: Path, member, tar, data_dir: str) -> None:
    """Private keys never appear as 0644 or as partially written key files."""
    private = is_private_key(member.name)
    validate_path(Path(data_dir).resolve(), member.name)
    if private and dest != Path(data_dir).resolve() / member.name.removeprefix("data/"):
        raise ValueError("Неверный путь восстановления приватного ключа SSH")
    src = tar.extractfile(member)
    if src is None:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not private:
        with src, dest.open("wb") as stream:
            stream.write(src.read())
        return
    os.chmod(dest.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".restore-key-", dir=dest.parent)
    try:
        with src, os.fdopen(fd, "wb") as stream:
            stream.write(src.read())
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, dest)
    finally:
        Path(temporary).unlink(missing_ok=True)
