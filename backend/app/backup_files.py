"""Stage full-panel restore files and compensate a rejected database update."""

import json
import logging
import os
import shutil
import stat
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from app import ssh_archives

WORK_PREFIX = ".panel-restore-"
log = logging.getLogger(__name__)


@dataclass
class RestoreCopies:
    directory: Path | None = None
    retain: bool = False


class RestoreRollbackError(OSError):
    pass


def _mkdir(directory: Path, created: list[Path]) -> None:
    missing = []
    while not directory.exists():
        missing.append(directory)
        directory = directory.parent
    for path in reversed(missing):
        path.mkdir()
        created.append(path)


@contextmanager
def replace_files(data_dir: str, files: dict[Path, tarfile.TarInfo],
                  stale: list[Path], tar: tarfile.TarFile):
    """Keep original files available until the database outcome is known."""
    copies = RestoreCopies()
    if not files and not stale:
        yield copies
        return

    root = Path(data_dir).resolve()
    ssh_dir = root / "ssh"
    created: list[Path] = []
    applied: list[tuple[Path, Path | None]] = []
    old_ssh_mode = None
    changed_ssh_mode = False
    complete = False
    try:
        _mkdir(root, created)
        # Keep the workspace on the data volume and inaccessible to other users.
        # mkdtemp creates 0700 storage and does not clean it up after a lost ACK.
        work = copies.directory = Path(tempfile.mkdtemp(prefix=WORK_PREFIX, dir=root))
        incoming = work / "incoming"
        originals = work / "original"
        previous: dict[Path, Path] = {}
        private_keys = any(ssh_archives.is_private_key(member.name) for member in files.values())
        if private_keys and ssh_dir.exists():
            old_ssh_mode = stat.S_IMODE(ssh_dir.stat().st_mode)

        for dest, member in files.items():
            ssh_archives.validate_path(root, member.name)
            relative = dest.relative_to(root)
            staged = incoming / relative
            ssh_archives.restore_file(staged, member, tar, str(incoming))
            if dest.exists():
                original = originals / relative
                original.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dest, original)
                previous[dest] = original
                if not ssh_archives.is_private_key(member.name):
                    os.chmod(staged, stat.S_IMODE(original.stat().st_mode))

        # Retained copies are usable for manual reconciliation. Their paths
        # mirror data/, and the manifest identifies newly installed files.
        (work / "changes.json").write_text(json.dumps({
            "replace": [path.relative_to(root).as_posix() for path in files],
            "remove": [path.relative_to(root).as_posix() for path in stale],
            "new": [path.relative_to(root).as_posix() for path in files if path not in previous],
            "ssh_directory_mode": old_ssh_mode,
        }), encoding="utf-8")

        for dest, member in files.items():
            _mkdir(dest.parent, created)
            if ssh_archives.is_private_key(member.name) and not changed_ssh_mode:
                os.chmod(ssh_dir, 0o700)
                changed_ssh_mode = True
            os.replace(incoming / dest.relative_to(root), dest)
            applied.append((dest, previous.get(dest)))
        for dest in stale:
            if dest.exists():
                original = originals / dest.relative_to(root)
                original.parent.mkdir(parents=True, exist_ok=True)
                os.replace(dest, original)
                applied.append((dest, original))

        yield copies
        complete = True
    except BaseException:
        if not copies.retain:
            errors = []
            for path, original in reversed(applied):
                try:
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        os.replace(original, path)
                except OSError as exc:
                    errors.append(exc)
            if changed_ssh_mode and old_ssh_mode is not None:
                try:
                    os.chmod(ssh_dir, old_ssh_mode)
                except OSError as exc:
                    errors.append(exc)
            if errors:
                copies.retain = True
                raise RestoreRollbackError(copies.directory.name) from errors[0]
        raise
    finally:
        if copies.retain:
            log.error("Panel restore needs manual reconciliation; original files kept in %s", copies.directory)
        else:
            if copies.directory is not None:
                try:
                    shutil.rmtree(copies.directory)
                except OSError:
                    log.warning("Could not remove panel restore workspace %s", copies.directory, exc_info=True)
            if not complete:
                for path in reversed(created):
                    try:
                        path.rmdir()
                    except OSError:
                        log.warning("Could not remove directory created by failed restore %s", path, exc_info=True)
