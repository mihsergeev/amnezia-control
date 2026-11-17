import os
import hashlib
from pathlib import Path

import asyncssh

KEY_COMMENT = "acontrol-panel"


def key_paths(data_dir: str) -> tuple[Path, Path]:
    ssh_dir = Path(data_dir) / "ssh"
    return ssh_dir / "id_ed25519", ssh_dir / "id_ed25519.pub"


def ensure_panel_key(data_dir: str) -> str:
    """Создаёт ключ панели при первом старте; возвращает публичный ключ."""
    key_path, pub_path = key_paths(data_dir)
    if not key_path.exists():
        key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(key_path.parent, 0o700)
        except OSError:
            pass
        key = asyncssh.generate_private_key("ssh-ed25519", comment=KEY_COMMENT)
        # атомарно создаём приватный ключ сразу с правами 0600 (без окна 0644)
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.export_private_key())
        pub_path.write_bytes(key.export_public_key())
    return pub_path.read_text().strip()


def jump_key_path(key_path: Path, server_id: int) -> Path:
    if not isinstance(server_id, int) or server_id <= 0:
        raise ValueError("Некорректная цель SSH")
    return key_path.parent / f"jump_{server_id}"


def ensure_jump_key(key_path: Path, server_id: int) -> str:
    path = jump_key_path(key_path, server_id)
    if not path.exists():
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = asyncssh.generate_private_key("ssh-ed25519", comment=f"acontrol-jump-{server_id}")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as fh:
                fh.write(key.export_private_key())
    return asyncssh.read_private_key(path).export_public_key().decode().strip()


def jump_username(key_path: Path, server_id: int) -> str:
    public = asyncssh.read_private_key(jump_key_path(key_path, server_id)).export_public_key()
    return "acj" + hashlib.sha256(public.split()[1]).hexdigest()[:24]
