import os
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
