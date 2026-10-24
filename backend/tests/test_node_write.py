"""Запись файлов на ноду (XRay, OpenVPN) проверяет код возврата."""

import pytest

from app import openvpn, xray


class _Conn:
    def __init__(self, rc: int):
        self.rc = rc
        self.cmds: list[str] = []

    async def run(self, cmd, input=None, check=False):  # noqa: A002
        self.cmds.append(cmd)
        return type("R", (), {"exit_status": self.rc, "stderr": "No space left on device", "stdout": ""})()


@pytest.mark.parametrize(
    ("mod", "err"), [(xray, xray.XrayError), (openvpn, openvpn.OpenVpnError)]
)
async def test_write_file_raises_on_failure(mod, err):
    conn = _Conn(1)
    with pytest.raises(err, match="No space left"):
        await mod._write_file(conn, "amnezia-x", "/opt/amnezia/x/clientsTable", "[]")
    # пишем во временный файл и только потом подменяем, старый не затирается
    assert "clientsTable.acontrol-tmp && { mv -f" in conn.cmds[0]


@pytest.mark.parametrize("mod", [xray, openvpn])
async def test_write_file_ok(mod):
    conn = _Conn(0)
    await mod._write_file(conn, "amnezia-x", "/opt/amnezia/x/clientsTable", "[]")
    assert len(conn.cmds) == 1
