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


class _OvpnConn:
    """Нода OpenVPN: отвечает на revoke, clientsTable, статус-лог и рестарт."""

    def __init__(self, online: str):
        self.online = online
        self.cmds: list[str] = []

    async def run(self, cmd, input=None, check=False):  # noqa: A002
        self.cmds.append(cmd)
        out = ""
        if "easyrsa revoke" in cmd:
            out = "REVOKED_OK\n"
        elif "openvpn-status.log" in cmd:
            out = (
                "OpenVPN CLIENT LIST\nCommon Name,Real Address,Bytes Received,"
                f"Bytes Sent,Connected Since\n{self.online},198.51.100.7:5000,1,2,x\n"
                "ROUTING TABLE\n"
            )
        elif "ps --format" in cmd:
            out = "amnezia-openvpn\n"
        elif "clientsTable" in cmd and "cat >" not in cmd:
            out = "[]"
        return type("R", (), {"exit_status": 0, "stdout": out, "stderr": ""})()


@pytest.mark.parametrize(("online", "restarted"), [("cid1", True), ("other", False)])
async def test_openvpn_revoke_drops_live_session(online, restarted):
    # CRL не рвет открытую сессию: подключенного отозванного рвем рестартом
    conn = _OvpnConn(online)
    await openvpn.revoke_client(conn, "amnezia-openvpn", "cid1")
    assert any(" restart " in c for c in conn.cmds) is restarted
