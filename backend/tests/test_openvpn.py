import shutil
import subprocess
from unittest.mock import AsyncMock

import pytest

from app import openvpn

TABLE = """[
    {
        "clientId": "O0qNFHmcnCoisMQyPcfco5Sv1DB0Pi7v",
        "userData": {
            "clientName": "Admin [Windows 11 Version 25H2]",
            "creationDate": "Thu May 14 12:49:56 2026"
        }
    },
    {"clientId": "abc", "userData": {"creationDate": "x"}}
]"""


def test_parse_clients() -> None:
    clients = openvpn.parse_clients(TABLE)
    assert len(clients) == 2
    assert clients[0].client_id == "O0qNFHmcnCoisMQyPcfco5Sv1DB0Pi7v"
    assert clients[0].name.startswith("Admin")
    assert clients[0].creation_date == "Thu May 14 12:49:56 2026"
    assert clients[1].name == "—"  # без clientName → прочерк


def test_parse_clients_garbage() -> None:
    assert openvpn.parse_clients("не json") == []
    assert openvpn.parse_clients("[]") == []


STATUS_LOG = """OpenVPN CLIENT LIST
Updated,Thu May 14 12:00:00 2026
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
abc123,10.0.0.2:5000,1048576,2097152,Thu May 14 11:00:00 2026
def456,10.0.0.3:5001,500,700,Thu May 14 11:30:00 2026
ROUTING TABLE
10.8.0.2,abc123,10.0.0.2:5000,Thu May 14 12:00:00 2026
GLOBAL STATS
END
"""


def test_parse_status_log() -> None:
    m = openvpn.parse_status_log(STATUS_LOG)
    assert set(m) == {"abc123", "def456"}
    assert m["abc123"] == {
        "rx": 1048576, "tx": 2097152, "since": "Thu May 14 11:00:00 2026",
    }
    assert m["def456"]["rx"] == 500 and m["def456"]["tx"] == 700
    # строки из ROUTING TABLE не считаются клиентами
    assert "10.8.0.2" not in m


def test_parse_status_log_empty() -> None:
    assert openvpn.parse_status_log("") == {}
    assert openvpn.parse_status_log("garbage\nno header") == {}


def test_deploy_script_preserves_live_pki_before_guard() -> None:
    """Регресс: (пере)деплой OpenVPN должен вытащить PKI из ЖИВОГО контейнера на
    хост ДО guard `test -f ca.crt`, иначе guard сгенерил бы новый CA и все
    клиентские сертификаты стали бы невалидны (класс инцидента de-hz)."""
    s = openvpn.build_deploy_script(8443, "tile.openstreetmap.org", "203.0.113.9")
    assert "-s 10.8.0.0/24 ! -o tun0 -j MASQUERADE" in s
    assert "-s 10.8.0.0/24 -o eth0 -j MASQUERADE" not in s
    assert 'grep -Fxq "$C"' in s
    assert 'SRC="$C"' in s
    # перенос конфига из контейнера на хост
    assert 'docker exec "$SRC" tar -czf -' in s
    assert "opt/amnezia/openvpn" in s and "opt/amnezia/cloak" in s
    # перенос идёт ДО guard генерации
    assert s.index('docker exec "$SRC" tar') < s.index("генерация нового конфига")
    # порт берётся из живого контейнера (клиентский endpoint зашит на старый порт)
    assert "DPORT=$(sudo docker inspect" in s
    assert '[ -n "$DPORT" ] && PORT=$DPORT' in s
    # A native or unrelated OpenVPN container must never be removed.
    removals = [line for line in s.splitlines() if "docker rm" in line]
    assert len(removals) == 2
    assert 'docker rm -f "$SRC"' in removals[0]
    assert 'docker rm -f "$(cat "$RUN_DIR/container.id")"' in removals[1]


def test_cloak_update_needs_a_running_cloak_container() -> None:
    script = openvpn.build_deploy_script(8443, "vpn.example.org", update=True)
    assert script.index('fail "existing Cloak container is stopped"') < script.index("docker build -t")
    assert script.index('fail "Cloak container not found"') < script.index("docker build -t")


@pytest.mark.skipif(shutil.which("bash") is None, reason="requires bash")
@pytest.mark.parametrize("already_revoked", [False, True])
async def test_revoke_requires_success_or_an_already_revoked_certificate(tmp_path, monkeypatch, already_revoked):
    pki = tmp_path / "pki"
    (pki / "issued").mkdir(parents=True)
    cert = pki / "issued" / "fixture.crt"
    cert.touch()
    (pki / "index.txt").write_text(
        f'{"R" if already_revoked else "V"}\tfixture-expiration\t\t01\tunknown\t/CN=fixture\n',
        encoding="utf-8", newline="\n",
    )
    (tmp_path / "easyrsa").write_text(
        '#!/bin/sh\n[ "$1" = gen-crl ] && echo updated > "$EASYRSA_PKI/crl.pem"\n',
        encoding="utf-8", newline="\n",
    )
    (tmp_path / "easyrsa").chmod(0o700)
    monkeypatch.setattr(openvpn, "EASYRSA", tmp_path.as_posix())
    monkeypatch.setattr(openvpn, "PKI", pki.as_posix())
    monkeypatch.setattr(openvpn, "OVPN_DIR", tmp_path.as_posix())
    monkeypatch.setattr(openvpn, "_docker_exec", lambda _container, command: command)

    async def run(_conn, command):
        result = subprocess.run(
            [shutil.which("bash"), "-s"],
            input='export PATH="/usr/bin:/bin:$PATH"\n' + command,
            capture_output=True, text=True,
        )
        if already_revoked:
            assert result.returncode == 0, result.stderr
        return result.stdout

    monkeypatch.setattr(openvpn, "_run", run)
    monkeypatch.setattr(openvpn, "_read_table", AsyncMock(return_value=[{"clientId": "fixture"}]))
    write_table = AsyncMock()
    monkeypatch.setattr(openvpn, "_write_table", write_table)
    monkeypatch.setattr(openvpn, "read_status_map", AsyncMock(return_value={}))
    active_crl = tmp_path / "crl.pem"
    active_crl.write_text("old", encoding="utf-8")

    if already_revoked:
        await openvpn.revoke_client(None, "fixture", "fixture")
        write_table.assert_awaited_once_with(None, "fixture", [])
        assert active_crl.read_text(encoding="utf-8").strip() == "updated"
        assert not cert.exists()
    else:
        with pytest.raises(openvpn.OpenVpnError):
            await openvpn.revoke_client(None, "fixture", "fixture")
        write_table.assert_not_awaited()
        assert active_crl.read_text(encoding="utf-8") == "old"
        assert cert.exists()
