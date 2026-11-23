"""full-access vpn:// link: правильная классификация контейнеров.

Регресс на баг, из-за которого новый AmneziaWG 2.0 (amnezia-awg2) кодировался
как legacy amnezia-awg → приложение метило «AmneziaWG Legacy» и падало с
ErrorCode 202 («отсутствует Docker-контейнер»)."""

import base64
import json
import struct
import zlib
from contextlib import asynccontextmanager

from app.awg import build_fullaccess_awg_object
from app.fullaccess import _canonical, build_full_access_link
from app.models import Server


async def test_unsupported_fullaccess_explains_conflict_without_installing_key(
    client, auth_headers, session_factory, monkeypatch, caplog,
):
    from app.api import fullaccess as api

    async with session_factory() as session:
        server = Server(name="private-display-name", host="192.0.2.20")
        session.add(server)
        await session.commit()
        sid = server.id

    @asynccontextmanager
    async def connect(server):
        yield object()

    async def detect(conn):
        return ["amnezia-awg3"]

    def generate():
        raise AssertionError("unsupported export must not generate a key")

    monkeypatch.setattr(api, "_connect", connect)
    monkeypatch.setattr(api.fullaccess, "detect_containers", detect)
    monkeypatch.setattr(api.fullaccess, "generate_keypair", generate)
    response = await client.post(f"/api/servers/{sid}/fullaccess", headers=auth_headers,
                                 json={"password": "testpass"})
    assert response.status_code == 409
    assert "Клиенты" in response.json()["detail"]
    assert "reason=fullaccess_unsupported_protocols" in caplog.text
    assert "private-display-name" not in caplog.text and "192.0.2.20" not in caplog.text

# серверный awg0.conf в формате панели/приложения: H1-H4 диапазонами (маркер 2.0),
# I1 закомментирован (CPS раздаётся клиентам, но awg-quick его не применяет)
_SERVER_CONF = """[Interface]
Address = 10.8.1.1/24
ListenPort = 45728
PrivateKey = privkeybase64==
Jc = 6
Jmin = 10
Jmax = 50
S1 = 116
S2 = 15
S3 = 23
S4 = 9
H1 = 362244257-2055058689
H2 = 2117589042-2121064189
H3 = 2131202284-2144532456
H4 = 2147357173-2147462980
# I1 = <r 2><b 0x858000010001>

[Peer]
PublicKey = clientpubkey==
AllowedIPs = 10.8.1.2/32
"""


def _decode(link: str) -> dict:
    raw = link[len("vpn://"):]
    raw += "=" * (-len(raw) % 4)
    blob = base64.urlsafe_b64decode(raw)
    return json.loads(zlib.decompress(blob[4:]))


def test_canonical_new_awg_not_collapsed_to_legacy() -> None:
    # новый AmneziaWG 2.0 — отдельный тип, НЕ схлопывается в legacy
    assert _canonical("amnezia-awg2") == "amnezia-awg2"
    # реальный legacy остаётся legacy
    assert _canonical("amnezia-awg") == "amnezia-awg"
    assert _canonical("amnezia-openvpn-cloak") == "amnezia-openvpn-cloak"
    assert _canonical("amnezia-xray") == "amnezia-xray"


def test_link_encodes_awg2_container() -> None:
    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=22,
        private_key="KEY", description="srv", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-awg2"],
    )
    top = _decode(link)
    assert top["defaultContainer"] == "amnezia-awg2"
    assert {"container": "amnezia-awg2"} in top["containers"]
    assert {"container": "amnezia-awg"} not in top["containers"]


def test_link_keeps_both_awg_when_present() -> None:
    # сервер с двумя AWG (legacy + new) — оба типа в ссылке
    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=22,
        private_key="KEY", description="srv", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-awg", "amnezia-awg2", "amnezia-xray"],
    )
    types = {c["container"] for c in _decode(link)["containers"]}
    assert types == {"amnezia-awg", "amnezia-awg2", "amnezia-xray"}


def test_awg_object_matches_app_format() -> None:
    # awg-объект для full-access строится из серверного конфига и повторяет
    # формат экспорта приложения (protocol_version="2", H диапазонами, I2-I5="")
    obj = build_fullaccess_awg_object(_SERVER_CONF)
    assert obj["protocol_version"] == "2"
    assert obj["transport_proto"] == "udp"
    assert obj["port"] == "45728"
    assert obj["subnet_address"] == "10.8.1.0"
    assert obj["H1"] == "362244257-2055058689"  # диапазон — маркер 2.0
    assert "-" in obj["H4"]
    assert obj["Jc"] == "6" and obj["S3"] == "23" and obj["S4"] == "9"
    assert obj["I1"].startswith("<r 2>")  # CPS из закомментированной строки
    assert obj["I2"] == "" == obj["I5"]  # пустые CPS явно присутствуют
    # last_config в full-access НЕ вкладывается (в отличие от клиентской ссылки)
    assert "last_config" not in obj


def test_link_embeds_awg2_protocol_config() -> None:
    # ключевой регресс: full-access должен нести вложенный awg-объект, иначе
    # приложение не видит версию 2 и метит сервер legacy (не подключается)
    awg2 = build_fullaccess_awg_object(_SERVER_CONF)
    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=2221,
        private_key="KEY\n", description="de-hz", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-awg2"], awg2_config=awg2,
    )
    top = _decode(link)
    entry = next(c for c in top["containers"] if c["container"] == "amnezia-awg2")
    assert entry["awg"]["protocol_version"] == "2"
    assert entry["awg"]["port"] == "45728"
    assert entry["awg"]["subnet_address"] == "10.8.1.0"
    assert top["defaultContainer"] == "amnezia-awg2"
    assert set(top) >= {"hostName", "userName", "password", "port", "dns1", "dns2"}


def test_link_without_awg2_config_stays_bare() -> None:
    # если конфиг не передан (нода без awg2) — контейнер без вложенного объекта
    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=22,
        private_key="KEY", description="srv", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-openvpn-cloak"],
    )
    entry = _decode(link)["containers"][0]
    assert entry == {"container": "amnezia-openvpn-cloak"}


def test_awg3_never_sent_as_legacy() -> None:
    """Регресс с боевого сервера: контейнер amnezia-awg3 попадал под условие
    startswith("amnezia-awg") и уезжал в ссылку как «amnezia-awg», из-за чего
    приложение показывало третью версию как «AmneziaWG Legacy» — на сервере,
    где legacy вообще нет. Приложение 5.0.0.5 знает только amnezia-awg,
    amnezia-awg2 и amnezia-openvpn-cloak; незнакомое имя = DockerContainer::None,
    поэтому 3.0 в полный доступ не отдаём вовсе."""
    assert _canonical("amnezia-awg3") is None
    # соседние версии по-прежнему распознаются
    assert _canonical("amnezia-awg2") == "amnezia-awg2"
    assert _canonical("amnezia-awg") == "amnezia-awg"

    link = build_full_access_link(
        host="203.0.113.10", ssh_user="amn", ssh_port=22,
        private_key="KEY", description="srv", dns1="1.1.1.1", dns2="1.0.0.1",
        container_names=["amnezia-awg2", "amnezia-awg3"],
    )
    types = {c["container"] for c in _decode(link)["containers"]}
    assert types == {"amnezia-awg2"}, f"в ссылку попало лишнее: {types}"
    assert "amnezia-awg3" not in types
    # и главное: 3.0 не выдаётся за legacy
    assert "amnezia-awg" not in types


def _bash(script: str, home) -> "subprocess.CompletedProcess[str]":
    import os
    import shutil
    import subprocess
    from pathlib import Path
    bash = "C:/Program Files/Git/usr/bin/bash.exe" if os.name == "nt" else shutil.which("bash")
    env = {**os.environ, "HOME": home.as_posix(), "PATH": str(Path(bash).parent) + os.pathsep + os.environ["PATH"]}
    return subprocess.run([bash, "-c", script], text=True, capture_output=True, env=env)


def test_revoke_removes_only_the_desktop_key_and_check_reports_it(tmp_path) -> None:
    """Ключ полного доступа работает с любого адреса: его надо уметь отозвать,
    не задев ключ панели, ключи администратора и строки, где метка лишь упомянута."""
    from app.fullaccess import DESKTOP_KEY_TAG, REVOKE_COMMAND
    from app.sshops import CHECK_COMMAND, _parse_check_output

    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    ak = ssh / "authorized_keys"
    keep = (
        'from="192.0.2.1",restrict ssh-ed25519 AAA acontrol-panel\n'
        "ssh-ed25519 BBB admin notes about acontrol-desktop keys\n"
        "# acontrol-desktop was exported once\n"
    )
    ak.write_text(keep + f"ssh-rsa CCC {DESKTOP_KEY_TAG}\n")
    probe = next(part for part in CHECK_COMMAND.split("; ") if "FULLACCESS_KEY" in part)
    assert _parse_check_output(_bash(probe, tmp_path).stdout).fullaccess_key is True
    result = _bash(REVOKE_COMMAND, tmp_path)
    assert result.returncode == 0 and "REVOKED=1" in result.stdout, result.stderr
    assert ak.read_text() == keep
    assert _parse_check_output(_bash(probe, tmp_path).stdout).fullaccess_key is False
    # повторный отзыв ничего не меняет
    again = _bash(REVOKE_COMMAND, tmp_path)
    assert again.returncode == 0 and "REVOKED=0" in again.stdout
    assert ak.read_text() == keep


async def test_revoke_endpoint_reports_and_audits(client, auth_headers, session_factory, monkeypatch) -> None:
    from app.api import fullaccess as api

    async with session_factory() as session:
        server = Server(name="srv", host="192.0.2.21")
        session.add(server)
        await session.commit()
        sid = server.id

    @asynccontextmanager
    async def connect(server):
        yield object()

    results = iter([1, 0])

    async def revoke(conn):
        return next(results)

    monkeypatch.setattr(api, "_connect", connect)
    monkeypatch.setattr(api.fullaccess, "revoke_desktop_key", revoke)
    first = await client.delete(f"/api/servers/{sid}/fullaccess", headers=auth_headers)
    assert first.status_code == 200 and first.json() == {"removed": True}
    second = await client.delete(f"/api/servers/{sid}/fullaccess", headers=auth_headers)
    assert second.status_code == 200 and second.json() == {"removed": False}
    audit = (await client.get("/api/audit", headers=auth_headers)).json()
    rows = audit["items"] if isinstance(audit, dict) else audit
    assert sum(1 for row in rows if row.get("action") == "fullaccess_revoke") == 2
    assert (await client.delete("/api/servers/99999/fullaccess", headers=auth_headers)).status_code == 404
