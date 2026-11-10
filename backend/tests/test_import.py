import base64
import json
import struct
import zlib

import pytest

from app import amnezia_import, server_ops
from app.amnezia_import import ImportParseError


def _make_vpn_link(data: dict, compress: bool = True) -> str:
    payload = json.dumps(data).encode()
    if compress:
        # формат qCompress: 4 байта BE (размер) + zlib
        payload = struct.pack(">I", len(payload)) + zlib.compress(payload)
    b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return "vpn://" + b64


AMNEZIA_CONFIG = {
    "description": "kz-almaty",
    "hostName": "203.0.113.10",
    "userName": "root",
    "password": "s3cretpass",
    "port": 22,
    "containers": [
        {"container": "amnezia-awg", "awg": {"port": "47180"}},
        {"container": "amnezia-openvpn-cloak"},
    ],
    "defaultContainer": "amnezia-awg",
}


def test_parse_amnezia_compressed() -> None:
    spec = amnezia_import.parse_amnezia_link(_make_vpn_link(AMNEZIA_CONFIG))
    assert spec.host == "203.0.113.10"
    assert spec.name == "kz-almaty"
    assert spec.ssh_user == "root"
    assert spec.ssh_port == 22
    assert spec.password == "s3cretpass"
    assert spec.protocols == ["awg", "openvpn-cloak"]


def test_parse_amnezia_uncompressed() -> None:
    spec = amnezia_import.parse_amnezia_link(_make_vpn_link(AMNEZIA_CONFIG, compress=False))
    assert spec.host == "203.0.113.10"
    assert spec.password == "s3cretpass"


def test_parse_amnezia_nested_credentials() -> None:
    nested = {"description": "srv", "credentials": AMNEZIA_CONFIG}
    spec = amnezia_import.parse_amnezia_link(_make_vpn_link(nested))
    assert spec.host == "203.0.113.10"


def test_parse_amnezia_private_key_not_used_as_password() -> None:
    cfg = dict(AMNEZIA_CONFIG, password="-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
    spec = amnezia_import.parse_amnezia_link(_make_vpn_link(cfg))
    assert spec.password is None  # ключ не годится для bootstrap по паролю


def test_parse_amnezia_no_host() -> None:
    with pytest.raises(ImportParseError):
        amnezia_import.parse_amnezia_link(_make_vpn_link({"description": "x"}))


def test_parse_amnezia_garbage() -> None:
    with pytest.raises(ImportParseError):
        amnezia_import.parse_amnezia_link("vpn://not-valid-base64-!!!")


async def test_bad_amnezia_port_does_not_abort_batch(client, auth_headers) -> None:
    broken = _make_vpn_link(
        {"password": "synthetic-secret", "hostName": "server.example.invalid", "port": "broken"},
        compress=False,
    )
    good = dict(AMNEZIA_CONFIG, port="2222", password=None)
    result = await client.post("/api/import/amnezia", headers=auth_headers, json={
        "links": [broken, _make_vpn_link(good)],
    })
    assert result.status_code == 200
    failed, imported = result.json()["results"]
    assert failed["ok"] is False and failed["name"] == "Ссылка 1"
    assert imported["ok"] is True
    assert broken[:24] not in result.text


@pytest.mark.parametrize("field", ["hostName", "description", "userName"])
async def test_preview_does_not_echo_malformed_credentials(client, auth_headers, field) -> None:
    secret = "synthetic-secret"
    config = dict(AMNEZIA_CONFIG, **{field: {"password": secret}})
    result = await client.post("/api/import/amnezia/preview", headers=auth_headers, json={
        "link": _make_vpn_link(config),
    })
    assert result.status_code == 422
    assert secret not in result.text


@pytest.mark.parametrize("throws", [False, True])
async def test_import_does_not_echo_bootstrap_diagnostics(client, auth_headers, monkeypatch, throws):
    secret = "synthetic-password"

    async def bootstrap(_session, _server, password, _settings):
        assert password == secret
        if throws:
            raise RuntimeError(f"bootstrap failed with {password}")
        return False, f"remote output: {password}"

    monkeypatch.setattr(server_ops, "bootstrap_and_check", bootstrap)
    result = await client.post("/api/import/bulk", headers=auth_headers, json={
        "text": f"203.0.113.10 root {secret}",
    })
    assert result.status_code == 200
    imported, = result.json()["results"]
    assert imported["ok"] and not imported["bootstrapped"]
    assert "автонастройка не удалась" in imported["message"]
    assert secret not in result.text


@pytest.mark.parametrize("port", [0, 65536, True, 22.5, []])
def test_parse_amnezia_rejects_invalid_ports(port) -> None:
    with pytest.raises(ImportParseError, match="порт SSH"):
        amnezia_import.parse_amnezia_link(_make_vpn_link(dict(AMNEZIA_CONFIG, port=port)))


@pytest.mark.parametrize("depth", [150, 1300])
async def test_preview_rejects_deep_amnezia_json(client, auth_headers, depth) -> None:
    payload = b"[" * depth + b'{"hostName":"server.example.invalid"}' + b"]" * depth
    encoded = base64.urlsafe_b64encode(payload).decode()
    result = await client.post("/api/import/amnezia/preview", headers=auth_headers, json={
        "link": "vpn://" + encoded,
    })
    assert result.status_code == 422
    assert "вложенность" in result.json()["detail"]


@pytest.mark.parametrize("compress", [False, True])
def test_amnezia_size_limit_applies_to_raw_and_compressed_payloads(monkeypatch, compress) -> None:
    monkeypatch.setattr(amnezia_import, "_MAX_UNCOMPRESSED", 256)
    config = dict(AMNEZIA_CONFIG, description="x" * 257)
    with pytest.raises(ImportParseError, match="слишком большой"):
        amnezia_import.parse_amnezia_link(_make_vpn_link(config, compress=compress))


def test_parse_bulk_various_formats() -> None:
    text = """
    # комментарий
    203.0.113.1 root pass1
    203.0.113.2:2222 admin pass2
    203.0.113.3
    """
    specs = amnezia_import.parse_bulk(text, default_user="acontrol")
    assert len(specs) == 3
    assert specs[0].host == "203.0.113.1" and specs[0].password == "pass1"
    assert specs[1].ssh_port == 2222 and specs[1].ssh_user == "admin"
    assert specs[2].host == "203.0.113.3"
    assert specs[2].ssh_user == "acontrol" and specs[2].password is None


def test_parse_bulk_empty() -> None:
    with pytest.raises(ImportParseError):
        amnezia_import.parse_bulk("\n  # только комментарий\n")


@pytest.mark.parametrize("target", ["203.0.113.10:65536 root", "203.0.113.10 wrong!"])
def test_invalid_bulk_line_error_omits_credentials(target) -> None:
    secret = "synthetic-password"
    with pytest.raises(ImportParseError, match="строке 2") as caught:
        amnezia_import.parse_bulk(f"# first line\n{target} {secret}")
    assert secret not in str(caught.value)
