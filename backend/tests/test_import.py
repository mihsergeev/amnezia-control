import base64
import json
import struct
import zlib

import pytest

from app import amnezia_import
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
