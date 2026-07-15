import base64
import json

from app import awg

SAMPLE_CONF = """[Interface]
PrivateKey = aaaa
Address = 10.8.1.0/24
ListenPort = 47180
Jc = 4
Jmin = 10
Jmax = 50
S1 = 142
S2 = 20
S3 = 62
S4 = 1
H1 = 1204862887-1882451066
H2 = 1925268845-1984487753
H3 = 2102816403-2145489392
H4 = 2147211240-2147260204
# I1 = <r 2>
[Peer]
PublicKey = 5Ai5cnecffo3Le2OesbVH26DrKBd1zJSDZLOadGmGwo=
PresharedKey = pppp
AllowedIPs = 10.8.1.1/32

[Peer]
PublicKey = RXEZrMcQn5mGHzIGggBDO6VGfwiUxCAEbgGVXV2DHUc=
PresharedKey = pppp
AllowedIPs = 10.8.1.2/32
"""

SAMPLE_TABLE = """[
    {"clientId": "5Ai5cnecffo3Le2OesbVH26DrKBd1zJSDZLOadGmGwo=",
     "userData": {"clientName": "Admin", "allowedIps": "10.8.1.1/32"}},
    {"clientId": "RXEZrMcQn5mGHzIGggBDO6VGfwiUxCAEbgGVXV2DHUc=",
     "userData": {"clientName": "codex", "allowedIps": "10.8.1.2/32"}}
]"""

SAMPLE_DUMP = (
    "priv\tpub\t47180\t4\t10\t50\toff\n"
    "5Ai5cnecffo3Le2OesbVH26DrKBd1zJSDZLOadGmGwo=\tpsk\t"
    "203.0.113.50:56261\t10.8.1.1/32\t1782910189\t1710695316\t18918770776\toff\n"
    "RXEZrMcQn5mGHzIGggBDO6VGfwiUxCAEbgGVXV2DHUc=\tpsk\t"
    "(none)\t10.8.1.2/32\t0\t0\t0\toff\n"
)


def test_parse_conf_params_and_peers() -> None:
    interface, peers = awg.parse_conf(SAMPLE_CONF)
    assert interface["Address"] == "10.8.1.0/24"
    assert interface["ListenPort"] == "47180"
    assert interface["Jc"] == "4"
    assert interface["S3"] == "62"
    assert len(peers) == 2
    assert peers[0]["AllowedIPs"] == "10.8.1.1/32"


def test_parse_dump_skips_interface_line() -> None:
    stats = awg._parse_dump(SAMPLE_DUMP)
    assert len(stats) == 2
    first = stats["5Ai5cnecffo3Le2OesbVH26DrKBd1zJSDZLOadGmGwo="]
    assert first["latest_handshake"] == 1782910189
    assert first["rx_bytes"] == 1710695316
    assert first["endpoint"] == "203.0.113.50:56261"
    assert stats["RXEZrMcQn5mGHzIGggBDO6VGfwiUxCAEbgGVXV2DHUc="]["endpoint"] == ""


def test_allocate_ip_next_free() -> None:
    # заняты .1 и .2, сервер .0 → следующий .3
    ip = awg.allocate_ip("10.8.1.0/24", {"10.8.1.1", "10.8.1.2"})
    assert ip == "10.8.1.3"


def test_allocate_ip_fills_gap() -> None:
    ip = awg.allocate_ip("10.8.1.0/24", {"10.8.1.1", "10.8.1.3"})
    assert ip == "10.8.1.2"


def test_generate_keypair_valid_wireguard_keys() -> None:
    priv, pub = awg.generate_keypair()
    assert len(base64.b64decode(priv)) == 32
    assert len(base64.b64decode(pub)) == 32
    assert priv != pub


def test_remove_peer_keeps_others_and_interface() -> None:
    target = "5Ai5cnecffo3Le2OesbVH26DrKBd1zJSDZLOadGmGwo="
    other = "RXEZrMcQn5mGHzIGggBDO6VGfwiUxCAEbgGVXV2DHUc="
    result = awg.remove_peer_from_conf(SAMPLE_CONF, target)
    assert target not in result
    assert other in result
    assert "[Interface]" in result
    assert "ListenPort = 47180" in result
    # остался ровно один [Peer]
    assert result.count("[Peer]") == 1


def test_build_client_config_mirrors_awg_params() -> None:
    interface, _ = awg.parse_conf(SAMPLE_CONF)
    params = {k: interface[k] for k in awg.AWG_PARAM_KEYS if k in interface}
    config = awg.build_client_config(
        client_private="CLIENTPRIV",
        address="10.8.1.3",
        server_public="SERVERPUB",
        preshared="PSK123",
        endpoint="203.0.113.10:47180",
        params=params,
        dns="1.1.1.1",
    )
    assert "Address = 10.8.1.3/32" in config
    assert "PrivateKey = CLIENTPRIV" in config
    assert "Jc = 4" in config
    assert "S3 = 62" in config
    # H1–H4 (2.0) зеркалятся диапазоном verbatim, НЕ схлопываются в одно число
    assert "H1 = 1204862887-1882451066" in config
    assert "H4 = 2147211240-2147260204" in config
    assert "PublicKey = SERVERPUB" in config
    assert "PresharedKey = PSK123" in config
    assert "Endpoint = 203.0.113.10:47180" in config
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in config


def test_names_from_table() -> None:
    names = awg._names_from_table(SAMPLE_TABLE)
    assert names["5Ai5cnecffo3Le2OesbVH26DrKBd1zJSDZLOadGmGwo="] == "Admin"
    assert names["RXEZrMcQn5mGHzIGggBDO6VGfwiUxCAEbgGVXV2DHUc="] == "codex"


def test_dns_pair() -> None:
    assert awg.dns_pair("1.1.1.1, 1.0.0.1") == ("1.1.1.1", "1.0.0.1")
    assert awg.dns_pair("8.8.8.8") == ("8.8.8.8", "8.8.8.8")
    assert awg.dns_pair("") == ("1.1.1.1", "1.1.1.1")


def test_derive_public_key_matches_generated() -> None:
    priv, pub = awg.generate_keypair()
    assert awg.derive_public_key(priv) == pub


def test_build_amnezia_link_roundtrip() -> None:
    from app import amnezia_import as ai

    priv, pub = awg.generate_keypair()
    conf = awg.build_client_config(
        client_private=priv,
        address="10.8.1.7",
        server_public="NSzHmLC7cq08Y7FK1EeAzPu51yZeOZiuoLIPYeeH3yk=",
        preshared="7jE5uKQj63MXTY7KX6oL90Oe5sCYvUCe/uab9fY3kao=",
        endpoint="203.0.113.10:47180",
        params={"Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "142", "S2": "20"},
        dns="1.1.1.1, 1.0.0.1",
    )
    link = awg.build_amnezia_link(conf, "203.0.113.10", "my-server", "1.1.1.1", "1.0.0.1")
    assert link.startswith("vpn://")

    # декодируем нашим же импорт-декодером
    payload = ai._maybe_uncompress(ai._b64_decode(link[len("vpn://"):]))
    data = json.loads(payload)
    assert data["hostName"] == "203.0.113.10"
    assert data["defaultContainer"] == "amnezia-awg2"
    assert data["description"] == "my-server"
    assert data["dns1"] == "1.1.1.1" and data["dns2"] == "1.0.0.1"

    awg_obj = data["containers"][0]["awg"]
    assert awg_obj["protocol_version"] == "2"
    assert awg_obj["subnet_address"] == "10.8.1.0"
    assert awg_obj["port"] == "47180"

    lc = json.loads(awg_obj["last_config"])
    assert lc["client_ip"] == "10.8.1.7"
    assert lc["client_priv_key"] == priv
    assert lc["client_pub_key"] == pub
    assert lc["clientId"] == pub
    assert lc["server_pub_key"] == "NSzHmLC7cq08Y7FK1EeAzPu51yZeOZiuoLIPYeeH3yk="
    assert lc["psk_key"] == "7jE5uKQj63MXTY7KX6oL90Oe5sCYvUCe/uab9fY3kao="
    assert lc["port"] == 47180
    assert "$PRIMARY_DNS" in lc["config"]  # DNS шаблонизирован


def test_section_extraction() -> None:
    bundle = "===CONF===\nline1\nline2\n===PUB===\nkeyvalue\n===DUMP===\nd1\n"
    assert awg._section(bundle, "CONF") == "line1\nline2"
    assert awg._section(bundle, "PUB") == "keyvalue"
    assert awg._section(bundle, "DUMP") == "d1"


def test_section_extraction_json_without_trailing_newline() -> None:
    # регрессия: clientsTable без завершающего \n, но printf ставит \n перед маркером
    table = '[\n    {"clientId": "abc", "userData": {"clientName": "X"}}\n]'
    bundle = f"===CONF===\n[Interface]\n\n===TABLE===\n{table}\n===DUMP===\npeer\n"
    extracted = awg._section(bundle, "TABLE")
    names = awg._names_from_table(extracted)
    assert names == {"abc": "X"}
