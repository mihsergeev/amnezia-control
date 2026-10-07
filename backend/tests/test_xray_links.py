import base64
import json
import struct
import zlib
from urllib.parse import parse_qs, unquote, urlsplit

from app import xray


def _server_with_xhttp(path="/abc123"):
    """Vision REALITY на 443 + XHTTP-вход за fallback."""
    return {
        "inbounds": [
            {
                "port": 443, "protocol": "vless",
                "settings": {
                    "clients": [
                        {"id": "DEF", "flow": xray.FLOW, "email": "DEF"},
                        {"id": "UID-A", "flow": xray.FLOW, "email": "UID-A"},
                    ],
                    "decryption": "none",
                    "fallbacks": [{"dest": "@vless-xhttp", "xver": 0}],
                },
                "streamSettings": {
                    "network": "tcp", "security": "reality",
                    "realitySettings": {"serverNames": ["video.example.org"]},
                },
            },
            {"listen": "127.0.0.1", "port": xray.STATS_API_PORT,
             "protocol": "dokodemo-door", "tag": "api"},
            {
                "tag": "vless-xhttp", "listen": "@vless-xhttp", "protocol": "vless",
                "settings": {"clients": [{"id": "DEF", "email": "DEF"}],
                             "decryption": "none"},
                "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": path}},
            },
        ],
    }


def _decode_vpn(link: str) -> dict:
    raw = base64.urlsafe_b64decode(link[len("vpn://"):] + "===")
    (size,) = struct.unpack(">I", raw[:4])
    payload = zlib.decompress(raw[4:])
    assert len(payload) == size
    return json.loads(payload)


def _last_config(link: str) -> dict:
    top = _decode_vpn(link)
    return json.loads(top["containers"][0]["xray"]["last_config"])


def test_sync_mirrors_primary_clients_without_flow_on_xhttp():
    server = _server_with_xhttp()
    assert xray.sync_extra_inbounds(server) is True
    xh = server["inbounds"][2]["settings"]["clients"]
    assert xh == [{"id": "DEF", "email": "DEF"}, {"id": "UID-A", "email": "UID-A"}]
    # повторная синхронизация ничего не меняет
    assert xray.sync_extra_inbounds(server) is False


def test_revoke_style_removal_propagates_to_extra_inbound():
    server = _server_with_xhttp()
    xray.sync_extra_inbounds(server)
    server["inbounds"][0]["settings"]["clients"] = [
        c for c in server["inbounds"][0]["settings"]["clients"] if c["id"] != "UID-A"
    ]
    # ensure_stats_config вызывается при любой правке клиентов и синхронизирует
    xray.ensure_stats_config(server)
    ids = [c["id"] for c in server["inbounds"][2]["settings"]["clients"]]
    assert ids == ["DEF"]


def test_sync_ignores_api_and_keeps_single_inbound_servers_untouched():
    server = {"inbounds": [
        {"port": 443, "protocol": "vless",
         "settings": {"clients": [{"id": "A", "flow": xray.FLOW}]}},
        {"listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
         "tag": "api", "settings": {"address": "127.0.0.1"}},
    ]}
    assert xray.sync_extra_inbounds(server) is False
    assert "clients" not in server["inbounds"][1]["settings"]
    assert xray.xhttp_fallback_path(server) is None


def test_xhttp_fallback_path_matches_socket_and_port_dests():
    assert xray.xhttp_fallback_path(_server_with_xhttp("/p1")) == "/p1"

    by_port = _server_with_xhttp("/p2")
    by_port["inbounds"][0]["settings"]["fallbacks"] = [{"dest": 8001}]
    by_port["inbounds"][2].pop("listen")
    by_port["inbounds"][2]["port"] = 8001
    assert xray.xhttp_fallback_path(by_port) == "/p2"

    # XHTTP-вход, на который нет fallback, не наш вариант: у него свой порт и ключи
    orphan = _server_with_xhttp()
    orphan["inbounds"][0]["settings"]["fallbacks"] = [{"dest": "@other"}]
    assert xray.xhttp_fallback_path(orphan) is None


BITS = {
    "pub": "PUBKEY", "short": "abcd", "site": "video.example.org", "port": 443,
    "flow": xray.FLOW, "xhttp_path": "/abc123",
}


def test_client_configs_vision_and_xhttp_variants():
    configs = xray.client_configs(
        BITS, host="198.51.100.7", description="ru-node", dns1="1.1.1.1",
        dns2="1.0.0.1", client_id="UID-A", name="phone",
    )
    assert [c["key"] for c in configs] == ["vision", "xhttp"]

    vision = _last_config(configs[0]["amnezia"])["outbounds"][0]
    assert vision["settings"]["vnext"][0]["users"][0]["flow"] == xray.FLOW
    assert vision["streamSettings"]["network"] == "tcp"
    assert vision["streamSettings"]["realitySettings"]["fingerprint"] == "firefox"

    xh_top = _decode_vpn(configs[1]["amnezia"])
    assert xh_top["description"] == "ru-node XHTTP"
    xh = json.loads(xh_top["containers"][0]["xray"]["last_config"])["outbounds"][0]
    assert "flow" not in xh["settings"]["vnext"][0]["users"][0]
    assert xh["streamSettings"]["network"] == "xhttp"
    assert xh["streamSettings"]["xhttpSettings"] == {"path": "/abc123"}
    assert xh["streamSettings"]["security"] == "reality"


def test_client_configs_without_xhttp_has_only_vision():
    bits = dict(BITS, xhttp_path=None)
    configs = xray.client_configs(
        bits, host="198.51.100.7", description="n", dns1="1.1.1.1", dns2="1.0.0.1",
        client_id="U", name="x",
    )
    assert [c["key"] for c in configs] == ["vision"]


def test_vless_uri_fields():
    configs = xray.client_configs(
        BITS, host="198.51.100.7", description="ru-node", dns1="1.1.1.1",
        dns2="1.0.0.1", client_id="UID-A", name="phone max",
    )
    vis = urlsplit(configs[0]["uri"])
    assert vis.scheme == "vless"
    assert vis.netloc == "UID-A@198.51.100.7:443"
    q = {k: v[0] for k, v in parse_qs(vis.query).items()}
    assert q == {
        "type": "tcp", "encryption": "none", "flow": xray.FLOW,
        "security": "reality", "sni": "video.example.org", "fp": "firefox",
        "pbk": "PUBKEY", "sid": "abcd",
    }
    assert unquote(vis.fragment) == "ru-node phone max"

    xh = urlsplit(configs[1]["uri"])
    q = {k: v[0] for k, v in parse_qs(xh.query).items()}
    assert q["type"] == "xhttp" and q["path"] == "/abc123" and q["mode"] == "auto"
    assert "flow" not in q
    assert unquote(xh.fragment) == "ru-node XHTTP phone max"


def test_vless_uri_brackets_ipv6_host():
    uri = xray.build_vless_uri(
        host="2001:db8::1", port=443, client_id="U", pub="P", short="s",
        site="example.org", flow=xray.FLOW, label="x",
    )
    assert uri.startswith("vless://U@[2001:db8::1]:443?")
