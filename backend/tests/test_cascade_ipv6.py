import base64
import ipaddress
import json
import re
import shutil
import subprocess
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app import cascade, cascade_awg, cascade_endpoints, cascade_exit, cascade_probe
from app.api import cascades as api
from app.schemas import CascadeCreate, CascadePair
from app.models import Cascade, Server
from test_cascade_probe import Process
from test_cascade_shared_exit import params, remote_mocks, setup_nodes

ENTRY, EXIT = "2001:db8::10", "2001:db8::20"


@pytest.mark.parametrize("endpoint", ["::", "::1", "fe80::1", "ff02::1", "::ffff:192.0.2.1",
                                      "2001:db8::1%eth0", "[2001:db8::1]:443", "192.0.2.1"])
def test_ipv6_request_rejects_ambiguous_or_unusable_endpoints(endpoint):
    with pytest.raises(ValidationError):
        CascadePair(entry_id=1, exit_id=2, address_family="ipv6", exit_endpoint=endpoint)


def test_ipv4_defaults_keep_existing_idempotency_payload():
    request = CascadeCreate(entry_id=1, exit_id=2, transport="gre")
    assert not {"address_family", "entry_endpoint", "exit_endpoint"} & api._create_request_data(request).keys()
    with pytest.raises(ValidationError):
        CascadePair(entry_id=1, exit_id=2, entry_endpoint=ENTRY)
    ipv6 = CascadeCreate(entry_id=1, exit_id=2, transport="gre", address_family="ipv6",
                         entry_endpoint="2001:0db8:0:0::10", exit_endpoint=EXIT)
    assert api._create_request_data(ipv6)["entry_endpoint"] == ENTRY
    assert api._create_request_data(ipv6)["address_family"] == "ipv6"


async def test_explicit_ipv6_uses_both_remote_routes_without_changing_management_hosts(monkeypatch):
    servers = [SimpleNamespace(host="192.0.2.10"), SimpleNamespace(host="192.0.2.20")]
    calls = []
    async def route(conn, peer):
        calls.append((conn, peer))
        return ENTRY if conn == "entry" else EXIT
    async def no_ipv4(*args): pytest.fail("IPv6 must never fall back to management IPv4")
    monkeypatch.setattr(cascade, "_route_src", route)
    monkeypatch.setattr(api, "_addresses", no_ipv4)
    request = CascadePair(entry_id=1, exit_id=2, address_family="ipv6", entry_endpoint=ENTRY, exit_endpoint=EXIT)
    assert await api._pair_addresses("entry", "exit", *servers, request) == (ENTRY, EXIT)
    assert calls == [("entry", EXIT), ("exit", ENTRY)]
    assert [server.host for server in servers] == ["192.0.2.10", "192.0.2.20"]


@pytest.mark.parametrize("missing", [False, True])
async def test_ipv6_route_or_discovery_failure_stops_before_mutation(monkeypatch, missing):
    async def discover(conn): return "" if missing else ENTRY if conn == "entry" else EXIT
    async def route(*args): return "2001:db8::99"
    monkeypatch.setattr(cascade_endpoints, "discover_ipv6", discover)
    monkeypatch.setattr(cascade, "_route_src", route)
    request = CascadePair(entry_id=1, exit_id=2, address_family="ipv6")
    with pytest.raises(HTTPException) as error:
        await api._pair_addresses("entry", "exit", None, None, request)
    assert error.value.status_code == 409
    assert error.value.detail == ("Укажите адреса IPv6 для связи между узлами каскада" if missing else
                                 "Выбранные IPv6 должны совпадать с адресами исходящего маршрута между узлами")


async def test_auto_ipv6_discovery_excludes_transient_and_ambiguous_addresses(monkeypatch):
    # Documentation addresses stand in for provider-assigned global addresses.
    monkeypatch.setattr(ipaddress.IPv6Address, "is_global", property(lambda self: True))
    addresses = [{"family": "inet6", "scope": "global", "local": ENTRY}]
    class Connection:
        async def run(self, command, **kwargs):
            assert command == "ip -j -6 address show scope global" and kwargs["timeout"] == 10
            return SimpleNamespace(exit_status=0, stdout=json.dumps([{"addr_info": addresses}]))
    assert await cascade_endpoints.discover_ipv6(Connection()) == ENTRY
    addresses.append({"family": "inet6", "scope": "global", "local": EXIT, "flags": ["temporary"]})
    assert await cascade_endpoints.discover_ipv6(Connection()) == ENTRY
    addresses[-1].pop("flags")
    assert await cascade_endpoints.discover_ipv6(Connection()) == ""
    assert cascade_endpoints.global_ipv6('[null, {"addr_info": [null]}]') == []


@pytest.mark.parametrize("transport", ["awg", "gre", "vless"])
def test_ipv6_install_and_remove_keep_ipv4_inner_network_and_ownership(transport):
    options = params(transport) | {"entry_ip": ENTRY, "exit_ip": EXIT, "address_family": "ipv6"}
    scripts = [cascade.build_entry_script(transport, EXIT, 7, options),
               cascade.build_exit_script(transport, ENTRY, 7, options),
               cascade.build_remove_entry(transport, 7, options),
               cascade.build_remove_exit(transport, 7, options)]
    decoded = [base64.b64decode(value).decode() for script in scripts
               for value in re.findall(r"echo ([A-Za-z0-9+/=]+) \| base64 -d", script)]
    if shutil.which("bash"):
        for script in scripts + [value for value in decoded if value.startswith("#!")]:
            checked = subprocess.run([shutil.which("bash"), "-n"], input=script, text=True, capture_output=True)
            assert checked.returncode == 0, checked.stderr
    assert "2001:db8::" in "\n".join(scripts + decoded)
    if transport == "awg":
        conf = cascade_awg.config("entry", options | {"entry_inner": "198.51.100.1"})
        assert f"Endpoint = [{EXIT}]:51831" in conf and "AllowedIPs = 0.0.0.0/0" in conf
        assert "::/0" not in conf
        assert "ip -6 rule del pref 1009 fwmark 0x400 table main" in cascade_awg.RUNTIME
    elif transport == "gre":
        assert "type ip6gre" in "\n".join(decoded)
        assert "ip6gre" in cascade_exit.entry_preflight(7, transport, options)
        assert "1452" in cascade_exit.RUNTIME and "PEER_IPTABLES" in cascade._GRE_TUN_SH
    else:
        conf = json.loads(cascade.exit_vless_config(options))
        assert conf["inbounds"][0]["listen"] == EXIT
        assert conf["outbounds"][0]["protocol"] == "freedom"


@pytest.mark.parametrize("transport", ["awg", "gre", "vless"])
async def test_ipv6_measurement_uses_selected_outer_addresses_and_ipv4_receiver(monkeypatch, transport):
    size = cascade_probe.PAYLOAD_BYTES
    processes = iter([
        Process([{"event": "ready", "receiver_port": 43123}, {"event": "result", "bytes": size},
                 {"event": "cleanup", "ok": True}]),
        Process([{"event": "ready"}, {"event": "result", "bytes": size, "sent": size,
                 "secs": 0.2, "digest_matches": True}, {"event": "cleanup", "ok": True}]),
    ])
    configs = []
    async def start(node, config):
        configs.append(config)
        return next(processes)
    async def port(*args): return 43123
    monkeypatch.setattr(cascade_probe, "_start", start)
    monkeypatch.setattr(cascade_probe, "_port", port)
    result = await cascade_probe.run(None, None, ENTRY, EXIT, transport)
    assert result["ok"] is True and result["bytes"] == size
    assert [config["peer_ip"] for config in configs] == [ENTRY, EXIT]
    for config in configs:
        assert config["address_family"] == 6
        assert ipaddress.ip_address(config["inner"]).version == 4
        assert ipaddress.ip_address(config["peer_inner"]).version == 4
    if transport == "vless":
        assert configs[0]["xray_config"]["inbounds"][0]["listen"] == EXIT


async def test_probe_rejects_mixed_families_before_start(monkeypatch):
    async def start(*args): pytest.fail("mixed families must not launch remote processes")
    monkeypatch.setattr(cascade_probe, "_start", start)
    with pytest.raises(ValueError, match="same address family"):
        await cascade_probe.run(None, None, ENTRY, "192.0.2.20", "gre")


@pytest.mark.parametrize("transport", ["awg", "gre", "vless"])
async def test_api_persists_ipv6_and_binds_replay_to_family_and_endpoints(
    client, auth_headers, session_factory, monkeypatch, transport,
):
    entry, exit_, *_ = await setup_nodes(session_factory)
    remote_mocks(monkeypatch)
    async def route(conn, peer): return ENTRY if peer == EXIT else EXIT
    monkeypatch.setattr(cascade, "_route_src", route)
    payload = {"entry_id": entry, "exit_id": exit_, "transport": transport,
               "address_family": "ipv6", "entry_endpoint": ENTRY, "exit_endpoint": EXIT,
               "request_id": "da93395d-a562-46b5-8f4a-515cf9bdffbe"}
    first = await client.post('/api/cascades', headers=auth_headers, json=payload)
    assert first.status_code == 202, first.text
    result = first.json()
    assert result["address_family"] == "ipv6"
    assert result["entry_ip"] == ENTRY and result["exit_ip"] == EXIT
    async with session_factory() as session:
        row = await session.get(Cascade, result["id"])
        saved = json.loads(row.params)
        assert saved["address_family"] == "ipv6" and saved["entry_ip"] == ENTRY and saved["exit_ip"] == EXIT
        assert (await session.get(Server, entry)).host == "192.0.2.10"
        assert (await session.get(Server, exit_)).host == "192.0.2.11"
    retry = await client.post('/api/cascades', headers=auth_headers, json=payload)
    assert retry.status_code == 202 and retry.json()["id"] == result["id"]
    changed = await client.post('/api/cascades', headers=auth_headers, json=payload | {"exit_endpoint": "2001:db8::21"})
    assert changed.status_code == 409
