import copy
import ipaddress
import json
import shlex
import uuid

import pytest

from app import awg, wg_bulk, xray, xray_bulk


async def test_wireguard_retry_after_config_write_and_untouched_peer(monkeypatch):
    _, server_key = awg.generate_keypair()
    psk, existing_key = awg.generate_keypair()
    existing_peer = {"PublicKey": existing_key, "AllowedIPs": "10.8.0.2/32", "PresharedKey": psk}
    state = awg.AwgState("wg-test", "wg0", 51820, server_key, "198.51.100.1:51820", "10.8.0.1/29")
    conf = "[Interface]\nAddress = 10.8.0.1/29\n\n[Peer]\n" + "".join(
        f"{key} = {value}\n" for key, value in existing_peer.items())
    runtime = {existing_key: existing_peer.copy()}
    node_table = [{"clientId": existing_key, "userData": {"clientName": "Existing", "custom": "Keep"}}]
    writes = []

    async def read_runtime(conn, interface):
        return copy.deepcopy(runtime)

    async def read_psk(conn, interface):
        return psk

    async def write_file(conn, container, path, payload):
        nonlocal conf
        conf = payload
        writes.append(path)

    async def write_table(conn, container, table):
        nonlocal node_table
        if not node_table or len(node_table) == 1:
            node_table = copy.deepcopy(table)
            if len(writes) == 1:
                # Files are committed even if the remote command ACK was lost.
                raise OSError("lost ACK")
        else:
            node_table = copy.deepcopy(table)

    async def command(conn, outer, **kwargs):
        cmd = shlex.split(shlex.split(outer.partition("$DOCKER exec ")[2])[-1])
        assert cmd[:3] == ["wg", "set", "wg0"]
        for start in [i for i, part in enumerate(cmd) if part == "peer"]:
            cid = cmd[start + 1]
            assert cid != existing_key
            if cmd[start + 2] == "remove":
                runtime.pop(cid, None)
            else:
                runtime[cid] = {"PublicKey": cid, "AllowedIPs": cmd[start + 5], "PresharedKey": psk}

    def snapshot():
        peers = {entry["PublicKey"]: entry for entry in awg.parse_conf(conf)[1]}
        return wg_bulk.NodeState(state, conf, peers, copy.deepcopy(runtime), copy.deepcopy(node_table))

    monkeypatch.setattr(wg_bulk, "runtime_peers", read_runtime)
    monkeypatch.setattr(wg_bulk, "_psk", read_psk)
    monkeypatch.setattr(awg, "_write_file", write_file)
    monkeypatch.setattr(awg, "_write_table", write_table)
    monkeypatch.setattr(awg, "_run", command)
    paused = {"paused-key": {"name": "Paused", "data": {"ip": "10.8.0.3"}}}
    items = await wg_bulk.plan(None, snapshot(), paused, ["Group-001", "Group-002"], "192.0.2.53", native=True)
    ids = [item["client_id"] for item in items]
    assert [item["ip"] for item in items] == ["10.8.0.4", "10.8.0.5"]
    assert len(set(ids)) == 2
    with pytest.raises(OSError, match="ACK"):
        await wg_bulk.apply(None, snapshot(), paused, items)
    await wg_bulk.apply(None, snapshot(), paused, items)
    assert set(runtime) == {existing_key, *ids}
    assert len(node_table) == 3
    assert "MTU = 1380" in items[0]["config"]

    await wg_bulk.revoke(None, snapshot(), ids)
    await wg_bulk.revoke(None, snapshot(), ids)
    assert runtime == {existing_key: existing_peer}
    assert [entry["clientId"] for entry in node_table] == [existing_key]
    assert node_table[0]["userData"]["custom"] == "Keep"
    assert awg.parse_conf(conf)[1] == [existing_peer]


def test_wireguard_allocation_does_not_enumerate_large_occupied_network():
    with pytest.raises(wg_bulk.PlanConflict):
        wg_bulk._available("10.0.0.1/8", [ipaddress.ip_network("0.0.0.0/0")], 2)


def _xray_server(listen):
    return {
        "api": {"tag": "management", "listen": listen, "services": ["StatsService"]},
        "inbounds": [
            {"protocol": "vless", "streamSettings": {"security": "reality"},
             "settings": {"clients": []}},
            {"protocol": "vless", "tag": "existing-xhttp",
             "streamSettings": {"network": "xhttp"}, "settings": {"clients": []}},
        ],
    }


@pytest.mark.parametrize("listen", ["0.0.0.0:10321", "@shared", "/tmp/shared.sock"])
def test_xray_management_disables_handler_service_on_other_endpoints(listen):
    exposed = _xray_server(listen)
    assert not xray_bulk.configure_management(exposed)
    assert xray_bulk._management_address(exposed) is None
    exposed["api"]["services"].append("hANDLERService")
    assert xray_bulk.configure_management(exposed)
    assert exposed["api"]["listen"] == listen
    assert exposed["api"]["services"] == ["StatsService"]


def test_xray_management_migrates_loopback_stats_to_private_socket():
    local = _xray_server("127.0.0.1:10321")
    local["api"]["services"].append("HandlerService")
    assert xray_bulk._management_address(local) is None
    assert xray_bulk.configure_management(local)
    assert not xray_bulk.configure_management(local)
    assert local["api"]["services"] == ["StatsService", "HandlerService"]
    assert local["api"]["listen"] == xray.MANAGEMENT_API_LISTEN
    assert xray_bulk._management_address(local) == f"unix:{xray.MANAGEMENT_API_SOCKET}"
    assert [row["tag"] for row in local["inbounds"]] == ["acontrol-vless", "existing-xhttp"]


def test_xray_management_migrates_only_dedicated_legacy_stats_route():
    legacy = _xray_server("")
    api_inbound = {"listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
                   "tag": "management", "settings": {"address": "127.0.0.1"}}
    unrelated = {"type": "field", "domain": ["example.com"], "outboundTag": "custom"}
    api_rule = {"type": "field", "inboundTag": ["management"], "outboundTag": "management"}
    legacy["inbounds"].append(api_inbound)
    legacy["routing"] = {"domainStrategy": "AsIs", "rules": [api_rule, unrelated]}
    custom = copy.deepcopy(legacy)
    custom["routing"]["rules"][0]["inboundTag"].append("existing-xhttp")
    before = copy.deepcopy(custom)
    assert not xray_bulk.configure_management(custom)
    assert custom == before
    assert xray_bulk.configure_management(legacy)
    assert not xray_bulk.configure_management(legacy)
    assert legacy["api"]["listen"] == xray.MANAGEMENT_API_LISTEN
    assert api_inbound not in legacy["inbounds"]
    assert legacy["routing"] == {"domainStrategy": "AsIs", "rules": [unrelated]}


def test_xray_management_refuses_socket_used_as_vless_fallback():
    server = _xray_server("127.0.0.1:10321")
    server["inbounds"][0]["settings"]["fallbacks"] = [
        {"dest": "/var" + xray.MANAGEMENT_API_SOCKET},
    ]
    before = copy.deepcopy(server)
    assert not xray_bulk.configure_management(server)
    assert server == before
    server["api"]["listen"] = xray.MANAGEMENT_API_LISTEN
    assert xray_bulk._management_address(server) is None


async def test_xray_uses_live_api_and_reconciles_partial_application(monkeypatch):
    document = _xray_server("127.0.0.1:10321")
    xray_bulk.configure_management(document)
    existing = str(uuid.uuid4())
    document["inbounds"][0]["settings"]["clients"] = [{"id": existing, "flow": xray.FLOW, "email": existing}]
    table = [{"clientId": existing, "userData": {"clientName": "Existing", "custom": "Keep"}}]
    tags = [inbound["tag"] for inbound in document["inbounds"]]
    runtime = {
        tags[0]: {existing: {"email": existing, "account": {"id": existing, "flow": xray.FLOW}}},
        tags[1]: {},
    }
    commands = []

    async def write_server(conn, container, data):
        nonlocal document
        document = copy.deepcopy(data)

    async def write_table(conn, container, data):
        nonlocal table
        table = copy.deepcopy(data)

    async def read_runtime(*args):
        return copy.deepcopy(runtime)

    class Conn:
        async def run(self, cmd, *, input=None, check=False):
            commands.append(cmd)
            if " api adu " in cmd:
                for inbound in json.loads(input)["inbounds"]:
                    for row in inbound["settings"]["clients"]:
                        cid = row["id"]
                        runtime[inbound["tag"]][cid] = {"email": cid, "account": row}
                if len(commands) == 1:
                    raise OSError("lost ACK")
            else:
                assert " api rmu " in cmd
                args = shlex.split(shlex.split(cmd.partition("$DOCKER exec ")[2])[-1])
                tag = args[args.index("-tag") + 1]
                for email in args[args.index("--") + 1:]:
                    runtime[tag].pop(email)

    def snapshot():
        return xray_bulk.NodeState("amnezia-xray", copy.deepcopy(document), copy.deepcopy(table),
                                   existing, f"unix:{xray.MANAGEMENT_API_SOCKET}", [], copy.deepcopy(runtime))

    def state():
        node = snapshot()
        node.inbounds = node.server["inbounds"]
        return node

    monkeypatch.setattr(xray, "_write_server", write_server)
    monkeypatch.setattr(xray, "_write_table", write_table)
    monkeypatch.setattr(xray_bulk, "_runtime", read_runtime)
    items = xray_bulk.plan(state(), {}, ["New-001", "New-002"])
    ids = [item["client_id"] for item in items]
    with pytest.raises(OSError, match="ACK"):
        await xray_bulk.apply(Conn(), state(), items)
    await xray_bulk.apply(Conn(), state(), items)
    assert len(commands) == 1
    assert set(runtime[tags[0]]) == {existing, *ids}
    assert set(runtime[tags[1]]) == set(ids)
    assert len(table) == 3

    failures = await xray_bulk.revoke(Conn(), state(), ids + [existing])
    assert failures == {existing: "Служебный UUID Xray нельзя отозвать группой"}
    assert not await xray_bulk.revoke(Conn(), state(), ids)
    assert set(runtime[tags[0]]) == {existing} and not runtime[tags[1]]
    assert table == [{"clientId": existing, "userData": {"clientName": "Existing", "custom": "Keep"}}]
    assert all("restart" not in command for command in commands)
