import copy
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app import native_snapshots
from app.models import AppSetting, AwgNote, ClientLimit, NativeVpnConfig, PausedClient, Server


async def prepare(session):
    server = Server(name="Native fixture", host="203.0.113.21", ssh_port=22, ssh_user="service")
    session.add(server)
    await session.flush()
    for protocol in ("wireguard", "openvpn-native"):
        session.add(NativeVpnConfig(server_id=server.id, protocol=protocol, client_id="fixture", name="Original", config="inert profile fixture"))
    session.add(AwgNote(server_id=server.id, protocol="wireguard", public_key="fixture", note="Keep note"))
    session.add(ClientLimit(server_id=server.id, protocol="wireguard", client_id="fixture", name="Original", expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc)))
    session.add(PausedClient(server_id=server.id, protocol="wireguard", client_id="fixture", name="Original", data=json.dumps({"ip": "10.85.0.2"})))
    await session.commit()
    return server


async def test_restore_pairs_keys_pause_notes_limits_and_scopes_protocol(session_factory):
    async with session_factory() as session:
        server = await prepare(session)
        await native_snapshots.save(session, server, "wireguard", "20260101-120000", {"port": 51820, "transport": "udp"})
        snapshot = await native_snapshots.load(session, server, "wireguard", "20260101-120000")
        row = await session.scalar(select(NativeVpnConfig).where(NativeVpnConfig.protocol == "wireguard"))
        row.config = "changed fixture"
        await session.commit()
        await native_snapshots.apply(session, server.id, "wireguard", snapshot, commit=True)
        restored = await native_snapshots.capture(session, server.id, "wireguard")
        assert restored == snapshot["rows"]
        other = await session.scalar(select(NativeVpnConfig).where(NativeVpnConfig.protocol == "openvpn-native"))
        assert other.config == "inert profile fixture"


async def test_restore_rejects_missing_wrong_target_and_corrupt_rows_before_mutation(session_factory):
    async with session_factory() as session:
        server = await prepare(session)
        with pytest.raises(ValueError, match="Нет метаданных"):
            await native_snapshots.load(session, server, "wireguard", "20260101-120000")
        await native_snapshots.save(session, server, "wireguard", "20260101-120000", {"port": 51820, "transport": "udp"})
        saved = await native_snapshots.load(session, server, "wireguard", "20260101-120000")
        server.host = "203.0.113.22"
        with pytest.raises(ValueError, match="другому серверу"):
            await native_snapshots.load(session, server, "wireguard", "20260101-120000")
        before = await native_snapshots.capture(session, server.id, "wireguard")
        bad = copy.deepcopy(saved)
        bad["rows"]["limits"][0]["expires_at"] = "not a date"
        with pytest.raises(ValueError, match="дата"):
            await native_snapshots.apply(session, server.id, "wireguard", bad)
        assert await native_snapshots.capture(session, server.id, "wireguard") == before
        bad = copy.deepcopy(saved)
        bad["rows"]["profiles"].append(bad["rows"]["profiles"][0])
        with pytest.raises(ValueError, match="идентификаторы"):
            await native_snapshots.apply(session, server.id, "wireguard", bad)
        assert await native_snapshots.capture(session, server.id, "wireguard") == before


async def test_prune_and_server_removal_remove_only_owned_private_manifests(session_factory):
    async with session_factory() as session:
        server = await prepare(session)
        session.add(AppSetting(key="alerts", value="preserve"))
        for protocol in ("wireguard", "openvpn-native"):
            for timestamp in ("20260101-120000", "20260102-120000"):
                await native_snapshots.save(session, server, protocol, timestamp, {"port": 51820, "transport": "udp"})
        await native_snapshots.prune(session, server.id, "wireguard", ["20260102-120000"])
        keys = set(await session.scalars(select(AppSetting.key)))
        assert len(keys) == 4
        assert f"native_snapshot:{server.id}:wireguard:20260101-120000" not in keys
        await native_snapshots.delete_server(session, server.id)
        await session.commit()
        assert list(await session.scalars(select(AppSetting.key))) == ["alerts"]


async def test_transfer_rewrites_identity_preserves_private_profiles_and_rejects_partial_batch(session_factory):
    async with session_factory() as session:
        source = await prepare(session)
        await native_snapshots.save(session, source, "wireguard", "20260101-120000", {"port": 51820, "transport": "udp"})
        exported = await native_snapshots.export_server(session, source.id)
        target = Server(name="Transferred fixture", host=source.host, ssh_port=source.ssh_port, ssh_user=source.ssh_user)
        session.add(target)
        await session.flush()
        bad = copy.deepcopy(exported)
        bad.append(copy.deepcopy(exported[0]))
        bad[-1]["snapshot_id"] = "20260102-120000"
        bad[-1]["manifest"]["rows"]["paused"][0]["paused_at"] = "invalid"
        with pytest.raises(ValueError, match="дата"):
            await native_snapshots.import_server(session, target, bad)
        assert await native_snapshots.export_server(session, target.id) == []
        bad = copy.deepcopy(exported)
        bad[0]["snapshot_id"] = 123
        with pytest.raises(ValueError, match="идентификатор"):
            await native_snapshots.import_server(session, target, bad)
        assert await native_snapshots.export_server(session, target.id) == []
        await native_snapshots.import_server(session, target, exported)
        restored = await native_snapshots.load(session, target, "wireguard", "20260101-120000")
        assert restored["server"]["id"] == target.id
        assert restored["rows"] == exported[0]["manifest"]["rows"]
        assert exported[0]["manifest"]["server"]["id"] == source.id
        with pytest.raises(ValueError, match="уже сохранены"):
            await native_snapshots.import_server(session, target, exported)
        target.host = "203.0.113.99"
        with pytest.raises(ValueError, match="другому серверу"):
            await native_snapshots.export_server(session, target.id)
        with pytest.raises(ValueError, match="другому серверу"):
            await native_snapshots.import_server(session, target, exported)
