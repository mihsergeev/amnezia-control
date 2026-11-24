import json
import os
import socket
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app import cascade, cascade_lock, cascade_routes


def test_route_normalization_and_order():
    update = cascade_routes.RouteUpdate(routes=[
        {"destination": " BÜCHER.example. ", "via": "entry"},
        {"destination": "192.0.2.5", "via": "exit"},
        {"destination": "198.51.100.0/24", "via": "entry"},
    ])
    rules = cascade_routes.xray_rules([route.model_dump() for route in update.routes])
    assert [(rule.get("domain"), rule.get("ip"), rule["outboundTag"]) for rule in rules[2:]] == [
        (["domain:xn--bcher-kva.example"], None, "direct"),
        (None, ["192.0.2.5"], "exit"),
        (None, ["198.51.100.0/24"], "direct"),
    ]
    assert rules[0]["inboundTag"] == ["tproxy", "check"]
    assert rules[1]["inboundTag"] == ["check"]
    assert all(rule["inboundTag"] == ["tproxy"] for rule in rules[2:])


@pytest.mark.parametrize("destination", [
    "https://example.com", "*.example.com", "999.2.3.4", "192.0.2.5/24",
    "2001:db8::1", "example..com", "api.ipify.org",
])
def test_invalid_destination(destination):
    with pytest.raises(ValidationError):
        cascade_routes.Route(destination=destination, via="entry")


def test_duplicate_route_rejected_after_normalization():
    with pytest.raises(ValidationError):
        cascade_routes.RouteUpdate(routes=[
            {"destination": "Example.com.", "via": "entry"},
            {"destination": "example.com", "via": "exit"},
        ])


@pytest.mark.parametrize("transport", ["awg", "gre", "vless"])
def test_gateway_preserves_private_block_and_defaults(transport):
    params = {"port": 443, "uuid": "fixture", "sni": "example.com",
              "public_key": "fixture", "short_id": "fixture"}
    routes = [{"destination": "example.com", "via": "exit"}]
    original = json.loads(cascade.entry_gateway_config(transport, "192.0.2.5", params, country="ru"))
    updated = json.loads(cascade.entry_gateway_config(
        transport, "192.0.2.5", params | {"routes": routes}, country="ru"))
    rules = updated["routing"]["rules"]
    assert rules[0] == original["routing"]["rules"][0]
    assert rules[1:4] == cascade_routes.xray_rules(routes)
    assert rules[4:] == original["routing"]["rules"][3:]
    assert updated["outbounds"] == original["outbounds"]
    assert updated["inbounds"] == original["inbounds"]


def test_edit_lock_supports_legacy_and_owned_cascades():
    for owner in ("", "b" * 32):
        command = cascade_lock.wrap(1, "true", owner, edit=True)
        assert "edit" in command
        assert "true" in command


@pytest.mark.parametrize("reinstalled", [False, True])
def test_retry_after_config_replace_reloads_the_gateway(tmp_path, monkeypatch, reinstalled):
    path = tmp_path / "config.json"
    original = [{"ip": ["geoip:private"], "outboundTag": "block"}]
    path.write_text(json.dumps({"routing": {"rules": original}}), encoding="utf-8")
    rules = cascade_routes.xray_rules([{"destination": "example.org", "via": "entry"}])
    payload = [str(tmp_path), "gateway", "owner", 1080, cascade_routes.RULE_TAG, rules,
               None, [], cascade.PRIVATE_RULE, cascade.LEGACY_PRIVATE_RULE]
    monkeypatch.setattr(sys, "argv", ["-c", json.dumps(payload)])
    restarts = []
    running = True
    container_id = "a" * 64

    def docker(args, **_kwargs):
        if args[1] == "inspect":
            return SimpleNamespace(stdout=json.dumps([{
                "Id": container_id,
                "Config": {"Labels": {"org.amnezia.control.owner": "owner"}},
                "State": {"Running": running},
                "Mounts": [{"Source": str(tmp_path), "Destination": "/usr/local/etc/xray"}],
            }]))
        if args[1] == "restart":
            restarts.append(json.loads(path.read_text(encoding="utf-8"))["routing"]["rules"])
        return SimpleNamespace(stdout="")

    lstat = Path.lstat

    def config_stat(self, *args, **kwargs):
        meta = lstat(self, *args, **kwargs)
        if self == path:
            return SimpleNamespace(st_mode=meta.st_mode, st_size=meta.st_size, st_uid=0)
        return meta

    replace = os.replace

    def interrupt_after_replacement(source, destination):
        replace(source, destination)
        if destination == path:
            raise InterruptedError("test interruption before reload")

    monkeypatch.setattr(Path, "lstat", config_stat)
    monkeypatch.setattr(subprocess, "run", docker)
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: nullcontext())
    with monkeypatch.context() as interrupted:
        interrupted.setattr(os, "replace", interrupt_after_replacement)
        with pytest.raises(InterruptedError):
            exec(cascade_routes._UPDATE, {})
    assert not restarts
    if reinstalled:
        container_id = "b" * 64
        new_base = {"ip": ["geoip:private"], "outboundTag": "block", "ruleTag": "new-base"}
        path.write_text(json.dumps({"routing": {"rules": [new_base]}}), encoding="utf-8")
    else:
        running = False
    exec(cascade_routes._UPDATE, {})
    # the update also moves the base rule from geoip:private to the explicit list
    assert restarts == ([[cascade.PRIVATE_RULE, *rules]] if reinstalled
                        else [original, [cascade.PRIVATE_RULE, *rules]])
    assert not (tmp_path / ".routes-pending").exists()


@pytest.mark.parametrize("failure", ["candidate", "restart", "recovery"])
def test_failed_route_update_retains_last_working_configuration(tmp_path, monkeypatch, failure):
    path = tmp_path / "config.json"
    original = json.dumps({"inbounds": [{"tag": "preserved-client"}], "routing": {"rules": [
        {"ip": ["geoip:private"], "outboundTag": "block"},
        {"domain": ["domain:example.com"], "outboundTag": "exit"},
    ]}}).encode()
    path.write_bytes(original)
    monkeypatch.setattr(sys, "argv", ["-c", json.dumps([
        str(tmp_path), "gateway", "owner", 1080, cascade_routes.RULE_TAG,
        cascade_routes.xray_rules([{"destination": "example.org", "via": "entry"}]),
        None, [], cascade.PRIVATE_RULE, cascade.LEGACY_PRIVATE_RULE,
    ])])
    restarts = []

    def docker(args, **_kwargs):
        if args[1] == "inspect":
            return SimpleNamespace(stdout=json.dumps([{
                "Id": "a" * 64, "Config": {"Labels": {"org.amnezia.control.owner": "owner"}},
                "State": {"Running": True},
                "Mounts": [{"Source": str(tmp_path), "Destination": "/usr/local/etc/xray"}],
            }]))
        if args[1] == "exec" and failure == "candidate":
            raise subprocess.CalledProcessError(1, args)
        if args[1] == "restart":
            restarts.append(path.read_bytes())
            if len(restarts) == 1 or failure == "recovery":
                raise subprocess.CalledProcessError(1, args)
        return SimpleNamespace(stdout="")

    lstat = Path.lstat

    def config_stat(self, *args, **kwargs):
        meta = lstat(self, *args, **kwargs)
        return (SimpleNamespace(st_mode=meta.st_mode, st_size=meta.st_size, st_uid=0)
                if self == path else meta)

    monkeypatch.setattr(Path, "lstat", config_stat)
    monkeypatch.setattr(subprocess, "run", docker)
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: nullcontext())
    if failure == "candidate":
        with pytest.raises(subprocess.CalledProcessError):
            exec(cascade_routes._UPDATE, {})
        assert not restarts
    else:
        with pytest.raises(SystemExit) as error:
            exec(cascade_routes._UPDATE, {})
        assert error.value.code == (74 if failure == "recovery" else 75)
        assert len(restarts) == 2 and restarts[-1] == original
    assert path.read_bytes() == original
    assert (tmp_path / ".routes-pending").exists() == (failure == "recovery")


def test_blocked_route_goes_to_the_blackhole_and_health_rules_stay_first():
    from app.cascade_routes import RouteUpdate, xray_rules

    update = RouteUpdate.model_validate({"routes": [
        {"destination": "probe.example", "via": "block"},
        {"destination": "198.51.100.0/24", "via": "block"},
        {"destination": "site.example", "via": "entry"},
    ]})
    rules = xray_rules([route.model_dump() for route in update.routes])
    assert [r["outboundTag"] for r in rules[:2]] == ["exit", "exit"]  # gateway health checks are never blocked
    assert rules[2]["domain"] == ["domain:probe.example"] and rules[2]["outboundTag"] == "block"
    assert rules[3]["ip"] == ["198.51.100.0/24"] and rules[3]["outboundTag"] == "block"
    assert rules[4]["outboundTag"] == "direct"


def test_private_networks_are_listed_not_taken_from_the_geo_databases():
    cfg = json.loads(cascade.entry_gateway_config("gre", "198.51.100.20", {"routes": []}, country="ru"))
    first = cfg["routing"]["rules"][0]
    assert first == cascade.PRIVATE_RULE
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
                "127.0.0.0/8", "fc00::/7", "fe80::/10"):
        assert net in first["ip"]
    assert "geoip:private" not in json.dumps(cfg)


def test_sync_state_accepts_the_legacy_base_as_pending():
    synced = [cascade.PRIVATE_RULE, *cascade_routes.xray_rules([]), *cascade.local_rules("ru")]
    legacy = [cascade.LEGACY_PRIVATE_RULE, *synced[1:]]
    assert cascade_routes.routing_state(synced, "ru", [])["state"] == "synced"
    assert cascade_routes.routing_state(legacy, "ru", [])["state"] == "pending"
    assert cascade_routes.routing_state([{"ip": ["geoip:ru"], "outboundTag": "block"}], "ru", [])["state"] == "unknown"


def test_update_script_carries_the_private_rule():
    import shlex
    script = cascade_routes.update_script("/d", "gw", 1080, "owner", [], "ru")
    payload = json.loads(shlex.split(script)[-1])
    assert payload[8] == cascade.PRIVATE_RULE and payload[9] == cascade.LEGACY_PRIVATE_RULE
    assert len(payload) == 10
    payload = json.loads(shlex.split(cascade_routes.update_script("/d", "gw", 1080, "owner", []))[-1])
    assert payload[6] is None and payload[7] == [] and len(payload) == 10
