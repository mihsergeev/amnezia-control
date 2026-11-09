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
    payload = [str(tmp_path), "gateway", "owner", 1080, cascade_routes.RULE_TAG, rules]
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
    assert restarts == ([[new_base, *rules]] if reinstalled else [original, original + rules])
    assert not (tmp_path / ".routes-pending").exists()
