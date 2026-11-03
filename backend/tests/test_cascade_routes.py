import json

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
    assert [(rule.get("domain"), rule.get("ip"), rule["outboundTag"]) for rule in rules[1:]] == [
        (["domain:xn--bcher-kva.example"], None, "direct"),
        (None, ["192.0.2.5"], "exit"),
        (None, ["198.51.100.0/24"], "direct"),
    ]
    assert all(rule["inboundTag"] == ["tproxy"] for rule in rules)


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
    assert rules[1:3] == cascade_routes.xray_rules(routes)
    assert rules[3:] == original["routing"]["rules"][1:]
    assert updated["outbounds"] == original["outbounds"]
    assert updated["inbounds"] == original["inbounds"]


def test_edit_lock_supports_legacy_and_owned_cascades():
    for owner in ("", "b" * 32):
        command = cascade_lock.wrap(1, "true", owner, edit=True)
        assert "edit" in command
        assert "true" in command
