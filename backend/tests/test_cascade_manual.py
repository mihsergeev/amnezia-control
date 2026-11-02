import copy
import json
import subprocess
from types import SimpleNamespace

import pytest

from app import cascade_manual


def config():
    return {"outbounds": [
        {"tag": "exit", "protocol": "vless",
         "settings": {"vnext": [{"address": "203.0.113.20", "port": 443,
                                   "users": [{"id": "never-export-client-id"}]}]},
         "streamSettings": {"network": "xhttp", "security": "reality",
                            "realitySettings": {"publicKey": "never-export-key", "serverName": "untrusted-name.invalid"}}},
        {"tag": "direct", "protocol": "freedom"},
    ], "private_key": "never-export-private"}


def run_probe(monkeypatch, capsys, tmp_path, *, body=None, running=True,
              entrypoint=None, cmd=None, mounted=True, extra_json=False, fail=None):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config() if body is None else body), encoding="utf-8")
    if extra_json:
        (tmp_path / "override.json").write_text("{}", encoding="utf-8")
    values = [running, entrypoint or ["/usr/local/bin/xray"],
              cmd or ["-confdir", "/usr/local/etc/xray/"],
              [{"Type": "bind", "Source": str(tmp_path), "Destination": "/usr/local/etc/xray"}] if mounted else []]
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        assert 0 < kwargs["timeout"] <= 1.25
        assert args[-1] == "xray-cascade"
        assert "exec" not in args
        if fail:
            raise fail
        return SimpleNamespace(returncode=0, stdout="\n".join(json.dumps(v) for v in values))

    monkeypatch.setattr("subprocess.run", fake_run)
    source = cascade_manual.PROBE_PY.replace("APPROVED = '/app/cascade/config'", "APPROVED = " + repr(str(tmp_path)))
    exec(compile(source, "<manual-probe>", "exec"), {})
    output = capsys.readouterr().out
    assert "never-export" not in output and "untrusted-name.invalid" not in output
    assert output.startswith("MANUAL_CASCADE=")
    return cascade_manual.parse_probe(output.removeprefix("MANUAL_CASCADE=").strip()), calls


def test_running_mounted_default_reality_carrier_exports_only_route(monkeypatch, capsys, tmp_path):
    result, calls = run_probe(monkeypatch, capsys, tmp_path)
    assert result == {"transport": "vless", "security": "reality", "network": "xhttp",
                      "exit_host": "203.0.113.20", "exit_port": 443}
    assert len(calls) == 1


@pytest.mark.parametrize("case", ["stopped", "foreign_entrypoint", "unmounted", "other_config",
                                 "multiple_fragments", "multiple_targets", "secondary_route", "timeout"])
def test_unrelated_stale_or_ambiguous_config_is_not_a_manual_cascade(monkeypatch, capsys, tmp_path, case):
    kwargs = {}
    if case == "stopped": kwargs["running"] = False
    if case == "foreign_entrypoint": kwargs["entrypoint"] = ["/bin/sh", "/untrusted/helper.sh"]
    if case == "unmounted": kwargs["mounted"] = False
    if case == "other_config": kwargs["cmd"] = ["-config", "/other/config.json"]
    if case == "multiple_fragments": kwargs["extra_json"] = True
    if case == "multiple_targets":
        value = config(); value["outbounds"][0]["settings"]["vnext"].append(copy.deepcopy(value["outbounds"][0]["settings"]["vnext"][0])); kwargs["body"] = value
    if case == "secondary_route":
        value = config(); value["outbounds"].reverse(); kwargs["body"] = value
    if case == "timeout": kwargs["fail"] = subprocess.TimeoutExpired("docker", 1.25)
    result, _ = run_probe(monkeypatch, capsys, tmp_path, **kwargs)
    assert result == {}


def test_explicit_config_file_inside_directory_mount(monkeypatch, capsys, tmp_path):
    result, _ = run_probe(monkeypatch, capsys, tmp_path, cmd=["run", "-config", "/usr/local/etc/xray/config.json"])
    assert result["exit_host"] == "203.0.113.20"


def test_none_security_is_reported_without_claiming_encryption(monkeypatch, capsys, tmp_path):
    value = config(); value["outbounds"][0]["streamSettings"]["security"] = "none"
    result, _ = run_probe(monkeypatch, capsys, tmp_path, body=value)
    assert result["security"] == "none" and "encrypted" not in result


def test_parser_rejects_bad_routes_and_never_trusts_names_or_secrets():
    base = {"transport": "vless", "security": "reality", "network": "tcp", "exit_host": "vpn.example.invalid", "exit_port": 8443}
    untrusted = {**base, "exit_name": "invented", "exit_country": "ZZ", "private_key": "never-export", "encrypted": True}
    assert cascade_manual.parse_probe(json.dumps(untrusted)) == base
    for field, bad in [("exit_host", "x\nPRIVATE_KEY=secret"), ("exit_host", "https://example.invalid"),
                       ("exit_port", True), ("exit_port", 0), ("exit_port", "443"),
                       ("security", "invented"), ("network", "invented")]:
        assert cascade_manual.parse_probe(json.dumps({**base, field: bad})) == {}
    assert cascade_manual.parse_probe("[1]") == {}
    assert cascade_manual.parse_probe("{broken") == {}
    assert cascade_manual.parse_probe(" " * 4097) == {}
