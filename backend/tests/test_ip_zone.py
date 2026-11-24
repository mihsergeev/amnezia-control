"""IPv6 zone IDs never pass as addresses.

ipaddress.ip_address accepts a zone of almost any characters after "%" and keeps
it in str(), so "fe80::1%$(id)" parsed fine and then reached node scripts.
"""
import inspect

import pytest
from pydantic import ValidationError

from app import awg, cascade, cascade_exit, ssh_firewall, ssh_host, ssh_policy, sshops
from app.native_schemas import NativeCreateRequest
from app.schemas import ServerCreate, ServerUpdate

ZONED = ["fe80::1%$(id)", "fe80::1%`id`", "fe80::1%x;id", "fe80::1%eth0", "fe80::/64%x"]


@pytest.mark.parametrize("value", ZONED)
def test_validators_reject_zoned_addresses(value):
    assert ssh_host.valid(value) is False
    with pytest.raises(ValueError):
        ssh_host.ip_literal(value)
    with pytest.raises(ValueError):
        ssh_policy.normalize_sources([value])
    with pytest.raises(awg.AwgError):
        awg._safe_ip(value)
    with pytest.raises(ValidationError):
        ServerCreate.model_validate({"name": "x", "host": value})
    with pytest.raises(ValidationError):
        ServerUpdate.model_validate({"ssh_source_mode": "custom", "ssh_source_ips": [value]})
    with pytest.raises(ValidationError):
        NativeCreateRequest.model_validate({"name": "x", "dns": value})


def test_plain_addresses_still_pass():
    assert ssh_host.valid("2001:db8::1") and ssh_host.valid("192.0.2.1") and ssh_host.valid("node.example.test")
    assert ssh_host.ip_literal("2001:0db8::0001") == "2001:db8::1"
    assert ssh_policy.normalize_sources(["2001:db8::/64", "192.0.2.1"]) == ["2001:db8::/64", "192.0.2.1"]
    assert awg._safe_ip("10.8.1.5") == "10.8.1.5"


def test_script_sinks_refuse_zoned_values():
    with pytest.raises(ValueError):
        ssh_firewall.script("a" * 32, ["fe80::1%$(id)"], 22)
    with pytest.raises(ValueError):
        sshops._firewall_snippet("fe80::1%$(id)", 22, "sudo")
    with pytest.raises(ValueError):
        cascade._gre_install("exit", "fe80::1%$(id)", "10.0.0.1/30", "10.0.0.0/30")
    with pytest.raises(ValueError):
        cascade.build_exit_script("vless", "fe80::1%$(id)", 1, {"port": 443})
    # A stored value that is not a plain address is never run on cleanup.
    assert cascade.ufw_cleanup("1.1.1.1;id", 443) == "true\n"
    assert cascade.ufw_cleanup("fe80::1%$(id)", None) == "true\n"
    assert "203.0.113.9" in cascade.ufw_cleanup("203.0.113.9", 443)
    assert cascade._ip_or_empty("fe80::1%$(id)") == ""


def test_scoped_exit_removal_quotes_the_transport():
    source = inspect.getsource(cascade_exit.remove)
    assert "'TRANSPORT={transport}'" not in source and "shlex.quote('TRANSPORT=' + transport)" in source


async def test_resume_refuses_a_zoned_ip_before_any_command():
    ran = []

    class Conn:
        async def run(self, command, **kwargs):
            ran.append(command)
            raise AssertionError("no command may run")

    state = awg.AwgState(container="amnezia-awg2", interface="awg0", listen_port=1,
                         server_public_key="", endpoint="", address="10.8.1.1/24")
    with pytest.raises(awg.AwgError):
        await awg.resume_client(Conn(), state, "A" * 43 + "=", "client", "fe80::1%$(id)")
    assert ran == []


async def test_restore_and_import_reject_zoned_values(client, auth_headers):
    import io
    import json
    import tarfile

    def archive(servers):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = json.dumps({"servers": servers}).encode()
            info = tarfile.TarInfo("db.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    base = {"id": 1, "name": "n", "host": "192.0.2.1", "ssh_port": 22, "ssh_user": "root"}
    for bad in ({"host": "fe80::1%$(id)"}, {"ssh_source_mode": "custom", "ssh_source_ips": ["fe80::1%$(id)"]},
                {"client_endpoint": "fe80::1%$(id)"}):
        r = await client.post("/api/backup/restore", content=archive([{**base, **bad}]),
                              headers={**auth_headers, "X-Confirm-Password": "testpass"})
        assert r.status_code == 400, (bad, r.text)

    payload = {"format": "acontrol-server", "server": {"name": "n", "host": "192.0.2.9", "ssh_port": 22,
                                                         "ssh_source_mode": "custom", "ssh_source_ips": ["fe80::1%$(id)"]},
               "tables": {}}
    from app.api import transfer
    payload["format"], payload["format_version"] = transfer.FORMAT, transfer.FORMAT_VERSION
    r = await client.post("/api/servers/import-file", content=json.dumps(payload), headers=auth_headers)
    assert r.status_code == 400, r.text
    assert (await client.get("/api/servers", headers=auth_headers)).json() == []


@pytest.mark.skipif(__import__("shutil").which("bash") is None or __import__("os").name == "nt", reason="needs bash")
def test_gre_defaults_file_keeps_node_values_inert(tmp_path):
    """LOCAL and EGRESS come from the node; the defaults file is sourced by root."""
    import subprocess

    lines = cascade._gre_install("exit", "192.0.2.1", "10.0.0.2/30", "10.0.0.0/30")
    heredoc = next(line for line in lines if "<<EOF" in line)
    target = tmp_path / "defaults"
    script = heredoc.split("\n", 1)[1].rsplit("EOF", 1)[0]
    for egress, local in (("eth0", "192.0.2.5"), ("e;touch pwned", "192.0.2.5")):
        body = f'LOCAL={local!r}; EGRESS={egress!r}; cat > {target} <<EOF\n{script}EOF\n'
        subprocess.run(["bash", "-c", body], check=True, cwd=tmp_path)
        sourced = subprocess.run(["bash", "-c", f". {target}; printf '%s|%s' \"$LOCAL\" \"$EGRESS\""],
                                 capture_output=True, text=True, cwd=tmp_path, check=True)
        assert sourced.stdout == f"{local}|{egress}"
        assert not (tmp_path / "pwned").exists()
