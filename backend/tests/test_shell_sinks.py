"""Values that reach node commands or client profiles stay inert."""
import base64

import pytest
from pydantic import ValidationError

from app import autobackup, awg, deploy
from app import awg_settings as settings
from app.schemas import CreateClientRequest


async def test_docker_hub_digest_is_used_only_when_it_is_a_digest(monkeypatch):
    good = "sha256:" + "a" * 64

    class Response:
        def raise_for_status(self): pass

        def json(self):
            return {"results": [
                {"name": "2.9.9", "digest": "sha256:0;id>/tmp/pwn;#", "last_updated": "2099-01-01"},
                {"name": "2.0.1", "digest": good, "last_updated": "2026-01-01"},
                {"name": "latest", "digest": "sha256:$(id)", "last_updated": "2099-01-01"},
            ]}

    class Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url): return Response()

    monkeypatch.setattr(deploy.httpx, "AsyncClient", Client)
    info = await deploy.hub_info()
    assert info["line_latest_digest"] == good
    assert info["latest_digest"] == ""
    assert "sha256:0;id>/tmp/pwn;#" not in info["digest_to_version"]


def test_update_script_accepts_only_a_pinned_base_image():
    cfg = {"conf": "", "pub": "", "priv": "", "psk": ""}
    script = deploy.build_script("update", 47180, cfg, base_ref=f"{deploy.BASE_REPO}@sha256:" + "b" * 64)
    assert f"docker pull {deploy.BASE_REPO}@sha256:" + "b" * 64 in script
    for bad in (f"{deploy.BASE_REPO}@sha256:0;id", "evil/image@sha256:" + "b" * 64, f"{deploy.BASE_REPO}:latest"):
        with pytest.raises(ValueError):
            deploy.build_script("update", 47180, cfg, base_ref=bad)


@pytest.mark.parametrize("dns", ["1.1.1.1 ,\nabcd", "1.1.1.1\n", "1.1.1.1,\r\n8.8.8.8"])
def test_client_dns_cannot_carry_a_line_break(dns):
    with pytest.raises(ValidationError):
        CreateClientRequest.model_validate({"name": "x", "dns": dns})
    assert CreateClientRequest.model_validate({"name": "x", "dns": "1.1.1.1, 8.8.8.8"}).dns == "1.1.1.1, 8.8.8.8"


def test_profile_refresh_keeps_backslashes_in_a_stored_endpoint_literal():
    private, _ = awg.generate_keypair()
    _, server_public = awg.generate_keypair()
    psk = base64.b64encode(bytes(32)).decode()
    params = deploy.generate_awg3_params()
    client = awg.build_client_config(client_private=private, address="10.73.1.7", server_public=server_public,
                                     preshared=psk, endpoint="h:1", params=params, dns="192.0.2.53")
    stored = client.replace("Endpoint = h:1", "Endpoint = h\\n[Interface]\\nPostUp = id:1")
    result = settings.refresh_profile(stored, settings.validate_params(params, "3.1"), "10.74.1.7/32", 47500, "10.74.1.0/24")
    lines = [line.strip() for line in result.splitlines()]
    assert lines.count("[Interface]") == 1 and not any(line.startswith("PostUp") for line in lines)
    assert "Endpoint = h\\n[Interface]\\nPostUp = id:47500" in lines


def test_names_with_a_trailing_newline_do_not_pass():
    assert not deploy._CONT_NAME_RE.fullmatch("amnezia-awg\n")
    assert deploy._CONT_NAME_RE.fullmatch("amnezia-awg2")
    assert not autobackup.is_backup_name("acontrol-backup-20261123-000000.tar.gz\n")
    assert autobackup.is_backup_name("acontrol-backup-20261123-000000.tar.gz")


def test_snapshot_quotes_the_container_name():
    import inspect
    assert "C={shlex.quote(cont)}" in inspect.getsource(deploy.snapshot_config)
