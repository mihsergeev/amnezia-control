"""Geo databases for cascade gateways: vetted by the panel, pinned on gateways."""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys

import httpx
import pytest

from app import alerts, cascade, cascadewatch, config, geo_vet, settings_store


# the Russian "available only inside" direct list, as the gateway config names it
INSIDE = geo_vet._direct_sites()["ru"][0]


# ---------- synthetic v2fly protobuf ----------

def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(num: int, payload) -> bytes:
    if isinstance(payload, int):
        return _varint(num << 3) + _varint(payload)
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def _geoip(entries: dict[str, list[tuple[str, int]]]) -> bytes:
    out = b""
    for code, nets in entries.items():
        body = _field(1, code.upper().encode())
        for net, prefix in nets:
            ip = bytes(int(x) for x in net.split(".")) if "." in net else bytes(16)
            body += _field(2, _field(1, ip) + _field(2, prefix))
        out += _field(1, body)
    return out


def _geosite(entries: dict[str, list[tuple[int, str]]]) -> bytes:
    out = b""
    for code, domains in entries.items():
        body = _field(1, code.upper().encode())
        for kind, value in domains:
            body += _field(2, (_field(1, kind) if kind else b"") + _field(2, value.encode()))
        out += _field(1, body)
    return out


def _sites(**override):
    sites = {
        "ru-blocked": [(2, d) for d in ("instagram.com", "facebook.com", "x.com", "linkedin.com", "rutracker.org")],
        INSIDE: [(2, "gosuslugi.ru"), (2, "nalog.gov.ru")],
        "category-ru": [(2, "ru"), (2, "su"), (2, "xn--p1ai"), (2, "moscow"), (2, "yandex.net")],
        "category-ir": [(2, "ir")],
        "other": [(2, "example.org")],
    }
    sites.update(override)
    return sites


def _ips(**override):
    ips = {
        # documentation and private ranges only: real addresses do not belong in the repository
        "ru": [("198.51.100.0", 24), ("203.0.113.0", 24)],
        "ru-blocked": [("192.0.2.0", 25)],
        "us": [("10.0.0.0", 7), ("192.0.2.128", 25)],  # a legitimate /7, as geoip:us really has
        "private": [("172.16.0.0", 12)],
    }
    ips.update(override)
    return ips


def _vet(ips, sites, previous=None):
    wanted = {geo_vet.BLOCKED_SITE, *(n for names in geo_vet._direct_sites().values() for n in names)}
    stats, problems = geo_vet.stats_and_problems(geo_vet.parse_geoip(_geoip(ips)), geo_vet.parse_geosite(_geosite(sites), wanted))
    return stats, problems + geo_vet.compare(previous or {}, stats)


def test_a_normal_release_passes():
    stats, problems = _vet(_ips(), _sites())
    assert problems == []
    assert stats["geoip"]["ru"] == [2, 512]
    assert stats["geosite"]["ru-blocked"] == 5


@pytest.mark.parametrize("ips, sites, expected", [
    (_ips(us=[("0.0.0.0", 1)]), _sites(), "geoip:us has an IPv4 network /1"),
    (_ips(ru=[("198.51.100.0", 24), ("192.0.2.128", 25)]), _sites(), "geoip:ru shares 128 addresses with geoip:us"),
    (_ips(), _sites(**{"category-ru": [(2, "ru"), (2, "com")]}), "sends whole zones direct: com"),
    (_ips(), _sites(**{"category-ru": [(2, "ru"), (2, "instagram.com")]}), "sends instagram.com direct"),
    (_ips(), _sites(**{INSIDE: [(0, "google")]}), "non-domain rules"),
    (_ips(), _sites(**{"ru-blocked": [(2, "instagram.com")]}), "lacks facebook.com"),
    (_ips(), {k: v for k, v in _sites().items() if k != "category-ru"}, "geosite:category-ru is missing"),
])
def test_altered_releases_are_refused(ips, sites, expected):
    _stats, problems = _vet(ips, sites)
    assert any(expected in p for p in problems), problems


def test_changes_against_the_accepted_release():
    accepted, _ = _vet(_ips(), _sites())
    blocked = [(2, d) for d in ("instagram.com", "facebook.com", "x.com", "linkedin.com")]  # 5 -> 4
    assert _vet(_ips(), _sites(**{"ru-blocked": blocked}), accepted)[1] == []
    shrunk = _sites(**{"ru-blocked": blocked[:4]})
    accepted_big = {**accepted, "geosite": {**accepted["geosite"], "ru-blocked": 100}}
    assert any("ru-blocked shrank" in p for p in _vet(_ips(), shrunk, accepted_big)[1])
    grown = _ips(ru=[("198.51.100.0", 24), ("100.64.0.0", 10)])
    assert any("geoip:ru grew" in p for p in _vet(grown, _sites(), accepted)[1])


def test_damaged_files_are_refused():
    with pytest.raises(geo_vet.GeoVetError):
        geo_vet.parse_geoip(_geoip(_ips())[:-3])


# ---------- one vetting round against a fake GitHub ----------

def _release(tag, ips, sites, digest_override=None):
    files = {"geoip.dat": _geoip(ips), "geosite.dat": _geosite(sites)}
    api = {"tag_name": tag, "assets": [
        {"name": n, "size": len(b), "digest": "sha256:" + (digest_override or hashlib.sha256(b).hexdigest())}
        for n, b in files.items()]}
    return api, files


def _client(release, seen):
    api, files = release

    def handler(request):
        seen.append(request.url.path)
        if request.url.path.endswith("/releases/latest"):
            return httpx.Response(200, json=api)
        name = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, content=files[name])
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_round_accepts_then_skips_then_refuses_with_one_alert(client, session_factory, tmp_path, monkeypatch):
    settings = config.get_settings()
    sent = []

    async def capture(session, settings, card):
        sent.append(card)
    monkeypatch.setattr(alerts, "security_alert", capture)

    seen = []
    state = await geo_vet.vet_once(session_factory, settings, _client(_release("202611241408", _ips(), _sites()), seen))
    assert state["accepted"]["tag"] == "202611241408" and not sent
    assert any(p.endswith("/202611241408/geosite.dat") for p in seen)
    async with session_factory() as s:
        pin = await geo_vet.accepted_pin(s)
    assert pin.split()[0] == "202611241408" and len(pin.split()) == 3

    seen.clear()
    await geo_vet.vet_once(session_factory, settings, _client(_release("202611241408", _ips(), _sites()), seen))
    assert seen == ["/repos/runetfreedom/russia-v2ray-rules-dat/releases/latest"]  # nothing downloaded again

    bad = _release("202611250101", _ips(ru=[("192.0.2.128", 25)]), _sites())
    for _ in range(2):
        state = await geo_vet.vet_once(session_factory, settings, _client(bad, []))
    assert state["accepted"]["tag"] == "202611241408"
    assert state["rejected_tag"] == "202611250101" and "geoip:us" in state["last_error"]
    assert len(sent) == 1 and "geoip:us" in alerts._text(sent[0].detail, "ru")

    wrong = _release("202611250202", _ips(), _sites(), digest_override="0" * 64)
    state = await geo_vet.vet_once(session_factory, settings, _client(wrong, []))
    assert state["accepted"]["tag"] == "202611241408" and "digest" in state["last_error"]


@pytest.mark.parametrize("pin", [None, "202611241408 " + "a" * 64 + " " + "b" * 64])
def test_entry_install_writes_the_pin_before_the_geo_download(pin):
    params = {
        "entry_ip": "203.0.113.10", "exit_ip": "198.51.100.20", "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555", "private_key": "priv",
        "public_key": "pub", "short_id": "0123456789abcdef", "sni": "www.example.com",
    }
    script = cascade.build_entry_script("vless", "198.51.100.20", 3, params, "ru", geo_pin=pin)
    download = script.index('geo-update.sh "$GW_TX/config"')
    if pin is None:
        assert "/geo/pin" not in script
    else:
        assert script.index("/geo/pin.new") < download


def test_pin_command_accepts_only_a_pin():
    good = "202611241408 " + "a" * 64 + " " + "b" * 64
    assert f"'{good}'" in cascade.geo_pin_command(good)
    for bad in ("x", good + "; id", good.replace("a", "A"), "2026112414 " + "a" * 64 + " " + "b" * 64):
        with pytest.raises(ValueError):
            cascade.geo_pin_command(bad)


# ---------- the gateway updater in pin mode ----------

@pytest.mark.skipif(sys.platform == "win32" or shutil.which("sh") is None, reason="needs a POSIX shell")
@pytest.mark.parametrize("mode", ["pinned", "tampered", "legacy"])
def test_geo_update_script_downloads_exactly_the_pinned_release(tmp_path, mode):
    base = tmp_path / "cascade"
    geo = base / "geo"
    geo.mkdir(parents=True)
    (base / "config").mkdir()
    payload = {"geoip.dat": b"ip-data", "geosite.dat": b"site-data"}
    sums = {n: hashlib.sha256(b).hexdigest() for n, b in payload.items()}
    if mode != "legacy":
        (geo / "pin").write_text(f"202611241408 {sums['geoip.dat']} {sums['geosite.dat']}\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "urls"
    served = dict(payload)
    if mode == "tampered":
        served["geosite.dat"] = b"evil"
    data_dir = tmp_path / "served"
    data_dir.mkdir()
    for n, b in served.items():
        (data_dir / n).write_bytes(b)
        (data_dir / (n + ".sha256sum")).write_text(f"{hashlib.sha256(b).hexdigest()}  {n}\n")
    (bin_dir / "curl").write_text(
        "#!/bin/sh\nout=''; url=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2;; -m|--retry|--socks5-hostname) shift 2;; -*) shift;; *) url=$1; shift;; esac; done\n"
        f"echo \"$url\" >> {log}\ncp \"{data_dir}/$(basename \"$url\")\" \"$out\"\n")
    (bin_dir / "docker").write_text("#!/bin/sh\nexit 0\n")
    for f in bin_dir.iterdir():
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    script = tmp_path / "geo-update.sh"
    script.write_text(cascade._fill(cascade._GEO_SH).replace(cascade.DIR, str(base)))
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    result = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    urls = log.read_text().split() if log.exists() else []
    if mode == "pinned":
        assert result.returncode == 0, result.stderr
        assert urls and all("/releases/download/202611241408/" in u for u in urls)
        assert not any(u.endswith(".sha256sum") for u in urls)  # sums come from the pin
        assert (geo / "geosite.dat").read_bytes() == b"site-data"
    elif mode == "tampered":
        assert result.returncode != 0
        assert not (geo / "geosite.dat").exists()
    else:
        assert result.returncode == 0, result.stderr
        assert any("/releases/latest/download/geoip.dat.sha256sum" in u for u in urls)
    # temporary files live next to the databases, never in /tmp (often in memory)
    assert not list(geo.glob(".update.*"))


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("sh") is None, reason="needs a POSIX shell")
@pytest.mark.parametrize("starts", [True, False])
def test_running_gateway_is_restarted_on_new_databases_without_a_second_xray(tmp_path, starts):
    """A test container next to the running gateway doubled the memory for the
    databases and took a 1 GiB entry down. With a gateway running, the files are
    swapped, the gateway restarted, and the old files come back if it does not listen."""
    base = tmp_path / "cascade"
    geo = base / "geo"
    geo.mkdir(parents=True)
    (base / "config").mkdir()
    (geo / "geoip.dat").write_bytes(b"old-ip")
    (geo / "geosite.dat").write_bytes(b"old-site")
    new = {"geoip.dat": b"new-ip", "geosite.dat": b"new-site"}
    sums = {n: hashlib.sha256(b).hexdigest() for n, b in new.items()}
    (geo / "pin").write_text(f"202611241408 {sums['geoip.dat']} {sums['geosite.dat']}\n")
    served = tmp_path / "served"
    served.mkdir()
    for n, b in new.items():
        (served / n).write_bytes(b)
    calls = tmp_path / "calls"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text(
        "#!/bin/sh\nout=''; url=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2;; -m|--retry|--socks5-hostname) shift 2;; -*) shift;; *) url=$1; shift;; esac; done\n"
        f"cp \"{served}/$(basename \"$url\")\" \"$out\"\n")
    (bin_dir / "docker").write_text(
        f"#!/bin/sh\necho \"docker $1\" >> {calls}\n"
        f"[ \"$1\" != ps ] || echo {cascade.GATEWAY}\nexit 0\n")
    (bin_dir / "ss").write_text("#!/bin/sh\n" + ("echo 'LISTEN 0 4096 127.0.0.1:12350'\n" if starts else "") + "exit 0\n")
    (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
    for f in bin_dir.iterdir():
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    script = tmp_path / "geo-update.sh"
    script.write_text(cascade._fill(cascade._GEO_SH).replace(cascade.DIR, str(base)))
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    result = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    docker = calls.read_text().split("\n")
    assert "docker run" not in docker  # no second xray next to the running gateway
    if starts:
        assert result.returncode == 0, result.stderr
        assert docker.count("docker restart") == 1
        assert (geo / "geosite.dat").read_bytes() == b"new-site"
    else:
        assert result.returncode != 0 and "previous ones restored" in result.stderr
        assert docker.count("docker restart") == 2
        assert (geo / "geosite.dat").read_bytes() == b"old-site"
        assert (geo / "geoip.dat").read_bytes() == b"old-ip"
    assert not list(geo.glob(".update.*"))
