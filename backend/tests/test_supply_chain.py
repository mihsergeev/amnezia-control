"""What nodes download is pinned to content, not to a movable name."""
import re

from app import cascade, cascade_probe, deploy, openvpn, xray


def test_cascade_xray_image_is_pinned_by_digest():
    assert re.fullmatch(r"ghcr\.io/xtls/xray-core:[0-9.]+@sha256:[0-9a-f]{64}", cascade.XRAY_IMAGE)
    assert cascade.XRAY_IMAGE.startswith(f"ghcr.io/xtls/xray-core:{cascade.XRAY_VERSION}@")
    # no other module names the image by tag; every pull and run goes through XRAY_IMAGE
    import pathlib
    app_dir = pathlib.Path(cascade.__file__).parent
    for path in app_dir.rglob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if "xray-core:" in line:
                assert path.name == "cascade.py" and "XRAY_IMAGE = f" in line, (path.name, line)


def test_probe_reports_the_xray_version_not_the_digest():
    import inspect
    assert "cascade.XRAY_VERSION" in inspect.getsource(cascade_probe)
    assert re.fullmatch(r"[0-9.]+", cascade.XRAY_VERSION)


def test_awg3_sources_are_checked_against_commits():
    for make, commit in ((deploy._V3_GO_MAKE, deploy.AWG3_GO_COMMIT), (deploy._V3_TOOLS_MAKE, deploy.AWG3_TOOLS_COMMIT)):
        assert re.fullmatch(r"[0-9a-f]{40}", commit)
        clone, rest = make.split(" && ", 1)
        assert clone.startswith("git clone")
        assert rest.startswith(f'test "$(git -C /src rev-parse HEAD)" = {commit} && ')
    assert deploy._V3_GO_MAKE in deploy._dockerfile_v3()


def test_cloak_binary_is_hash_checked_before_use():
    lines = openvpn._OVPN_DOCKERFILE
    fetch = lines.index("ck-server-linux-amd64-v2.12.0")
    check = lines.index("| sha256sum -c -")
    chmod = lines.index("chmod +x /usr/local/bin/ck-server")
    assert fetch < check < chmod
    assert re.search(r"echo '[0-9a-f]{64}  /usr/local/bin/ck-server'", lines)


def test_xray_release_without_a_pinned_hash_fails_the_build():
    text = xray._XRAY_DOCKERFILE
    assert f"{xray.XRAY_RELEASE}) SUM=" in text
    assert 'no pinned sha256 for $XRAY_RELEASE" >&2; exit 1' in text
    assert "if [ \"$XRAY_RELEASE\"" not in text  # the old check skipped other releases silently
