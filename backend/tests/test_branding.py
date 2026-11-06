import asyncio
import base64
import json
import re
import struct
import zlib

import pytest
from sqlalchemy import select

from app.logo_png import MAX_PNG_BYTES
from app.models import AppSetting, AuditLog


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png(pixel, *, width=1, raw=None, extra=b""):
    header = struct.pack(">IIBBBBB", width, 1, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + extra
        + chunk(b"IDAT", zlib.compress(b"\0" + pixel if raw is None else raw))
        + chunk(b"IEND", b"")
    )


def b64(image):
    return base64.b64encode(image).decode("ascii")


LIGHT = png(b"\x11\x22\x33\xff")
DARK = png(b"\xdd\xee\xff\xff")


@pytest.mark.asyncio
async def test_public_logo_lifecycle_and_audit(client, auth_headers, session_factory):
    async with session_factory() as session:
        session.add(AppSetting(key="unrelated", value="unrelated-setting"))
        await session.commit()

    default = await client.get("/api/branding")
    assert default.json() == {"version": None}
    assert default.headers["cache-control"] == "no-store"
    assert (await client.get("/api/branding/logo/dark")).status_code == 404

    data = {"light": b64(LIGHT), "dark": b64(DARK)}
    assert (await client.put("/api/branding", json=data)).status_code == 401
    assert (await client.delete("/api/branding", headers={"X-API-Key": "ignored"})).status_code == 401

    # Ancillary content from source files must never reach a viewer.
    annotated_light = png(b"\x11\x22\x33\xff", extra=chunk(b"tEXt", b"Description\0not public"))
    saved = await client.put(
        "/api/branding", headers=auth_headers, json={**data, "light": b64(annotated_light)}
    )
    assert saved.status_code == 200
    version = saved.json()["version"]
    assert re.fullmatch(r"[0-9a-f]{64}", version)
    assert (await client.get("/api/branding")).json() == {"version": version}
    for theme, expected in (("light", LIGHT), ("dark", DARK)):
        image = await client.get(f"/api/branding/logo/{theme}", params={"v": version})
        assert image.status_code == 200
        assert image.content == expected
        assert image.headers["content-type"] == "image/png"
        assert image.headers["x-content-type-options"] == "nosniff"
        assert "immutable" in image.headers["cache-control"]
    assert (await client.get(f"/api/branding/logo/other?v={version}")).status_code == 404

    replaced = await client.put("/api/branding", headers=auth_headers, json={"light": b64(DARK), "dark": b64(LIGHT)})
    assert replaced.status_code == 200
    assert replaced.json()["version"] != version
    stale = await client.get(f"/api/branding/logo/light?v={version}")
    assert stale.status_code == 404
    assert stale.headers["cache-control"] == "no-store"

    reset = await client.delete("/api/branding", headers=auth_headers)
    assert reset.status_code == 200
    assert reset.json() == {"version": None}
    assert (await client.get("/api/branding")).json() == {"version": None}
    assert (await client.get("/api/branding/logo/dark", params={"v": replaced.json()["version"]})).status_code == 404
    async with session_factory() as session:
        assert list(await session.scalars(select(AppSetting.key))) == ["unrelated"]
        events = list(await session.scalars(select(AuditLog).where(AuditLog.action.like("branding.%")).order_by(AuditLog.id)))
        assert [event.action for event in events] == ["branding.update", "branding.update", "branding.reset"]
        assert all(event.username == "admin" and not event.detail for event in events)


@pytest.mark.asyncio
async def test_rejected_uploads_do_not_disclose_data_or_replace_existing_logo(client, auth_headers):
    data = {"light": b64(LIGHT), "dark": b64(DARK)}
    saved = await client.put("/api/branding", headers=auth_headers, json=data)
    assert saved.status_code == 200
    for bad in (
        "<svg>do-not-reflect</svg>",
        b64(LIGHT + b"unexpected trailer"),
        b64(png(b"\0" * 4, width=289)),
        b64(png(b"", raw=b"\0" * 1_000_000)),
        b64(png(b"", raw=b"\x05" + b"\0" * 4)),
        b64(LIGHT[:-1] + b"\0"),
    ):
        invalid = await client.put("/api/branding", headers=auth_headers, json={**data, "dark": bad})
        assert invalid.status_code == 400
        assert bad not in invalid.text

    oversized = await client.put("/api/branding", headers=auth_headers, json={**data, "dark": b64(b"x" * (MAX_PNG_BYTES + 1))})
    assert oversized.status_code == 413

    async def oversized_stream():
        for _ in range(4):
            yield b"x" * (256 * 1024)

    streamed = await client.put("/api/branding", headers=auth_headers, content=oversized_stream())
    assert streamed.status_code == 413
    assert (await client.get("/api/branding")).json() == saved.json()


@pytest.mark.asyncio
async def test_simultaneous_first_uploads_keep_a_complete_pair(client, auth_headers):
    light_first, dark_first = png(b"\x10\x20\x30\xff"), png(b"\x40\x50\x60\xff")
    pairs = ((light_first, dark_first), (LIGHT, DARK))
    results = await asyncio.gather(*(
        client.put("/api/branding", headers=auth_headers, json={"light": b64(light), "dark": b64(dark)})
        for light, dark in pairs
    ))
    assert all(result.status_code == 200 for result in results)
    current = (await client.get("/api/branding")).json()
    matching = [pair for pair, result in zip(pairs, results) if current == result.json()]
    assert len(matching) == 1
    for theme, expected in zip(("light", "dark"), matching[0]):
        image = await client.get(f"/api/branding/logo/{theme}", params={"v": current["version"]})
        assert image.content == expected


@pytest.mark.asyncio
async def test_change_size_without_replacing_logo(client, auth_headers):
    size = {"desktop": 125, "mobile": 75}
    data = {"light": b64(LIGHT), "dark": b64(DARK)}
    assert (await client.put("/api/branding", json={"size": size})).status_code == 401
    default_logo = await client.put("/api/branding", headers=auth_headers, json={"size": size})
    assert default_logo.json() == {"version": None, "size": size}

    uploaded = await client.put("/api/branding", headers=auth_headers, json=data)
    assert uploaded.status_code == 200
    version = uploaded.json()["version"]
    assert uploaded.json()["size"] == size
    changed = await client.put(
        "/api/branding", headers=auth_headers, json={"size": {"desktop": 140, "mobile": 60}}
    )
    assert changed.status_code == 200
    assert changed.json() == {"version": version, "size": {"desktop": 140, "mobile": 60}}
    assert (await client.get("/api/branding")).json() == changed.json()
    assert (await client.get(f"/api/branding/logo/light?v={version}")).content == LIGHT

    for invalid in (None, {}, {"desktop": 100}, *(
        {**size, "mobile": value} for value in (True, "100", 100.0, 59, 131)
    )):
        rejected = await client.put(
            "/api/branding", headers=auth_headers, json={"light": b64(DARK), "dark": b64(LIGHT), "size": invalid}
        )
        assert rejected.status_code == 400
    incomplete = await client.put("/api/branding", headers=auth_headers, json={"light": b64(DARK), "size": size})
    assert incomplete.status_code == 400
    assert (await client.get("/api/branding")).json() == changed.json()


@pytest.mark.asyncio
async def test_login_size_is_independent_and_validated(client, auth_headers):
    assert (await client.put("/api/branding", json={"login_size": 140})).status_code == 401
    saved = await client.put("/api/branding", headers=auth_headers, json={"login_size": 140})
    assert saved.status_code == 200
    assert saved.json() == {"version": None, "login_size": 140}

    size = {"desktop": 125, "mobile": 75}
    saved = await client.put("/api/branding", headers=auth_headers, json={
        "light": b64(LIGHT), "dark": b64(DARK), "size": size,
    })
    assert saved.status_code == 200
    version = saved.json()["version"]
    assert saved.json() == {"version": version, "size": size, "login_size": 140}

    changed = await client.put("/api/branding", headers=auth_headers, json={"login_size": 60})
    assert changed.status_code == 200
    assert changed.json() == {"version": version, "size": size, "login_size": 60}
    for invalid in (None, True, "100", 100.0, 59, 141):
        rejected = await client.put("/api/branding", headers=auth_headers, json={
            "size": {"desktop": 100, "mobile": 100}, "login_size": invalid,
        })
        assert rejected.status_code == 400
    assert (await client.get("/api/branding")).json() == changed.json()
    assert (await client.get(f"/api/branding/logo/light?v={version}")).content == LIGHT


@pytest.mark.asyncio
async def test_titles_are_independent_and_reject_invalid_updates(client, auth_headers):
    data = {"header_title": "  Пример <VPN>  ", "hide_header_title": True, "tab_title": "VPN admin"}
    assert (await client.put("/api/branding", json=data)).status_code == 401
    saved = await client.put("/api/branding", headers=auth_headers, json=data)
    expected = {"version": None, **data, "header_title": "Пример <VPN>"}
    assert saved.status_code == 200
    assert saved.json() == expected
    assert (await client.get("/api/branding")).json() == expected

    for invalid in (
        {"header_title": "x" * 81}, {"header_title": "x\ny"}, {"header_title": "\ud800"},
        {"tab_title": None}, {"tab_title": "x\x00"}, {"tab_title": 5},
        {"hide_header_title": 1}, {"hide_header_title": "false"},
    ):
        rejected = await client.put(
            "/api/branding", headers=auth_headers, content=json.dumps({"login_size": 110, **invalid}),
        )
        assert rejected.status_code == 400
    assert (await client.get("/api/branding")).json() == expected

    changed = await client.put(
        "/api/branding", headers=auth_headers, json={"hide_header_title": False, "tab_title": " "},
    )
    assert changed.status_code == 200
    assert changed.json() == {**expected, "hide_header_title": False, "tab_title": ""}
    assert (await client.delete("/api/branding", headers=auth_headers)).json() == {"version": None}
    assert (await client.get("/api/branding")).json() == {"version": None}


@pytest.mark.asyncio
async def test_panel_backup_restores_branding(client, auth_headers):
    saved = await client.put(
        "/api/branding", headers=auth_headers,
        json={
            "light": b64(LIGHT), "dark": b64(DARK), "size": {"desktop": 140, "mobile": 130},
            "login_size": 110, "header_title": "Example VPN", "hide_header_title": True, "tab_title": "VPN panel",
        },
    )
    assert saved.status_code == 200
    assert saved.json()["size"] == {"desktop": 140, "mobile": 130}
    assert saved.json()["login_size"] == 110
    backup = await client.post("/api/backup/download", headers=auth_headers, json={"password": "testpass"})
    assert backup.status_code == 200
    assert (await client.delete("/api/branding", headers=auth_headers)).json() == {"version": None}

    restore = await client.post(
        "/api/backup/restore", headers={**auth_headers, "X-Confirm-Password": "testpass"},
        content=backup.content,
    )
    assert restore.status_code == 200
    assert (await client.get("/api/branding")).json() == saved.json()
    image = await client.get("/api/branding/logo/dark", params={"v": saved.json()["version"]})
    assert image.status_code == 200
    assert image.content == DARK
