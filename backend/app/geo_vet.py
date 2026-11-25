"""Geo databases for cascade gateways, vetted by the panel before gateways use them.

The entry gateway routes by geoip.dat and geosite.dat from a third-party repository
(runetfreedom/russia-v2ray-rules-dat): its "direct" lists decide which traffic leaves
through the entry's own provider instead of the exit. Gateways used to take the
latest release on their own every day. Now the panel takes the latest release,
checks it, and gives gateways the exact tag and hashes it accepted (a pin file).

The checks catch a crude or broad change of the routing categories the gateway
uses, not a careful edit of a single site; the rules are deliberately simple:
- every category the gateway refers to is present;
- no country in geoip has a network wider than /6 (IPv4) or /12 (IPv6), and
  geoip:ru shares no address with large foreign countries;
- "direct" domain lists hold only plain domains, no blocked canary site and no
  bare generic zone such as "com";
- canary blocked sites are in geosite:ru-blocked;
- against the last accepted release, the blocked lists did not shrink by more
  than a fifth and the direct lists did not grow sharply.
A release that fails stays out; gateways keep the last accepted one, and the
panel sends one alert per rejected release.
"""

import asyncio
import hashlib
import logging
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app import alerts, settings_store

log = logging.getLogger("acontrol.geo_vet")

REPO = "runetfreedom/russia-v2ray-rules-dat"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
DOWNLOAD = f"https://github.com/{REPO}/releases/download"
FILES = ("geoip.dat", "geosite.dat")
MAX_SIZE = {"geoip.dat": 64 * 1024 * 1024, "geosite.dat": 256 * 1024 * 1024}
TAG_RE = re.compile(r"[0-9]{12}")
SHA_RE = re.compile(r"[0-9a-f]{64}")
CHECK_EVERY = 6 * 3600
START_DELAY = 300
TIMEOUT = httpx.Timeout(60, connect=20)

BLOCKED_SITE = "ru-blocked"
BLOCKED_IP = "ru-blocked"
# sites blocked in Russia for years; a release without them is not a blocked list
BLOCKED_CANARIES = ("instagram.com", "facebook.com", "x.com", "linkedin.com")
# sites that must never go direct from an entry
DIRECT_CANARIES = BLOCKED_CANARIES + ("youtube.com", "google.com", "telegram.org", "torproject.org",
                                      "signal.org", "github.com", "whatsapp.com")
# countries whose addresses never overlap geoip:ru in a sound release (checked on
# real releases: zero shared addresses); an overlap sends their traffic direct
FOREIGN_CODES = ("us", "de", "nl", "gb", "fr")
# wider than this is a "send everything" network, not an allocation (geoip:us has a /7)
MIN_PREFIX = {4: 6, 6: 12}
# bare zones a direct list may never hold; national and IDN zones (moscow, онлайн) may
GENERIC_ZONES = frozenset("com net org info io me app dev xyz co tv biz cc ai tech site online top club".split())
BLOCKED_KEEP = 0.8
DIRECT_GROWTH = 1.3
DIRECT_GROWTH_SLACK = 50
GEOIP_GROWTH = 1.15
GEOIP_GROWTH_SLACK = 1 << 16


class GeoVetError(Exception):
    """The release cannot be used; the text explains why (for the alert)."""


# ---------- protobuf (geoip.dat / geosite.dat are v2fly GeoIPList / GeoSiteList) ----------

def _varint(b: memoryview, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        if i >= len(b):
            raise GeoVetError("damaged file (truncated varint)")
        x = b[i]
        i += 1
        result |= (x & 0x7F) << shift
        if not x & 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise GeoVetError("damaged file (varint too long)")


def _fields(b: memoryview):
    i, n = 0, len(b)
    while i < n:
        key, i = _varint(b, i)
        num, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _varint(b, i)
        elif wire == 2:
            size, i = _varint(b, i)
            if i + size > n:
                raise GeoVetError("damaged file (field past the end)")
            value = b[i:i + size]
            i += size
        elif wire == 5:
            value, i = b[i:i + 4], i + 4
        elif wire == 1:
            value, i = b[i:i + 8], i + 8
        else:
            raise GeoVetError(f"damaged file (wire type {wire})")
        yield num, value


def parse_geoip(data: bytes, keep: frozenset[str] = frozenset({"ru", *FOREIGN_CODES})) -> tuple[dict, dict]:
    """Per country code: [networks, IPv4 addresses, widest IPv4 prefix, widest IPv6 prefix].
    Networks themselves are kept only for the codes in keep: the whole file is about
    a million networks, too many objects to hold on a small panel host."""
    stats: dict[str, list[int]] = {}
    kept: dict[str, list[tuple[int, int, int]]] = {}
    for num, entry in _fields(memoryview(data)):
        if num != 1:
            continue
        code, count, v4, widest4, widest6, nets = "", 0, 0, 129, 129, []
        for field, value in _fields(entry):
            if field == 1:
                code = bytes(value).decode("ascii", "replace").lower()
            elif field == 2:
                length, prefix, ip = 0, 0, b""
                for sub, item in _fields(value):
                    if sub == 1:
                        length = len(item)
                        if code in keep:
                            ip = bytes(item)
                    elif sub == 2:
                        prefix = item
                if length not in (4, 16):
                    raise GeoVetError("damaged file (address length)")
                count += 1
                if length == 4:
                    v4 += 1 << (32 - min(prefix, 32))
                    widest4 = min(widest4, prefix)
                else:
                    widest6 = min(widest6, prefix)
                if code in keep:
                    nets.append((4 if length == 4 else 6, int.from_bytes(ip, "big"), prefix))
        stats[code] = [count, v4, widest4, widest6]
        if code in keep:
            kept[code] = nets
    return stats, kept


def parse_geosite(data: bytes, wanted: set[str]) -> dict[str, list[tuple[int, str]]]:
    """code -> [(type, value)] for the wanted codes; codes of all lists in the file."""
    out: dict[str, list[tuple[int, str]]] = {}
    for num, entry in _fields(memoryview(data)):
        if num != 1:
            continue
        code, domains = "", []
        for field, value in _fields(entry):
            if field == 1:
                code = bytes(value).decode("ascii", "replace").lower()
            elif field == 2 and code in wanted:
                kind, text = 0, ""
                for sub, item in _fields(value):
                    if sub == 1:
                        kind = item
                    elif sub == 2:
                        text = bytes(item).decode("utf-8", "replace").lower()
                domains.append((kind, text))
        out[code] = domains if code in wanted else []
    return out


# ---------- checks ----------

def _direct_sites() -> dict[str, list[str]]:
    from app import cascade
    return {cc: [name.removeprefix("geosite:") for name in names] for cc, names in cascade._GEOSITE.items()}


def _ranges(nets: list[tuple[int, int, int]]) -> list[list[int]]:
    """Merged IPv4 ranges [start, end) of a network list."""
    out: list[list[int]] = []
    for start, end in sorted((net >> (32 - prefix) << (32 - prefix), (net >> (32 - prefix) << (32 - prefix)) + (1 << (32 - prefix)))
                             for version, net, prefix in nets if version == 4):
        if out and start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return out


def _shared(a: list[list[int]], b: list[list[int]]) -> int:
    i = j = total = 0
    while i < len(a) and j < len(b):
        start, end = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        total += max(0, end - start)
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total


def _site_matches(domains: list[tuple[int, str]], site: str) -> str | None:
    for kind, value in domains:
        if kind in (2, 3) and (site == value or (kind == 2 and site.endswith("." + value))):
            return value
        if kind == 0 and value and value in site:
            return value
    return None


def stats_and_problems(geoip: tuple[dict, dict], geosite: dict) -> tuple[dict, list[str]]:
    """Absolute checks of one release and the numbers the next release is compared with."""
    problems: list[str] = []
    ip_counts, kept = geoip
    direct = sorted({name for names in _direct_sites().values() for name in names})
    for code in (BLOCKED_IP, "ru"):
        if not ip_counts.get(code, [0])[0]:
            problems.append(f"geoip:{code} is missing or empty")
    for code in (BLOCKED_SITE, *direct):
        if not geosite.get(code):
            problems.append(f"geosite:{code} is missing or empty")
    ip_stats = {code: values[:2] for code, values in ip_counts.items() if code == BLOCKED_IP}
    for code, (count, v4, widest4, widest6) in ip_counts.items():
        if not re.fullmatch(r"[a-z]{2}", code):
            continue
        ip_stats[code] = [count, v4]
        for version, widest in ((4, widest4), (6, widest6)):
            if widest < MIN_PREFIX[version]:
                problems.append(f"geoip:{code} has an IPv{version} network /{widest}")
    ru = _ranges(kept.get("ru", []))
    for code in FOREIGN_CODES:
        shared = _shared(ru, _ranges(kept.get(code, [])))
        if shared:
            problems.append(f"geoip:ru shares {shared} addresses with geoip:{code}")
    for code in direct:
        domains = geosite.get(code, [])
        kinds = sorted({kind for kind, _value in domains} - {2, 3})
        if kinds:
            problems.append(f"geosite:{code} has non-domain rules (types {kinds})")
        loose = sorted({value for kind, value in domains if value in GENERIC_ZONES})
        if loose:
            problems.append(f"geosite:{code} sends whole zones direct: {', '.join(loose[:5])}")
        for site in DIRECT_CANARIES:
            hit = _site_matches(domains, site)
            if hit:
                problems.append(f"geosite:{code} sends {site} direct (via {hit})")
    for site in BLOCKED_CANARIES:
        if not _site_matches(geosite.get(BLOCKED_SITE, []), site):
            problems.append(f"geosite:{BLOCKED_SITE} lacks {site}")
    site_stats = {code: len(geosite.get(code, [])) for code in (BLOCKED_SITE, *direct)}
    zones = _national_zones()
    outside = {code: sum(1 for _kind, value in geosite.get(code, []) if value.rsplit(".", 1)[-1] not in zones)
               for code in direct}
    return {"geoip": ip_stats, "geosite": site_stats, "geosite_outside": outside}, problems


def _national_zones() -> set[str]:
    """Zones the gateway already sends direct by its own domain rules (domain:ru,
    domain:xn--p1ai, ...): entries inside them do not change any route."""
    from app import cascade
    return {tld for tlds in cascade._TLDS.values() for tld in tlds} | set(cascade._GEOSITE)


def compare(previous: dict, current: dict) -> list[str]:
    """Checks against the last accepted release."""
    problems = []
    if not previous:
        return problems
    old_site, new_site = previous.get("geosite", {}), current.get("geosite", {})
    old_ip, new_ip = previous.get("geoip", {}), current.get("geoip", {})
    if old_site.get(BLOCKED_SITE) and new_site.get(BLOCKED_SITE, 0) < old_site[BLOCKED_SITE] * BLOCKED_KEEP:
        problems.append(f"geosite:{BLOCKED_SITE} shrank from {old_site[BLOCKED_SITE]} to {new_site.get(BLOCKED_SITE, 0)}")
    if old_ip.get(BLOCKED_IP) and new_ip.get(BLOCKED_IP, [0])[0] < old_ip[BLOCKED_IP][0] * BLOCKED_KEEP:
        problems.append(f"geoip:{BLOCKED_IP} shrank from {old_ip[BLOCKED_IP][0]} to {new_ip.get(BLOCKED_IP, [0])[0]} networks")
    # Growth of a direct list counts only entries outside the national zones: a
    # list gaining hundreds of .ru municipal sites changes no route (domain:ru is
    # direct anyway), a list gaining foreign domains does.
    # A release accepted before this count existed has nothing to compare with;
    # the absolute checks (generic zones, canaries) still apply to it.
    old_out, new_out = previous.get("geosite_outside"), current.get("geosite_outside", {})
    for code in sorted({name for names in _direct_sites().values() for name in names}) if old_out is not None else ():
        before, after = old_out.get(code, 0), new_out.get(code, 0)
        if before and after > before * DIRECT_GROWTH + DIRECT_GROWTH_SLACK:
            problems.append(f"geosite:{code} grew from {before} to {after} entries outside national zones")
    for code, (_count, addresses) in new_ip.items():
        if code == BLOCKED_IP or code not in old_ip:
            continue
        before = old_ip[code][1]
        if addresses > before * GEOIP_GROWTH + GEOIP_GROWTH_SLACK:
            problems.append(f"geoip:{code} grew from {before} to {addresses} IPv4 addresses")
    return problems


# ---------- release download ----------

async def _latest(client: httpx.AsyncClient) -> tuple[str, dict[str, str], dict[str, int]]:
    r = await client.get(API_LATEST, headers={"Accept": "application/vnd.github+json"})
    r.raise_for_status()
    data = r.json()
    tag = data.get("tag_name") if isinstance(data, dict) else None
    if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
        raise GeoVetError("the release has no usable tag")
    digests, sizes = {}, {}
    for asset in data.get("assets") or []:
        name = asset.get("name")
        if name in FILES:
            digest = str(asset.get("digest") or "").removeprefix("sha256:")
            if not SHA_RE.fullmatch(digest):
                raise GeoVetError(f"{name} has no sha256 digest in the release")
            digests[name], sizes[name] = digest, int(asset.get("size") or 0)
    if set(digests) != set(FILES):
        raise GeoVetError("the release lacks geoip.dat or geosite.dat")
    for name, size in sizes.items():
        if not 0 < size <= MAX_SIZE[name]:
            raise GeoVetError(f"{name} has an unexpected size ({size} bytes)")
    return tag, digests, sizes


async def _download(client: httpx.AsyncClient, tag: str, name: str, digest: str, target: Path) -> None:
    sha = hashlib.sha256()
    size = 0
    async with client.stream("GET", f"{DOWNLOAD}/{tag}/{name}", follow_redirects=True) as r:
        r.raise_for_status()
        with target.open("wb") as fh:
            async for chunk in r.aiter_bytes():
                size += len(chunk)
                if size > MAX_SIZE[name]:
                    raise GeoVetError(f"{name} is larger than {MAX_SIZE[name]} bytes")
                sha.update(chunk)
                fh.write(chunk)
    if sha.hexdigest() != digest:
        raise GeoVetError(f"{name} does not match the digest of the release")


async def vet_release(client: httpx.AsyncClient, previous: dict, workdir: Path) -> dict:
    """Latest release -> accepted state, or GeoVetError with the reasons."""
    tag, digests, _sizes = await _latest(client)
    if previous.get("tag") == tag:
        return previous
    for name in FILES:
        await _download(client, tag, name, digests[name], workdir / name)
    wanted = {BLOCKED_SITE, *(n for names in _direct_sites().values() for n in names)}

    def parse():
        return (parse_geoip((workdir / "geoip.dat").read_bytes()),
                parse_geosite((workdir / "geosite.dat").read_bytes(), wanted))

    geoip, geosite = await asyncio.to_thread(parse)
    stats, problems = stats_and_problems(geoip, geosite)
    problems += compare(previous.get("stats") or {}, stats)
    if problems:
        error = GeoVetError("; ".join(problems[:6]) + (f" (+{len(problems) - 6} more)" if len(problems) > 6 else ""))
        error.tag = tag  # type: ignore[attr-defined]
        raise error
    return {"tag": tag, "sha256": {name: digests[name] for name in FILES}, "stats": stats,
            "accepted_at": datetime.now(timezone.utc).isoformat()}


def pin_line(state: dict) -> str | None:
    """The pin file for gateways: '<tag> <geoip sha256> <geosite sha256>'."""
    tag = state.get("tag")
    sha = state.get("sha256") or {}
    values = [tag, sha.get("geoip.dat"), sha.get("geosite.dat")]
    if not (isinstance(tag, str) and TAG_RE.fullmatch(tag)
            and all(isinstance(v, str) and SHA_RE.fullmatch(v) for v in values[1:])):
        return None
    return " ".join(values)


async def vet_once(session_factory, settings, client: httpx.AsyncClient | None = None) -> dict:
    """One round: vets the latest release if it is new. Returns the stored state."""
    async with session_factory() as session:
        state = await settings_store.get_cascade_geo(session)
    accepted = state.get("accepted") or {}
    try:
        # ~100 MiB of downloads: on the data volume, not in the container's /tmp
        Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="geo-vet-", dir=settings.data_dir) as workdir:
            if client is None:
                async with httpx.AsyncClient(timeout=TIMEOUT) as own:
                    result = await vet_release(own, accepted, Path(workdir))
            else:
                result = await vet_release(client, accepted, Path(workdir))
    except GeoVetError as exc:
        tag = getattr(exc, "tag", "")
        state["last_error"] = str(exc)
        if tag and state.get("rejected_tag") != tag:
            state["rejected_tag"] = tag
            log.warning("геобазы %s отклонены: %s", tag, exc)
            async with session_factory() as session:
                await settings_store.set_cascade_geo(session, state)
                await alerts.security_alert(
                    session, settings,
                    alerts.Card("crit", "🗺", alerts.t("Геобазы каскадов не приняты"),
                                alerts.t("Выпуск {tag}: {reason}. Шлюзы остаются на {current}",
                                         tag=tag, reason=str(exc)[:500], current=accepted.get("tag") or "-")),
                )
            return state
    except (httpx.HTTPError, OSError, ValueError) as exc:
        state["last_error"] = f"{type(exc).__name__}"
        log.info("геобазы не проверены: %s", type(exc).__name__)
    else:
        if result is not accepted:
            state["accepted"] = result
            state.pop("last_error", None)
            log.info("геобазы %s приняты", result["tag"])
        else:
            state.pop("last_error", None)
    state["checked_at"] = datetime.now(timezone.utc).isoformat()
    async with session_factory() as session:
        await settings_store.set_cascade_geo(session, state)
    return state


async def accepted_pin(session) -> str | None:
    state = await settings_store.get_cascade_geo(session)
    return pin_line(state.get("accepted") or {})


async def geo_vet_loop(session_factory, settings) -> None:
    from sqlalchemy import select

    from app.models import Cascade
    await asyncio.sleep(START_DELAY)
    while True:
        try:
            async with session_factory() as session:
                used = await session.scalar(select(Cascade.id).limit(1))
            if used is not None:
                await vet_once(session_factory, settings)
        except Exception:  # noqa: BLE001 - the loop must not stop
            log.exception("проверка геобаз упала")
        await asyncio.sleep(CHECK_EVERY)
