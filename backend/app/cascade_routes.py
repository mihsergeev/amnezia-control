"""Validated manual destination rules and an in-place gateway config update."""

import ipaddress
import json
import re
import shlex
from typing import Annotated, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from app import geo

RULE_TAG = "acontrol-manual-route-"
COUNTRY_TAG = "acontrol-country-route-"
HEALTH_HOST = "api.ipify.org"
HEALTH_FALLBACK_HOST = "ipv4.icanhazip.com"


class Route(BaseModel):
    destination: str = Field(min_length=1, max_length=253)
    via: Literal["entry", "exit"]

    @field_validator("destination", mode="before")
    @classmethod
    def normalize(cls, value):
        if not isinstance(value, str):
            raise ValueError("Enter a domain, IP address or subnet")
        value = value.strip().rstrip(".")
        try:
            if "/" in value:
                return str(ipaddress.IPv4Network(value, strict=True))
            return str(ipaddress.IPv4Address(value))
        except ValueError:
            pass
        try:
            domain = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            domain = ""
        labels = domain.split(".")
        if domain == HEALTH_HOST:
            raise ValueError("This domain is reserved for cascade health checks")
        if (len(domain) <= 253 and len(labels) >= 2 and not labels[-1].isdigit()
                and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
            return domain
        raise ValueError("Enter a domain, IP address or subnet")


class RouteUpdate(BaseModel):
    routes: list[Route] = Field(max_length=100)
    entry_country: str | None = None

    @field_validator("entry_country")
    @classmethod
    def country(cls, value):
        return geo.country_override(value) if value is not None else None

    @model_validator(mode="after")
    def unique_destinations(self):
        if len({route.destination for route in self.routes}) != len(self.routes):
            raise ValueError("Each destination can have only one route")
        return self


class RoutePreview(BaseModel):
    destinations: list[Annotated[str, Field(strict=True, max_length=1024)]] = Field(max_length=200)


class ValidDestination(BaseModel):
    valid: Literal[True] = True
    destination: str


class InvalidDestination(BaseModel):
    valid: Literal[False] = False
    error: Literal["invalid_destination", "reserved_destination"]


class RoutePreviewOut(BaseModel):
    results: list[ValidDestination | InvalidDestination]


def preview_destinations(destinations: list[str]) -> RoutePreviewOut:
    results: list[ValidDestination | InvalidDestination] = []
    for destination in destinations:
        try:
            route = Route(destination=destination, via="entry")
        except ValidationError as exc:
            # Return stable validation codes, never echo the raw input or
            # Pydantic details. Route remains the sole destination validator.
            reserved = any(str(error.get("ctx", {}).get("error", "")) ==
                           "This domain is reserved for cascade health checks" for error in exc.errors())
            results.append(InvalidDestination(error="reserved_destination" if reserved else "invalid_destination"))
        else:
            results.append(ValidDestination(destination=route.destination))
    return RoutePreviewOut(results=results)


def xray_rules(routes: list[dict]) -> list[dict]:
    # The gateway must verify its exit even when the entry country's rules
    # would send the IP service directly. Preserve user routes on the fallback.
    result = [{
        "domain": [f"full:{HEALTH_HOST}"],
        "ruleTag": f"{RULE_TAG}health",
        "inboundTag": ["tproxy", "check"],
        "outboundTag": "exit",
    }, {
        "domain": [f"full:{HEALTH_FALLBACK_HOST}"],
        "ruleTag": f"{RULE_TAG}health-fallback",
        "inboundTag": ["check"],
        "outboundTag": "exit",
    }]
    for index, route in enumerate(routes):
        destination = route["destination"]
        try:
            ipaddress.ip_network(destination)
            match = {"ip": [destination]}
        except ValueError:
            match = {"domain": [f"domain:{destination}"]}
        result.append({
            **match,
            "ruleTag": f"{RULE_TAG}{index}",
            "inboundTag": ["tproxy"],
            "outboundTag": "direct" if route["via"] == "entry" else "exit",
        })
    return result


# The gateway directory is mounted into the running container. Test the
# candidate using the exact installed binary and geodata before replacing it.
_UPDATE = r"""
import json, os, pathlib, socket, stat, subprocess, sys, tempfile, time

payload = json.loads(sys.argv[1])
directory, gateway, owner, port, prefix, rules = payload[:6]
country_rules, legacy_groups = payload[6:] if len(payload) > 6 else (None, [])
directory = pathlib.Path(directory)
path = directory / 'config.json'
pending = directory / '.routes-pending'
mount = '/usr/local/etc/xray'
docker = ['docker']
def run(args, timeout=30):
    return subprocess.run(docker + args, capture_output=True, check=True, timeout=timeout).stdout

container, = json.loads(run(['inspect', '--type=container', gateway]))
container_id = container['Id']
labels = container['Config'].get('Labels') or {}
if (labels.get('org.amnezia.control.owner', '') != owner
    or not any(item['Source'] == str(directory) and item['Destination'] == mount
               for item in container['Mounts'])):
    sys.exit(73)

meta = path.lstat()
if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_size > 1024 * 1024:
    sys.exit(73)
def temporary(data, parent=directory):
    fd, name = tempfile.mkstemp(prefix='.routes-', suffix='.json' if parent != directory else '', dir=parent)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return pathlib.Path(name)

def restart():
    run(['restart', gateway])
    for _ in range(25):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError('Gateway did not start')


def recover(original):
    os.replace(temporary(original), path)
    try:
        restart()
    except Exception:
        sys.exit(74)
    pending.unlink()


# The route lock is held across this script. If the previous process exited
# before confirming the reload, restore the last known configuration first.
if pending.exists():
    previous_id, _, previous_config = pending.read_bytes().partition(b'\n')
    if previous_id == container_id.encode():
        recover(previous_config)
    else:
        # A completed reinstall owns the new config and must not be undone.
        pending.unlink()
        if not container['State']['Running']:
            sys.exit(73)
elif not container['State']['Running']:
    sys.exit(73)

original = path.read_bytes()
config = json.loads(original)
current = config['routing']['rules']
if not current or current[0].get('outboundTag') != 'block' or 'geoip:private' not in current[0].get('ip', []):
    sys.exit(73)
base = [rule for rule in current if not rule.get('ruleTag', '').startswith(prefix)]
if country_rules is not None:
    base = [rule for rule in base if not rule.get('ruleTag', '').startswith('acontrol-country-route-')]
    # Older versions generated untagged country rules as the exact suffix.
    # Never remove arbitrary GeoIP rules or another administrator's rules.
    for group in legacy_groups:
        if group and base[-len(group):] == group:
            base = base[:-len(group)]
            break
updated = base[:1] + rules + base[1:]
if country_rules is not None:
    updated += country_rules
config['routing']['rules'] = updated

with tempfile.TemporaryDirectory(prefix='.routes-test-', dir=directory) as staging:
    candidate = temporary(json.dumps(config, indent=2).encode(), staging)
    candidate_path = mount + '/' + str(candidate.relative_to(directory))
    run(['exec', gateway, 'xray', 'run', '-test', '-config', candidate_path])
    os.replace(temporary(original), directory / '.routes-previous')
    os.replace(temporary(container_id.encode() + b'\n' + original), pending)
    os.replace(candidate, path)
    try:
        restart()
    except Exception:
        recover(original)
        sys.exit(75)
    pending.unlink()
"""


def country_rules(country: str) -> list[dict]:
    from app.cascade import local_rules
    return [rule | {"ruleTag": f"{COUNTRY_TAG}{index}"}
            for index, rule in enumerate(local_rules(country))]


def update_script(directory: str, gateway: str, port: int, owner: str, routes: list[dict],
                  country: str | None = None) -> str:
    payload = [directory, gateway, owner, port, RULE_TAG, xray_rules(routes)]
    if country is not None:
        from app.cascade import local_rules
        payload += [country_rules(country), [local_rules(code) for code in sorted(geo._COUNTRY_CODES)]]
    return "sudo -n python3 -c " + shlex.quote(_UPDATE) + " " + shlex.quote(json.dumps(payload))


_READ = r"""
import datetime, json, pathlib, stat, subprocess, sys
directory, gateway, owner = json.loads(sys.argv[1])
directory = pathlib.Path(directory)
result = subprocess.run(['docker', 'inspect', '--type=container', gateway],
                        capture_output=True, check=True, timeout=15)
container, = json.loads(result.stdout)
entrypoint = container['Config'].get('Entrypoint')
cmd = container['Config'].get('Cmd')
approved = [
    ['-confdir', '/usr/local/etc/xray'],
    ['-confdir', '/usr/local/etc/xray/'],
    ['run', '-confdir', '/usr/local/etc/xray'],
    ['run', '-confdir', '/usr/local/etc/xray/'],
    ['run', '-config', '/usr/local/etc/xray/config.json'],
    ['run', '-c', '/usr/local/etc/xray/config.json'],
]
if ((container['Config'].get('Labels') or {}).get('org.amnezia.control.owner', '') != owner
    or entrypoint not in (['/usr/local/bin/xray'], ['xray']) or cmd not in approved
    or not container['State']['Running']
    or not any(item['Source'] == str(directory) and item['Destination'] == '/usr/local/etc/xray'
               for item in container['Mounts'])):
    sys.exit(73)
path = directory / 'config.json'
meta = path.lstat()
if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_size > 1024 * 1024
    or (directory / '.routes-pending').exists()
    or sorted(item.name for item in directory.glob('*.json')) != ['config.json']):
    sys.exit(73)
started = datetime.datetime.fromisoformat(container['State']['StartedAt'].replace('Z', '+00:00')).timestamp()
if meta.st_mtime > started:
    # A disk edit newer than the running process is not proof of a reload.
    sys.exit(73)
# Rules contain destination metadata only. Never emit the transport config.
print(json.dumps(json.loads(path.read_bytes())['routing']['rules']))
"""


def read_script(directory: str, gateway: str, owner: str) -> str:
    return "sudo -n python3 -c " + shlex.quote(_READ) + " " + shlex.quote(json.dumps([directory, gateway, owner]))


def routing_state(rules: list[dict], country: str, routes: list[dict]) -> dict:
    """Describe a live file observation without confusing desired metadata with it."""
    from app.cascade import local_rules
    if not isinstance(rules, list) or not rules or rules[0] != {"ip": ["geoip:private"], "outboundTag": "block"}:
        return {"state": "unknown", "applied_country": None}
    tail = [rule for rule in rules[1:] if not rule.get("ruleTag", "").startswith(RULE_TAG)]
    def without_country_tag(rule):
        return ({key: value for key, value in rule.items() if key != "ruleTag"}
                if rule.get("ruleTag", "").startswith(COUNTRY_TAG) else rule)

    plain = [without_country_tag(rule) for rule in tail]
    applied = next((code for code in sorted(geo._COUNTRY_CODES) if plain == local_rules(code)), None)
    if not plain:
        applied = ""
    expected_manual = xray_rules(routes)
    if applied is None:
        return {"state": "unknown", "applied_country": None}
    expected = [rules[0], *expected_manual, *local_rules(country)]
    return {"state": "synced" if [without_country_tag(rule) for rule in rules] == expected else "pending",
            "applied_country": applied}
