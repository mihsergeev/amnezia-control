"""Validated manual destination rules and an in-place gateway config update."""

import ipaddress
import json
import re
import shlex
from typing import Annotated, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

RULE_TAG = "acontrol-manual-route-"
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

directory, gateway, owner, port, prefix, rules = json.loads(sys.argv[1])
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
updated = base[:1] + rules + base[1:]
if current == updated:
    sys.exit(0)
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


def update_script(directory: str, gateway: str, port: int, owner: str, routes: list[dict]) -> str:
    payload = [directory, gateway, owner, port, RULE_TAG, xray_rules(routes)]
    return "sudo -n python3 -c " + shlex.quote(_UPDATE) + " " + shlex.quote(json.dumps(payload))
