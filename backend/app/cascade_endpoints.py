"""Interserver addresses are independent from SSH and VPN client endpoints."""

import ipaddress
import json


def address(value: str, version: int | None = None) -> str:
    if not isinstance(value, str) or '%' in value:
        raise ValueError("Enter an IPv4 or IPv6 address without a port or zone")
    ip = ipaddress.ip_address(value)
    if (version is not None and ip.version != version or ip.is_unspecified
            or ip.is_loopback or ip.is_multicast or ip.is_link_local
            or getattr(ip, "ipv4_mapped", None) is not None):
        raise ValueError("Enter a routable unicast address of the selected family")
    return str(ip)


def endpoint(value: str) -> str:
    return address(value) if value else ""


def family(value: str) -> int:
    return ipaddress.ip_address(value).version


def host_port(host: str, port: int) -> str:
    host = address(host)
    return f"[{host}]:{port}" if family(host) == 6 else f"{host}:{port}"


def global_ipv6(output: str) -> list[str]:
    candidates = []
    interfaces = json.loads(output)
    if not isinstance(interfaces, list):
        raise ValueError("Invalid address inventory")
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        for item in interface.get("addr_info", []):
            if not isinstance(item, dict):
                continue
            value = item.get("local", "")
            if (item.get("family") != "inet6" or item.get("scope") != "global"
                    or any(item.get(flag) for flag in ("tentative", "dadfailed", "deprecated", "temporary"))
                    or set(item.get("flags", [])) & {"tentative", "dadfailed", "deprecated", "temporary"}
                    or item.get("preferred_life_time") == 0):
                continue
            try:
                ip = ipaddress.IPv6Address(address(value, 6))
            except ValueError:
                continue
            if ip.is_global:
                candidates.append(str(ip))
    return sorted(set(candidates))


async def discover_ipv6(conn) -> str:
    result = await conn.run("ip -j -6 address show scope global", check=False, timeout=10)
    if result.exit_status:
        return ""
    try:
        candidates = global_ipv6(result.stdout)
    except (ValueError, TypeError, KeyError):
        return ""
    # Multiple provider prefixes require an administrator's explicit choice.
    return candidates[0] if len(candidates) == 1 else ""
