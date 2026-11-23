"""Validated access policies. No network access or implicit node migration."""
import ipaddress

from app import ssh_host


def normalize_sources(values: list[str]) -> list[str]:
    result = []
    for value in values:
        try:
            if "%" in value:  # an IPv6 zone keeps any characters and reaches firewall scripts
                raise ValueError(value)
            network = ipaddress.ip_network(value.strip(), strict=False)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("Источники SSH должны быть IP-адресами или CIDR") from exc
        if network.is_unspecified or network.is_multicast or network.prefixlen == 0:
            raise ValueError("Для доступа без ограничения выберите отдельный режим")
        item = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
        if item not in result:
            result.append(item)
    if len(result) > 32:
        raise ValueError("Допускается не более 32 источников SSH")
    return result


def sources(server, panel_ip: str) -> list[str]:
    mode = getattr(server, "ssh_source_mode", None) or "panel"
    if mode == "any":
        return []
    if mode == "panel" and not panel_ip:
        raise ValueError("IP панели не задан. Укажите источники SSH вручную или явно выберите доступ без ограничения")
    result = normalize_sources(getattr(server, "ssh_source_ips", None) or []) if mode == "custom" else normalize_sources(panel_ip.split(",")) if panel_ip else []
    if mode == "custom" and not result:
        raise ValueError("Укажите хотя бы один разрешенный источник SSH")
    if getattr(server, "ssh_jump_server_id", None) and mode == "panel":
        jump = getattr(server, "ssh_jump_server", None)
        try:
            candidate = ssh_host.ip_literal(jump.host)
        except (ValueError, AttributeError) as exc:
            raise ValueError("У промежуточной ноды указан домен. В расширенных настройках укажите IP/CIDR источника SSH") from exc
        result = normalize_sources([*result, candidate])
    return result


FIELDS = ("host", "ssh_port", "ssh_user", "ssh_jump_server_id", "ssh_source_mode", "ssh_source_ips", "ssh_firewall_mode")


def values(server) -> dict:
    return {field: getattr(server, field) for field in FIELDS}
