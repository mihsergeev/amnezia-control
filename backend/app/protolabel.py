"""Подпись протокола клиента с ВЕРСИЕЙ - одна на всю панель.

Ключ протокола в статистике и поиске (awg / awg3 / awglegacy / openvpn / xray)
версию не несет. В amnezia-awg2 бывает и 1.0 (у Amnezia так назван контейнер
старой версии), и 2.0, и обновленная на месте 3.1, а в amnezia-awg3 - и старая
3.0, и 3.1. Реальную версию знает только последняя проверка ноды: там она
определена по содержимому конфига каждого контейнера (sshops, _PROTO_PROBE).

Подпись повторяет плашки на карточке сервера (protocolsFromContainers во
фронтенде), чтобы клиент в поиске или в топе на "Обзоре" назывался тем же
протоколом, что и на самом сервере. Раньше в топе клиенты Legacy и 3.x
выходили с пустой плашкой, а в поиске 3.1 подписывалась как 3.0.
"""

import json

KIND_LABEL = {
    "awg1": "AmneziaWG 1.0",
    "awg2": "AmneziaWG 2.0",
    "awg3": "AmneziaWG 3.0",
    "awg31": "AmneziaWG 3.1",
}

_FIXED = {
    "openvpn": "OpenVPN/Cloak",
    "xray": "XRay/REALITY",
}


def _check(server) -> tuple[list[str], dict[str, str]]:
    """Контейнеры ноды и версия каждого AWG-контейнера из последней проверки."""
    raw = getattr(server, "last_check_info", "") or ""
    try:
        info = json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        info = {}
    if not isinstance(info, dict):
        info = {}
    conts = info.get("amnezia_containers") or []
    kinds = info.get("protocols") or {}
    if not isinstance(conts, list):
        conts = []
    if not isinstance(kinds, dict):
        kinds = {}
    return [str(c) for c in conts], {str(c): str(k) for c, k in kinds.items()}


def _is_awg3(name: str) -> bool:
    return name.lower().startswith("amnezia-awg3")


def _is_awg_other(name: str) -> bool:
    n = name.lower()
    return n.startswith("amnezia-awg") and not _is_awg3(n)


def protocol_label(server, protocol: str) -> str:
    """Человекочитаемый протокол клиента: "AmneziaWG 2.0", "AmneziaWG Legacy"..."""
    if protocol in _FIXED:
        return _FIXED[protocol]
    conts, kinds = _check(server)

    if protocol == "awg3":
        # панель ставит 3.1, но на ноде может жить и раньше развернутая 3.0
        kind = next((k for c, k in kinds.items() if _is_awg3(c)), "")
        return KIND_LABEL.get(kind, "AmneziaWG 3.1")

    # AWG-контейнеры кроме 3.x; если проверка старая и списка контейнеров в ней
    # нет, берем их из версий
    others = [c for c in conts if _is_awg_other(c)] or [c for c in kinds if _is_awg_other(c)]

    if protocol == "awglegacy":
        # Старый контейнер рядом с новым карточка сервера подписывает "Legacy".
        # Если он на ноде один, карточка подписывает его версией - так же и тут.
        if len(others) >= 2:
            return "AmneziaWG Legacy"
        kind = kinds.get(others[0], "") if others else ""
        return KIND_LABEL.get(kind, "AmneziaWG Legacy")

    if protocol == "awg":
        # у Amnezia новый контейнер - amnezia-awg2; если он один, берем его
        main = next((c for c in others if c.lower().startswith("amnezia-awg2")), None)
        if main is None and others:
            main = others[0]
        kind = kinds.get(main, "") if main else ""
        return KIND_LABEL.get(kind, "AmneziaWG")

    return protocol
