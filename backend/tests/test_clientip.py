"""IP клиента за обратным прокси (caddy → nginx → backend). Раньше в журнал/
алерты/rate-limit попадал внутренний адрес прокси (172.20.0.x). Тесты фиксируют,
что берётся реальный клиент из X-Forwarded-For и что подделать его нельзя."""

from types import SimpleNamespace

from app.clientip import client_ip


def _req(host="172.20.0.4", xff=None):
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    return SimpleNamespace(client=SimpleNamespace(host=host), headers=headers)


# Настоящие публичные IP: документационные 203.0.113.x/198.51.100.x
# классифицируются ipaddress как private, поэтому для «клиента» берём глобальные.
def test_direct_peer_when_no_header():
    assert client_ip(_req(host="8.8.8.8")) == "8.8.8.8"


def test_real_client_behind_proxy():
    # caddy кладёт реальный IP, nginx дописывает свой внутренний справа
    assert client_ip(_req(xff="8.8.8.8, 172.20.0.2")) == "8.8.8.8"


def test_spoofed_leftmost_is_ignored():
    # клиент подсунул фейковый публичный IP слева — реальный всегда правее
    assert client_ip(_req(xff="1.1.1.1, 8.8.8.8, 172.20.0.2")) == "8.8.8.8"


def test_all_internal_falls_back_to_peer():
    assert client_ip(_req(host="172.20.0.4", xff="10.0.0.1, 172.20.0.2")) == "172.20.0.4"


def test_garbage_entries_skipped():
    assert client_ip(_req(xff="not-an-ip, 9.9.9.9, ::1")) == "9.9.9.9"


def test_missing_headers_attr_is_safe():
    # старые фейковые request в тестах без .headers не должны падать
    assert client_ip(SimpleNamespace(client=SimpleNamespace(host="8.8.4.4"))) == "8.8.4.4"
