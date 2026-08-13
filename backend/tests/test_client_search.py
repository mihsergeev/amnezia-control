"""Глобальный поиск клиентов по парку и массовый отзыв."""

import httpx

from app.models import AwgConfig, AwgNote, ClientName


async def _seed(client: httpx.AsyncClient, headers: dict) -> dict:
    """Два сервера с клиентами одного человека на разных протоколах."""
    ids = {}
    for name, host in (("srv-a", "203.0.113.10"), ("srv-b", "203.0.113.11")):
        r = await client.post(
            "/api/servers",
            json={"name": name, "host": host, "ssh_port": 22, "ssh_user": "acontrol"},
            headers=headers,
        )
        ids[name] = r.json()["id"]
    return ids


async def test_search_finds_client_across_servers(client, auth_headers, session_factory):
    """Поиск обязан покрывать ВЕСЬ парк и разные источники имени: кэш имён с
    ноды, панельные заметки и сохранённые конфиги."""
    ids = await _seed(client, auth_headers)
    async with session_factory() as s:
        # имя пришло с ноды (клиент заведён мимо панели)
        s.add(ClientName(server_id=ids["srv-a"], protocol="awg",
                         client_id="KEY_A=", name="Петров ноутбук"))
        # на другом сервере — только заметка
        s.add(AwgNote(server_id=ids["srv-b"], protocol="xray",
                      public_key="KEY_B=", note="петров, отдел продаж"))
        # и выданный панелью конфиг
        s.add(AwgConfig(server_id=ids["srv-b"], public_key="KEY_C=",
                        name="Петров телефон", config="[Interface]"))
        await s.commit()

    r = await client.get("/api/clients/search?q=петров", headers=auth_headers)
    assert r.status_code == 200
    hits = r.json()
    assert len(hits) == 3, hits
    # найдено на ОБОИХ серверах и в разных протоколах
    assert {h["server_name"] for h in hits} == {"srv-a", "srv-b"}
    assert {h["protocol"] for h in hits} == {"awg", "xray"}
    # конфиг, выданный панелью, помечен
    assert any(h["has_config"] for h in hits)


async def test_search_is_case_insensitive_and_matches_key(client, auth_headers, session_factory):
    ids = await _seed(client, auth_headers)
    async with session_factory() as s:
        s.add(ClientName(server_id=ids["srv-a"], protocol="awg",
                         client_id="AbCdEf123=", name="Иванов"))
        await s.commit()
    for q in ("иванов", "ИВАНОВ", "abcdef"):
        r = await client.get(f"/api/clients/search?q={q}", headers=auth_headers)
        assert len(r.json()) == 1, f"не нашлось по запросу {q}"


async def test_search_ignores_orphans_of_deleted_servers(client, auth_headers, session_factory):
    """Хвосты удалённых серверов не должны всплывать в выдаче — отзывать их
    негде, а в списке они только путают."""
    async with session_factory() as s:
        s.add(ClientName(server_id=99999, protocol="awg",
                         client_id="X=", name="Сидоров"))
        await s.commit()
    r = await client.get("/api/clients/search?q=сидоров", headers=auth_headers)
    assert r.json() == []


async def test_search_requires_auth(client):
    assert (await client.get("/api/clients/search?q=abc")).status_code == 401


async def test_bulk_revoke_keeps_traces_when_node_unreachable(
    client, auth_headers, session_factory, monkeypatch
):
    """КЛЮЧЕВОЕ: если нода недоступна, клиент на ней остался — значит стирать его
    следы в панели НЕЛЬЗЯ. Иначе он исчезнет из поиска и повторить отзыв будет
    нечем, а доступ у человека сохранится."""
    from app import expiry

    ids = await _seed(client, auth_headers)
    async with session_factory() as s:
        s.add(ClientName(server_id=ids["srv-a"], protocol="awg",
                         client_id="KEY_A=", name="Петров"))
        await s.commit()

    async def boom(*a, **kw):
        raise OSError("нода недоступна")

    monkeypatch.setattr(expiry, "revoke_on_node", boom)
    r = await client.post(
        "/api/clients/revoke-bulk",
        json={"items": [{"server_id": ids["srv-a"], "protocol": "awg",
                         "client_id": "KEY_A="}], "query": "петров"},
        headers=auth_headers,
    )
    body = r.json()
    assert body["revoked"] == 0 and body["failed"] == 1
    assert "недоступна" in body["items"][0]["error"]
    # клиент по-прежнему находится поиском — отзыв можно повторить
    assert len((await client.get("/api/clients/search?q=петров", headers=auth_headers)).json()) == 1


async def test_bulk_revoke_cleans_panel_data_on_success(
    client, auth_headers, session_factory, monkeypatch
):
    """Успешный отзыв убирает клиента из панели: он больше не должен находиться."""
    from app import expiry

    ids = await _seed(client, auth_headers)
    async with session_factory() as s:
        s.add(ClientName(server_id=ids["srv-a"], protocol="awg",
                         client_id="KEY_A=", name="Петров"))
        s.add(AwgConfig(server_id=ids["srv-a"], public_key="KEY_A=",
                        name="Петров", config="[Interface]"))
        await s.commit()

    async def ok(*a, **kw):
        return None

    monkeypatch.setattr(expiry, "revoke_on_node", ok)
    r = await client.post(
        "/api/clients/revoke-bulk",
        json={"items": [{"server_id": ids["srv-a"], "protocol": "awg",
                         "client_id": "KEY_A="}]},
        headers=auth_headers,
    )
    assert r.json()["revoked"] == 1
    assert (await client.get("/api/clients/search?q=петров", headers=auth_headers)).json() == []


async def test_bulk_revoke_reports_each_item(client, auth_headers, session_factory, monkeypatch):
    """Одна недоступная нода не срывает остальные: ответ поимённый."""
    from app import expiry

    ids = await _seed(client, auth_headers)

    async def selective(server, protocol, client_id, *a, **kw):
        if server.name == "srv-b":
            raise OSError("таймаут")

    monkeypatch.setattr(expiry, "revoke_on_node", selective)
    r = await client.post(
        "/api/clients/revoke-bulk",
        json={"items": [
            {"server_id": ids["srv-a"], "protocol": "awg", "client_id": "A="},
            {"server_id": ids["srv-b"], "protocol": "xray", "client_id": "B="},
        ]},
        headers=auth_headers,
    )
    body = r.json()
    assert body["revoked"] == 1 and body["failed"] == 1
    by_srv = {i["server_name"]: i for i in body["items"]}
    assert by_srv["srv-a"]["ok"] is True
    assert by_srv["srv-b"]["ok"] is False
