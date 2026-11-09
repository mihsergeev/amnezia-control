"""Перенос одного сервера между панелями: выгрузка в файл и загрузка из него.

Смысл проверок — в том, что именно доезжает. Живых клиентов новая панель всё
равно прочитает с ноды; ценность файла в панельной обвязке, которой на ноде нет:
сохранённые конфиги (без них клиенту нельзя отдать файл — только перевыпустить),
заметки, сроки действия и паузы. Если что-то из этого потеряется, узнают об этом
уже после переезда, когда старая панель выключена.
"""

import json
from urllib.parse import unquote
from uuid import uuid4

import httpx
from sqlalchemy import select

from app.api.transfer import _selected_models, server_scoped_models
from app.models import AwgConfig, AwgNote, BulkClientIssue, ClientLimit, PausedClient, User

SERVER = {
    "name": "vpn-f",
    "host": "203.0.113.77",
    "ssh_port": 2221,
    "ssh_user": "amn",
    "note": "боевой узел",
    "group_name": "acme-corp",
}


def _pw(headers: dict) -> dict:
    """Выгрузка сервера - со степ-апом: пароль заголовком."""
    return {**headers, "X-Confirm-Password": "testpass"}


async def _make_server(client: httpx.AsyncClient, auth_headers, **over) -> int:
    r = await client.post(
        "/api/servers", json={**SERVER, **over}, headers=auth_headers
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _seed(session_factory, server_id: int) -> None:
    """Панельная обвязка сервера: конфиг, заметка, срок и пауза."""
    async with session_factory() as session:
        session.add_all([
            AwgConfig(
                server_id=server_id, public_key="cHVia2V5MQ==", name="phone-max",
                config="[Interface]\nPrivateKey = c2VjcmV0\n",
            ),
            AwgNote(
                server_id=server_id, protocol="awg", public_key="cHVia2V5MQ==",
                note="выдан Максу",
            ),
            ClientLimit(
                server_id=server_id, protocol="awg", client_id="cHVia2V5MQ==",
                name="phone-max", expires_at=None,
            ),
            PausedClient(
                server_id=server_id, protocol="awg", client_id="cHVia2V5Mg==",
                name="laptop", data='{"ip": "10.8.1.5"}',
            ),
        ])
        await session.commit()


async def test_export_requires_auth(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/servers/1/export")).status_code == 401


async def test_export_missing_server_is_404(
    client: httpx.AsyncClient, auth_headers
) -> None:
    r = await client.get("/api/servers/999/export", headers=_pw(auth_headers))
    assert r.status_code == 404


async def test_export_carries_panel_side_data(
    client: httpx.AsyncClient, auth_headers, session_factory
) -> None:
    sid = await _make_server(client, auth_headers)
    await _seed(session_factory, sid)

    r = await client.get(f"/api/servers/{sid}/export", headers=_pw(auth_headers))
    assert r.status_code == 200
    assert r.headers["content-disposition"] == 'attachment; filename="vpn-f.acontrol-server.json"'
    data = r.json()

    assert data["format"] == "acontrol-server-export"
    assert data["server"]["host"] == "203.0.113.77"
    assert data["server"]["ssh_user"] == "amn"
    assert data["server"]["group_name"] == "acme-corp"
    # именно то, чего нет на ноде
    assert data["tables"]["awg_configs"][0]["name"] == "phone-max"
    assert "PrivateKey" in data["tables"]["awg_configs"][0]["config"]
    assert data["tables"]["awg_notes"][0]["note"] == "выдан Максу"
    assert len(data["tables"]["client_limits"]) == 1
    assert data["tables"]["paused_clients"][0]["name"] == "laptop"
    # id/server_id локальны для БД-источника и в файл не попадают
    assert "id" not in data["tables"]["awg_configs"][0]
    assert "server_id" not in data["tables"]["awg_configs"][0]


async def test_export_preserves_unicode_filename(client, auth_headers) -> None:
    name = 'Тестовый узел "01"'
    sid = await _make_server(client, auth_headers, name=name)

    r = await client.get(f"/api/servers/{sid}/export?history=false", headers=_pw(auth_headers))

    assert r.status_code == 200
    plain, extended = r.headers["content-disposition"].split("; filename*=UTF-8''")
    assert plain == 'attachment; filename="01.acontrol-server.json"'
    assert extended.isascii()
    assert unquote(extended) == "Тестовый-узел--01.acontrol-server.json"
    assert r.json()["server"]["name"] == name


async def test_export_skips_history_unless_asked() -> None:
    # у боевой ноды это сотни тысяч строк — по умолчанию файл ими не раздуваем
    light = {m.__tablename__ for m in _selected_models(False)}
    full = {m.__tablename__ for m in _selected_models(True)}
    assert "client_traffic_samples" not in light
    assert "traffic_samples" not in light
    assert {"traffic_samples", "client_traffic_samples"} <= full


async def test_export_skips_runtime_tables() -> None:
    # статус проверки и метрики новая панель наберёт сама; переносить их значило
    # бы показывать чужое «онлайн» до первого опроса
    light = {m.__tablename__ for m in _selected_models(True)}
    assert "server_status" not in light
    assert "node_metrics" not in light


async def test_every_server_scoped_table_is_accounted_for() -> None:
    # страховка от тихой потери: новая таблица с server_id обязана попасть либо
    # в перенос, либо в осознанные исключения
    known = {"server_status", "node_metrics", "traffic_samples",
             "client_traffic_samples", "torrent_hits", "bulk_client_issues"}
    exported = {m.__tablename__ for m in _selected_models(False)}
    for model in server_scoped_models():
        t = model.__tablename__
        assert t in exported or t in known, f"таблица {t} не учтена в переносе"


async def test_transfer_keeps_profiles_but_does_not_move_pending_issue(client, auth_headers, session_factory):
    sid = await _make_server(client, auth_headers)
    await _seed(session_factory, sid)
    async with session_factory() as session:
        owner = await session.scalar(select(User))
        pending = {
            "request_id": str(uuid4()), "owner_id": owner.id, "protocol": "awg3",
            "prefix": "Test", "count": 1, "complete": False,
            "items": [{"name": "Test-001", "client_id": "planned-client", "config": "synthetic profile"}],
        }
        session.add(BulkClientIssue(server_id=sid, **pending))
        await session.commit()

    for history in ("true", "false"):
        response = await client.get(f"/api/servers/{sid}/export?history={history}", headers=_pw(auth_headers))
        assert response.status_code == 200
        dump = response.json()
        assert "bulk_client_issues" not in dump["tables"]
        assert len(dump["tables"]["awg_configs"]) == 1

    # Older transfer files include the pending journal of the source panel.
    dump["tables"]["bulk_client_issues"] = [pending]
    dump["server"]["host"] = "203.0.113.78"
    response = await client.post("/api/servers/import-file", json=dump, headers=auth_headers)
    assert response.status_code == 200, response.text
    result = response.json()
    assert "bulk_client_issues" in result["skipped_tables"]
    assert result["imported"]["awg_configs"] == 1
    url = "/api/servers/{}/bulk-clients/awg3/issue/pending"
    before = await client.get(url.format(sid), headers=auth_headers)
    after = await client.get(url.format(result["server_id"]), headers=auth_headers)
    assert before.status_code == after.status_code == 200
    assert before.json()["request_id"] == pending["request_id"]
    assert after.json() is None


async def test_import_restores_server_with_its_data(
    client: httpx.AsyncClient, auth_headers, session_factory
) -> None:
    sid = await _make_server(client, auth_headers)
    endpoint = "192.0.2.9"
    response = await client.patch(
        f"/api/servers/{sid}", json={"client_endpoint": endpoint}, headers=auth_headers
    )
    assert response.status_code == 200, response.text
    await _seed(session_factory, sid)
    dump = (await client.get(f"/api/servers/{sid}/export", headers=_pw(auth_headers))).json()
    assert dump["server"]["client_endpoint"] == endpoint
    dump["server"]["alerts_enabled"] = True

    # эмулируем другую панель: исходного сервера тут нет
    assert (await client.delete(f"/api/servers/{sid}", headers=auth_headers)).status_code == 200

    r = await client.post(
        "/api/servers/import-file", content=json.dumps(dump), headers=auth_headers
    )
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["host"] == "203.0.113.77"
    assert res["imported"]["awg_configs"] == 1
    assert res["imported"]["awg_notes"] == 1
    new_id = res["server_id"]
    server = (await client.get(f"/api/servers/{new_id}", headers=auth_headers)).json()
    assert server["alerts_enabled"] is False
    assert server["client_endpoint"] == endpoint

    # строки перепривязаны к НОВОМУ id, а не тащат старый
    async with session_factory() as session:
        cfg = await session.scalar(
            select(AwgConfig).where(AwgConfig.server_id == new_id)
        )
        paused = await session.scalar(
            select(PausedClient).where(PausedClient.server_id == new_id)
        )
    assert cfg is not None and cfg.name == "phone-max"
    assert "PrivateKey" in cfg.config
    # полезная нагрузка паузы (IP клиента) доезжает дословно — иначе клиента
    # нельзя вернуть на его же адрес
    assert paused is not None and json.loads(paused.data) == {"ip": "10.8.1.5"}


async def test_import_refuses_duplicate_host(
    client: httpx.AsyncClient, auth_headers, session_factory
) -> None:
    # две карточки одной ноды правили бы один конфиг вслепую друг от друга
    sid = await _make_server(client, auth_headers)
    dump = (await client.get(f"/api/servers/{sid}/export", headers=_pw(auth_headers))).json()
    r = await client.post(
        "/api/servers/import-file", content=json.dumps(dump), headers=auth_headers
    )
    assert r.status_code == 409
    assert "уже есть" in r.json()["detail"]


async def test_import_rejects_foreign_file(
    client: httpx.AsyncClient, auth_headers
) -> None:
    for body in ('{"format": "something-else"}', "не json вовсе", "[]"):
        r = await client.post(
            "/api/servers/import-file", content=body, headers=auth_headers
        )
        assert r.status_code == 400, body


async def test_import_rejects_newer_format(
    client: httpx.AsyncClient, auth_headers
) -> None:
    body = json.dumps({
        "format": "acontrol-server-export", "format_version": 99,
        "server": {"name": "x", "host": "203.0.113.5"}, "tables": {},
    })
    r = await client.post(
        "/api/servers/import-file", content=body, headers=auth_headers
    )
    assert r.status_code == 400
    assert "99" in r.json()["detail"]


async def test_import_rejects_broken_expiry_instead_of_permanent_client(client, auth_headers):
    payload = {
        "format": "acontrol-server-export", "format_version": 1,
        "server": SERVER,
        "tables": {"client_limits": [{
            "protocol": "awg", "client_id": "test-client", "expires_at": "not-a-date",
        }]},
    }
    r = await client.post("/api/servers/import-file", headers=auth_headers,
                          content=json.dumps(payload))
    assert r.status_code == 400
    assert (await client.get("/api/servers", headers=auth_headers)).json() == []


async def test_import_names_tables_it_could_not_take(
    client: httpx.AsyncClient, auth_headers
) -> None:
    # файл из более новой панели: неизвестную таблицу пропускаем, но называем —
    # тихая потеря данных при переезде хуже, чем названная вслух
    body = json.dumps({
        "format": "acontrol-server-export", "format_version": 1,
        "server": {"name": "srv", "host": "203.0.113.8", "ssh_port": 22,
                   "ssh_user": "amn"},
        "tables": {"future_widgets": [{"a": 1}]},
    })
    r = await client.post(
        "/api/servers/import-file", content=body, headers=auth_headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["skipped_tables"] == ["future_widgets"]


async def test_import_drops_past_limits_and_runtime(
    client: httpx.AsyncClient, auth_headers, session_factory
) -> None:
    # прошедший срок отозвал бы живого клиента сразу после загрузки
    body = json.dumps({
        "format": "acontrol-server-export", "format_version": 1,
        "server": {"name": "srv", "host": "203.0.113.9", "ssh_port": 22,
                   "ssh_user": "amn"},
        "tables": {
            "client_limits": [
                {"protocol": "awg", "client_id": "old", "name": "a",
                 "expires_at": "2020-01-01T00:00:00+00:00"},
                {"protocol": "awg", "client_id": "new", "name": "b",
                 "expires_at": "2099-01-01T00:00:00+00:00"},
            ],
            "server_status": [{"online": True}],
        },
    })
    r = await client.post(
        "/api/servers/import-file", content=body, headers=auth_headers
    )
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["imported"] == {"client_limits": 1}
    assert res["skipped_tables"] == []
    async with session_factory() as session:
        ids = [
            lim.client_id
            for lim in await session.scalars(
                select(ClientLimit).where(ClientLimit.server_id == res["server_id"])
            )
        ]
    assert ids == ["new"]
