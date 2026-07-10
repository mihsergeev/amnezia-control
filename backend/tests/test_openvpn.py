from app import openvpn

TABLE = """[
    {
        "clientId": "O0qNFHmcnCoisMQyPcfco5Sv1DB0Pi7v",
        "userData": {
            "clientName": "Admin [Windows 11 Version 25H2]",
            "creationDate": "Thu May 14 12:49:56 2026"
        }
    },
    {"clientId": "abc", "userData": {"creationDate": "x"}}
]"""


def test_parse_clients() -> None:
    clients = openvpn.parse_clients(TABLE)
    assert len(clients) == 2
    assert clients[0].client_id == "O0qNFHmcnCoisMQyPcfco5Sv1DB0Pi7v"
    assert clients[0].name.startswith("Admin")
    assert clients[0].creation_date == "Thu May 14 12:49:56 2026"
    assert clients[1].name == "—"  # без clientName → прочерк


def test_parse_clients_garbage() -> None:
    assert openvpn.parse_clients("не json") == []
    assert openvpn.parse_clients("[]") == []


def test_deploy_script_preserves_live_pki_before_guard() -> None:
    """Регресс: (пере)деплой OpenVPN должен вытащить PKI из ЖИВОГО контейнера на
    хост ДО guard `test -f ca.crt`, иначе guard сгенерил бы новый CA и все
    клиентские сертификаты стали бы невалидны (класс инцидента de-hz)."""
    s = openvpn.build_deploy_script(8443, "tile.openstreetmap.org", "203.0.113.9")
    # источник — любой openvpn/cloak-контейнер (в т.ч. родной с иным именем)
    assert 'grep -iE "openvpn|cloak"' in s
    # перенос конфига из контейнера на хост
    assert 'docker exec "$SRC" tar -czf -' in s
    assert "opt/amnezia/openvpn" in s and "opt/amnezia/cloak" in s
    # перенос идёт ДО guard генерации
    assert s.index('docker exec "$SRC" tar') < s.index("генерация нового конфига")
    # порт берётся из живого контейнера (клиентский endpoint зашит на старый порт)
    assert "DPORT=$(sudo docker inspect" in s
    assert '[ -n "$DPORT" ] && PORT=$DPORT' in s
    # сносится ЛЮБОЙ openvpn/cloak-контейнер (не только панельный $C)
    assert 'docker ps -aq --filter "name=openvpn" --filter "name=cloak"' in s
