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


STATUS_LOG = """OpenVPN CLIENT LIST
Updated,Thu May 14 12:00:00 2026
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
abc123,10.0.0.2:5000,1048576,2097152,Thu May 14 11:00:00 2026
def456,10.0.0.3:5001,500,700,Thu May 14 11:30:00 2026
ROUTING TABLE
10.8.0.2,abc123,10.0.0.2:5000,Thu May 14 12:00:00 2026
GLOBAL STATS
END
"""


def test_parse_status_log() -> None:
    m = openvpn.parse_status_log(STATUS_LOG)
    assert set(m) == {"abc123", "def456"}
    assert m["abc123"] == {
        "rx": 1048576, "tx": 2097152, "since": "Thu May 14 11:00:00 2026",
    }
    assert m["def456"]["rx"] == 500 and m["def456"]["tx"] == 700
    # строки из ROUTING TABLE не считаются клиентами
    assert "10.8.0.2" not in m


def test_parse_status_log_empty() -> None:
    assert openvpn.parse_status_log("") == {}
    assert openvpn.parse_status_log("garbage\nno header") == {}


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
