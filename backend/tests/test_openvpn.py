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
