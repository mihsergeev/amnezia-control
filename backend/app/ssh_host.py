import ipaddress

import idna


INVALID = "Адрес SSH должен быть IP-адресом или DNS-именем без порта и пробелов"


def valid(host: object) -> bool:
    """IP or a DNS name: one rule for the form, Amnezia links, transfer files and backups.

    The address reaches SSH, node scripts and client configs, so spaces, line breaks,
    ports and shell or option syntax (`$(...)`, `-o...`) never pass.
    """
    if not isinstance(host, str) or not 1 <= len(host) <= 255 or any(char.isspace() for char in host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        # The system resolver also supports local aliases with underscores.
        # Substitute them for the syntax check only, preserving the stored address.
        idna.encode(host.replace("_", "a"), uts46=True, std3_rules=True)
    except idna.IDNAError:
        return False
    return True


def normalize(value: str) -> str:
    """Form input: surrounding spaces are a typing slip, anything else must be valid."""
    host = value.strip()
    if not valid(host):
        raise ValueError(INVALID)
    return host
