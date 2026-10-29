"""Проверка выхода клиентов: откуда трафик клиентов уходит в интернет и
открываются ли через него популярные сайты. Подходит для любого сервера, в том
числе для каскада, собранного руками: панель не знает, как он устроен, и
проверяет только результат.

Пробы идут curl хоста внутри сетевого пространства VPN-контейнера (nsenter -n),
то есть тем же путем, что трафик клиентов: через мост контейнера, tproxy,
GRE и т.п. Свой curl в контейнере не нужен (в AWG и OpenVPN его нет), и в
контейнере не остаются зомби. DNS резолвит хост: в пространстве контейнера его
резолвер на 127.0.0.53 недоступен. Маршрут по домену это не меняет, шлюзы
каскадов смотрят на SNI."""

import base64
import ipaddress
import re

from app import cascade

# (название, адрес). Google - есть ли интернет вообще, остальное то, что режут
SITES = (
    ("Google", "https://www.google.com/generate_204"),
    ("Telegram", "https://telegram.org/"),
    ("Instagram", "https://www.instagram.com/"),
    ("YouTube", "https://www.youtube.com/"),
)
TIMEOUT = 10

_SCRIPT = r"""
D=docker
[ -w /var/run/docker.sock ] || [ -w /run/docker.sock ] || D="sudo -n docker"
command -v curl >/dev/null 2>&1 || { echo "EC_ERROR=на сервере нет curl"; exit 0; }
C=$($D ps --format '{{.Names}}' 2>/dev/null | grep -i '^amnezia' | grep -vx 'amnezia-dns' | head -1)
[ -n "$C" ] || { echo "EC_ERROR=нет VPN-контейнеров"; exit 0; }
P=$($D inspect -f '{{.State.Pid}}' "$C" 2>/dev/null)
[ -n "$P" ] && [ "$P" != 0 ] || { echo "EC_ERROR=контейнер $C не запущен"; exit 0; }
echo "EC_CONTAINER=$C"
host_of() { echo "$1" | sed 's#^https://\([^/]*\).*#\1#'; }
addr_of() { getent ahostsv4 "$1" | awk 'NR == 1 {print $1}'; }
# curl в сети контейнера; адрес сайта подставляем сами (--resolve)
fetch() {
  h=$(host_of "$1"); a=$(addr_of "$h")
  [ -n "$a" ] || return 1
  sudo -n nsenter -t "$P" -n curl -4 -sS -m @TIMEOUT@ --resolve "$h:443:$a" "$@"
}
ip_from() { grep -oE '([0-9]{1,3}[.]){3}[0-9]{1,3}' | head -1; }
echo "EC_EGRESS=$(fetch https://api.ipify.org 2>/dev/null | ip_from)"
[ -z "@LOCAL@" ] || echo "EC_LOCAL=$(fetch @LOCAL@ 2>/dev/null | ip_from)"
for s in @SITES@; do
  name=${s%%=*}; url=${s#*=}
  r=$(fetch "$url" -o /dev/null -w '%{http_code} %{time_total}' 2>/dev/null) || true
  echo "EC_SITE=$name ${r:-000 0}"
done
"""


def build_command(country: str = "") -> str:
    local = cascade._LOCAL_IP_URL.get((country or "").lower(), "")
    sites = " ".join(f"{name}={url}" for name, url in SITES)
    script = (
        _SCRIPT.replace("@TIMEOUT@", str(TIMEOUT))
        .replace("@LOCAL@", local)
        .replace("@SITES@", sites)
    )
    # base64: в скрипте свои кавычки и шаблоны docker, а запускает его оболочка ssh
    b64 = base64.b64encode(script.encode()).decode()
    return f"echo {b64} | base64 -d | sh\n"


def _ip(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ValueError:
        return ""


def parse(text: str) -> dict:
    """Вывод проверки -> {error, container, egress, local, sites: [...]}."""
    out: dict = {"error": "", "container": "", "egress": "", "local": "", "sites": []}
    for line in (text or "").splitlines():
        m = re.match(r"^EC_([A-Z]+)=(.*)$", line.strip())
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if key == "ERROR":
            out["error"] = value
        elif key == "CONTAINER":
            out["container"] = value
        elif key in ("EGRESS", "LOCAL"):
            out[key.lower()] = _ip(value)
        elif key == "SITE":
            parts = value.split()
            name = parts[0] if parts else "?"
            code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            try:
                secs = float(parts[2]) if len(parts) > 2 else 0.0
            except ValueError:
                secs = 0.0
            # любой HTTP-ответ значит, что TLS до сайта прошел и он отвечает;
            # 000 - не подключилось или оборвалось
            out["sites"].append({"name": name, "ok": code > 0, "code": code,
                                 "ms": round(secs * 1000) if code else 0})
    return out
