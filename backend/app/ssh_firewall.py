"""Source-specific allow transactions. Never reset, enable or reload firewalls."""
import ipaddress
import re

from app import sshops


def script(token: str, addresses: list[str], port: int, operation: str = "stage", *, sudo="sudo -n") -> str:
    if not re.fullmatch(r"[a-f0-9]{32}", token) or operation not in {"stage", "commit", "rollback", "status"}:
        raise ValueError("Некорректная операция firewall")
    port = int(port)
    networks = [ipaddress.ip_network(item, strict=False) for item in addresses]
    header = f'''set -eu
umask 077
command -v flock >/dev/null 2>&1 || exit 1
BASE=/lib65/acontrol-ssh-firewall
for path in /lib65 "$BASE"; do
  [ ! -L "$path" ] || exit 1
  if [ -e "$path" ]; then [ -d "$path" ] && [ "$(stat -c %u "$path")" = 0 ] || exit 1; else mkdir "$path"; fi
done
chmod 700 "$BASE"
STATE="$BASE/{token}"
[ ! -L "$STATE" ] || exit 1
'''
    lock = '''[ -d "$STATE" ] || { echo ACONTROL_FIREWALL_ROLLEDBACK; exit 0; }
[ ! -L "$STATE/lock" ] || exit 1
exec 9>"$STATE/lock"
flock -w 5 9 || { echo 'Firewall operation busy' >&2; exit 1; }
'''
    rollback = '''[ -d "$STATE" ] || { echo ACONTROL_FIREWALL_ROLLEDBACK; exit 0; }
[ ! -e "$STATE/committed" ] || exit 1
FAILED=0
if [ -f "$STATE/ufw-intents" ]; then
  while IFS= read -r rule; do
    added=$(ufw show added) || { FAILED=1; continue; }
    if printf '%s\\n' "$added" | grep -Fqx "ufw $rule"; then
      eval "ufw --force delete $rule" >/dev/null || FAILED=1
    fi
  done < "$STATE/ufw-intents"
fi
for mode in runtime permanent; do
  OPT=""; [ "$mode" = runtime ] || OPT="--permanent"
  if [ -f "$STATE/firewalld-$mode-intents" ]; then
    raw=$(firewall-cmd $OPT --list-rich-rules) || { FAILED=1; continue; }
    current=$(printf '%s\\n' "$raw" | LC_ALL=C sort)
    expected=$(cat "$STATE/firewalld-$mode-after" 2>/dev/null) || { FAILED=1; continue; }
    while IFS= read -r rule; do
      if firewall-cmd $OPT --query-rich-rule="$rule" >/dev/null 2>&1; then
        if [ "$current" != "$expected" ]; then
          echo "Firewall изменен после подготовки, требуется проверка собственного правила: $rule" >&2
          FAILED=1
        else
          firewall-cmd $OPT --remove-rich-rule="$rule" >/dev/null || FAILED=1
        fi
      else
        status=$?; [ "$status" = 1 ] || FAILED=1
      fi
    done < "$STATE/firewalld-$mode-intents"
  fi
done
[ "$FAILED" = 0 ] || exit 1
touch "$STATE/rolledback"
echo ACONTROL_FIREWALL_ROLLEDBACK
'''
    if operation == "status":
        body = header + lock + '''if [ -e "$STATE/rolledback" ]; then echo ACONTROL_FIREWALL_STATE_ROLLEDBACK
elif [ -e "$STATE/committed" ]; then echo ACONTROL_FIREWALL_STATE_COMMITTED
else echo ACONTROL_FIREWALL_STATE_STAGED; fi
'''
    elif operation == "rollback":
        body = header + lock + rollback
    elif operation == "commit":
        body = header + lock + '''[ -d "$STATE" ] && [ ! -e "$STATE/rolledback" ] || exit 1
touch "$STATE/committed"
echo ACONTROL_FIREWALL_COMMITTED
'''
    else:
        body = header + '''[ ! -e "$STATE" ] || exit 1
mkdir -m 700 "$STATE"
''' + lock
        for network in networks:
            address = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
            canonical = f"allow from {address} to any port {port} proto tcp"
            rule = canonical + f" comment 'acontrol-ssh-{token}'"
            rich = f'rule family="ipv{network.version}" source address="{address}" port port="{port}" protocol="tcp" accept'
            body += f'''if command -v ufw >/dev/null 2>&1; then
  ADDED=$(ufw show added)
  if ! printf '%s\\n' "$ADDED" | grep -F 'ufw {canonical}' | grep -Eq 'proto tcp($| comment )'; then
    printf '%s\\n' {sshops._sh_quote(rule)} >> "$STATE/ufw-intents"
    ufw {rule} >/dev/null
  fi
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  for mode in runtime permanent; do
    OPT=""; [ "$mode" = runtime ] || OPT="--permanent"
    RULE={sshops._sh_quote(rich)}
    if firewall-cmd $OPT --query-rich-rule="$RULE" >/dev/null 2>&1; then :; else
      status=$?; [ "$status" = 1 ] || exit 1
      printf '%s\\n' "$RULE" >> "$STATE/firewalld-$mode-intents"
      firewall-cmd $OPT --add-rich-rule="$RULE" >/dev/null
    fi
    RAW=$(firewall-cmd $OPT --list-rich-rules)
    printf '%s\\n' "$RAW" | LC_ALL=C sort > "$STATE/firewalld-$mode-after"
  done
fi
'''
        guard = header + '''i=0
while [ "$i" -lt 180 ]; do
  [ ! -e "$STATE/committed" ] && [ ! -e "$STATE/rolledback" ] || exit 0
  sleep 1; i=$((i + 1))
done
''' + lock + '[ ! -e "$STATE/committed" ] || exit 0\n' + rollback
        body += f'''nohup sh -c {sshops._sh_quote(guard)} 9>&- </dev/null >/dev/null 2>&1 &
echo ACONTROL_FIREWALL_READY
'''
    return f'''if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO={sshops._sh_quote(sudo)}; fi
$SUDO sh -c {sshops._sh_quote(body)}
'''
