#!/bin/bash
# Хостовый сторож Amnezia Control (dead-man's-switch, вне docker).
#
# Панель не может сама сообщить о собственной смерти по своему же каналу, поэтому
# нужен наблюдатель ВНЕ её процесса. Этот скрипт — такой наблюдатель на самом
# хосте панели: он читает «пульс», который панель пишет раз в минуту в
# $ACONTROL_HEARTBEAT (backend/app/heartbeat.py), и НЕЗАВИСИМО шлёт в
# Telegram/webhook, если:
#   • пульс протух (>MAX_AGE) — контейнер/БД мертвы или зависли;
#   • alerts_ok=0 — self-тест канала алертов панели не прошёл.
# Креды (токен/чат/зеркало) берёт из самого пульса, поэтому достучится даже когда
# панель и БД уже не отвечают. Алертит только на переходе (без спама).
#
# НАСТРОЙКА через переменные окружения (по умолчанию значения ниже):
#   ACONTROL_DIR         каталог установки панели (где compose.yml и data/),
#                        по умолчанию /app/acontrol
#   ACONTROL_HEARTBEAT   файл пульса, по умолчанию $ACONTROL_DIR/data/heartbeat
#   ACONTROL_WD_DIR      куда сторож пишет свое состояние, по умолчанию /lib65/acontrol
#   ACONTROL_WD_STATE    файл состояния, по умолчанию $ACONTROL_WD_DIR/watchdog.state
#   ACONTROL_HB_MAX_AGE  через сколько секунд пульс считается протухшим (600)
#   ACONTROL_WD_STRIKES  сколько проверок подряд с проблемой до тревоги (2)
# Свои пути можно задать прямо в строке cron, например:
#   */5 * * * * root ACONTROL_DIR=/opt/acontrol ACONTROL_WD_DIR=/var/lib/acontrol /opt/acontrol/ops/panel-watchdog.sh
#
# УСТАНОВКА с путями по умолчанию (на хосте панели, от root):
#   install -D -m755 ops/panel-watchdog.sh /lib65/acontrol/panel-watchdog.sh
#   echo '*/5 * * * * root /lib65/acontrol/panel-watchdog.sh' > /etc/cron.d/acontrol-watchdog
#   chmod 644 /etc/cron.d/acontrol-watchdog

set -u
ACONTROL_DIR="${ACONTROL_DIR:-/app/acontrol}"
HB="${ACONTROL_HEARTBEAT:-$ACONTROL_DIR/data/heartbeat}"
WD_DIR="${ACONTROL_WD_DIR:-/lib65/acontrol}"
STATE="${ACONTROL_WD_STATE:-$WD_DIR/watchdog.state}"
MAX_AGE="${ACONTROL_HB_MAX_AGE:-600}"
STRIKES="${ACONTROL_WD_STRIKES:-2}"                       # проверок ПОДРЯД с проблемой до тревоги
NOW=$(date +%s)

val(){ grep -m1 "^$1=" "$HB" 2>/dev/null | cut -d= -f2-; }

send(){
  local msg="$1" token chat api hook
  token=$(val tg_token); chat=$(val tg_chat); api=$(val tg_api); hook=$(val webhook)
  [ -z "$api" ] && api="https://api.telegram.org"
  if [ -n "$token" ] && [ -n "$chat" ]; then
    curl -s --max-time 15 "$api/bot$token/sendMessage" \
      --data-urlencode "chat_id=$chat" --data-urlencode "text=$msg" \
      --data-urlencode "disable_web_page_preview=true" >/dev/null 2>&1
  fi
  [ -n "$hook" ] && curl -s --max-time 15 -H 'Content-Type: application/json' \
    --data "{\"text\": \"$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g')\"}" "$hook" >/dev/null 2>&1
}

# проблема карточкой, как алерты панели: уровень, заголовок, подробность
problem=""
if [ ! -f "$HB" ]; then
  problem="🔴|Панель не пишет пульс|файла heartbeat нет, похоже, панель не запущена"
else
  ts=$(val ts); ok=$(val alerts_ok); age=$(( NOW - ${ts:-0} ))
  if [ "${ts:-0}" -eq 0 ] || [ "$age" -gt "$MAX_AGE" ]; then
    problem="🔴|Панель молчит $(( age / 60 )) мин|контейнер или база упали либо зависли"
  elif [ "$ok" = "0" ]; then
    problem="⚠️|Канал алертов сломан|панель жива, но Telegram не отвечает или токен неверный"
  fi
fi

# какая именно панель (из пульса): в один чат пишут несколько панелей, первая
# строка алерта - домен панели, ссылка - последней строкой
panel=$(val panel)
host=${panel#*://}; host=${host%%/*}
[ -z "$host" ] && host="$(hostname)"

card(){  # card "уровень|заголовок|подробность"
  local level title detail
  IFS='|' read -r level title detail <<< "$1"
  printf '%s🚑 %s\n%s' "$level" "$host" "$title"
  [ -n "$detail" ] && printf '\n%s' "$detail"
  [ -n "$panel" ] && printf '\n%s' "$panel"
}

# Дебаунс: тревогу шлём лишь после STRIKES проверок ПОДРЯД с проблемой — чтобы
# кратковременные события (рестарт панели при деплое, разовый блип канала) не
# будили сторожа. Состояние: строка1 = слали ли уже (ok|problem), строка2 = стрик.
alerted=$(sed -n 1p "$STATE" 2>/dev/null); [ -z "$alerted" ] && alerted=ok
strikes=$(sed -n 2p "$STATE" 2>/dev/null); case "$strikes" in ''|*[!0-9]*) strikes=0;; esac

if [ -n "$problem" ]; then
  strikes=$((strikes + 1))
  if [ "$alerted" != "problem" ] && [ "$strikes" -ge "$STRIKES" ]; then
    send "$(card "$problem")"
    alerted=problem
  fi
else
  strikes=0
  if [ "$alerted" = "problem" ]; then
    send "$(card "✅|Панель снова в норме|")"
    alerted=ok
  fi
fi
mkdir -p "$(dirname "$STATE")" 2>/dev/null
printf '%s\n%s\n' "$alerted" "$strikes" > "$STATE"
