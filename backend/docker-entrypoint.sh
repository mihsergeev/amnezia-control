#!/bin/sh
# Процесс панели держит SSH-ключ ко всем нодам, поэтому работает не от root.
# Root нужен только на старте: отдать /data пользователю панели (у установок
# до 0.57 файлы там созданы root'ом), после чего права сбрасываются.
set -e
APP_UID=10001

if [ "$(id -u)" = "0" ]; then
  # ./data/postgres в compose лежит внутри того же каталога, это база со своим
  # владельцем, ее не трогаем
  if find /data -path /data/postgres -prune -o ! -user "$APP_UID" \
      -exec chown "$APP_UID:$APP_UID" {} + 2>/dev/null; then
    exec setpriv --reuid="$APP_UID" --regid="$APP_UID" --clear-groups \
      env HOME=/data "$@"
  fi
  # без CAP_CHOWN (свой compose с cap_drop: ALL) не выйдет отдать файлы, а без
  # этого панель не прочитает свой ключ - работаем как раньше и говорим об этом
  echo "acontrol: не удалось передать /data пользователю $APP_UID, запуск от root" >&2
fi
exec "$@"
