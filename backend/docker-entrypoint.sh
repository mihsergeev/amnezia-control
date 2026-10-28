#!/bin/sh
# Процесс панели держит SSH-ключ ко всем нодам, поэтому работает не от root.
# Root нужен только на старте: отдать /data пользователю панели (у установок
# до 0.57 файлы там созданы root'ом), после чего права сбрасываются. От root
# панель не запускается никогда: не вышло отдать файлы - контейнер падает
# и пишет, что сделать.
set -e
APP_UID=10001

as_app() {
  setpriv --reuid="$APP_UID" --regid="$APP_UID" --clear-groups "$@"
}

# что в /data не принадлежит панели или ей не видно (первые строки);
# ./data/postgres в compose лежит внутри того же каталога, это база со своим
# владельцем, ее не трогаем
foreign() {
  as_app find /data -path /data/postgres -prune -o ! -user "$APP_UID" -print 2>&1 | head -n 5
}

if [ "$(id -u)" = "0" ]; then
  [ -d /data ] || mkdir /data
  if [ -n "$(foreign)" ]; then
    # root здесь без DAC_OVERRIDE и DAC_READ_SEARCH, т.е. проходит только свои
    # каталоги: у старых установок там все от root, а в закрытые каталоги
    # панели он не попадет, но там и так все ее. -depth отдает каталог после
    # содержимого, чтобы прерванный старт не оставил каталог панели с чужими
    # файлами внутри. Что не вышло, покажет повторная проверка
    find /data -depth ! -path /data/postgres ! -path '/data/postgres/*' \
      ! -user "$APP_UID" -exec chown -h "$APP_UID:$APP_UID" {} + 2>/dev/null || true
    left=$(foreign)
    if [ -n "$left" ]; then
      echo "acontrol: в /data есть файлы не пользователя панели ($APP_UID), отдать их не вышло:" >&2
      echo "$left" >&2
      echo "acontrol: контейнеру нужны cap_add CHOWN, SETUID, SETGID (см. compose.yml), либо на хосте в каталоге панели:" >&2
      echo "acontrol:   sudo find data -path data/postgres -prune -o -exec chown -h $APP_UID:$APP_UID {} +" >&2
      exit 1
    fi
  fi
  exec setpriv --reuid="$APP_UID" --regid="$APP_UID" --clear-groups \
    env HOME=/data "$@"
fi
exec "$@"
