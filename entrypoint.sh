#!/bin/sh
set -e

# (опционально) сгенерировать root.key, если его нет
[ -f /etc/unbound/root.key ] || unbound-anchor -a /etc/unbound/root.key

# запускаем DNS-сервер
exec /usr/local/bin/godns -c /etc/godns.yaml
#exec tail -f /dev/null