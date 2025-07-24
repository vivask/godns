#!/bin/sh
set -e

# запускаем DNS-сервер
exec /usr/local/bin/godns -c /etc/godns.yaml
#exec tail -f /dev/null