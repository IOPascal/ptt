#!/bin/bash
# health-check.sh – Remote-Befehl ausführen und Exit-Code auswerten.
# Nutzung: PTT_HOST=192.168.1.42 ./health-check.sh [BEFEHL ...]
#   (ohne BEFEHL: uptime; PTT_PORT/PTT_TIMEOUT optional)
set -u

: "${PTT_HOST:?Bitte PTT_HOST setzen, z. B. PTT_HOST=192.168.1.42}"
if [ $# -eq 0 ]; then
  set -- uptime
fi

err=$(mktemp)
trap 'rm -f "$err"' EXIT
out=$(ptt exec "$PTT_HOST" --quiet --timeout "${PTT_TIMEOUT:-30}" -- "$@" 2>"$err")
rc=$?
case $rc in
  0) printf '%s\n' "$out" ;;
  124)
    echo "health-check: Zeitlimit (Exit 124) – Host langsam oder weg?" >&2
    exit 124
    ;;
  *)
    echo "health-check: Fehlschlag (Exit $rc):" >&2
    cat "$err" >&2
    exit "$rc"
    ;;
esac
