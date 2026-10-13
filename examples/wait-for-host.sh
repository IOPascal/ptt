#!/bin/bash
# wait-for-host.sh – Warten, bis der Host Befehle annimmt (z. B. nach Reboot).
# Nutzung: PTT_HOST=192.168.1.42 ./wait-for-host.sh [VERSUCHE]
set -u

: "${PTT_HOST:?Bitte PTT_HOST setzen, z. B. PTT_HOST=192.168.1.42}"
tries=${1:-20}
i=1
while [ "$i" -le "$tries" ]; do
  if ptt exec "$PTT_HOST" --quiet --timeout 10 -- true 2>/dev/null; then
    echo "Host bereit (Versuch $i)."
    exit 0
  fi
  echo "Versuch $i/$tries: Host noch nicht bereit, warte 3 s ..."
  sleep 3
  i=$((i + 1))
done
echo "Host nach $tries Versuchen nicht bereit." >&2
exit 1
