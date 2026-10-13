#!/bin/bash
# push-files.sh – Lokale Dateien per PTT_HOST hochladen (ohne Host-Argument).
# Nutzung: PTT_HOST=192.168.1.42 ./push-files.sh DATEI [...]
set -u

: "${PTT_HOST:?Bitte PTT_HOST setzen, z. B. PTT_HOST=192.168.1.42}"
if [ $# -eq 0 ]; then
  echo "Nutzung: PTT_HOST=<host> $0 DATEI [...]" >&2
  exit 2
fi

ok=0
fail=0
for file in "$@"; do
  if ptt connect --quiet --timeout "${PTT_TIMEOUT:-60}" --put "$file"; then
    echo "ok: $file"
    ok=$((ok + 1))
  else
    echo "FEHLER: $file" >&2
    fail=$((fail + 1))
  fi
done
echo "$ok ok, $fail fehlgeschlagen."
[ "$fail" -eq 0 ]
