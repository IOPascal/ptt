#!/bin/bash
# fetch-logs.sh – Remote-Dateien per PTT_HOST herunterladen (ohne Host-Argument).
# Nutzung: PTT_HOST=192.168.1.42 ./fetch-logs.sh REMOTE-DATEI [...]
set -u

: "${PTT_HOST:?Bitte PTT_HOST setzen, z. B. PTT_HOST=192.168.1.42}"
if [ $# -eq 0 ]; then
  echo "Nutzung: PTT_HOST=<host> $0 REMOTE-DATEI [...]" >&2
  exit 2
fi

ok=0
fail=0
for remote in "$@"; do
  base=$(basename "$remote")
  if ptt connect --quiet --timeout "${PTT_TIMEOUT:-60}" --get "$remote:$base"; then
    echo "ok: $remote -> $base"
    ok=$((ok + 1))
  else
    echo "FEHLER: $remote" >&2
    fail=$((fail + 1))
  fi
done
echo "$ok ok, $fail fehlgeschlagen."
[ "$fail" -eq 0 ]
