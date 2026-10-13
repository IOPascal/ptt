#!/bin/bash
# scan-inventory.sh – WLAN-Hosts als Tabelle ausgeben (portabel, nur Python).
# Nutzung: ./scan-inventory.sh
set -u

ptt scan --json | python3 -c '
import json, sys
hosts = json.load(sys.stdin)
if not hosts:
    print("Keine Hosts gefunden.")
    sys.exit(0)
for h in hosts:
    busy = " (belegt)" if h.get("busy") else ""
    print("%s %s:%s [%s]%s" % (
        h.get("name", "?"), h.get("address", "?"),
        h.get("port", "?"), str(h.get("auth", "?")).upper(), busy))
'
