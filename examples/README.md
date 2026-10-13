# PTT Skript-Beispiele

Kleine Bash-Skripte für Automatisierung (`connect`/`exec` mit `--quiet`,
Env-Fallbacks, Exit-Code-Matrix). Alle nutzen das installierte `ptt`-Kommando
(bzw. `./ptt.sh` per `PATH`) und POSIX-Standardwerkzeuge.

| Skript | Zweck |
|---|---|
| `health-check.sh` | Remote-Befehl ausführen, Exit-Code auswerten (0 ok, 124 Zeitlimit) |
| `fetch-logs.sh` | Remote-Dateien holen (`--get`-Stapel mit Fehlerbilanz) |
| `push-files.sh` | Lokale Dateien hochladen (`--put`-Stapel mit Fehlerbilanz) |
| `wait-for-host.sh` | Warten, bis der Host Befehle annimmt (braucht `true` auf dem Host) |
| `scan-inventory.sh` | WLAN-Hosts als Tabelle (`scan --json` + Python-Auswertung) |

Umgebung (statt CLI-Argumente):

```sh
export PTT_HOST=192.168.1.42 PTT_TOKEN=...   # PTT_PORT/PTT_TIMEOUT optional
./health-check.sh uptime
./fetch-logs.sh /var/log/app.log
```

Hinweise:

- `PTT_HOST` gilt nur für `connect`; `exec` braucht weiter das Host-Argument
  (siehe `health-check.sh`).
- `wait-for-host.sh` ruft `true` auf dem Host auf (POSIX-Hosts; auf einem
  Windows-Host ggf. durch einen dort vorhandenen Befehl ersetzen).
- Exit-Codes: siehe „Exit-Codes“ in der Haupt-README.
