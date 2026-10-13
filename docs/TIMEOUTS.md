# Timeouts (PTT 0.11.6)

Alle Zeitgeber auf einen Blick (Werte in Sekunden, außer anders
angegeben). Nutzer-Flags stehen zuerst, dann interne Konstanten.

## Nutzer-Flags

| Flag | Default | Bedeutung |
|---|---|---|
| `connect`/`exec` `--timeout` | aus | Gesamt-Zeitlimit; Ende mit Exit 124 (`PTT_TIMEOUT`) |
| `--retry` / `--retry-delay` | 0 / 2 s | Wiederholungen; Wartezeit verdoppelt sich bis `RETRY_BACKOFF_CAP` (30 s) |
| `host` `--idle-timeout` | aus | Sitzung bei Inaktivität beenden (Minuten) |
| `host` `--max-session` | aus | Maximale Sitzungsdauer (Minuten) |

## Intern (Konstanten)

| Was | Konstante | Wert |
|---|---|---|
| Selbsttest gesamt / je Schritt | `SELF_TEST_TIMEOUT` / `SELF_TEST_STEP_TIMEOUT` | 90 s / 20 s |
| LAN-Suche je Durchlauf | `DISCOVER_TIMEOUT` | 2 s |
| Host-Auth (Login-Zeile) | `AUTH_TIMEOUT` | 30 s |
| Transfer-Bestätigung | `TRANSFER_ACK_TIMEOUT` | 10 s |
| Update-Netz (Pull/pip) | `UPDATE_TIMEOUT` | 120 s |
| TCP-Keepalive (Start/Abstand) | `KEEPALIVE_AFTER` / `KEEPALIVE_INTERVAL` | 60 s / 10 s |
| Thread-Joins (Reader/Shutdown) | `READER_JOIN_TIMEOUT` / `SHUTDOWN_JOIN_TIMEOUT` | 5 s / 15 s |
| Shell-Prozess abräumen | (fest) | 5 s, dann Kill |

Budget-Regel Selbsttest: Gesamt-Cap > 3 × Schritt-Timeout (Zertifikat-
und Host-Starts brauchen zusätzlich Zeit); per Test festgeschrieben.
