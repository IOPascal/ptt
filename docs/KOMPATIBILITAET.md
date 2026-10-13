# Kompatibilität (PTT 0.11.4)

Getestet heißt: läuft in CI (Linux + Windows, Python 3.9–3.13).
Alles andere ist Best Effort.

## Plattformen

| System | Python | Status |
|---|---|---|
| Linux (x86-64) | 3.9, 3.10, 3.11, 3.12, 3.13 | getestet (CI) |
| Windows 10/11 | 3.9, 3.10, 3.11, 3.12, 3.13 | getestet (CI) |
| macOS | 3.9+ | Best Effort (kein CI-Job; Keepalive-Zweig vorhanden) |

Mindestversion: Python 3.9 (`requires-python`, `doctor`-Check
`python`). TLS mindestens 1.2.

## Protokoll

- Draht-Protokoll `ptt1`: Shell-Modus (`ptt1-shell`) und Transfer-Modus
  (`ptt1-transfer`, per TLS-ALPN verhandelt).
- Keine Versionsverhandlung: Unbekannte/gemischte Peers scheitern sauber
  mit lesbarer Meldung statt Traceback oder Hängen (Tests:
  `tests/test_legacy_peers.py`). Unbekannte Frame-Typen toleriert jede
  Seite bis zu einer Grenze (`MAX_UNKNOWN_FRAMES`).

## Feature-Grenzen (Client neu, Host alt)

| Funktion | braucht Host | sonst |
|---|---|---|
| Datei-Transfer (`--put`/`--get`) | ≥ 0.8 | `Host unterstützt keinen Datei-Transfer` |
| `exec`-stdin-Weiterleitung | ≥ 0.9.2 | stdin wird ignoriert (`--timeout` als Abhilfe) |
| Sitzungs-Statistiken, Resume | ≥ jeweiliger Linie | ältere Hosts liefern Basis-Verhalten |

Faustregel: Host und Client auf demselben Stand halten (`ptt update`).

## Bekannte Plattform-Einschränkungen

- Host auf Windows: ohne Pseudo-Terminal — nur einfache Befehle, kein
  `vim`/`htop` (Client überall ok).
- Windows ohne `openssl`: Zertifikate entstehen per `cryptography`-Paket
  (automatischer Fallback, kein Zutun nötig).
- LAN-Suche braucht UDP-Broadcast; ohne Broadcast direkt verbinden:
  `ptt connect <IP>` (s. `doctor`-Check `net-udp`).
