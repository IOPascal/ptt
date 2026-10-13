# PTT – Private Terminal Tunnel

[![CI](https://github.com/IOPascal/ptt/actions/workflows/ci.yml/badge.svg)](https://github.com/IOPascal/ptt/actions/workflows/ci.yml)

PTT öffnet einen verschlüsselten Tunnel, über den du dich im lokalen
Netzwerk (z. B. WLAN) auf das Terminal eines anderen Geräts schalten kannst.

- **`ptt host`** – Tunnel auf diesem Gerät öffnen (gibt das Terminal frei)
- **`ptt connect`** – sich von einem anderen Gerät auf einen offenen Tunnel schalten
- **`ptt doctor`** – Umgebung prüfen (bei Problemen zuerst)

Verschlüsselung: TLS (selbstsigniertes Zertifikat) + Token-Auth.
Nur Python aus der Standardbibliothek nötig – keine `pip`-Pakete.

## Voraussetzungen

- Python 3.9+ auf beiden Geräten
  - Linux: meist vorinstalliert (`python3 --version`)
  - Windows: von [python.org](https://www.python.org/downloads/) installieren,
    dabei **„Add python.exe to PATH"** anhaken
- Zum **Hosten**: `openssl`-Programm (Linux: vorinstalliert;
  Windows: alternativ `pip install cryptography`)
- Beide Geräte im selben WLAN/LAN

## Schnellstart

Ohne Installation, direkt aus dem Projektordner
(Linux: `./ptt.sh`, Windows: `ptt` via `ptt.cmd` –
oder als festes Kommando [installieren](#als-ptt-kommando-installieren)).

**0. Prüfen** (auf beiden Geräten, bei Problemen zuerst):

```sh
cd ptt
./ptt.sh doctor
```

**1. Host: Tunnel öffnen** (z. B. auf dem Linux-Rechner)

```sh
./ptt.sh host
```

Der Host zeigt Name, PIN und Direkt-Adressen im Rahmen. Die 6-stellige
PIN steht nur dort – sie wird nach jeder Sitzung neu erzeugt.

**2. Client: verbinden** (z. B. auf dem Windows-PC)

```bat
cd <pfad-zum-ptt-ordner>
ptt connect
```

`ptt connect` findet den Host von selbst – du wählst ihn aus der Liste
und gibst die PIN vom Host-Bildschirm ein. Fertig.
Beenden mit `exit` in der Remote-Shell.

> Tipp: Den `ptt`-Ordner einfach per USB-Stick, Netzwerkfreigabe
> oder `git clone` auf den anderen Rechner kopieren.

## Optionen

(`ptt` steht hier für `./ptt.sh`, `ptt.cmd` bzw. das installierte Kommando.)

```sh
# Host: Name im WLAN, feste PIN, eigene Shell
ptt host --name wohnzimmer --pin 123456 --shell /bin/bash

# Host: nicht im WLAN ankündigen (nur Direkt-Verbindung)
ptt host --no-discover

# Host: langes Token statt PIN (für Skripte / unsichere Netze)
ptt host --token mein-geheimes-token

# Host: nach einer Sitzung automatisch beenden
ptt host --once

# Host: Farbausgabe steuern (auto/always/never, Default: auto)
ptt host --color always

# Host: Sitzung bei 10 Min. Inaktivität beenden (Exit-Code 124 beim Client)
ptt host --idle-timeout 10

# Host: Sitzungsdauer auf 60 Min. begrenzen
ptt host --max-session 60

# Host: bis zu 3 parallele Sitzungen (Default: 1, 0 = unbegrenzt)
ptt host --max-sessions 3

# Host: Upload-Ziel und Größenlimit für Datei-Transfer
ptt host --transfer-dir ~/ptt-inbox --max-transfer-size 100M

# Client: direkt per IP (ohne Suche)
ptt connect 192.168.1.42

# Client: Secret direkt mitgeben (für Skripte)
ptt connect 192.168.1.42 --token 482913

# Client: bis zu 5-mal neu versuchen (z. B. wenn der Host später startet)
ptt connect 192.168.1.42 --retry 5 --retry-delay 2

# Client: Datei hoch-/herunterladen (Zielname jeweils optional)
ptt connect 192.168.1.42 --put bericht.pdf
ptt connect 192.168.1.42 --put bericht.pdf:inbox/neu.pdf
ptt connect 192.168.1.42 --get daten.csv
ptt connect 192.168.1.42 --get daten.csv:/tmp/lokal.csv

# Client: mehrere Transfers in einem Aufruf (erst alle --put, dann --get)
ptt connect 192.168.1.42 --put a.bin --put b.bin --get erg.log

# Client: Transfer von vorn beginnen statt fortzusetzen
ptt connect 192.168.1.42 --put big.iso --fresh

# Skript-freundlich ohne `ps`-Sichtbarkeit: Env oder Datei (gilt auch für `host`)
PTT_TOKEN=482913 ptt connect 192.168.1.42
ptt connect 192.168.1.42 --token-file ~/.ptt-token

# Verbindungsdaten per Env (CLI gewinnt, sonst Env, sonst Default)
PTT_HOST=192.168.1.42 PTT_PORT=8022 PTT_TIMEOUT=30 ptt connect
PTT_PORT=8022 PTT_TIMEOUT=30 ptt exec 192.168.1.42 uptime

# Ruhig für Skripte: Status nach stderr, stdout nur Nutzdaten
ptt exec 192.168.1.42 --quiet uptime > last-boot.txt
ptt connect 192.168.1.42 --quiet --get daten.csv

# Ausführlich für Diagnose: Zeit-Phasen nach stderr (gilt auch für `host`)
ptt exec 192.168.1.42 --verbose uptime

# Fertige Skript-Beispiele: siehe examples/ (health-check, fetch-/push, wait, scan)

# Umgebung prüfen (bei Problemen zuerst)
ptt doctor

# Gründlich: Ende-zu-Ende-Selbsttest bzw. Bericht für Support
ptt doctor --self-test
ptt doctor --report bericht.md

# PTT selbst aktualisieren
ptt update
```

Exit-Codes: siehe Tabelle „Exit-Codes“ unten (`exec` reicht den
Programm-Code durch, `--timeout`/Idle endet mit `124`).

Sitzungen: Der Host meldet Belegung in der LAN-Suche, protokolliert
Dauer und Traffic pro Sitzung und beendet auf SIGTERM/Strg+C sauber
(2. Strg+C bricht sofort ab).

Datei-Transfer: läuft über dieselbe TLS-Verbindung + Auth wie die
Shell (eigener ALPN-Modus), mit Fortschrittsbalken, SHA-256-Prüfung
und atomarem Ablegen. Abgebrochene Transfers setzt ein erneuter
Aufruf automatisch fort (Teil-Dateien `*.ptt-part`, `--fresh` startet
neu); Teile älter als 24 h räumt der Host beim Start weg. Bei Stapeln
ist der Exit-Code 1, sobald mindestens ein Transfer scheitert.

## Automatisierung

Für Skripte: ein Befehl ohne TTY, Remote-Ausgabe nach stdout,
Remote-Exit-Code als Exit-Code (inkl. `127` für unbekannte Programme
und `128+N` bei Signal-Tod, wie ssh; stderr ist in stdout gemergt):

```sh
ptt exec 192.168.1.42 uptime
printf 'ok\nFehler!\n' | ptt exec 192.168.1.42 -- grep -i fehler
```

Bausteine (alle kombinierbar, siehe Optionen oben und `examples/`):

- `--quiet`: Status nach stderr, stdout nur Nutzdaten
  (`out=$(ptt exec …)` ist direkt weiterverarbeitbar).
- `--timeout SEK`: begrenzt den gesamten Aufruf (Ende mit `124`).
- Env statt Argumente: `PTT_HOST` (nur `connect`), `PTT_PORT`,
  `PTT_TIMEOUT` — Vorrang: CLI > Env > Default.
- `scan [--json]` / `doctor [--json]`: Hosts und Diagnose
  maschinenlesbar (leere Suche ist Exit-Code `0`).
- Exit-Codes: Tabelle unten; `examples/` zeigt fertige Skripte.

## Als `ptt`-Kommando installieren

Damit `ptt` überall ohne Pfad läuft, wahlweise:

```sh
# Variante A: Projekt-venv (empfohlen für Entwicklung)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

```sh
# Variante B: global via pipx (einmalig: pipx installieren)
pipx install .
```

Windows (installiert `ptt.exe`):

```bat
py -m pip install .
```

Danach überall: `ptt doctor`, `ptt host`, `ptt connect 192.168.1.42`, `ptt update`.

## Sicherheit

- Jede Verbindung ist TLS-verschlüsselt (mind. TLS 1.2, Zertifikat in
  `~/.ptt/`, wird beim ersten Start erzeugt und wiederverwendet).
- Datei-Transfers nutzen dieselbe TLS-Verbindung, Auth und
  Host-Prüfung wie die Shell; zusätzlich sichert SHA-256 jede Datei
  gegen Verfälschung.
- Standard ist die **PIN**: 6-stellig, steht nur auf dem Host-Bildschirm
  und wird nach jeder Sitzung neu erzeugt. Nach 5 falschen Versuchen pro
  IP sperrt der Host mit Wartezeit, zusätzlich bremst Backoff (Schutz
  vor Raten); Erfolg setzt den Zähler zurück.
- Direktverbindungen merken sich den Fingerabdruck (`~/.ptt/known_hosts`)
  und brechen bei Änderung ab; bei Suche wird gegen die Ankündigung
  geprüft. Details und Updates in `SECURITY.md`.
- Die Host-Suche per Broadcast vertraut dem lokalen Netz: Für ein
  normales Heim-WLAN passt das. In **fremden/unsicheren Netzen**
  lieber `--token` mit langem Geheimnis nutzen und den Fingerabdruck
  manuell vergleichen.
- PIN/Token nie in Screenshots/Chats teilen, außer mit demjenigen,
  der sich verbinden soll.
- `--token` steht in `ps` und Shell-History: für Skripte `PTT_TOKEN` oder
  `--token-file` nutzen (Warnung erfolgt automatisch).

## Exit-Codes

| Code | Bedeutung | Beispiel |
|---|---|---|
| 0 | Erfolg | Shell normal beendet, Transfer ok, `scan` (auch ohne Treffer) |
| 1 | Fehler | keine Verbindung, Zugriff verweigert, Host ausgelastet, Transfer gescheitert, Fingerabdruck falsch |
| 2 | Fehlgebrauch | falsche Optionen, `exec` ohne Befehl, Befehl zu lang |
| 124 | Zeitlimit | `--timeout` abgelaufen (connect/exec/Transfer) oder Sitzung wegen Inaktivität beendet (wie `timeout(1)`) |
| sonstige (nur `exec`) | Code des Remote-Programms | `exit 3` → 3; 127 = unbekanntes Programm; 128+N = Tod durch Signal N (z. B. SIGTERM → 143, wie ssh) |
| 130 | Abgebrochen | Strg+C |

Bei mehreren Transfers (`--put`/`--get` wiederholt) ist der Code 1,
sobald mindestens ein Transfer scheitert (der Rest läuft trotzdem).

## Diagnose

Bei Problemen zuerst die Umgebung prüfen — jede Prüfung meldet
`OK`, `WARN` oder `FAIL`, und unter WARN/FAIL steht als
`Hinweis:`-Zeile direkt der nächste Schritt:

```sh
ptt doctor
```

Modi (nicht kombinierbar, außer `--json` mit `--list`/`--check`):

| Befehl | Zweck |
|---|---|
| `ptt doctor --list` | Alle 13 Prüfungen mit ID auflisten |
| `ptt doctor --check net-udp,shell` | Nur diese Prüfungen ausführen |
| `ptt doctor --json` | Maschinenlesbar (`checks` mit `id`, `title`, `status`, `message`, `hint`) |
| `ptt doctor --fix [--dry-run]` | Sichere Befunde reparieren (Dateirechte; Vorschau mit `--dry-run`) |
| `ptt doctor --self-test` | Ende-zu-Ende-Test: Test-Zertifikat, exec, Upload, Download (Loopback, ohne `~/.ptt`) |
| `ptt doctor --report [DATEI]` | Redigierter Markdown-Bericht für Support-Anfragen (stdout oder Datei) |

Exit-Codes: `0` = kein FAIL (auch bei Warnungen), `1` = mindestens
ein FAIL, `2` = Fehlgebrauch (z. B. unbekannte Prüf-ID).

Der `--report` ist zum Weitergeben gedacht: Heimverzeichnis wird zu
`~`, LAN-IP-Adressen zu `<ip>` (Loopback bleibt lesbar). Für
detaillierte Verbindungs-Phasen gibt es zusätzlich `--verbose` bei
`connect`/`exec`/`host` (Zeitstempel nach stderr).

## Fehlerbehebung

| Problem | Lösung |
|---|---|
| Irgendwas geht nicht | Zuerst `ptt doctor` laufen lassen, `Hinweis:`-Zeilen beachten; für Support `ptt doctor --report` anhängen |
| Keine Hosts gefunden | Gleiches WLAN? Läuft `ptt host`? Firewall: UDP 8023 + TCP 8022 frei? Notfalls direkt: `ptt connect <ip>` |
| `Keine Verbindung` / Timeout | WLAN prüfen, `Direkt:`-Zeile im Banner nutzen, Firewall prüfen |
| Windows-Firewall blockt | Einmalig eingehende Regel für Port 8022 erlauben (nur privates Netzwerk) |
| `openssl nicht gefunden` (Host) | `pip install cryptography` als Alternative |
| Fingerabdruck GEÄNDERT | Host neu aufgesetzt? Eintrag aus `~/.ptt/known_hosts` entfernen und erneut versuchen, sonst abbrechen |
| Neu anfangen (Zertifikat/Hosts vergessen) | `ptt reset --dry-run` zur Vorschau, `ptt reset` fragt vorher |
| Kauderwelsch/Umlaute falsch | Terminal auf UTF-8 stellen (Windows Terminal passt meist) |
| Nur eine Sitzung gleichzeitig | Clients werden nacheinander bedient – erst `exit`, dann der Nächste |
| `Host unterstützt keinen Datei-Transfer` | PTT auf dem Host aktualisieren (Transfer gibt es ab 0.8) |
| `Datei zu groß` beim Transfer | Host-Limit `--max-transfer-size` prüfen/erhöhen |
| `Prüfsumme falsch` beim Transfer | Erneut versuchen (Teil wird verworfen, Neustart von vorn); bei Wiederholung Medium/Netz prüfen |
| Alter Teil blockiert Resume | Mit `--fresh` neu starten oder `*.ptt-part` löschen |

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## Einschränkungen (Stand 0.9)

- `exec`-stdin-Weiterleitung braucht Host ≥ 0.9.2 (ältere Hosts
  ignorieren die EOF-Markierung, `cat`-artige Befehle warten dann —
  Abhilfe: `--timeout`)
- Datei-Transfer nur für einzelne Dateien (keine Verzeichnisse,
  keine Wildcards – dafür `--put`/`--get` wiederholen)
- Parallele Sitzungen per `--max-sessions` (Default: 1; volle Hosts melden
  „Host ist ausgelastet")
- Host auf Windows: ohne Pseudo-Terminal, daher nur einfache Befehle
  (kein `vim`/`htop`); Host auf Linux hat keine Einschränkung

## Lizenz

PTT steht unter der European Union Public Licence 1.2 (EUPL-1.2,
Copyright © 2026 PascalIO) — Volltext in `LICENSE`. Kurz: kostenlos
nutzen, ändern und weitergeben; weitergegebene Änderungen bleiben
unter EUPL (oder kompatibler Lizenz) offen. Der deutsche Rechtstext
steht auf der [EUPL-Seite der EU](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12).
