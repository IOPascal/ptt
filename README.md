# PTT – Private Terminal Tunnel

[![CI](https://github.com/IOPascal/ptt/actions/workflows/ci.yml/badge.svg)](https://github.com/IOPascal/ptt/actions/workflows/ci.yml)

PTT öffnet einen verschlüsselten Tunnel, über den du dich im lokalen
Netzwerk (z. B. WLAN) auf das Terminal eines anderen Geräts schalten kannst.

- **`ptt host`** – Tunnel auf diesem Gerät öffnen (gibt das Terminal frei)
- **`ptt connect`** – sich von einem anderen Gerät auf einen offenen Tunnel schalten

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
oder als festes Kommando [installieren](#als-ptt-kommando-installieren)):

**1. Host: Tunnel öffnen** (z. B. auf dem Linux-Rechner)

```sh
cd ptt
./ptt.sh host
```

Der Host zeigt seine PIN im Rahmen, z. B.:

```
╭────────────────────────────────────────────────╮
│ PTT Host - Tunnel offen                        │
│                                                │
│ Name:           wohnzimmer                     │
│ PIN:            482-913                        │
│                                                │
│ Client:         ptt connect → wählen → PIN     │
╰────────────────────────────────────────────────╯
```

**2. Client: verbinden** (z. B. auf dem Windows-PC)

```bat
cd <pfad-zum-ptt-ordner>
ptt connect
```

`ptt connect` findet den Host von selbst – du wählst ihn aus der Liste
und gibst die 6-stellige PIN vom Host-Bildschirm ein. Fertig.
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

# Client: direkt per IP (ohne Suche)
ptt connect 192.168.1.42

# Client: Secret direkt mitgeben (für Skripte)
ptt connect 192.168.1.42 --token 482913

# PTT selbst aktualisieren
ptt update
```

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

Danach überall: `ptt host`, `ptt connect 192.168.1.42`, `ptt update`.

## Sicherheit

- Jede Verbindung ist TLS-verschlüsselt (Zertifikat in `~/.ptt/`,
  wird beim ersten Start erzeugt und wiederverwendet).
- Standard ist die **PIN**: 6-stellig, steht nur auf dem Host-Bildschirm
  und wird nach jeder Sitzung neu erzeugt. Nach 5 falschen Versuchen
  sperrt der Host kurz (Schutz vor Raten).
- Die Host-Suche per Broadcast vertraut dem lokalen Netz: Für ein
  normales Heim-WLAN passt das. In **fremden/unsicheren Netzen**
  lieber `--token` mit langem Geheimnis nutzen und den Fingerabdruck
  manuell vergleichen.
- PIN/Token nie in Screenshots/Chats teilen, außer mit demjenigen,
  der sich verbinden soll.

## Fehlerbehebung

| Problem | Lösung |
|---|---|
| Keine Hosts gefunden | Gleiches WLAN? Läuft `ptt host`? Firewall: UDP 8023 + TCP 8022 frei? Notfalls direkt: `ptt connect <ip>` |
| `Keine Verbindung` / Timeout | WLAN prüfen, `Direkt:`-Zeile im Banner nutzen, Firewall prüfen |
| Windows-Firewall blockt | Einmalig eingehende Regel für Port 8022 erlauben (nur privates Netzwerk) |
| `openssl nicht gefunden` (Host) | `pip install cryptography` als Alternative |
| Kauderwelsch/Umlaute falsch | Terminal auf UTF-8 stellen (Windows Terminal passt meist) |
| Nur eine Sitzung gleichzeitig | v1 nimmt Clients nacheinander an – erst `exit`, dann der Nächste |

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## Einschränkungen (0.2)

- Nur Terminal (kein Datei-Transfer – geplant für später)
- Ein Client gleichzeitig (weitere warten, bis die Sitzung endet)
- Host auf Windows: ohne Pseudo-Terminal, daher nur einfache Befehle
  (kein `vim`/`htop`); Host auf Linux hat keine Einschränkung
