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

**1. Auf diesem Gerät (Host): Tunnel öffnen**

```sh
cd ptt
python3 -m ptt host
```

Der Host zeigt dann alles, was der Client braucht:

```
=== PTT Host (Tunnel offen) ===
Port:          8022
Connect:       python -m ptt connect 192.168.1.42 --port 8022
Token:         3fa2-9c1d-77b0-e4f5
Fingerabdruck: SHA256:AA:BB:CC:...
==============================
```

**2. Auf dem Windows-PC (Client): verbinden**

```bat
cd <pfad-zum-ptt-ordner>
py -m ptt connect 192.168.1.42
```

Token vom Host eingeben, Fingerabdruck vergleichen – fertig.
Beenden mit `exit` in der Remote-Shell.

> Tipp: Den `ptt`-Ordner einfach per USB-Stick, Netzwerkfreigabe
> oder `git clone` auf den Windows-PC kopieren.

## Optionen

```sh
# Host: eigener Port, eigene Shell, festes Token
python3 -m ptt host --port 8022 --shell /bin/bash --token mein-token

# Host: nach einer Sitzung automatisch beenden
python3 -m ptt host --once

# Host: Farbausgabe steuern (auto/always/never, Default: auto)
python3 -m ptt host --color always

# Client: Token direkt mitgeben (für Skripte)
python -m ptt connect 192.168.1.42 --token 3fa2-9c1d-77b0-e4f5
```

Als installierter Befehl (optional):

```sh
pip install -e .
ptt host
ptt connect 192.168.1.42
```

## Sicherheit

- Jede Verbindung ist TLS-verschlüsselt (Zertifikat in `~/.ptt/`,
  wird beim ersten Start erzeugt und wiederverwendet).
- Ohne das Token weist der Host jede Verbindung ab.
- Beim Verbinden zeigt der Client den **Fingerabdruck** des Hosts –
  mit der Anzeige auf dem Host vergleichen (schützt vor Geräten,
  die sich im WLAN als der Host ausgeben).
- Token nie in Screenshots/Chats teilen, außer mit demjenigen,
  der sich verbinden soll.

## Fehlerbehebung

| Problem | Lösung |
|---|---|
| `Keine Verbindung` / Timeout | WLAN prüfen, IP im `Connect:`-Hinweis nutzen, Firewall prüfen |
| Windows-Firewall blockt | Einmalig eingehende Regel für Port 8022 erlauben (nur privates Netzwerk) |
| `openssl nicht gefunden` (Host) | `pip install cryptography` als Alternative |
| Kauderwelsch/Umlaute falsch | Terminal auf UTF-8 stellen (Windows Terminal passt meist) |
| Nur eine Sitzung gleichzeitig | v1 nimmt Clients nacheinander an – erst `exit`, dann der Nächste |

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## Einschränkungen (v1)

- Nur Terminal (kein Datei-Transfer – geplant für v2)
- Ein Client gleichzeitig (weitere warten, bis die Sitzung endet)
- Host auf Windows: ohne Pseudo-Terminal, daher nur einfache Befehle
  (kein `vim`/`htop`); Host auf Linux hat keine Einschränkung
