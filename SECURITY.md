# Sicherheit (PTT)

## Vertrauensmodell

- PTT ist für das **eigene Heimnetz (LAN/WLAN)** gedacht. Die Host-Suche per
  Broadcast vertraut dem lokalen Netz: Wer das Netz kontrolliert, kann
  Discovery-Antworten fälschen.
- Jede Sitzung läuft über **TLS** (selbstsigniertes Zertifikat in `~/.ptt/`).
  Da es keine CA-Kette gibt, prüft der Client stattdessen:
  - bei **Suche**: Fingerabdruck gegen die Discovery-Ankündigung (Mismatch →
    Abbruch),
  - bei **Direktverbindung**: Fingerabdruck gegen `known_hosts` (TOFU, ab 0.5.1;
    Änderung → Abbruch).
- In **fremden/unsicheren Netzen**: langes `--token` nutzen und den
  Fingerabdruck manuell mit dem Host-Bildschirm vergleichen.

## PIN und Token

- Standard ist die **PIN**: 6-stellig, steht nur auf dem Host-Bildschirm,
  rotiert nach jeder Sitzung (außer `--pin`/`--token` gesetzt).
- Rate-Limit: 5 Fehlversuche pro IP und 5-Minuten-Fenster, danach Lockout mit
  Wartezeit; zusätzlich exponentielles Backoff (ab 0.5.9). Erfolg setzt
  den Zähler zurück.
- Falsche PIN/Token erscheinen nie in Host-Meldungen (nur Zähler/Lockout).
- Die PIN-Eingabe am Client erfolgt sichtbar (bewusst, zum leichteren
  Abtippen); schulterblick-sichere Umgebung wählen.
- Secrets möglichst **nicht** per CLI-Flag übergeben (sichtbar in `ps` und
  Shell-History): `PTT_TOKEN`-Env oder `--token-file` nutzen (ab 0.5.2).
- PIN/Token nie in Screenshots/Chats teilen, außer mit demjenigen, der sich
  verbinden soll.

## Dateien und Rechte (POSIX)

- `~/.ptt/`: `0o700`; privater Schlüssel und `known_hosts`: `0o600`.
- `ptt reset` (ab 0.11.8) löscht Zertifikat und `known_hosts`
  kontrolliert (Vorschau, Bestätigung, nur bekannte Dateien).

## Updates

- `ptt update` zeigt vor dem Pull die neuen Commits und fragt um Bestätigung
  (ab 0.5.6; `--yes` für Skripte). Bei schmutzigem Arbeitsbaum bricht es ab.

## Lücken melden

- Sicherheitslücken bitte **nicht** als öffentliches Issue melden, sondern
  direkt an den Maintainer (siehe GitHub-Profil des Repos).
