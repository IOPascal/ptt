# Upgrade-Pfad (PTT 0.11.9)

## Wie aktualisieren

- Aus Checkout: `ptt update` (zeigt erst die Änderung, fragt um
  Bestätigung; `--yes` für Skripte).
- Installiert: `pipx upgrade ptt-private-terminal-tunnel` bzw.
  `pip install -U ptt-private-terminal-tunnel`.
- Danach: `ptt --version` und `ptt doctor` (sollte keine FAIL zeigen).

## Grundregeln

- **Host und Client gemeinsam** aktualisieren (Feature-Grenzen:
  Transfer ab Host 0.8, exec-stdin ab Host 0.9.2 — s.
  `docs/KOMPATIBILITAET.md`).
- `~/.ptt` bleibt kompatibel: Zertifikat wird wiederverwendet,
  `known_hosts` bleibt gültig. Notfalls neu anfangen: `ptt reset`.
- Skripte prüfen: Exit-Codes unten haben sich teils geändert.

## Verhaltensänderungen (aufsteigend)

| Ab | Änderung | Zu tun |
|---|---|---|
| 0.5.3 | `--pin` braucht 6–12 Ziffern (vorher 4–12) | 4-stellige PINs ersetzen |
| 0.5.6 | `ptt update` fragt um Bestätigung | Skripte: `--yes` ergänzen |
| 0.6.4 | Strg+C endet mit Exit 130 („Abgebrochen.“) | Exit-Auswertung anpassen |
| 0.7.5 | Voller Host weist sofort ab („Host ist ausgelastet“) statt zu warten | Wiederhol-Logik ggf. selbst bauen (`--retry`) |
| 0.8.7 | Abgebrochene Transfers behalten `.ptt-part` (Resume) | Reste ggf. löschen oder `--fresh` nutzen |
| 0.8.9 | `--put` + `--get` gemeinsam = Stapel (vorher Fehler); Exit 1 bei Teilfehler | Fehlerzweig entfernen, Teilfehler auswerten |
| 0.9.5 | `--timeout`-Ablauf endet mit 124 statt 1 | Exit-Auswertung anpassen |
| 0.9.5 | Signal-Tod meldet 128+N (wie ssh) statt Umbruch | Exit-Auswertung anpassen |
| 0.9.6 | `PTT_HOST` gilt nur für `connect` (bei `exec` kein Env-Host) | `exec` immer mit positionsgebundenem Host aufrufen |
| 0.11.1 | Lizenz: EUPL-1.2 (vorher: keine Lizenz gewählt) | Weiterverbreitung unter EUPL |

Additiv (nichts zu tun): `doctor --json` kennt `id`/`title`/`hint`,
neue doctor-Checks und `--fix`/`--self-test`/`--report`, `ptt reset`.
