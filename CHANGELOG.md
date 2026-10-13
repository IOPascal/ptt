# Changelog

Format: Version / Datum / Änderungen. Verhaltensänderungen sind als solche markiert.

## 0.11.13

- CI-Fixes (rot auf Windows/frischen Runnern/3.9): exec-Argv immer POSIX-shlex parsen (Windows verstand POSIX-Quoting falsch, Self-Test-exec Exit 1); Fortschrittsbalken rendert Erst-Update immer (`shown=-inf` statt `0.0`, frische Boots haben kleines monotonic); Future-Import für 3.9-Annotationen in `tests/test_cert.py` plus AST-Guard; Legacy-Stub-Readiness per Event statt TCP-Probe (deterministisch) plus eigenem Junk-Toleranz-Test.

## 0.11.12

- CI-Fix: `License :: ...`-Classifier entfernt (setuptools≥77 verbietet ihn neben SPDX-`license`). Keine Verhaltensänderung.

## 0.11.11

- CI-Fix: `pyproject.toml` nutzt SPDX-String `license = "EUPL-1.2"` (setuptools≥77 lehnt die `{text=...}`-Form ab — CI war rot). Keine Verhaltensänderung.

## 0.11.10

- Abschluss Linie 0.11.x Release-Reife und des Gesamtpakets: Dogfood-Runde grün (Host/Client mit exec/put/get/Batch/scan, Diagnose, reset-Vorschau). Hinweis: `~/.ptt`-Rechte in Sandbox-Umgebungen ggf. einmalig außerhalb per `ptt doctor --fix` korrigieren.

## 0.11.9

- Neu: Upgrade-Pfad unter `docs/UPGRADE.md` (Aktualisieren per `ptt update`/pipx/pip, alle Verhaltensänderungen 0.5.3–0.11.1 mit Handlungsanweisung, `~/.ptt`-Kompatibilität). Keine Verhaltensänderung.

## 0.11.8

- Neu: `ptt reset` löscht eigene PTT-Daten kontrolliert (Zertifikat + `known_hosts` aus `~/.ptt`, nur bekannte Dateien, Symlinks nie): Vorschau, Bestätigung mit Default Nein, `--yes` für Skripte, `--dry-run` für reine Vorschau.

## 0.11.7

- Security-Review: alle SECURITY.md-Aussagen gegen Code geprüft (TLS 1.2 beidseitig, 6-stellige PIN, 5 Versuche/5-Min-Fenster + Backoff, keine Secret-Echos, 0700/0600-Rechte, Update-Vorschau) — ein Befund: `ptt reset` war als „ab 0.11.8“ dokumentiert, existiert aber erst als Plan (kommt in 0.11.8); Referenz korrigiert, dokumentierte Zahlen per Test festgeschrieben. Keine Verhaltensänderung.

## 0.11.6

- Timeout-Review: Selbsttest-Cap 60 s → 90 s (3×20-s-Schritte plus Zertifikat-/Host-Overhead passten nicht ins alte Budget; per Test festgeschrieben). Neu: `docs/TIMEOUTS.md` mit allen Nutzer-Flags und internen Konstanten.

## 0.11.5

- Meldungs-Review: alle Nutzer-Texte deutsch mit Satzzeichen, „Nächster Schritt:“ überall Singular, CLI-Fehlgebrauch ohne Punkt (argparse-Konvention) — ohne Befund, Konventionen jetzt per Guard-Test festgeschrieben. Keine Verhaltensänderung.

## 0.11.4

- Neu: Kompatibilitäts-Matrix unter `docs/KOMPATIBILITAET.md` (getestete Plattformen/Python-Versionen, Protokoll `ptt1`, Feature-Grenzen 0.8/0.9.2, Plattform-Einschränkungen). Keine Verhaltensänderung.

## 0.11.3

- CI-Härtung: CI löst die Paket-Metadaten auf (fängt stale Versionen) und fährt den Live-`doctor --self-test`; Release bricht ab, wenn der Tag nicht zu `__version__` passt. `LICENSE` liegt sdist/wheel bei (`license-files`, Build-Floor setuptools≥77). Keine Verhaltensänderung.

## 0.11.2

- Fix: Paket-Version aus einer Quelle — `pyproject.toml` übernimmt `ptt.__version__` dynamisch (bisher stale `0.2.0`); Guard-Tests verhindern künftiges Auseinanderlaufen. Keine Verhaltensänderung.

## 0.11.1

- Lizenz gewählt: EUPL-1.2 (Copyright © 2026 PascalIO). Neu: `LICENSE` mit offiziellem Lizenztext, Lizenz in `pyproject.toml`, README-Kapitel „Lizenz“, Entscheidung in `docs/LIZENZ-ENTSCHEIDUNG.md` festgehalten. Keine Verhaltensänderung.

## 0.11.0

- Auftakt Linie 0.11.x Release-Reife: Lizenz-Entscheidungsbrief unter `docs/LIZENZ-ENTSCHEIDUNG.md` (Vergleich MIT / Apache-2.0 / EUPL-1.2 / GPLv3 mit Empfehlung). Die Wahl selbst fällt in 0.11.1 — bis dahin keine LICENSE-Datei, keine Verhaltensänderung.

## 0.10.10

- Abschluss Linie 0.10.x Diagnose: README-Kapitel „Diagnose“ (alle doctor-Modi, Hinweise, Exit-Codes), Fehlerbehebung verweist auf `Hinweis:`-Zeilen und `--report`.

## 0.10.9

- Neu: `doctor --report [DATEI]` schreibt einen redigierten Diagnosebericht als Markdown (Version, Plattform, alle Prüfungen mit Hinweisen) nach stdout oder in eine Datei; Heimverzeichnis wird zu `~`, LAN-IP-Adressen zu `<ip>` (Loopback bleibt lesbar). Exit-Code wie `doctor`.

## 0.10.8

- Neu: `doctor --list` zählt alle Prüfungen mit ID auf; `doctor --check ID[,ID...]` führt nur diese aus (unbekannte IDs scheitern mit Exit 2 und gültiger Auswahl). Jede Prüfung trägt einen Hinweis (`hint`): Bei WARN/FAIL zeigt die Textausgabe eine `Hinweis:`-Zeile mit dem nächsten Schritt, `doctor --json` liefert ihn additiv im Feld `hint` mit.

## 0.10.7

- Neu: `doctor --self-test` führt einen Ende-zu-Ende-Selbsttest aus (Test-Zertifikat, exec-Roundtrip, Upload, Download — alles gegen Loopback-Hosts in einem temporären Verzeichnis, ohne `~/.ptt` anzufassen); harte 60-s-Grenze, `--json`-fähig, mit `--fix` nicht kombinierbar.

## 0.10.6

- Neu: doctor-Transfer-Checks `transfer-dir` (Arbeitsverzeichnis beschreibbar, sonst FAIL), `disk-space` (WARN unter 100 MB frei) und `stale-parts` (zählt `.ptt-part`-Resume-Material).

## 0.10.5

- Neu: `doctor --fix` repariert sichere Befunde (Rechte im PTT-Datenverzeichnis: Verzeichnisse 0700, Dateien 0600, ohne Symlinks zu folgen); `--dry-run` zeigt nur die Vorschau. Zweiter Lauf meldet „nichts zu tun“.

## 0.10.4

- Neu: `--verbose` für `connect`/`exec`/`host` schreibt Zeit-Phasen nach stderr (`[+0.12s] TCP verbunden`, TLS, Host-Prüfung, Auth, Modus, Sitzungs-Ende).

## 0.10.3

- Neu: doctor-TLS-Checks `cert-expiry` (Ablaufdatum, WARN unter 30 Tagen und bei Ablauf) und `cert-key` (Zertifikat/Schlüssel ladbar und zusammengehörig, sonst FAIL).

## 0.10.2

- Neu: doctor-Netzwerk-Checks `net-tcp` (TCP-Loopback, FAIL bei Störung) und `net-udp` (UDP-Broadcast sendbar, sonst WARN mit Direkt-Verbindungs-Hinweis).
- Fix: doctor-Port-Probe stürzt bei Socket-Erzeugungsfehlern nicht mehr ab (meldet belegt).

## 0.10.1

- Neu: doctor-Checks als Registry (stabile IDs + Titel); `doctor --json` nennt je Prüfung zusätzlich `id` und `title` (additiv — bestehende Auswertung nach `status`/`message` läuft weiter).

## 0.10.0

- Auftakt Linie 0.10.x (Diagnose): Baseline gesichert, keine Verhaltensänderung.

## 0.9.10

- Abschluss Linie 0.9.x: README-Kapitel „Automatisierung“ (`exec`, stdin, `--quiet`, `--timeout`, Env, `--json`, Exit-Codes, `examples/`), Gesamt-Loopback aller Automatisierungs-Features grün.

## 0.9.9

- Neu: Alt-Gegenstellen-Stabilität nachgewiesen und festgezurrt (keine Verhaltensänderung nötig): `connect`/`exec` gegen ausgelastete (BUSY), schweigsame (Close/Abbruch) und fremde (Müll-Antwort) Hosts scheitern sauber mit Exit 1 ohne Hänger; `--put`/`--get` gegen Hosts ohne Transfer-ALPN melden „keinen Datei-Transfer“; Discovery ignoriert unbekannte Zusatzfelder.

## 0.9.8

- Neu: `examples/` mit fertigen Automatisierungs-Skripten (health-check, fetch-logs, push-files, wait-for-host, scan-inventory) inkl. Kurzdoku.

## 0.9.7

- Neu: `--quiet` für `connect`/`exec` (auch Transfers): Status- und Fehlermeldungen gehen nach stderr, stdout trägt nur Nutzdaten (Remote-Ausgabe) — `out=$(ptt exec h …)` ist direkt weiterverarbeitbar.

## 0.9.6

- Neu: Env-Fallbacks für `connect`/`exec` (Vorrang: CLI > Env > Default; leere Werte zählen als nicht gesetzt; ungültige Werte brechen mit Exit 2 ab): `PTT_HOST` (nur `connect` — bei `exec` mit positionsgebundenem Host und Befehl gäbe es keine eindeutige Auflösung), `PTT_PORT` (auch für `host`), `PTT_TIMEOUT`.

## 0.9.5

- Neu: Exit-Code-Matrix (README): 0 Erfolg, 1 Fehler, 2 Fehlgebrauch, 124 Zeitlimit (wie `timeout(1)`), `exec` reicht den Programm-Code durch, 130 bei Strg+C.
- Verhaltensänderung: abgelaufenes `--timeout` endet mit 124 statt 1 (connect/exec/Transfer, inkl. Transfer-Timeout-Meldung).
- Verhaltensänderung: `exec`-Programm, das durch Signal N stirbt, meldet 128+N (z. B. SIGTERM → 143, wie ssh) statt des umbrochenen Werts.

## 0.9.4

- Neu: `ptt scan` listet Hosts im WLAN ohne zu verbinden (leere Suche ist rc 0); `--json` für `scan` und `doctor` gibt maschinenlesbar aus.

## 0.9.3

- Neu: `--timeout` (Sekunden, 0 = aus) für `connect`/`exec` begrenzt den gesamten Aufruf (Verbinden, Auth, Shell/exec/Transfer); bei Ablauf Meldung + Exit 1. Abgebrochene Transfers behalten ihr `.ptt-part` für Resume.

## 0.9.2

- Neu: `ptt exec` leitet lokales stdin an den Remote-Befehl weiter (`… | ptt exec HOST …`); leeres stdin sendet nur die EOF-Markierung (leerer STDIN-Frame schließt Remote-stdin). Volle Weiterleitung braucht Host ≥ 0.9.2 (ältere Hosts ignorieren die Markierung).

## 0.9.1

- Neu: `ptt exec HOST BEFEHL [ARG …]` führt einen Befehl ohne TTY aus (direkt, ohne Shell; `sh -c` ggf. explizit), Remote-stdout (stderr gemergt) nach stdout, Remote-Exit-Code als Exit-Code. Hello-Typ `EXEC <secret> <argv …>`; gegen alte Hosts kommt sauber DENIED.

## 0.9.0

- Auftakt Linie 0.9.x (Automatisierung & Skript-Modus): Baseline gesichert, keine Verhaltensänderung.

## 0.8.10

- Abschluss Linie 0.8.x: Datei-Transfer in README dokumentiert (Optionen, Resume, Stapel, Fehlerbehebung), Gesamt-Loopback aller Transfer-Features grün.

## 0.8.9

- Neu: `--put`/`--get` sind wiederholbar und kombinierbar (erst alle Uploads, dann alle Downloads; je eine Verbindung, Suche nur einmal, Schluss-Bilanz „n/m Transfers ok").
- Verhaltensänderung: `--put` + `--get` gemeinsam war ein Fehler, läuft jetzt als Stapel; Exit-Code ist 1, sobald mindestens ein Transfer scheitert (Rest läuft trotzdem).

## 0.8.8

- Neu: `connect --fresh` startet Up-/Download von vorn statt fortzusetzen (verwirft lokale und Host-Teil-Dateien).
- Neu: Host räumt beim Start abgebrochene `.ptt-part`-Dateien älter als 24 h aus `--transfer-dir` weg (nur dort, keine Symlinks).

## 0.8.7

- Neu: Automatisches Resume abgebrochener Transfers (Up- und Download): Wiederholen setzt per TREQ/TACK-Offset fort, Client meldet „Setze … fort".
- Verhaltensänderung: Abgebrochene Transfers behalten `.ptt-part` (vorher: gelöscht); nur korrupte/inkonsistente Teile (Prüfsumme, Größe, Pfad) werden verworfen. Chunks werden pro Block geflusht, damit der Resume-Offset nach SIGTERM stimmt. Alte Peers (≤ 0.8.6) ohne Resume-Felder starten sauber bei 0.

## 0.8.6

- Neu: Gehärtete Transfer-Pfade (Windows: ADS-/Laufwerks-/Reserviert-/Punkt-Schutz; Symlink-Escape-Abwehr mit Angriffs-Tests; Client lehnt leere/relative Auto-Ziele ab).

## 0.8.5

- Neu: Sauberer Transfer-Abbruch (Strg+C, Verbindungsabriss, SIGTERM): Teil-Dateien werden gelöscht, Exit-Codes 130/1, Host meldet sauber heruntergefahrene Transfers.

## 0.8.4

- Neu: `--max-transfer-size` (z. B. `100M`, 0 = aus) begrenzt einzelne Transfer-Dateien; `--idle-timeout`/`--max-session` gelten auch für Transfer-Verbindungen.

## 0.8.3

- Neu: Fortschrittsbalken mit Rate bei Up-/Download (nur im Terminal, gedrosselt).

## 0.8.2

- Neu: Datei-Download per `connect --get REMOTE[:LOKAL]` (SHA-256-geprüft, atomar, Verzeichnis als Ziel möglich).

## 0.8.1

- Neu: Datei-Upload per `connect --put DATEI[:NAME]` (SHA-256-geprüft, atomar via `.ptt-part`, Ziel `--transfer-dir`, Default: Arbeitsverzeichnis).

## 0.8.0

- Neu (Grundlage, noch ohne Funktion): Transfer-Modus per TLS-ALPN (`ptt1-transfer`), TREQ/TACK-Codecs in neuem Modul `ptt/transfer.py`; alte Peers verhandeln nichts, Clients erkennen das sauber.

## 0.7.10

- Abschluss Linie 0.7.x: Sitzungs-Optionen in README dokumentiert, Gesamt-Loopback aller Sitzungs-Features grün.

## 0.7.9

- Neu: `connect --retry N --retry-delay S` wiederholt Verbindungsversuche mit exponentiellem Backoff (Default: keine Wiederholung).

## 0.7.8

- Neu: Sitzungszähler im Host-Log („N aktiv, M gesamt" pro beendeter Sitzung, Limit beim Start).

## 0.7.7

- Neu: Discovery-Ankündigung meldet Belegung (`busy`); belegte Hosts werden in der Auswahl als „belegt" markiert.

## 0.7.6

- Neu: TCP-Keepalive (60 s/10 s, wo einstellbar) auf beiden Seiten; tote Verbindungen werden erkannt und beendet.

## 0.7.5

- Neu: `--max-sessions N` begrenzt parallele Sitzungen (Default 1, 0 = unbegrenzt).
- Neu: Herunterfahren beendet auch parallele Sitzungen sauber (EXIT-Frame, 2. Strg+C bricht ab).
- Verhaltensänderung: Ein zweiter Client wird bei vollem Host sofort mit „Host ist ausgelastet" abgewiesen (bisher: stilles Warten); Sitzungen laufen in Threads.

## 0.7.4

- Neu: Sitzungs-Bilanz im Host-Log (Dauer, Bytes up/down).

## 0.7.3

- Neu: SIGTERM beendet den Host sauber (Sitzung + Listener, Exit-Code 0).
- Neu: Zweites Strg+C während des Herunterfahrens bricht sofort ab (Exit-Code 130).

## 0.7.2

- Neu: `--max-session` (Minuten, 0 = aus) begrenzt die Sitzungsdauer (Exit-Code 124).

## 0.7.1

- Neu: `--idle-timeout` (Minuten, 0 = aus) beendet untätige Sitzungen mit Exit-Code 124; Pipes-Modus gibt die Shell bei Sitzungsende frei.

## 0.7.0

- Auftakt Linie 0.7.x (Sitzungs-Steuerung): Timeouts, Limits, Retry, Keepalive. Baseline grün.

## 0.6.10

- Abschluss: Regression (Tests, Starter-Skripte, `doctor`, Loopback) bestanden. Linie 0.6.x abgeschlossen.
- Fix aus der Regression: nicht beschreibbares `known_hosts` warnt statt abzustürzen.

## 0.6.9

- Farben: `connect` hat `--color`, Client-Meldungen nutzen die Marker aus `output` (`NO_COLOR` gilt überall).

## 0.6.8

- Banner zeigt die Shell-Zeile (`doctor` zeigt die Standardshell seit 0.6.6).

## 0.6.7

- README: Schnellstart gekürzt (`doctor` zuerst), Troubleshooting + Optionen aktualisiert, alle Beispiele gegen `--help` geprüft.

## 0.6.6

- Neu: `ptt doctor` prüft Python, TLS-Werkzeuge, Zertifikat, Ports und Shell (OK/WARN/FAIL + Exit-Code).

## 0.6.5

- Client: leere Suche fragt nach (erneut/IP/abbrechen, max 3 Runden) statt sofort zu scheitern.

## 0.6.4

- Client: Such-Fortschritt + Verbindungsphasen; **Verhaltensänderung:** Strg+C → „Abgebrochen." mit Exit 130 (Exit-Codes in README dokumentiert).

## 0.6.3

- Banner: Direkt-Zeilen kompakt (alle bis 3 IPs, sonst erste + „+N weitere").

## 0.6.2

- Fehlertexte: „Nächster Schritt"-Hinweise bei Verbindungs-/TLS-/Auth-/Suchfehlern; fehlendes openssl endet mit Exit 1 statt Traceback.

## 0.6.1

- Hilfe: Beispiele im `--help`-Epilog, Subkommando-Beschreibungen (Suche vs. Direkt bei `connect`).

## 0.6.0

- Auftakt Linie 0.6.x (Nutzer-Verbesserung): Hilfetexte, Fehlermeldungen, Banner, `doctor`. Baseline grün.

## 0.5.10

- Review: 0.5.x gegen `SECURITY.md` geprüft; README-Sicherheitskapitel und Rate-Limit-Doku aktualisiert. Linie 0.5.x abgeschlossen.

## 0.5.9

- Auth: exponentielles Backoff pro IP (1s/2s/4s… max 30s + Jitter); Erfolg setzt Fehlzähler zurück.

## 0.5.8

- Rechte: zentrale `secure_write`/`ensure_data_dir`-Helfer (Key/`known_hosts` 0600, Cert 0644, Dir 0700, bestehende Dirs nachgezogen).

## 0.5.7

- Audit: keine Secrets in Logs/Fehlermeldungen (Ausnahmen Banner + PIN-Echo dokumentiert); DENIED-Hygiene per Test fixiert.

## 0.5.6

- **Verhaltensänderung:** `ptt update` zeigt neue Commits/Befehl und fragt um Bestätigung (`--yes` für Skripte).

## 0.5.5

- Discovery: Auswahlliste zeigt Kurz-Fingerabdruck + Auth-Kind + LAN-Hinweis.

## 0.5.4

- TLS: Minimum 1.2 (Host+Client, zentrale Kontext-Helfer); Zertifikat mit SAN und 397 Tagen Laufzeit (vorher nur CN, 825 Tage).

## 0.5.3

- **Verhaltensänderung:** `--pin` braucht 6–12 Ziffern (vorher 4–12); Client-Prompt folgt.
- Host warnt bei `--token` kürzer als 16 Zeichen (Client-PINs nicht betroffen).

## 0.5.2

- Secrets: `PTT_TOKEN`-Env und `--token-file` für Host/Client (Flag > Env > Datei > interaktiv); Warnung bei `--token` per CLI.

## 0.5.1

- Sicherheit: TOFU-`known_hosts` bei Direktverbindung (neu → speichern, geändert → Abbruch). Discovery-Fall unverändert.

## 0.5.0

- Auftakt Linie 0.5.x (Sicherheit): `SECURITY.md` mit Vertrauensmodell angelegt. Baseline grün.

## 0.4.10

- Audit: Sockets/Timeouts/`select`-Loops geprüft; `_serve_pipes` schließt Pipes explizit; Pipes-Pfad per Test abgedeckt. Linie 0.4.x abgeschlossen.

## 0.4.9

- Update: Abbruch bei schmutzigem Arbeitsbaum (mit Hinweis); 120-s-Timeout für Pull/pip.

## 0.4.8

- Zertifikat: vorhandene PEMs werden validiert (defekt/unvollständig → neu mit Hinweis); `~/.ptt` 0o700, Schreiben atomar.

## 0.4.7

- Client: TTY-/Netz-/Eingabefehler enden mit Meldung + Exit-Code statt Traceback (`_run_unix`, `_read_loop`, Prompts).

## 0.4.6

- Host: Bind-Fehler enden mit Hinweis + Exit 1 statt Traceback; Sitzungs-Schreibfehler (EPIPE/Broken-Pipe) als sauberes Ende verifiziert.

## 0.4.5

- Discovery: Fingerprint-Längenlimit, Steuerzeichen aus Namen entfernt, max 64 Einträge.

## 0.4.4

- Protokoll: unbekannte Frame-Typen erkannt (`UnknownFrameError`), Abbruch ab 10 pro Verbindung; `recv_line` toleriert CRLF.

## 0.4.3

- Validierung: `--port` auf 1–65535 begrenzt, `--pin` auf 4–12 Ziffern, `--shell` wird auf Ausführbarkeit geprüft (Abbruch mit klarer Meldung).

## 0.4.2

- Host: TLS-Handshake mit `AUTH_TIMEOUT`-Budget (Slowloris-Schutz); eigene Timeout-Meldung.

## 0.4.1

- Host: Rate-Limit pro IP statt global (kein Fremd-DoS); Lockout-Meldung nennt Wartezeit.

## 0.4.0

- Auftakt Linie 0.4.x (Härtung): Schwerpunkte Rate-Limit, Timeouts, Validierung, Fehlerpfade. Baseline grün.

## 0.3.10

- Konsistenz: Type-Hints in `protocol.py`/`discover.py` vervollständigt (`auth.py` war vollständig), Future-Imports und ungenutzte Imports geprüft. Linie 0.3.x abgeschlossen.

## 0.3.9

- Zertifikat: gemeinsame `_write_private_key`/`_write_cert`/`_chmod_private_key`-Helfer für beide Generator-Pfade.

## 0.3.8

- Update: gemeinsamer `_run_git`-Helfer für alle Git-Aufrufe.

## 0.3.7

- Discovery: `_sorted_hosts`-Helfer statt Closure, Deadline auf `time.monotonic()`.

## 0.3.6

- Ausgabe: Farb-/Marker-Helfer in neuem `ptt/output.py`; `ptt.host.use_color` bleibt eine Linie als deprecated Re-Export.

## 0.3.5

- CLI: gemeinsame `--port`-Definition, vollständigere Hilfetexte, `tests/test_cli.py` neu.

## 0.3.4

- Host: gemeinsamer `_start_session_reader`-Helfer und `READER_JOIN_TIMEOUT` für beide Sitzungs-Modi.

## 0.3.3

- Protokoll: neuer `send_exit`-Helfer; Host nutzt ihn an beiden Sendestellen.

## 0.3.2

- Client: doppelte Reader-Threads (`_run_unix`/`_run_windows`) nutzen gemeinsamen `_read_loop`.

## 0.3.1

- Tests: gemeinsame Helfer in `tests/helpers.py` (Ports, TLS-Connect, `echo_and_exit`); Duplikate in `test_integration.py`/`test_discover.py` entfernt.

## 0.3.0

- Auftakt Linie 0.3.x (Vereinfachung): CHANGELOG angelegt, Baseline gesichert.
- Baseline: `python -m compileall -q ptt tests` und `python -m unittest discover -s tests -v` grün.
