# Lizenz-Entscheidung (PTT 0.11.0)

Stand: Auftakt Linie 0.11.x Release-Reife. Diese Datei bereitet die
Entscheidung vor; sie trifft sie nicht. Die Entscheidung fällt in
0.11.1 — bis dahin bleibt das Repo ohne LICENSE-Datei.

## Ausgangslage

- PTT enthält keinen fremden Code: nur Python-Stdlib plus optionales
  `cryptography` (Laufzeit-Abhängigkeit, nicht vendoriert). Es gibt
  keine fremden Copyright-Vermerke freizuhalten.
- `pyproject.toml` nennt bisher keine Lizenz, es gibt keine
  `LICENSE`-Datei. Ohne gewählte Lizenz gilt: Alle Rechte vorbehalten
  — niemand darf das Repo legal nutzen, forken oder weitergeben.
- PTT ist ein deutsches LAN-Werkzeug für Endnutzer (wird ausgeführt,
  nicht als Bibliothek eingebettet). Das prägt die Auswahl unten.

## Kandidaten

### MIT

- Typ: permissiv (kurz, ~20 Zeilen). Erlaubt fast alles, inkl.
  proprietärer Forks; einzige Pflicht: Copyright-Vermerk behalten.
- Passt, wenn: maximale Verbreitung wichtiger ist als Offenheit von
  Weiterentwicklungen.
- Passt nicht, wenn: Verbesserungen der Community offen bleiben sollen.

### Apache-2.0

- Typ: permissiv mit expliziter Patentklausel. Wie MIT plus Schutz vor
  Patentklagen von Mitwirkenden; Pflicht: Copyright- und Änderungs-
  Vermerke behalten.
- Passt, wenn: Firmen PTT einsetzen/forken sollen (Apache-2.0 ist dort
  Standard) und trotzdem alles erlaubt bleiben soll.
- Passt nicht, wenn: Copyleft gewünscht ist.

### EUPL-1.2 (European Union Public Licence)

- Typ: Copyleft aus der EU, mit **amtlicher deutscher Fassung**.
  Weiterverbreitete Änderungen müssen unter EUPL (oder kompatibler
  Lizenz, inkl. GPLv2/GPLv3) offengelegt werden; rein privater Einsatz
  und unveränderte Weitergabe bleiben frei.
- Passt, wenn: PTT als EU-Projekt mit deutscher UI eine Copyleft-
  Lizenz mit deutschem Rechtstext bekommen soll und Forks offen
  bleiben müssen.
- Passt nicht, wenn: proprietäre Forks erlaubt sein sollen.

### GPLv3

- Typ: starkes Copyleft (FSF). Wie EUPL erzwingt sie offene Forks,
  zusätzlich mit Anti-Tivoization und Patentschutz; es gibt keinen
  amtlichen deutschen Text.
- Passt, wenn: maximale Copyleft-Strenge gewünscht ist und der
  englische Rechtstext ok ist.
- Passt nicht, wenn: ein deutscher Rechtstext oder proprietäre
  Nutzung wichtig ist.

## Vergleich

| Kriterium | MIT | Apache-2.0 | EUPL-1.2 | GPLv3 |
|---|---|---|---|---|
| Proprietäre Forks | ja | ja | nein | nein |
| Patentklausel | nein | ja | ja | ja |
| Deutscher Rechtstext (amtlich) | nein | nein | ja | nein |
| GPL-kompatibel | ja | ja (v3) | ja | — |
| Länge/Komplexität | minimal | mittel | mittel | hoch |

## Empfehlung

**EUPL-1.2**, ersatzweise Apache-2.0.

Begründung: PTT ist ein deutsches Nutzer-Werkzeug ohne kommerzielle
Abhängigkeiten — Copyleft kostet hier wenig (niemand bettet PTT als
Bibliothek ein) und hält Community-Verbesserungen offen. Die EUPL
bringt dafür als einzige Kandidatin einen amtlichen deutschen Text
mit und bleibt GPL-kompatibel. Wer keine Copyleft-Pflicht will,
nimmt Apache-2.0 (permissiv + Patentklausel, Firmen-Standard).

## Entscheidung (in 0.11.1 ausgefüllt)

- [x] Gewählte Lizenz: EUPL-1.2
- [x] Copyright-Inhaber: PascalIO (2026)
- [x] Datum: 2026-10-11

## Was nach der Entscheidung passiert (0.11.1)

1. `LICENSE`-Datei mit dem offiziellen Lizenztext anlegen.
2. Lizenz in `pyproject.toml` eintragen (Feld + Classifier).
3. README-Kapitel „Lizenz“ mit Kurzfassung ergänzen.
4. CHANGELOG-Eintrag 0.11.1 mit der Wahl.
