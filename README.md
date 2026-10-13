![Balter Logo](https://github.com/LucaHerrero/balter-evo-ha/blob/main/logo.png?raw=true)

# Balter EVO – Home Assistant Integration

Inoffizielle Integration für **Balter-EVO-Video-Türsprechanlagen** (Homaxi / Qualvision / Quvii).

Türöffnen, Kamerabild und Livestream. Der Öffnen-Befehl geht **direkt** per P2P an die Türstation; das Cloud-Konto dient nur dazu, die Geräte zu finden und die wöchentlich wechselnden Geheimnisse abzuholen.

> **Getestet an einer Balter EVO 7 WiFi.** Andere EVO-Modelle und baugleiche Homaxi-/Qualvision-/Quvii-Anlagen sprechen dasselbe Protokoll und sollten funktionieren — ungetestet, Rückmeldungen willkommen. Das Protokoll wurde aus der Android-App *Balter EVO 2* reverse-engineert.

## Funktionen

| Entität / Dienst | Funktion |
|---|---|
| `lock.*` (je Türöffner-Relais) | Öffnet die Tür. Als Erfolg gilt die Bestätigung der Station, nicht das bloße Absenden. |
| `camera.*` (je Türstation) | Standbild (60 s Cache) und auf Wunsch Livestream (~11 fps MJPEG). |
| `balter_evo.record_clip` | Nimmt einen kurzen MP4-Clip auf. |

Geräte werden automatisch erkannt (inkl. zweitem Schloss derselben Station). Keine fest eingebauten Zugangsdaten, kein Telefon, keine App-Registrierung — die Integration holt alles zur Laufzeit aus deinem Konto und erzeugt ihre Identität selbst.

## Voraussetzungen

- Home Assistant **2025.2.0** oder neuer
- ein **Quvii-Cloud-Konto** (dasselbe wie in der Balter-/Quvii-App) mit gebundener Türstation
- **`ffmpeg`** auf dem HA-Host (für Bild/Stream/Clip; bei HA OS vorhanden). Türöffnen funktioniert auch ohne.

## Installation

**HACS (empfohlen):** HACS → ⋮ → *Benutzerdefinierte Repositories* → `https://github.com/LucaHerrero/balter-evo-ha` als Kategorie **Integration** → „Balter EVO" herunterladen → Home Assistant neu starten. Updates erscheinen danach automatisch.

**Manuell:** `custom_components/balter_evo` aus diesem Repo nach `<config>/custom_components/balter_evo` kopieren → Home Assistant neu starten.

## Einrichtung

**Einstellungen → Geräte & Dienste → Integration hinzufügen → Balter EVO.**

Abgefragt werden nur **E-Mail und Passwort deines Quvii-Kontos** — dieselben wie in der App, *nicht* das lokale Gerätepasswort. Alles Weitere findet die Integration selbst.

## Optionen

**Einstellungen → Geräte & Dienste → Balter EVO → Konfigurieren**

- **Tür-PIN** *(Standard: leer)* — Leer lassen ist der Normalfall; dann wird der in der Cloud hinterlegte Öffnungscode verwendet. Eine falsche PIN lehnt die Station **stillschweigend** ab (das Log warnt bei Verdacht).
- **Sitzung offen halten** *(Standard: 10 s, Bereich 0–60)* — hält die Verbindung nach einem Befehl offen; in dieser Zeit öffnet ein weiterer Druck sofort. Solange sie steht, ist die Station für Klingel und App belegt, also nicht höher setzen als nötig. `0` schaltet es ab.

## Kamera & Livestream

Außerhalb eines Streams liefert die Kamera sparsame Einzelbilder (60 s Cache) — jedes Bild belegt kurz die einzige P2P-Sitzung der Anlage. Stream **starten:** Live-Ansicht öffnen oder `camera.turn_on`. **Stoppen:** `camera.turn_off` (sonst endet er nach 90 s selbst). Ein Türöffnen hat immer Vorrang und übernimmt eine laufende Sitzung.

## Clip aufnehmen

```yaml
action: balter_evo.record_clip
target:
  entity_id: camera.tuerstation_kamera
data:
  filename: /media/tuerstation.mp4
  seconds: 5
```

Das Zielverzeichnis muss in `allowlist_external_dirs` freigegeben sein.

## Wie es funktioniert (kurz)

Die Türstation bedient immer **nur eine P2P-Sitzung** und braucht danach 60–90 s Erholung. Türöffnen, Standbild und Stream teilen sich deshalb intern einen Slot; ein Öffnen verdrängt die anderen beiden. Ein kalter Verbindungsaufbau dauert rund 4 s (Cloud-Signalisierung, UDP-Hole-Punching, Login) — darum hält die Integration die Sitzung kurz offen, sodass ein zweites Öffnen sofort geht, wie in der offiziellen App. Protokolldetails: [`P2P_PROTOCOL.md`](P2P_PROTOCOL.md).

## Fehlersuche

Ablauf mitlesen (`configuration.yaml`):

```yaml
logger:
  logs:
    custom_components.balter_evo: debug
```

| Symptom | Wahrscheinliche Ursache |
|---|---|
| „Die Türstation ist gerade noch beschäftigt" | Eine andere Sitzung läuft (Klingel, App oder Stream). Kurz warten, dann **einmal** erneut öffnen. |
| Öffnen wird angenommen, aber nichts passiert | Meist eine Tür-PIN, die nicht zum Gerät passt — Feld leer lassen. |
| Kein Kamerabild, Türöffnen geht | `ffmpeg` fehlt auf dem HA-Host. |

## Rechtliches

Inoffizielles Projekt, nicht von Balter, Homaxi, Qualvision oder Quvii unterstützt oder geprüft. Das Protokoll wurde durch Analyse der eigenen App und des eigenen Geräts erschlossen. Nutzung auf eigene Verantwortung.

Lizenz: siehe [LICENSE](LICENSE).
