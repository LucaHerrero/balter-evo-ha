![Balter Logo](https://github.com/LucaHerrero/balter-evo-ha/blob/main/logo.png?raw=true)

# Balter EVO – Home Assistant Integration

Inoffizielle Integration für **Balter-EVO-Video-Türsprechanlagen** (Homaxi / Qualvision / Quvii P2P).

Sie öffnet die Tür, liefert das Kamerabild und einen Livestream — der Öffnen-Befehl geht dabei **direkt** über das native P2P-Protokoll der Anlage an die Türstation, nicht über einen Cloud-Dienst. Das Cloud-Konto wird nur gebraucht, um die Geräte zu finden und die wöchentlich wechselnden Geheimnisse abzuholen.

> ### Getestet an einer **Balter EVO 7 WiFi**
>
> Dort läuft die Integration im Alltagsbetrieb: Türöffnen, mehrfaches Öffnen hintereinander, Standbild, Livestream und Clip-Aufnahme.
>
> Das Protokoll selbst wurde aus der Android-App **Balter EVO 2** (`de.balter.evo.two` v1.8) reverse-engineert und byte-genau gegen echte Mitschnitte verifiziert. Weitere EVO-Modelle und baugleiche Homaxi- / Qualvision- / Quvii-Anlagen sprechen dasselbe Protokoll und sollten funktionieren — **getestet sind sie nicht**. Rückmeldungen dazu sind willkommen.

---

## Was du bekommst

| Entität | Was sie tut |
|---|---|
| `button.*` — eine je Türstation | **Live-Bild (90 s)** — startet eine begrenzte Live-Sitzung. Der ausdrückliche „ich will jetzt schauen"-Auslöser; danach ist die Station wieder frei. |
| `lock.*` — ein Eintrag je Türöffner-Relais | Öffnet die Tür. Als Erfolg gilt erst die **Empfangsbestätigung der Türstation**, nicht das bloße Absenden. Danach fällt die Anzeige nach 8 s optisch wieder zu (das Relais ist ohnehin ein Taster). |
| `camera.*` — eine je Türstation | Standbild auf Abruf (60 s zwischengespeichert) und auf Wunsch ein echter Livestream (~11 fps MJPEG). |
| `balter_evo.record_clip` | Nimmt einen kurzen MP4-Clip der Türstation auf. |

Dazu:

- **Automatische Geräteerkennung** — alle im Cloud-Konto gebundenen Türstationen und Schlösser, inklusive eines zweiten Schlosses derselben Station.
- **Keine fest eingebauten Zugangsdaten.** Passwörter, Schlüssel und der Tür-Auth-Code kommen zur Laufzeit aus deinem Konto, die Client-Identität erzeugt die Integration selbst. Kein Telefon, keine App-Registrierung.
- **Erneute Anmeldung** über den Reauth-Dialog von Home Assistant, falls die Cloud die Zugangsdaten einmal abweist.

## Voraussetzungen

- Home Assistant **2025.2.0** oder neuer
- ein **Quvii-Cloud-Konto** (dasselbe wie in der Balter-/Quvii-App) mit der gebundenen Türstation
- **`ffmpeg`** auf dem Home-Assistant-Host — nötig für Standbild, Livestream und Clip. Beim Standard-HA-OS ist es vorhanden. Ohne ffmpeg funktioniert das Türöffnen trotzdem.

## Installation

### Über HACS (empfohlen)

1. HACS → ⋮ → **Benutzerdefinierte Repositories**
2. `https://github.com/LucaHerrero/balter-evo-ha` als Kategorie **Integration** hinzufügen
3. „Balter EVO" herunterladen
4. Home Assistant neu starten

Updates erscheinen danach automatisch in HACS.

### Manuell

`custom_components/balter_evo` aus diesem Repo nach `<config>/custom_components/balter_evo` kopieren und Home Assistant neu starten.

## Einrichtung

**Einstellungen → Geräte & Dienste → Integration hinzufügen → Balter EVO**

Es werden nur **E-Mail und Passwort deines Quvii-Cloud-Kontos** abgefragt — dieselben wie in der App, *nicht* das lokale Gerätepasswort. Alles Weitere findet die Integration selbst.

## Einstellungen

**Einstellungen → Geräte & Dienste → Balter EVO → Konfigurieren**

| Einstellung | Standard | Bedeutung |
|---|---|---|
| **Tür-PIN** | leer | Leer lassen ist der Normalfall: dann wird der in der Cloud hinterlegte Öffnungscode der Station verwendet. Nur eintragen, wenn du bewusst eine abweichende PIN senden willst — eine falsche PIN lehnt die Station **stillschweigend** ab (die Integration warnt im Log, wenn sie den Verdacht erkennt). |
| **Sitzung offen halten** | 10 s | Wie lange die Verbindung zur Türstation nach einem Befehl offen bleibt. In dieser Zeit öffnet ein weiterer Druck sofort. Solange die Verbindung steht, ist die Station für Klingel und Handy-App belegt — also nicht höher setzen als nötig. Bereich 0–60 s; **0 schaltet das Offenhalten ab**. |

Änderungen greifen sofort, die Integration lädt sich dafür selbst neu.

## Kamera und Livestream

Außerhalb eines Streams zeigt die Kamera sparsame Einzel-Standbilder mit 60 s Cache. Das ist Absicht: Jedes Bild belegt kurz die einzige P2P-Sitzung der Anlage.

**Livestream starten:** den Button **Live-Bild (90 s)** drücken, die Live-Ansicht der Kamera öffnen **oder** die Entität einschalten (`camera.turn_on`).
**Stoppen:** Entität ausschalten (`camera.turn_off`) — sonst endet der Stream nach **90 Sekunden** von selbst und gibt die Station wieder frei.

Während einer laufenden Sitzung liefert die Kamera den **unveränderten H.264-Strom an die `stream`-Integration** von Home Assistant (HLS/WebRTC im Browser, ohne Transkodieren). Außerhalb einer Sitzung gibt es bewusst **keine** Stream-Quelle: `stream` und go2rtc öffnen Quellen von sich aus und halten sie offen — mit einer dauerhaft verfügbaren URL würden sie den einzigen P2P-Slot der Station belegen und Klingel wie Handy-App aussperren. Wann eine Sitzung läuft, entscheidet also allein der Button (oder `camera.turn_on`).

> Der Stream beginnt rund 8–10 s nach dem Öffnen: erst der P2P-Handshake, dann sendet das Gerät selbst noch etwa zwei Sekunden nichts.

Ein angefordertes **Türöffnen hat immer Vorrang** und beendet einen laufenden Stream sofort — es übernimmt dessen bereits aufgebaute Verbindung sogar direkt, statt sie wegzuwerfen.

## Videoclip aufnehmen

```yaml
action: balter_evo.record_clip
target:
  entity_id: camera.tuerstation_kamera
data:
  filename: /media/tuerstation.mp4
  seconds: 5
```

Das Zielverzeichnis muss in `allowlist_external_dirs` freigegeben sein.

## Wie das Türöffnen funktioniert

Zwei Eigenschaften der Anlage bestimmen das ganze Verhalten:

**Die Türstation bedient immer nur EINE P2P-Sitzung** — und braucht nach deren Ende 60–90 s Erholung. Ein Versuch, der startet, während sie noch belegt ist, *verlängert* die Belegung. Türöffnen, Standbild und Livestream teilen sich deshalb intern einen Slot mit Mindestabstand, und ein Öffnen verdrängt die anderen beiden.

**Ein Verbindungsaufbau kostet 5–8 Sekunden** (NAT-Check, Cloud-Discovery, MQTT-Signalisierung, UDP-Hole-Punching, Login). Genau deshalb hält die Integration die Sitzung nach einem Befehl offen: Das zweite Öffnen ist dann nur noch ein einzelnes Datenpaket und dauert Millisekunden — so, wie es sich auch in der offiziellen App anfühlt.

Bevor auf einer offen gehaltenen Sitzung ein Befehl abgeht, wird sie mit einem harmlosen Frame geprüft. Erst wenn dessen Quittung kommt, steht fest, dass die Station noch zuhört. Der Öffner-Frame selbst taugt dafür nicht — ein zweiter Versuch würde die Tür zweimal öffnen.

Kommt die Verbindung nicht zustande, meldet die Integration das klar und bittet, **etwa 30 s zu warten und dann nur einmal** erneut zu öffnen. Der Befehl ist in diesem Fall nachweislich nie gesendet worden.

Details zum Protokoll: [`P2P_PROTOCOL.md`](P2P_PROTOCOL.md), Abschnitte 9 und 10.

## Geheimnisse und Identität

Die Integration ermittelt alles Geheime selbst aus deinem Cloud-Konto — nichts davon steht im Code oder muss eingetippt werden:

| Wert | Herkunft | Rotation |
|---|---|---|
| `dynamic_password` | Cloud-Geräteliste, zur Laufzeit (15-min-Cache) | wöchentlich |
| `data_encode_key` | Cloud-Geräteliste, zur Laufzeit | wöchentlich |
| Tür-Auth-Code | `out-auth-code` der Geräteliste (= `SHA256(PIN)`) | mit der PIN |
| MQTT-Zugangsdaten | Discovery-Dienst, pro Client-ID ausgestellt | pro Sitzung |
| Client-ID | wird bei der Einrichtung **selbst erzeugt** (16 Hex) | — |

Die Integration erzeugt bei der Einrichtung eine eigene 16-stellige Client-ID und leitet den installationsspezifischen Schlüssel für die P2P-Signalisierung selbst ab; die KDF der App wurde vollständig aus der nativen Bibliothek reverse-engineert (`qv_kdf.py`). Damit funktioniert die komplette Kette — Cloud-Login, MQTT-Signalisierung und P2P-Login am Gerät — mit einer frei erzeugten ID. **Kein Telefon, keine App, keine Registrierung.**

Weil das Öffnen nicht auf die Cloud warten soll, wird ein gespeichertes Geheimnispaar bis 12 h Alter sofort benutzt; frische Werte werden dabei bis zu 1,5 s abgewartet und sonst im Hintergrund nachgeholt.

## Fehlersuche

<details>
<summary>Ablauf mitlesen</summary>

```yaml
# configuration.yaml
logger:
  default: warning
  logs:
    custom_components.balter_evo: debug
```
</details>

| Symptom | Wahrscheinliche Ursache |
|---|---|
| „Die Türstation ist gerade noch beschäftigt" | Eine vorherige Sitzung läuft noch — Klingel, Handy-App oder ein eigener Stream. Einmal warten, dann **einmal** erneut öffnen. |
| Tür geht auf, HA meldet trotzdem einen Fehler | Sollte seit v0.9.0 nicht mehr vorkommen. Mit Debug-Log melden. |
| Öffnen wird angenommen, aber nichts passiert | Meist eine eingetragene Tür-PIN, die nicht zum Gerät passt. Feld leer lassen. Das Log warnt in diesem Fall. |
| Kein Kamerabild, Türöffnen geht | `ffmpeg` fehlt auf dem HA-Host. |

## Entwicklung

Zwei Regressionstests laufen ohne Türstation und ohne Home Assistant:

```bash
python tools/verify_frames.py     # Frame-Format byte-genau gegen einen Mitschnitt (braucht den pcap)
python tools/verify_sessions.py   # Slot-, Sitzungs- und Öffnen-Logik (22 Prüfungen, ohne Netz)
python tools/verify_media.py      # Medienkette: MJPEG- und MPEG-TS-Ausgang (braucht ffmpeg)
```

`tools/verify_sessions.py` deckt genau die Fälle ab, die sich an echter Hardware kaum provozieren lassen: Übernahme und Ablauf einer offen gehaltenen Sitzung, „genau ein Schliessen" auf jedem Abbauweg, ein verlorenes Prüf-Paket, ein hängender Keepalive-Thread — und dass ein zweites Öffnen wirklich ein neuer Befehl auf einem neuen Byte-Offset ist.

## Versionsgeschichte

Die vollständigen Notizen stehen unter [Releases](https://github.com/LucaHerrero/balter-evo-ha/releases).

| Version | Kurz |
|---|---|
| **0.12.0** | Button **Live-Bild (90 s)** je Türstation; der Livestream steht zusätzlich der `stream`-Integration als H.264 zur Verfügung. Behoben: `-fflags nobuffer` legte ab ffmpeg 9 den kompletten Videoweg still lahm. |
| **0.11.x** | Haltedauer der Sitzung einstellbar (Standard 10 s, 0 = aus); Robustheit: verlorene Pakete verwerfen die Sitzung nicht mehr, sauberes Aufräumen beim Entladen, Netzfehler zur Cloud werden abgefangen. |
| **0.10.0** | Sitzung bleibt nach dem Öffnen stehen → **mehrfaches Öffnen hintereinander**, erstes Öffnen deutlich schneller. Kamerasitzungen werden ans Türöffnen weitergereicht. |
| **0.9.2** | Türöffnen hat Vorrang vor dem Kamerabild; Standbild-Cache auf 60 s. |
| **0.9.0** | Cloud-Sitzung wird erneuert (die Integration funktionierte vorher nur kurz nach der Einrichtung); Türöffnen wird transportseitig quittiert statt auf eine nie kommende App-Antwort zu warten; zweites Schloss erkannt; Reauth-Dialog. |
| **0.8.0** | Live-Videostream (MJPEG über ffmpeg). |
| **0.7.x** | Ein Klick = ein sauberer Verbindungsversuch; klareres Feedback und Bestätigungs-Benachrichtigung beim Öffnen. |
| **0.4.0** | Protokollschicht neu aufgesetzt: App-Frame-Kopf ist 56 Byte, nicht 48 — davor gab es weder Login noch Video noch zuverlässiges Öffnen. |

## Rechtliches

Inoffizielles Projekt, nicht von Balter, Homaxi, Qualvision oder Quvii unterstützt oder geprüft. Das Protokoll wurde durch Analyse der eigenen App und des eigenen Geräts erschlossen. Nutzung auf eigene Verantwortung.

Lizenz: siehe [LICENSE](LICENSE).
