![Balter Logo](https://github.com/LucaHerrero/balter-evo-ha/blob/main/logo.png?raw=true)

# Balter EVO (Quvii Cloud / P2P) – Home Assistant Integration

Inoffizielle Home-Assistant-Integration für die **Balter EVO 2** Video-Türsprechanlage (und kompatible Homaxi / Qualvision / Quvii P2P-Systeme).

---

### Neu in v0.11.0 — Haltedauer der Sitzung einstellbar

Die in v0.10.0 eingeführte offen gehaltene Sitzung lässt sich jetzt unter **Konfigurieren → „Sitzung offen halten"** einstellen. **Der Standard sinkt von 30 s auf 10 s** — das deckt das Öffnen hintereinander ab, ohne die Türstation länger als nötig für Klingel und Handy-App zu belegen.

- Bereich 0–60 Sekunden. **0 schaltet das Offenhalten ab** (Verhalten wie vor v0.10.0: jedes Öffnen baut die Verbindung komplett neu auf).
- Gilt für alle P2P-Kommandos, also auch für die Übergabe einer laufenden Kamerasitzung ans Türöffnen.
- Bestehende Installationen übernehmen automatisch die 10 s; ein Neueinrichten ist nicht nötig.

### Neu in v0.10.0 — schnelleres Türöffnen, mehrfaches Öffnen hintereinander

Die Türstation bedient nur **eine** P2P-Sitzung und braucht nach deren Ende 60–90 s Erholung. Bisher baute jedes Kommando eine eigene Sitzung auf und riss sie wieder ab: ein Öffnen kostete ~7,7 s, ein zweites kurz danach lief in den Mindestabstand von 30 s und scheiterte als „Station besetzt". Die offizielle App hat das Problem nicht, weil sie gar nicht neu verbindet.

- **Die Sitzung bleibt nach dem Öffnen stehen** und bedient das nächste Kommando in Millisekunden. Davor geht ein harmloser Setup-Frame raus; erst dessen Quittung beweist, dass das Gerät noch zuhört — der Öffner-Frame taugt dafür nicht, ein zweiter Versuch würde die Tür zweimal öffnen.
- **Snapshot und Livestream übergeben ihre eingeloggte Sitzung** an ein wartendes Türöffnen, statt sie zu schließen.
- **Das Öffnen wartet nicht mehr auf die Cloud:** ein gespeichertes Geheimnispaar bis 12 h Alter wird sofort benutzt und im Hintergrund aufgefrischt (sie rotieren wöchentlich).
- NAT-Check läuft parallel zur Cloud-Signalisierung, die Discovery-Antwort wird 30 min zwischengespeichert, der Erholungsabstand gilt pro Gerät statt pro Prozess.

### Neu in v0.9.2 — Türöffnen hat Vorrang vor dem Kamerabild

Die Türstation bedient immer nur **eine** P2P-Sitzung. Der häufigste Ablauf — es klingelt, man schaut das Kamerabild an und öffnet dann — lief damit genau in die Blockade: Der Livestream hielt den Slot bis zu 90 Sekunden, das Türöffnen wartete stumm darauf und scheiterte danach scheinbar grundlos an einer „besetzten" Station.

- **Ein angefordertes Türöffnen beendet einen laufenden Livestream sofort** und übernimmt den Slot.
- **Standbild-Cache 15 s → 60 s.** Der alte Wert lag unter dem Slot-Zyklus (30 s Mindestabstand + ~10 s pro Snapshot): Ein offenes Dashboard hielt die Türstation dadurch dauerhaft belegt — auch für die Klingel und die Handy-App.
- Wer den Slot hält, steht jetzt im Log (`Door unlock` / `Live stream` / `Snapshot`), samt Wartezeit.

### Neu in v0.9.0 — Fehlerbehebungen und Anpassung an die HA-Richtlinien

**Behoben — die Integration funktionierte bisher nur kurz nach der Einrichtung:**
Die Quvii-Cloud lässt eine Sitzung nur wenige Minuten leben. Lief sie ab, wurde sie nie erneuert; das Gerätepasswort blieb leer, und die Türstation lehnte den P2P-Login stillschweigend ab — in der Oberfläche sah das wie eine besetzte Station aus. Die Sitzung wird jetzt automatisch erneuert.

**Behoben — die Tür ging auf, Home Assistant meldete trotzdem einen Fehler:**
Auf eine App-Quittung für das Türöffnen zu warten war aussichtslos, denn das Gerät sendet keine. Quittiert wird transportseitig. Nebenwirkung des alten Verhaltens: die vermeintlichen Wiederholungen gingen als **neue** Befehle raus — die Tür konnte dreimal öffnen. Und weil die Sitzung bis zum Timeout offen blieb, scheiterte jeder Folgeversuch.

Weiter:

- **Zweites Schloss** einer Türstation wird jetzt erkannt (die Cloud meldet Codes als `lock_chn1 1`, nicht als `door1-lock1`).
- **Erneute Anmeldung:** Weist die Cloud die Zugangsdaten ab, bietet Home Assistant jetzt einen Reauth-Dialog an, statt die Integration nur scheitern zu lassen.
- **Signalisierungs-ID entfernt:** Das Feld war überflüssig — eine selbst erzeugte ID funktioniert durchgängig. Bestehende Einträge werden automatisch bereinigt.
- **Diagnose:** Eine Tür-PIN, die nicht zum Gerät passt, wird jetzt im Log gemeldet statt still zu scheitern.
- Log-Ausgaben folgen den HA-Konventionen: der Protokollablauf liegt auf `debug`, `warning`/`error` bleiben echten Problemen vorbehalten.

<details>
<summary>Ablauf mitlesen (Fehlersuche)</summary>

```yaml
# configuration.yaml
logger:
  default: warning
  logs:
    custom_components.balter_evo: debug
```
</details>

### Neu in v0.8.0 — Live-Videostream (Start/Stop)

Die Kamera liefert jetzt einen **echten Live-Stream** (~11 fps MJPEG), nicht nur Standbilder. Der H.264-P2P-Strom wird live über `ffmpeg` transkodiert.

- **Start:** Kamera-Live-Ansicht öffnen **oder** die Entität einschalten (`camera.turn_on`).
- **Stop:** Entität ausschalten (`camera.turn_off`) — sonst endet der Stream automatisch nach **90 Sekunden** und gibt die P2P-Sitzung wieder frei, damit die Türstation für andere Bewohner/die Klingel frei bleibt.
- Außerhalb eines Streams zeigt die Kamera weiterhin sparsame Einzel-Standbilder.

> Der Stream startet erst ~8–10 s nach dem Öffnen (P2P-Handshake + das Gerät beginnt erst ~2 s nach dem Login zu senden). `ffmpeg` muss auf dem HA-Host installiert sein.

### Neu in v0.7.1 — zuverlässigerer Verbindungsaufbau

Live-Mitschnitte zeigen: Die Türstation bedient immer nur **eine** P2P-Sitzung und braucht danach Erholung. Jeder Versuch, der startet, während sie noch belegt ist, verlängert die Belegung — schnelles, wiederholtes Öffnen senkt die Erfolgsquote also, statt sie zu erhöhen.

Darum jetzt:

- **Ein Klick = genau ein sauberer Verbindungsversuch** (kein internes Hämmern mehr).
- **Mindestabstand zwischen Sitzungen 20 s → 30 s**, damit sich die Station erholen kann.
- Klappt der Aufbau nicht, kommt sofort der Hinweis, **~30 s zu warten und dann nur einmal** erneut zu öffnen.
- Das Öffnen selbst ist zuverlässig, **sobald** die Verbindung steht.

### Neu in v0.7.0 — klareres Feedback beim Türöffnen

Das Öffnen wird erst an der **echten Gerätequittung** als Erfolg gewertet.

Für alle, die aus der Ferne öffnen und den Summer nicht hören können, gibt es jetzt eine kurze **Bestätigungs-Benachrichtigung**, und der `lock` bleibt sichtbar länger auf „entsperrt“, bevor er optisch wieder zufällt.

Startet die Türstation die P2P-Sitzung nicht (weil sie noch mit einer vorherigen Sitzung beschäftigt ist), erscheint jetzt ein klarer Hinweis, ~20–30 s zu warten — statt einer generischen Fehlermeldung.

Der Befehl wird in diesem Fall nachweislich **nie** gesendet, ein erneuter Versuch öffnet die Tür also nicht doppelt.

---

## ✨ Features

- ✅ **Cloud-Login & automatische Geräteerkennung:** Liest alle gebundenen Türstationen und Schlösser aus dem Quvii-Cloud-Konto aus.
- ✅ **P2P Türöffner (`lock`):** Öffnet die Tür direkt über das native P2P-UDP/KCP-Protokoll. Als Erfolg gilt erst die **Empfangsbestätigung der Türstation** auf der Transportschicht, nicht das bloße Absenden.
- ✅ **On-Demand Kamera-Snapshot (`camera`):** Live-Bild aus dem H.264-P2P-Strom; die Session wird sofort wieder freigegeben, damit die Anlage für andere Bewohner frei bleibt.
- 🎬 **Videoclip-Service:** `balter_evo.record_clip` nimmt einen kurzen MP4-Clip der Türstation auf (benötigt `ffmpeg` auf dem HA-Host).
- 🔑 **Ermittelt seine Geheimnisse selbst:** Rotierende Passwörter, Verschlüsselungs-Keys und der Tür-Auth-Code kommen zur Laufzeit aus dem Cloud-Konto. Die Client-Identität und der Signalisierungs-Schlüssel werden von der Integration selbst erzeugt bzw. berechnet — keine Registrierung und kein Telefon nötig.
- ✅ **Keine Hardcoded-Credentials:** Alle Passwörter, Tokens und Keys werden dynamisch bezogen. Ohne konfigurierte PIN wird der `out-auth-code` der Geräteliste verwendet.

### Neu in v0.4.0 — Protokollschicht neu aufgesetzt

Der App-Frame-Kopf ist **56 Byte**, nicht 48. Alle bisherigen Versionen sendeten einen 8 Byte zu kurzen Kopf: Der Transport quittierte weiter, die App-Schicht des Geräts verwarf aber jeden Frame — kein Login, kein Video, kein zuverlässiges Türöffnen.

Alle Frames sind jetzt byte-genau gegen einen echten App-Mitschnitt verifiziert (`tools/verify_frames.py`, 12/12).

Weitere behobene Fehler:

- fehlende Quittung für Fortsetzungspakete (der Videostrom blieb nach ~8 kB stehen)
- ARQ-Retransmits am falschen Byte-Offset (Handshake blieb hängen)
- zu früh gesendetes `OPENDOOR` (vor der Freigabe der App-Session)
- Kandidatenauswahl beim Dekodieren, die nach Länge statt nach Dekodierbarkeit ging

Details: [`P2P_PROTOCOL.md`](P2P_PROTOCOL.md), Abschnitt 9 und 10.

> **Hinweis zum Verhalten:** Die Türstation verträgt keine parallelen oder dicht aufeinanderfolgenden P2P-Sitzungen. Snapshot und Türöffner teilen sich deshalb intern einen Slot mit 30 s Mindestabstand. Ein hängengebliebener Handshake wird automatisch wiederholt — beim Türöffner allerdings **nur**, solange der Befehl nachweislich noch nicht gesendet wurde.

---

## 🔑 Geheimnisse & Identität

Die Integration ermittelt alles Geheime selbst aus deinem Cloud-Konto — nichts davon steht im Code oder muss eingetippt werden:

| Wert | Herkunft | Rotation |
|---|---|---|
| `dynamic_password` | Cloud-Geräteliste, zur Laufzeit (15-min-Cache) | wöchentlich |
| `data_encode_key` | Cloud-Geräteliste, zur Laufzeit | wöchentlich |
| Tür-Auth-Code | `out-auth-code` der Geräteliste (= `SHA256(PIN)`) | mit der PIN |
| MQTT-Zugangsdaten | Discovery-Dienst, pro Client-ID ausgestellt | pro Sitzung |
| Client-ID | wird bei der Einrichtung **selbst erzeugt** (16 Hex) | — |

Die Tür-PIN ist deshalb **optional**: Ohne Eingabe wird der Auth-Code aus der Geräteliste verwendet.

### Selbst erzeugte Identität — keine Registrierung nötig

Die Integration erzeugt bei der Einrichtung eine eigene 16-stellige Client-ID und leitet den installationsspezifischen Schlüssel für die P2P-Signalisierung **selbst ab**. Die KDF der App wurde vollständig aus der nativen Lib reverse-engineert (`qv_kdf.py`).

Damit funktioniert die komplette Kette — Cloud-Login, MQTT-Signalisierung und P2P-Login am Gerät — mit einer frei erzeugten ID.

**Kein Telefon, keine App, keine Registrierung.**

Das frühere Feld **Signalisierungs-ID** ist seit v0.9.0 entfernt: Die Annahme, die P2P-Signalisierung akzeptiere nur beim Hersteller registrierte IDs, hat sich im Livebetrieb als falsch erwiesen. Bestehende Einträge werden beim nächsten Start automatisch bereinigt.

---

## 🎬 Videoclip aufnehmen

```yaml
action: balter_evo.record_clip
target:
  entity_id: camera.tuerstation_kamera
data:
  filename: /media/tuerstation.mp4
  seconds: 5