<p align="center">
  <img src="images/logo.png" alt="Balter Logo" width="200">
</p>

# Balter EVO (Quvii Cloud / P2P) – Home Assistant Integration

Inoffizielle Home-Assistant-Integration für die **Balter EVO 2** Video-Türsprechanlage (und kompatible Homaxi / Qualvision / Quvii P2P-Systeme).

---

## ✨ Features (v0.4.0)

- ✅ **Cloud-Login & automatische Geräteerkennung:** Liest alle gebundenen Türstationen und Schlösser aus dem Quvii-Cloud-Konto aus.
- ✅ **P2P Türöffner (`lock`):** Öffnet die Tür direkt über das native P2P-UDP/KCP-Protokoll. Der Erfolg wird an der **echten Gerätequittung** festgemacht, nicht am bloßen Absenden.
- ✅ **On-Demand Kamera-Snapshot (`camera`):** Live-Bild aus dem H.264-P2P-Strom; die Session wird sofort wieder freigegeben, damit die Anlage für andere Bewohner frei bleibt.
- 🎬 **Videoclip-Service (neu):** `balter_evo.record_clip` nimmt einen kurzen MP4-Clip der Türstation auf (braucht `ffmpeg` auf dem HA-Host).
- 🔄 **Rotierende Geheimnisse automatisch:** `dynamic_password` und `data_encode_key` wechseln wöchentlich und werden zur Laufzeit frisch geholt statt einmal beim Setup.
- ✅ **Keine Hardcoded-Credentials:** Alle Passwörter, Tokens und Keys werden dynamisch bezogen. Ohne konfigurierte PIN wird der `out-auth-code` der Geräteliste verwendet.

### Neu in v0.4.0 — Protokollschicht neu aufgesetzt

Der App-Frame-Kopf ist **56 Byte**, nicht 48. Alle bisherigen Versionen sendeten
einen 8 Byte zu kurzen Kopf: der Transport quittierte weiter, die App-Schicht des
Geräts verwarf aber jeden Frame — kein Login, kein Video, kein zuverlässiges
Türöffnen. Alle Frames sind jetzt byte-genau gegen einen echten App-Mitschnitt
verifiziert (`tools/verify_frames.py`, 12/12).

Weitere behobene Fehler: fehlende Quittung für Fortsetzungspakete (der Videostrom
blieb nach ~8 kB stehen), ARQ-Retransmits am falschen Byte-Offset (Handshake blieb
hängen), zu früh gesendetes OPENDOOR (vor der Freigabe der App-Session) und eine
Kandidatenauswahl beim Dekodieren, die nach Länge statt nach Dekodierbarkeit ging.
Details: [`P2P_PROTOCOL.md`](P2P_PROTOCOL.md) §9 und §10.

> **Hinweis zum Verhalten:** Die Türstation verträgt keine parallelen oder dicht
> aufeinanderfolgenden P2P-Sitzungen. Snapshot und Türöffner teilen sich deshalb
> intern einen Slot mit ~20 s Mindestabstand; ein hängengebliebener Handshake wird
> automatisch wiederholt — beim Türöffner allerdings **nur**, solange der Befehl
> nachweislich noch nicht gesendet wurde.

---

## 🎬 Videoclip aufnehmen

```yaml
action: balter_evo.record_clip
target:
  entity_id: camera.turstation_kamera
data:
  filename: /media/tuerstation.mp4
  seconds: 5
```

Das Zielverzeichnis muss in `allowlist_external_dirs` freigegeben sein. Die
Türstation beginnt erst rund zwei Sekunden nach dem Login zu senden — der Recorder
nimmt deshalb länger auf und kürzt auf die gewünschte Länge.

---

## 📦 Installation über HACS

1. HACS öffnen → Drei-Punkte-Menü (oben rechts) → **Benutzerdefinierte Repositories**
2. Repository-URL dieses Projekts eintragen, Kategorie **Integration**
3. **Balter EVO (Quvii Cloud)** auswählen und installieren
4. Home Assistant neu starten
5. **Einstellungen ➔ Geräte & Dienste ➔ Integration hinzufügen ➔ "Balter EVO"**
6. E-Mail, Passwort und Tür-PIN eingeben

---

## 🛠️ Manuelle Installation

Ordner `custom_components/balter_evo` in das `custom_components`-Verzeichnis deiner Home-Assistant-Installation kopieren und Home Assistant neu starten.

---

## ⚖️ Haftungsausschluss

Kein offizielles Produkt von Balter, Qualvision/Quvii oder Homaxi. Nutzung auf eigene Verantwortung.
