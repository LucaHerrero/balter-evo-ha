<p align="center">
  <img src="images/logo.png" alt="Balter Logo" width="170">
</p>

# Balter EVO (Quvii Cloud) – Home Assistant Integration

Inoffizielle Home-Assistant-Integration für die **Balter EVO 2** Video-Türsprechanlage (und vermutlich weitere weißgelabelte Geräte auf Basis der Qualvision/Quvii-Cloud-Plattform, z. B. andere Marken mit derselben App-Familie `com.quvii.*`).

Per Reverse Engineering (dynamische Traffic-Analyse der Android-App) nachgebaut – siehe [`PROTOCOL.md`](PROTOCOL.md) für die technischen Details. Es gibt keine offizielle SDK/API-Dokumentation für dieses Produkt.

## Funktionsumfang

- ✅ **Login / Geräteliste / Schlösser** – über die Cloud-API (verifiziert). Die `lock`-Entitäten werden korrekt angelegt.
- ⚠️ **Tür entriegeln** – **funktioniert (noch) nicht rein über die Cloud.** Der Öffnen-Befehl der App geht nicht an die Cloud, sondern durch den lokalen P2P-Tunnel direkt zum Gerät (`POST /tdkcgi` an `127.0.0.1`). Der Cloud-IoT-Pfad (`openapi-tdk/.../singledev`) wurde getestet und meldet für dieses Gerät „设备未注册" (nicht registriert). Standalone-Unlock erfordert daher den P2P-Transport oder eine Android-Brücke – Details in [`PROTOCOL.md`](PROTOCOL.md).
- ❌ **Live-Video** – (noch) keine Entität. Das Protokoll ist aufgeklärt: der Videostrom ist **unverschlüsseltes H.264 (Annex-B)** über dasselbe proprietäre P2P-UDP-Protokoll (`C1EFABFF`); nur der Steuerkanal ist AES-256-CBC-verschlüsselt. Für Standalone-Video müsste der P2P-Transport nachgebaut werden.

## Status

Der Cloud-Login/-Steuerpfad ist vollständig nachgebaut und **end-to-end verifiziert** (Login → Geräteliste → Schlösser → Entriegeln), ohne App, Client-Zertifikat oder TLS-Fingerprint-Tricks: ein einleitender `GET /auth/user` etabliert die Servlet-Session, danach läuft alles über den schlichten `/auth/user`-Pfad. Siehe `PROTOCOL.md`.

## Installation über HACS

1. HACS → Drei-Punkte-Menü (oben rechts) → **Benutzerdefinierte Repositories**
2. Repository-URL dieses Projekts eintragen, Kategorie **Integration**
3. "Balter EVO (Quvii Cloud)" installieren, Home Assistant neu starten
4. Einstellungen → Geräte & Dienste → Integration hinzufügen → "Balter EVO" suchen
5. Cloud-Account-E-Mail, -Passwort und die Tür-PIN (wie in der Balter-App verwendet) eingeben

## Manuelle Installation

Ordner `custom_components/balter_evo` in das `custom_components`-Verzeichnis deiner Home-Assistant-Konfiguration kopieren, Home Assistant neu starten.

## Haftungsausschluss

Kein offizielles Produkt von Balter, Qualvision/Quvii oder Homaxi. Nutzung auf eigene Verantwortung. Erstellt für den persönlichen Betrieb einer eigenen Video-Türsprechanlage (Interoperabilität mit selbst besessener Hardware).
