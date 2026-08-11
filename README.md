<p align="center">
  <img src="images/logo.png" alt="Balter Logo" width="170">
</p>

# Balter EVO (Quvii Cloud) – Home Assistant Integration

Inoffizielle Home-Assistant-Integration für die **Balter EVO 2** Video-Türsprechanlage (und vermutlich weitere weißgelabelte Geräte auf Basis der Qualvision/Quvii-Cloud-Plattform, z. B. andere Marken mit derselben App-Familie `com.quvii.*`).

Per Reverse Engineering (dynamische Traffic-Analyse der Android-App) nachgebaut – siehe [`PROTOCOL.md`](PROTOCOL.md) für die technischen Details. Es gibt keine offizielle SDK/API-Dokumentation für dieses Produkt.

## Funktionsumfang

- ✅ **Tür entriegeln** – als `lock`-Entität pro erkanntem Schlosskanal (verifiziert funktionierend gegen die echte Cloud-API). Der Türöffner ist momentan: Entriegeln löst den Relais-Impuls aus, danach fällt die Entität nach kurzer Zeit automatisch wieder auf „verriegelt" zurück (optimistischer Zustand, das Gerät verriegelt selbsttätig).
- ❌ **Live-Video** – (noch) keine Entität. Das Protokoll ist inzwischen aufgeklärt: der Videostrom ist **unverschlüsseltes H.264 (Annex-B)**, das über ein separates, proprietäres P2P-UDP-Protokoll (`C1EFABFF`) läuft; nur der Steuerkanal ist AES-256-CBC-verschlüsselt. Für ein reines Standalone-Video müsste noch der P2P-Transport nachgebaut werden – Details in [`PROTOCOL.md`](PROTOCOL.md).

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
