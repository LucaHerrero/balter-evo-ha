<p align="center">
  <img src="images/logo.png" alt="Balter Logo" width="170">
</p>

# Balter EVO (Quvii Cloud) – Home Assistant Integration

Inoffizielle Home-Assistant-Integration für die **Balter EVO 2** Video-Türsprechanlage (und vermutlich weitere weißgelabelte Geräte auf Basis der Qualvision/Quvii-Cloud-Plattform, z. B. andere Marken mit derselben App-Familie `com.quvii.*`).

Per Reverse Engineering (dynamische Traffic-Analyse der Android-App) nachgebaut – siehe [`PROTOCOL.md`](PROTOCOL.md) für die technischen Details. Es gibt keine offizielle SDK/API-Dokumentation für dieses Produkt.

## Funktionsumfang

- ✅ **Tür/Schloss öffnen** – als `button`-Entität pro erkanntem Schlosskanal (verifiziert funktionierend gegen die echte Cloud-API)
- ❌ **Live-Video** – noch nicht unterstützt (läuft über ein separates, proprietäres P2P-Binärprotokoll, siehe `PROTOCOL.md`)

## Bekannte Einschränkung

Der Cloud-Login funktioniert nachweislich aus der echten App heraus, aber die Nachimplementierung mit Standard-HTTP-Clients bekommt aktuell einen `404` vom Server (vermutlich TLS-Fingerprinting oder eine Verbindungsreihenfolge-Abhängigkeit). **Diese Integration ist aktuell experimentell / work in progress** – Beiträge zur Lösung sind willkommen.

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
