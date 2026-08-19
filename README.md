<p align="center">
  <img src="images/logo.png" alt="Balter Logo" width="200">
</p>

# Balter EVO (Quvii Cloud / P2P) – Home Assistant Integration

Inoffizielle Home-Assistant-Integration für die **Balter EVO 2** Video-Türsprechanlage (und kompatible Homaxi / Qualvision / Quvii P2P-Systeme).

---

## ✨ Features (v0.3.1)

- ✅ **Cloud-Login & automatische Geräteerkennung:** Liest alle gebundenen Türstationen und Schlösser aus dem Quvii-Cloud-Konto aus.
- ✅ **P2P Türöffner (`lock`):** Öffnet die Tür zuverlässig direkt über das native P2P-UDP/KCP-Protokoll mit rotierendem Sicherheitstoken und PIN-Verschlüsselung.
- ✅ **On-Demand Kamera-Snapshot (`camera`):** Erfasst aktuelle Live-Bilder über den H.264 P2P-Strom und gibt die Session sofort wieder frei, damit die Anlage für andere Bewohner frei bleibt.
- ✅ **Keine Hardcoded-Credentials:** Alle Passwörter, Tokens und Verschlüsselungs-Keys werden dynamisch zur Laufzeit bezogen.

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
