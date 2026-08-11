# Reverse-engineertes Protokoll

Diese Integration spricht die Cloud-API von **QUALVISION TECHNOLOGY CO.,LTD** (Paketname `com.quvii.*`, Cloud-Domain `qvcloud.net`), auf der die Balter-EVO-App sowie mehrere andere weißgelabelte Video-Türsprechanlagen-Apps basieren.

Das Protokoll wurde durch dynamische Instrumentierung (Frida-Hooks auf `SSL_write`/`SSL_read` in allen geladenen nativen Bibliotheken der Android-App) aus echtem Traffic gewonnen, nicht aus offizieller Dokumentation (es existiert keine öffentliche SDK/API-Doku für dieses Produkt).

Alle Werte unten sind **Platzhalter** – die tatsächlichen Werte (E-Mail, Passwort, PIN, Geräte-ID) sind pro Account/Gerät unterschiedlich.

## Login

```
POST /auth/user;jus_duplex=up HTTP/1.1
Content-Type: application/xml
Host: r1-8.qvcloud.net

<?xml version="1.0" encoding="UTF-8"?><envelope>
   <content class="com.quvii.qvweb.userauth.bean.request.LoginReqContent">
      <account>{email}</account>
      <auth-code></auth-code>
      <ip-region-id>1</ip-region-id>
      <password>{sha256(password)}</password>
      <auth-type>0</auth-type>
   </content>
   <header>
      <client><app>4028</app><id>{client_id}</id><oem>G0028,G0126</oem><type>3</type></client>
      <command>login</command><flag>tdkcloud</flag><seq>1</seq>
      <user-data></user-data><version>v1.13</version>
   </header>
</envelope>
```

Antwort enthält `Set-Cookie: jsessionid=...` – dieser Cookie wird für alle folgenden Aufrufe benötigt (klassische Servlet-Session).

**Bekannte Einschränkung:** Der Login-Request funktioniert nachweislich innerhalb der echten App (per Traffic-Capture verifiziert), schlägt aber bei Nachbau mit einem einfachen HTTP-Client (curl/aiohttp) mit `404` fehl – auch nach Hinzufügen des in der App gebündelten Client-Zertifikats (Mutual TLS, siehe unten) und passendem `User-Agent`. Vermutlich spielt TLS-Fingerprinting (JA3) oder eine Verbindungs-Reihenfolge-Abhängigkeit (z. B. vorheriger Location-/OAuth-Call auf derselben TCP-Verbindung) eine Rolle. **Wer das löst, bitte per Pull Request beitragen.**

Die App bündelt außerdem ein Client-Zertifikat für mTLS (`assets/client.pem` + `assets/client.txt` als privater Schlüssel, ausgestellt von "QUALVISION TECHNOLOGY CO.,LTD"). Ob dieses für die Cloud-API zwingend nötig ist, ist nicht abschließend geklärt.

## Geräteliste

```
POST /auth/user;jus_duplex=up  (Content-Type: application/xml, Cookie: jsessionid=...)

<content class="com.quvii.qvweb.userauth.bean.request.DevListReqContent">...</content>
<header>...<command>get-device-list</command><flag>tdkcloud</flag>...</header>
```

Antwort liefert pro Gerät `<id>` (duid), `<dynamic-password>` (rotierendes Geräte-Passwort, ca. 1 Woche gültig), `<out-auth-code>` (SHA256 der aktuellen Tür-PIN).

## Sub-Geräte (Kanäle/Schlösser)

```json
POST /auth/user;jus_duplex=up  (Content-Type: application/json)
{"content":{"duids":["{duid}"]},"header":{...,"command":"get-subdev-list","flag":"tdkcloud",...}}
```

Liefert pro Kanal zwei Schlösser (`lock_chn{N} 1`, `lock_chn{N} 2` → `door={N}`, `locknumber=1|2`).

## Tür öffnen (verifiziert funktionierend)

```
POST /tdkcgi HTTP/1.1
Content-Type: application/xml; charset=UTF-8
Cookie: jsessionid=...

<envelope>
   <content class="com.quvii.qvweb.device.bean.requset.DeviceUnlockContent">
      <door>{channel}</door>
      <locknumber>{1|2}</locknumber>
      <password>{sha256(pin)}</password>
   </content>
   <header>
      <password>{dynamic_password aus Geräteliste}</password>
      <security>username</security>
   </header>
   <command>set.device.opendoor</command>
</envelope>
```

Erfolgsantwort: `<envelope><body><error>0</error><content></content></body></envelope>`

## Video

**Nicht implementiert.** Der Live-Videostream läuft über ein separates, proprietäres P2P-Binärprotokoll über UDP (Magic-Header `C1 EF AB FF`, eigene Sequenzierung/ACK-Schicht) direkt zwischen App und Gerät (NAT-Hole-Punching), nicht über die HTTPS-API. Ob die Nutzdaten darin verschlüsselt sind, ist ungeklärt. Eine Umsetzung würde eine vollständige Reimplementierung dieses Binärprotokolls erfordern (natives SDK: `libqv-p2p-v2.so`, `liblive_player.so`).
