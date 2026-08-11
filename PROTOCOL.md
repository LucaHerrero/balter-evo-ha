# Reverse-engineertes Protokoll

Diese Integration spricht die Cloud-API von **QUALVISION TECHNOLOGY CO.,LTD** (Paketname `com.quvii.*`, Cloud-Domain `qvcloud.net`), auf der die Balter-EVO-App sowie mehrere andere weißgelabelte Video-Türsprechanlagen-Apps basieren.

Das Protokoll wurde durch dynamische Instrumentierung (Frida-Hooks auf `SSL_write`/`SSL_read` in allen geladenen nativen Bibliotheken der Android-App) aus echtem Traffic gewonnen, nicht aus offizieller Dokumentation (es existiert keine öffentliche SDK/API-Doku für dieses Produkt).

Alle Werte unten sind **Platzhalter** – die tatsächlichen Werte (E-Mail, Passwort, PIN, Geräte-ID) sind pro Account/Gerät unterschiedlich.

## Login

**Zwei-Schritt-Ablauf (wichtig):** Der Login-POST liefert `404`, solange keine Servlet-Session existiert. Daher **zuerst** ein einfacher `GET /auth/user`, der per `Set-Cookie: jsessionid=...` eine anonyme Session vergibt, **dann** der Login-POST mit diesem Cookie. Der Login-POST geht an den **schlichten** Pfad `/auth/user` – **nicht** an `/auth/user;jus_duplex=up` (das ist ein Duplex-Long-Poll-Tunnel, der nur leere ACKs zurückgibt; die eigentliche Antwort käme dort asynchron über den parallel offen gehaltenen `;jus_duplex=down`-Kanal).

```
1) GET /auth/user            -> Set-Cookie: jsessionid=...
2) POST /auth/user HTTP/1.1   (mit Cookie: jsessionid=...)
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

Antwort (synchron im POST-Body): `<envelope><header>...<session><id>..</id></session><result>0</result></header><content><account-id>..</account-id>...</content></envelope>`. Dazu `Set-Cookie: jsessionid=...` – dieser Cookie wird für alle folgenden Aufrufe benötigt (klassische Servlet-Session). Die `<session><id>` wird zusätzlich in den `<header><session>` der Folgeaufrufe gespiegelt.

**GELÖST (früher „404"-Blocker):** Der Nachbau mit einem einfachen HTTP-Client (curl/aiohttp) funktioniert vollständig. Der 404 lag **ausschließlich** an der fehlenden Vorab-Session: ohne den einleitenden `GET /auth/user` (der die anonyme `jsessionid` vergibt) und/oder beim POST an den `;jus_duplex=up`-Tunnelpfad antwortet der Knoten mit 404. Mit `GET` → dann `POST /auth/user` (schlicht) klappt Login, Geräteliste, Sub-Geräte und Türöffnen synchron. **Kein Client-Zertifikat, kein JA3-Workaround nötig** – der TLS-Handshake eines Standard-Python-Clients wird akzeptiert, das gebündelte mTLS-Cert ändert am Ergebnis nichts. Verifiziert am 2026-08-11 gegen `r1-8.qvcloud.net`.

Die App bündelt zwar ein Client-Zertifikat für mTLS (`assets/client.pem` + `assets/client.txt`, ausgestellt von „QUALVISION TECHNOLOGY CO.,LTD"), dieses ist für die Cloud-API aber **nicht erforderlich**.

## Geräteliste

```
POST /auth/user  (Content-Type: application/xml, Cookie: jsessionid=...)

<content class="com.quvii.qvweb.userauth.bean.request.DevListReqContent">...</content>
<header>...<command>get-device-list</command><flag>tdkcloud</flag>...</header>
```

Antwort liefert pro Gerät u.a.:
- `<id>` (duid), `<model>` (z. B. `IDS9459AW`), `<name>`, `<channel-num>`
- `<dynamic-password>` (rotierendes Geräte-Passwort, ca. 1 Woche gültig, `<password-expired>` nennt das Ablaufdatum)
- `<out-auth-code>` (SHA256 der aktuellen Tür-PIN), `<default-out-auth-code>` (Werks-PIN im Klartext)
- `<data-encode-key>` (32-Zeichen-Geräteschlüssel – **starker Kandidat für die Ver-/Entschlüsselung des P2P-Medienstroms**, siehe „Video")
- `<transparent-basedata>` (base64, Geräte-Roh-Konfig)

## Sub-Geräte (Kanäle/Schlösser)

```json
POST /auth/user  (Content-Type: application/json)
{"content":{"duids":["{duid}"]},"header":{...,"command":"get-subdev-list","flag":"tdkcloud",...}}
```

Liefert `chn`-Einträge (`CAM1..4` = Türstationen, `CCTV1..8` = Kameras, je mit `enable`) und `lock`-Einträge. Pro Kanal zwei Schlösser (`lock_chn{N} 1`, `lock_chn{N} 2` → `door={N}`, `locknumber=1|2`), insgesamt 16. Nur Schlösser unter einem `enable:1`-Kanal entsprechen einer real verdrahteten Tür (hier nur `CAM1`/`door=1`).

## Tür öffnen — NICHT über die Cloud möglich (korrigiert 2026-08-11)

**Wichtige Korrektur:** Frühere Notizen behaupteten, Türöffnen liefe über Cloud-HTTPS. Das ist **falsch**. Ein Frida-`SSL_write`-Mitschnitt eines echten Öffnen-Vorgangs zeigt:

```
POST /tdkcgi   Host: 127.0.0.1:41163
```

Der Befehl geht an einen **lokalen Loopback-Proxy** der nativen Bibliothek und wird durch den **P2P-Tunnel direkt zum Gerät** getunnelt – es gibt **keinen Cloud-`/tdkcgi`-Endpunkt** (jeder `r1-*`-Knoten antwortet mit nginx-404). Der CGI-Envelope (unten) ist korrekt, wird aber **im Tunnel** übertragen, nicht per Internet-HTTPS:

```xml
<envelope>
   <content class="com.quvii.qvweb.device.bean.requset.DeviceUnlockContent">
      <door>{channel}</door><locknumber>{1|2}</locknumber>
      <password>{sha256(pin)}</password>
   </content>
   <header><password>{dynamic_password}</password><security>username</security></header>
   <command>set.device.opendoor</command>
</envelope>
```

**Cloud-IoT/MQTT-Alternative getestet – funktioniert für dieses Gerät NICHT.** Die App nutzt eine IoT-Ebene auf `tdkopenapir1.qvcloud.net` (Auth per JWT im `token:`-Header, aus `/qvoauthv2/token`). Der dokumentierte Steuer-Endpunkt

```
POST https://tdkopenapir1.qvcloud.net/openapi-tdk/devctr/synccontrol/singledev
token: <JWT>
{"deviceId":"{duid}","password":"{dynamic_password}","command":"set.device.opendoor",
 "content":{"password":"{sha256(pin)}","door":1,"locknumber":2}}
```

liefert `HTTP 200 {"result":3,"message":"...iotserver...设备未注册"}` = **„Gerät nicht registriert"**. Der Endpunkt akzeptiert Auth+Format, aber dieses Gerät (`IDS9459AW`) ist auf der IoT-/MQTT-Steuerebene nicht registriert – es läuft ausschließlich über die P2P/NetSDK-Schiene.

**Fazit:** Türöffnen erfordert – wie das Video – den **P2P-Tunnel** (`libqv-p2p-v2.so`). Ohne dessen Reimplementierung ist Standalone-Unlock nicht möglich; als Brücke bleibt ein eingeloggtes Android-Gerät (ADB-Tap auf den Entriegeln-Button der App). Der Transport ist inzwischen aus einem echten Session-Mitschnitt weitgehend rekonstruiert – siehe **[`P2P_PROTOCOL.md`](P2P_PROTOCOL.md)**.

Nebenbefund: `/openapi-tdk/client/push/token` registriert einen **FCM-Push-Token** – Klingel-/Ruf-Events kommen also per FCM-Push (potenziell als HA-Event nutzbar).

## Video

**Nicht implementiert.** Der Live-Videostream läuft über ein separates, proprietäres P2P-Binärprotokoll über UDP (Magic-Header `C1 EF AB FF`, eigene Sequenzierung/ACK-Schicht) direkt zwischen App und Gerät (NAT-Hole-Punching), nicht über die HTTPS-API. Eine Umsetzung würde eine Reimplementierung dieses Binärprotokolls erfordern (natives SDK: `libqv-p2p-v2.so`, `liblive_player.so`).

**Zwei getrennte Kanäle im P2P-Tunnel (Frida-verifiziert, 2026-08-11):**

1. **Steuer-/Signalisierungskanal → AES-256-CBC.** `liblive_player.so` ruft `AES_set_encrypt_key`/`AES_set_decrypt_key` (256 bit) mit exakt dem `<data-encode-key>` aus der Cloud-Geräteliste auf (32 ASCII-Bytes, nicht base64-dekodiert) und ver-/entschlüsselt über `AES_cbc_encrypt` mit **festem IV `"0000000000000000"`** (`0x30`×16). Nutzdaten sind klein und 16-Byte-blockaligned (32/48/80/240 …, hunderte kurze Blöcke/s) – also Kontroll-/Reliability-Nachrichten, **kein Video**.

2. **Bulk-Video → unverschlüsselt.** Der eigentliche Videostrom ist **nicht** AES-verschlüsselt (`libqv-p2p-v2.so!AES_cbc_encrypt` mit enc=0: **0 Aufrufe** während des Streams). Nach der P2P-Reliability-Schicht liegt der Strom direkt als **H.264 (Annex-B)** vor.

**Video End-to-End verifiziert:** Am FFmpeg-Eintritt `libavcodec.so!avcodec_send_packet` (`AVPacket->data`@Offset 24, `->size`@32) wurden die Access-Units gedumpt (10 s ≈ 126 Pakete / 341 KB ≈ 34 KB/s). `ffprobe` erkennt den Rohstrom als **H.264, Profile Main, 352×280, yuv420p**; NAL-Folge SPS/PPS/IDR + P-Frames, 126 Frames dekodiert und zu MP4/JPG gerendert (zeigt das reale Türstations-Kamerabild). Skript: `scratchpad/frida_dumpvideo.py`.

**Konsequenz für Standalone-Video:** Kein Krypto-Problem mehr – es fehlt nur noch die Reimplementierung des `C1EFABFF`-**Transports** (Session-Handshake, NAT-Hole-Punching, ACK/Reliability in `libqv-p2p-v2.so`), um die H.264-Access-Units ohne App zu empfangen. Der AES-256-CBC-Key/IV oben wird nur für die begleitenden Steuernachrichten dieses Transports gebraucht.

Pragmatische Alternative bis dahin: eingeloggtes Android-Gerät als Brücke – entweder ADB-Screencapture des Live-Bilds **oder** ein Frida-Tap auf `avcodec_send_packet`, der die H.264-Access-Units live an Home Assistant weiterreicht (RTSP/Snapshot). Türöffnen läuft bereits vollständig über die Cloud-API.
