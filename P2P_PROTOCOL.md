# P2P-Transportprotokoll (`C1EFABFF`) — Reverse-Engineering-Stand

Dokumentiert das proprietäre UDP-P2P-Protokoll der Balter-EVO-2 / Qualvision-Quvii-Plattform (native Libs `libqv-p2p-v2.so`, `liblive_player.so`), über das **Video UND Gerätebefehle (Türöffnen)** laufen. Die Cloud-HTTPS-API (`qvcloud.net`) macht nur Login/Geräteliste/Schlösser – siehe [`PROTOCOL.md`](PROTOCOL.md); Steuerung/Video gehen ausschließlich über diesen Tunnel.

> Stand 2026-08-12. Basis: ein vollständiger tcpdump-Mitschnitt einer echten Live-Session (`downloads/p2p-capture/session.pcap`, 2801 Pakete / 2756× `C1EFABFF`). „Bestätigt" = direkt aus dem Mitschnitt reproduziert; „vermutet" = plausibel, aber nicht verifiziert.

**Der Mitschnitt ist vollständig dekodiert.** Aus dem rohen pcap wurden ohne App, ohne Telefon und ohne Frida **505 Videoframes (352×280, H.264 Main)** sowie die Steuerkanal-Nachrichten im Klartext rekonstruiert. Werkzeug: [`tools/p2p_decode.py`](tools/p2p_decode.py).

```
python tools/p2p_decode.py session.pcap --key <data-encode-key> -o out/
ffmpeg -f h264 -r 17 -i out/stream.h264 -c:v libx264 -pix_fmt yuv420p out.mp4
```

## 1. Aufzeichnungsmethode

Frida-Hooks auf `sendto/recvfrom` scheitern: die native Lib nutzt vermutlich **direkte Syscalls** an libc vorbei. Zuverlässig ist **tcpdump auf dem Gerät** (root):

```
adb shell "su -c 'timeout 30 tcpdump -i any -s0 -w /sdcard/cap.pcap udp'"
```

Die Auswertung braucht kein Telefon mehr – `tools/p2p_decode.py` liest das pcap dependency-arm (nur `cryptography`) und liefert H.264 + JSON.

## 2. Netzwerk-Topologie

| Rolle | Adresse (Beispiel-Session) | Bemerkung |
|---|---|---|
| Client (Telefon) | `192.168.0.184:56775` | dynamischer Quellport |
| Gerät (Klingel) | `<WAN-IP>:45269` | öffentliche IP + dyn. Port, per NAT-Hole-Punch direkt erreicht (Adresse redigiert) |
| Gerät im lokalen LAN | `192.168.178.143:45269` | **private** Adresse (RFC1918) – der Client punched parallel dorthin (ICE-artig) |
| Rendezvous-Server | `195.154.119.43:15017` | Scaleway Paris; nur für den Hole-Punch, **kein** Video-Relay |

Der gesamte **Video-Bulk (1,79 MB/30 s) läuft direkt Gerät→Telefon**. Dass der Client die *private* Adresse des Geräts mitprobiert, beweist: er bekommt Kandidatenadressen (privat + öffentlich) vorab von der Cloud oder vom Rendezvous-Server geliefert.

## 3. Session-Ablauf

```
t=0.000  TX Telefon -> Rendezvous, Gerät-WAN UND Gerät-LAN:  164-B INIT   [Hole-Punch, parallel]
t=0.062  RX Gerät -> Telefon:      164-B INIT-Echo (Antwort-Flag gesetzt)
t=0.106  RX Rendezvous -> Telefon: 164-B INIT-Echo
t=1.104  RX Gerät -> Telefon:      Datenstrom beginnt (Byte-Offset = ISN 277)
t=1.335  TX Telefon -> Gerät:      erstes Steuerkommando (Offset = ISN 493)
…        Gerät sendet Video, Telefon ackt jeden Offset
```

## 4. Transportschicht

Alle Pakete beginnen mit dem 4-Byte-Magic **`C1 EF AB FF`** (LE-uint32 `0xFFABEFC1`). Darauf folgt ein **28-Byte-Header**.

### 4a. Header-Felder — *bestätigt*

| # | Offset | Typ | Bedeutung |
|---|---|---|---|
| 0 | 0 | LE-uint32 | Magic `0xFFABEFC1` |
| 1 | 4 | LE-uint32 | **src-Verbindungs-ID** |
| 2 | 8 | LE-uint32 | **dst-Verbindungs-ID** |
| 3 | 12 | LE-uint32 | **seq** – Byte-Offset im *eigenen* Sendestrom |
| 4 | 16 | LE-uint32 | **ack** – bisher lückenlos empfangener Byte-Offset des *Gegenstroms* |
| 5 | 20 | LE-uint32 | Empfangsfenster (typ. `0x1900` = 6400) |
| 6 | 24 | 2× LE-uint16 | `[0..1]` **Rest-Bytes** der aktuellen Nachricht, `[2..3]` **Gesamtlänge des UDP-Payloads** |

> **Korrektur gegenüber früheren Fassungen dieses Dokuments:** Feld 3 ist der Sende-Offset und Feld 4 die ACK-Nummer – nicht „Offset bzw. msg-id". Der scheinbar konstante Wert `0x1ED` in Feld 4 war schlicht die ACK-Nummer 493 in der Anfangsphase.
>
> **Feld 6, untere 16 Bit ist KEINE Prüfsumme.** Empirisch (session.pcap): `f6_low + seq = konstant` über einen ganzen Nachrichten-Burst (z. B. `0x6DC5`), d. h. `f6_low = Nachrichtenende_Offset − seq` = **verbleibende Bytes der aktuellen Nachricht**, deterministisch. Es gibt also **keine kryptografische Header-Prüfsumme** – der gesamte 28-B-Header ist ohne Geheimnis berechenbar. (Bei Kontroll-/INIT-Paketen ist f6_low = 0.)

Damit ist die Transportschicht **TCP über UDP**: fortlaufende Byte-Offsets, kumulative ACKs, Retransmits mit identischem Offset. Datenpakete tragen bis zu 1420 B Payload (1448 B UDP gesamt), reine ACKs sind 28 B ohne Payload.

### 4b. Verbindungs-IDs — *bestätigt*

Beobachtet wurden zwei parallele Verbindungen:

| Verbindung | Gerät→Telefon | Telefon→Gerät |
|---|---|---|
| 1 (Medien) | `0x05000002` | `0x7D000035` |
| 2 (Nebenkanal) | `0x06000003` | `0x7E000036` |

Als zwei LE-uint16 gelesen, sind beide Hälften **schlichte Zähler**, die pro neuer Verbindung um 1 hochlaufen (`0002/0005` → `0003/0006` bzw. `0035/007D` → `0036/007E`). Es handelt sich also nicht um ausgehandelte Zufalls-IDs, sondern um lokal vergebene Slot-Nummern, die im Handshake mitgeteilt werden.

**ISN:** Beide Richtungen starten bei einem von 0 verschiedenen Offset (hier Downstream 277, Upstream 493) – wie eine TCP-Initial-Sequence-Number.

### 4c. INIT / Hole-Punch (164 Byte) — *bestätigt*

Das Telefon sendet dieses Paket zu Session-Beginn **gleichzeitig** an Rendezvous-Server, Geräte-WAN- und Geräte-LAN-Adresse; die Gegenstellen echoen es zurück (NAT-Loch öffnen).

```
0x00  c1efabff              Magic
0x04  00000000 00000000     src-id / dst-id = 0 (noch keine Session)
0x1a  a400                  len16 = 164
0x1c  ffffffff              „no session"-Marker
0x20  88000000              App-Frame, Typ 0x88 (CONNECT)
0x2e  0001 0000 0200 1200   konstante Handshake-Felder (Byte @0x2e: 0=Anfrage/1=Antwort)
0x40  60000000              Body-Länge 0x60 = 96
0x44  <session-flag>        Token (ASCII, ~44–62 Zeichen) – identisch mit MQTT `session-flag` (§7a)
0x8c  "192.168.178.143\0"   Ziel-loc-ip als ASCII-String
0x9c  d5b0                  loc-udpport = 0xB0D5 = 45269 (LE-uint16)
```

Der **Hole-Punch-Ablauf** (aus `open.pcap`, chronologisch):
1. **STUN-artige Vorphase** zu einem Init-/STUN-Server (`8.211.5.8`): 8× 96–112-B-Pakete (`ffffffff 54…`/`44…`) – vermutlich zur Ermittlung der eigenen `pub-ip`/`pub-udpport` (fließt dann in MQTT-`update-netinfo`, §7a).
2. **INIT parallel** (Typ `0x88`) an `loc-ip`, `pub-ip` und `utd-pub-ip` – exakt die drei Kandidaten aus der `p2pconnect`-Antwort.
3. Gegenstellen **echoen** das INIT (Byte @0x2e = 1); Retransmits bis der Punch steht.
4. Danach laufen die Datenpakete mit den etablierten `src`/`dst`-IDs (hier `01000000`/`83000000`).

- Der Token (`vvt3djhrescpxvvudoyyaeui8owkmwigxpnlgmj`) ist die Session-Kennung und entspricht dem CGI `get.device.streamkey`.
- **Korrektur:** Das früher als „Pakettyp `88`" beschriebene Byte ist in Wahrheit das erste Byte der **App-Frame-Länge** (`0x88` = 136). Es gibt an dieser Stelle kein Typfeld.

## 5. App-Schicht im Byte-Stream — *bestätigt*

Der reassemblierte Strom besteht lückenlos aus App-Frames (im Mitschnitt: 820 Frames, 100 % Abdeckung):

```
+00  ff ff ff ff              Frame-Marker
+04  uint32  gesamtlaenge     inkl. dieser 56 B Kopf
+08  8 B     handle           Session-Handle (0 im ersten Frame)
+10  uint32  0x00000100       konstant
+14  uint32  0x00120103       konstant
+18  uint32  seq              Nachrichtenzähler
+1c  8 B     0
+24  uint32  bodylen + 16
+28  uint32  0x04000027       konstant
+2c  uint32  0xA9190000       konstant
+30  uint32  bodylen
+34  4 B     0
+38  body                     <- ab hier: erste 64 B verschlüsselt, Rest Klartext
```

### 5a. Krypto: byte9-gesteuerte Teilverschlüsselung — *bestätigt*

**Das ist der Schlüssel zu Video UND Türöffnen.** Pro App-Frame sind **zwei Bereiche** mit **AES-256-CBC** verschlüsselt, jeder als **eigenes Segment mit IV-Reset**; alles dazwischen/danach ist Klartext:

1. **Kopf**: Body-Bytes `0..32` (2 Blöcke)
2. **Nutzteil**: Body-Bytes `32 .. 32+plen`, wobei **`plen` = Byte 9 des entschlüsselten Kopfs**

- **Key** = `<data-encode-key>` aus der Cloud-Geräteliste, als 32 ASCII-Bytes (nicht base64-dekodiert).
- **IV** = `"0000000000000000"` (16× ASCII-Null `0x30`) – **beide Segmente starten neu mit diesem IV**.

Bei **Medien-Frames** ist `plen = 32` → Kopf + Nutzteil = **64 B verschlüsselt**, danach roher H.264. Genau diese 64 B hatte die frühere Analyse als festen Wert gefunden – es ist aber nur der Spezialfall. Bei **Steuerframes** ist `plen` größer (beim Türöffnen 112).

Empirisch bestätigt am Video (Durchprobieren aller Blockgrenzen, ffmpeg als Schiedsrichter):

| verschlüsselte Länge | dekodierte Frames | Auflösung |
|---|---|---|
| 0 / 16 / 32 / 48 | 0 | — |
| **64** (= plen 32) | **505** | **352×280 Main** |
| 80 | 468 | 352×92 (defekt) |
| 96 und mehr | ≤166 | defekt |

Das erklärt zugleich den früheren Frida-Befund, `AES_cbc_encrypt` feuere nur mit kurzen Längen: verschlüsselt wird eben nur Kopf + kurzer Nutzteil, und der H.264-Bulk läuft im Klartext. Die frühere Formulierung „Video ist unverschlüsselt" war **im Ergebnis richtig, in der Begründung aber unvollständig** – auch Medien-Frames sind kopf-verschlüsselt, nur nicht in den Slice-Daten.

`tools/p2p_decode.py` implementiert beide Wege: `decrypt_head()` (schnelle 64-B-Näherung für Video) und `decrypt_control()` (exakte byte9-Regel für Steuerframes).

### 5b. Entschlüsselter Frame-Kopf — *bestätigt*

```
+00  uint8   Frame-Typ    0xA0 = Medien (768×), 0xFE = Steuerung/Info (31×)
+01  uint32  Zeitstempel  Unix-Sekunden (0x6A7BABAC = 2026-08-11)
+09  uint8   0x20 bei Medien, 0x30 bei Steuerframes
+10  16 B    0
+20  16 B    Binärfeld (Hash/ID)
+30  uint16  Breite   = 352
+32  uint16  Höhe     = 280
+34  …       Beginn der H.264-Daten (Annex-B)
```

Die Auflösung 352×280 steht in 539 Frames an dieser Stelle und deckt sich exakt mit dem dekodierten Video.

### 5c. Steuerkanal ist JSON — *bestätigt*

Der Steuerkanal überträgt **JSON**, nicht nur den XML-CGI-Envelope. Aus dem Mitschnitt entschlüsselt (gekürzt):

```json
{"total":8,"ability":{"switchdirectly":0},
 "catalogs":[{"type":"cam","total":4},{"type":"cctv","total":4}, …],
 "subs":{"total":16,"catalogs":[{"type":"lock","total":16,"enable":1}]},
 "sub-devlist":[
   {"id":1,"code":"CAM1","name":"Türstation 1","type":"chn",
    "children":[{"code":"lock_chn1 1"},{"code":"lock_chn1 2"}],
    "sub-type":"cam","monenable":1,"talkenable":1,"enable":1},
   {"id":2,"code":"CAM2","name":"Türstation 2", … ,"enable":0}, … ]}
```

Das ist inhaltlich dieselbe Sub-Geräteliste, die die Cloud-API als `get-subdev-list` liefert – hier aber vom Gerät selbst durch den P2P-Tunnel. Der Gerätename „Türstation 1" im Klartext war der erste Beleg, dass Key und IV stimmen.

## 6. Upstream (Telefon → Gerät) & Türöffnen — *bestätigt*

Der Upstream trägt die Steuerkommandos als App-Frames mit Frame-Typ `0xFE`. Ein separater Mitschnitt eines **echten Türöffnen-Vorgangs** (`downloads/p2p-open/open.pcap`, ausgelöst am Telefon, Ergebnis „Unlock successfully") hat den Öffnen-Befehl vollständig geliefert.

**Kopf jedes Steuerframes (entschlüsselt, 32 B):**

```
+00  uint8   Frame-Typ    0xFE
+01  uint32  Zeitstempel  Unix-Sekunden
+09  uint8   plen         Länge des verschlüsselten Nutzteils ab Body-Offset 32
+0b  uint8   clen         Länge des Kommando-Payloads (ohne Trailer)
+0d  uint8   msg-id/seq
```

**Türöffnen-Kommando** (Nutzteil, `plen` = 112 B, eigenes CBC-Segment):

```
+00  uint8   door         Kanal / Türstation (hier 1)
+01  uint8   ?            0
+02  uint8   locknumber   Schlossnummer (hier 1)
+03  uint8   ?            1  (vermutlich Aktion: 1 = entriegeln)
+04  12 B    0
+10  64 B    SHA256(Tür-PIN) als Hex-ASCII      <- clen deckt +00..+50 ab (16+64)
+50  32 B    Trailer      = SHA256(Kopf[32] ++ Payload[0..clen])
```

Verifiziert: Der Hash im abgefangenen Frame ist exakt `SHA256(<Tür-PIN>)` – identisch mit dem Hash im Cloud-Pfad (`PROTOCOL.md`/Notes) und mit dem `out-auth-code` der Geräteliste. `door`/`locknumber` entsprechen den Feldern des Cloud-CGI `set.device.opendoor`. Das Kommando läuft also **nicht** über die Cloud, sondern durch den P2P-Tunnel – wie in 5h vorhergesagt.

`tools/p2p_decode.py` erkennt das automatisch und gibt aus (Hash hier gekürzt):
`@900 typ=0xfe plen=112 [Trailer OK]  <== TUEROEFFNEN door=1 locknumber=1 pin_sha256=<64 hex>`

### 6a. Trailer / Integritäts-Prüfsumme — *bestätigt (Frida)*

Der 32-B-Trailer am Ende jedes Steuerframe-Nutzteils ist **keine geheime Signatur**, sondern schlicht:

```
Trailer = SHA256( Kopf[0..32]  ++  Payload[0..clen] )
```

d. h. SHA256 über die **entschlüsselten** 32 Kopf-Bytes gefolgt vom Kommando-Payload (ohne den Trailer selbst). Kein HMAC, kein Schlüssel, kein Nonce – nur die Frame-Daten.

Gefunden per Frida-Hook auf `liblive_player.so!SHA256_Final`: Der Digest jedes Aufrufs taucht unmittelbar danach im Klartext-Input von `AES_cbc_encrypt(enc=1)` als Trailer auf. Der Input von `SHA256_Final` ist exakt `Kopf ++ Payload`.

**Offline bit-genau verifiziert** gegen `open.pcap`: `SHA256(Kopf ++ Payload)` reproduziert den Trailer aller vier aufgezeichneten Steuerframes (`tools/p2p_decode.py` → `verify_trailer()`, Ausgabe `[Trailer OK]`).

**Konsequenz:** Der Trailer ist **ohne jedes Geheimnis berechenbar**. Für einen eigenständigen Öffner genügen der `data-encode-key` (Verschlüsselung) und die Tür-PIN (deren SHA256 im Payload steht) – beide stehen in der Cloud-Geräteliste. Es fehlt damit **kein kryptografischer Baustein** mehr; offen ist nur noch die Transport-/Sende-Schicht (§7).

## 7. Bestätigt vs. offen

**Bestätigt:**
- UDP-Transport vollständig: Magic, 28-B-Header, src/dst-ID, seq/ack-basiertes ARQ, Fenster, Längenfeld.
- Hole-Punch über Rendezvous + WAN- und LAN-Adresse des Geräts, INIT-Struktur mit Token und Antwort-Flag.
- Verbindungs-IDs sind hochlaufende Zählerpaare; beide Richtungen mit ISN ≠ 0.
- App-Frame-Format (56-B-Kopf) und lückenlose Reassembly (100 % des Mitschnitts).
- **Krypto vollständig: byte9-gesteuerte AES-256-CBC (Kopf 32 B + Nutzteil `plen` B, je IV = `"0"×16`), Key = `data-encode-key`.** Bei Medien = 64 B, bei Steuerframes länger.
- **Video vollständig rekonstruiert:** 505 Frames, 352×280, H.264 Main, gerendert und visuell verifiziert (Fisheye-Bild der Türstation).
- Steuerkanal-Payload ist JSON (Sub-Geräteliste im Klartext gelesen).
- **Türöffnen-Kommando entschlüsselt:** Upstream-Steuerframe Typ `0xFE`, Nutzteil `door`/`locknumber` + `SHA256(<Tür-PIN>)` (Hex-ASCII); Hash gegen die bekannte PIN verifiziert.
- **Trailer geknackt:** `SHA256(Kopf ++ Payload)`, keine geheime Signatur, für alle vier aufgezeichneten Steuerframes bit-genau reproduziert (§6a). Damit ist die **gesamte Krypto-/Kommando-Ebene vollständig** und ohne Geheimnis nachbaubar.

**Offen / nächste Schritte – nur noch die Transport-Sendeseite:**
1. **Adress-Discovery:** Woher bekommt der Client die WAN/LAN-Kandidaten des Geräts und die Rendezvous-Adresse? Vermutlich ein Cloud-Call vor dem Punch – per Frida `SSL_write` beim Verbindungsaufbau mitzuschneiden. **Wichtigster verbleibender Baustein.**
2. **Prüfsumme (Transport-Feld 6, untere 16 Bit):** Algorithmus unbekannt. Für einen eigenen Client nötig, sofern das Gerät sie prüft. (Kandidat: CRC16 über den 28-B-Header.)
3. **Sende-Seite:** NAT-Hole-Punch (164-B-INIT parallel an die Kandidaten), Verbindungs-ID-Vergabe, seq/ack-ARQ, Fensterlogik, Retransmit-Timing.
4. **Stream-Start-Kommando** (optional, für Live-Video in HA): die zwei Vorbereitungs-Frames (`plen=48`, Typ `0xFE`) vor dem Öffnen semantisch zuordnen.

Der **Türöffner** braucht nur 1–3 (kein Video). Die Krypto- und Kommando-Schicht (Frame bauen, verschlüsseln, Trailer) ist fertig und in `tools/p2p_decode.py` implementiert.

## 7a. Verbindungsaufbau: MQTT-Discovery + KCP — *bestätigt (Frida)*

Der Verbindungsaufbau wurde per Frida-Hook auf `libqv-p2p-v2.so!SSL_write/SSL_read` (die App-eigene MQTT-Implementierung `tdkcloud::MqttSession`) beim App-Start vollständig erfasst. Wichtig: **Frida `spawn`** nötig – die Signalisierung läuft direkt nach dem Start, ein späteres `attach` verpasst sie.

**0. Bootstrap: Server-Discovery** über `GET https://global.qvcloud.net/mst/query` (Kommando `query-hlrv2`, `server-type=userapp,alarmapp,p2papp,natcheck,appinfo,oauth2,log,openapi`). Die XML-Antwort liefert pro Dienst URL + Parameter, u. a.:
- `p2papp`: `url = mqtts://mqttsr1.qvcloud.net:1884`, `uri = /app/ust/json`, und ein `param`-Feld mit `username=<b64>&password=<b64>&JwtExp=…` (die MQTT-Credentials, **verschlüsselt**, s. u.).
- `natcheck`: `url = udp://8.211.5.8:8300` (STUN-artiger Init-Server für die eigene `pub-ip`).
- weitere: `oauth2r1.qvcloud.net`, `tdkopenapir1.qvcloud.net`, `r1-x.qvcloud.net` (tdkcloud). Werte werden in `shared_prefs/save.xml` gecacht (`ip-validity` ~7 Tage).

**MQTT-Credential-Dekodierung** (des `param`-Felds): Jeder Wert ist `base64` → **AES-256-CBC** entschlüsselt, **IV = `"0000000000000000"`** (16× ASCII-`0x30`, wie beim Frame-Krypto), Ergebnis null-gepadded:
- `username` → `B_<cli-id>`
- `password` → der RS256-JWT
Der **AES-256-Schlüssel** ist **nicht** in der Lib hinterlegt (zur Laufzeit erzeugt) und wurde per Frida-Hook auf `AES_set_decrypt_key`/`AES_cbc_encrypt(enc=0)` erfasst. **Er war über alle App-Neustarts stabil** (account-gebunden), seine Ableitung ist aber noch offen – bis dahin muss er einmalig per Frida abgegriffen werden (Geheimnis, nicht im Repo).

**1. MQTT-Verbindung** zum Broker `mqttsr1.qvcloud.net:1884` (TLS):
- Protokoll `MQIsdp` (MQTT 3.1), Client-ID `app_<cli-id>_<user-id>_`
- Username `B_<cli-id>`, **Password = RS256-JWT** (Payload: `cli-id`, `cli-type:app`, `exp`, `oem-group:G0028,G0126`, `qv-rgn:1`) – beide aus dem `param`-Feld dekodiert (s. o.).
- Publish-Topic `app/ust/json/<cli-id>`, Subscribe-Topic `<cli-id>/ust/json`. Nutzlast ist JSON mit `header.command` + `content`.

**2. Signalisierungs-Kommandos** (JSON über MQTT):
- `register` → Broker bestätigt (`heartbeat.interval`, `MqttKeepAliveSec`).
- `sub-device-state` (mit `devid`) → Online-Status des Geräts.
- **`p2pconnect`** (Client → Gerät): trägt `devid`, eine selbst erzeugte **`session-flag`** (44-Zeichen-Token – identisch mit dem Token im UDP-INIT, §4c), `requ-session-id` (zufällige int32) und die **`kcpParam`** (s. u.).
- `update-netinfo` (Client → Gerät): eigene `pub-ip`/`pub-udpport` + `loc-ip`/`loc-udp-port`.
- **`p2pconnect`-Antwort** (Gerät → Client): liefert **alle Adress-Kandidaten**:
  - `loc-ip` + `loc-udpport` — LAN-Adresse des Geräts
  - `pub-ip` + `pub-udpport` — WAN-Adresse (NAT-Außenseite)
  - `utd-pub-ip` + `utd-pub-udpport` — Rendezvous-/Relay-Server (die Scaleway-IP aus §2)
  - `resp-session-id` (= `requ-session-id`), `session-flag`, `dest-port`, `kcpParam`.

Der Client punched dann UDP-INIT (§4c) mit der `session-flag` parallel an `loc`, `pub` und `utd` – exakt die drei Ziele aus dem Session-Mitschnitt.

**3. Transport = KCP.** Die `kcpParam` sind 1:1 die Konfiguration von **KCP** (github.com/skywind3000/kcp): `mode`, `sndwnd`, `rcvwnd`, `nodelay`, `interval`, `resend`, `nc`, `rto`, `fastresend`, `mtu:1200`, `kcpVersion:v1.0`. Das erklärt das seq/ack/Window-ARQ des `C1EFABFF`-Protokolls: Es ist ein **KCP-Derivat mit eigenem 28-B-Wire-Header** (Standard-KCP hat 24 B: conv/cmd/frg/wnd/ts/sn/una/len – die genaue Zuordnung zum 28-B-Header aus §4a ist der nächste Verifikationsschritt).

**Damit ist der komplette Weg zum eigenständigen Türöffner kartiert:**
Cloud-Login → `get-device-list` (duid, `data-encode-key`, `dynamic-password`, PIN-Hash) → JWT holen → MQTT-`p2pconnect` (Adressen + `session-flag`) → UDP-Hole-Punch → KCP-Session → Öffnen-Frame (AES + SHA256-Trailer) senden.

**Verbleibende Implementierungs-Unbekannte** (Stand nach Discovery- + Wire-Analyse):
- **(a) Ableitung des MQTT-Credential-AES-Keys** (§0) – account-stabil, aber laufzeit-erzeugt; bis geklärt einmalig per Frida abzugreifen. **Einziger nicht vollständig eigenständiger Baustein.**
- **(b) STUN-Austausch mit dem `natcheck`-Server** (`udp://8.211.5.8:8300`, Typ `0x54`/`0x44`) zur eigenen `pub-ip` – für den Öffner umgehbar (der Rendezvous `utd-pub-ip` ermittelt die WAN-Adresse aus dem eintreffenden UDP-Paket selbst; `update-netinfo` mit der LAN-Adresse genügt notfalls).

Alles andere ist vollständig geklärt: Bootstrap (`mst/query`), MQTT-Flow (`register`/`p2pconnect`), Credential-Dekodierung (AES-256-CBC, IV=`"0"×16`), INIT-Format (§4c), Header-Semantik (§4a, „keine Prüfsumme") und der Öffnen-Frame (§6a, bit-genau).

## 7b. Eigenständige Sende-Seite — *live verifiziert (Python-Client)*

Ein reiner Python-Client (ohne App/Frida, nur `paho-mqtt` + `cryptography`) wurde gebaut und gegen die **echte Cloud + das echte Gerät** getestet. **Live bestätigt:**

1. **Bootstrap** `GET global.qvcloud.net/mst/query` (GET mit XML-Body, **keine Auth**) → alle Server-URLs + verschlüsseltes MQTT-`param`. ✅
2. **MQTT-Credential-Dekodierung** (AES-256-CBC, IV=`"0"×16`, account-stabiler Key) → `B_<cli-id>` + JWT. ✅ (liefert live gültige Credentials)
3. **MQTT-CONNECT** (mqttsr1:1884, MQIsdp) + `register` + **`p2pconnect`** → das Gerät antwortet mit seinen aktuellen `loc`/`pub`/`utd`-Adressen + `session-flag`. ✅
4. **natcheck-STUN** (`8.211.5.8:8300`, Typ `0x54`): Request mit Nonce @0x44, Antwort trägt die **eigene öffentliche IP als ASCII-String @0x4c** + Port @0x5c. ✅ (getestet: NAT ist port-preserving)
5. **Hole-Punch**: 164-B-INIT (Typ `0x88`, `session-flag` + Ziel-IP-String + Port + Kandidaten-Index @0x38) parallel an `loc`/`pub`/`utd`. Der **Rendezvous echot das INIT** (Antwort-Flag @0x2e=1, eigene Nonce zurückgespiegelt) und relayt den **App-CONNECT-Handshake**. ✅

**Session-Handshake** (aus `open.pcap`, verstanden): nach dem CONNECT sendet der Client einen 28-B-**SYN** (`src=0, dst=<client-id>`), das Gerät antwortet mit `src=<client-id>, dst=<device-id>, ack=1` (verrät seine ID), dann bestätigt der Client. Danach Datenpakete `src=<device-id>, dst=<client-id>`.

**Update (paketgenauer App-Vergleich):** Ein gleichzeitiger tcpdump+MQTT-Mitschnitt eines echten App-Öffnens zeigte, dass **auch die App keinen direkten Punch zum Gerät bekommt** – der **`utd`-Rendezvous ist ein voller Daten-Relay** (die gesamte Session, 1,09 MB, lief über ihn). Damit wurden die letzten Bausteine geknackt und **live gegen das echte Gerät verifiziert**:

6. **Relay-Datenpfad:** Verkehr läuft über `utd-pub-ip:utd-pub-udpport`. ✅
7. **Bidirektionaler CONNECT-Handshake:** eingehende INIT-`rf=0` müssen mit **`rf=1` geechot** werden (nicht nur selbst `rf=0` senden). ✅
8. **Header-Prüfsumme = Internet-Checksum** (RFC 1071, aus `TDK_F_SYS_CheckSum` disassembliert): Ones-complement-Summe der 16-Bit-Wörter über den 28-B-Header, gefaltet, invertiert → Feld 6 `[csum | len]`. Erklärt rückwirkend „f6_lo+seq=konstant" (die Prüfsumme kompensiert seq). Kontrollpakete tragen `win_hi=0xffff`. ✅
9. **KCP-Session-Handshake:** 28-B-SYN (`s=0,d=<client-id>`) → SYN-ACK (`s=<client-id>,d=<device-id>,ack=1`) → ACK. **Live etabliert** – das Gerät akzeptiert den SYN und **ackt anschließend meine Datenpakete** (BW-Test + Öffnen-Frame, `ack` läuft korrekt mit). ✅

**Verbleibender Blocker – App-Session-Layer:** Das Gerät **ackt** den Öffnen-Frame auf KCP-Ebene, **verarbeitet** ihn aber nicht auf App-Ebene und sendet nach der SYN-ACK **keine eigenen Daten** (kein Downstream-Handshake/Video). Der Vergleich mit dem erfolgreichen Mitschnitt zeigt die App-Session-Struktur im Byte-Stream: BW-Test → Setup-Frames (`typ=0xFE clen=1`, `typ=0x00 clen=0`) → `opendoor` → `typ=0x07`-Close, mit fortlaufender App-`msg-id` (3,4,5,6,7). Entscheidend: Der **App-Frame-Kopf trägt bei `@0x2a` eine 3-Byte-Session-ID**, die über alle Frames einer Session konstant ist (`0x09c63b` bzw. `0x48442e` in zwei Sessions) und **client-generiert** ist – sie leitet sich nicht per Hash/CRC aus der `session-flag` ab. Ohne die korrekte Session-ID (und den vollständigen Session-Open-Ablauf) ignoriert der App-Parser des Geräts den `opendoor`.

**Nächster Schritt:** Frida-Hook auf die App-Frame-Erzeugung (`tdkcloud::KcpLinkConn`/`IQVCGIConfig`), um die Herkunft der `@0x2a`-Session-ID und den genauen Session-Open-Ablauf zu klären. Die gesamte Transport-Schicht (Discovery → Relay-Punch → KCP-Session) ist **live verifiziert**; es fehlt nur noch dieser App-Session-Layer.

## 8. Artefakte

- `tools/p2p_decode.py` — konsolidierter Dekoder (pcap → H.264 + JSON + Türöffnen-Erkennung), verifiziert
- `downloads/p2p-capture/session.pcap` — vollständiger Live-View-Mitschnitt
- `downloads/p2p-capture/decoded/stream.h264`, `session.mp4`, `frame120.jpg` — dekodiertes Video
- `downloads/p2p-capture/decoded/control.json` — entschlüsselter Steuerkanal
- `downloads/p2p-open/open.pcap` — Mitschnitt eines echten Türöffnen-Vorgangs
- `scratchpad/frida_aeskey.py`, `frida_mode.py` — AES-Key/IV/Modus (Herkunft des Keys)
