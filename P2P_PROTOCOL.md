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
| Gerät (Klingel, Elternhaus) | `146.52.36.168:45269` | öffentliche IP + dyn. Port, per NAT-Hole-Punch direkt erreicht |
| Gerät im Eltern-LAN | `192.168.178.143:45269` | **private** Adresse – der Client punched parallel dorthin (ICE-artig) |
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
| 6 | 24 | 2× LE-uint16 | `[0..1]` Prüfsumme, `[2..3]` **Gesamtlänge des UDP-Payloads** |

> **Korrektur gegenüber früheren Fassungen dieses Dokuments:** Feld 3 ist der Sende-Offset und Feld 4 die ACK-Nummer – nicht „Offset bzw. msg-id". Der scheinbar konstante Wert `0x1ED` in Feld 4 war schlicht die ACK-Nummer 493 in der Anfangsphase. Feld 6 ist keine reine Prüfsumme, sondern enthält in den oberen 16 Bit die Paketlänge.

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
c1efabff 00000000 00000000 00000000 00000000 00000000 0000 a400   <- Transport-Header, IDs = 0
ffffffff 88000000 …                                              <- App-Frame (siehe §5)
00 01 00 00 …                                                    <- Byte @0x2e: 0 = Anfrage, 1 = Antwort
… 88f6a602 …                                                     <- Transaktions-Nonce (Echo trägt ihn zurück)
… 767674 33646a68…                                               <- 38-Zeichen-Token (Stream-Key)
```

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
+50  32 B    Trailer      Signatur/MAC, Ableitung noch offen
```

Verifiziert: Der Hash im abgefangenen Frame ist exakt `SHA256(<Tür-PIN>)` – identisch mit dem Hash im Cloud-Pfad (`PROTOCOL.md`/Notes) und mit dem `out-auth-code` der Geräteliste. `door`/`locknumber` entsprechen den Feldern des Cloud-CGI `set.device.opendoor`. Das Kommando läuft also **nicht** über die Cloud, sondern durch den P2P-Tunnel – wie in 5h vorhergesagt.

`tools/p2p_decode.py` erkennt das automatisch und gibt aus (Hash hier gekürzt):
`@900 typ=0xfe plen=112  <== TUEROEFFNEN door=1 locknumber=1 pin_sha256=<64 hex>`

**Offen:** Der 32-B-Trailer (Feld `+50`) ist kein naheliegender Hash (getestet: SHA256 über param/hash/key/Kombinationen – kein Treffer). Vermutlich HMAC oder Signatur mit einem Session-Geheimnis (dynamic-password?). Für einen eigenständigen Öffner muss dessen Ableitung noch geklärt werden – das ist der letzte fehlende Baustein.

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

**Offen / nächste Schritte für eine eigenständige Implementierung:**
1. **Öffnen-Trailer (32 B):** die Signatur/MAC am Ende des Kommandos ableiten – ohne sie akzeptiert das Gerät ein selbstgebautes Kommando vermutlich nicht. Kandidaten: HMAC mit `dynamic-password` oder dem INIT-Token. **Wichtigster verbleibender Baustein für den Standalone-Türöffner.**
2. **Stream-Start-Kommando:** die zwei Vorbereitungs-Frames (`plen=48`, Typ `0xFE`) vor dem Öffnen semantisch zuordnen; analog für „Live Kanal 1 starten".
3. **Adress-Discovery:** Woher bekommt der Client die WAN/LAN-Kandidaten und die Rendezvous-Adresse? Vermutlich ein Cloud-Call vor dem Punch – noch mitzuschneiden (TLS, daher Frida `SSL_write` beim Verbindungsaufbau).
4. **Prüfsumme (Transport-Feld 6, untere 16 Bit):** Algorithmus unbekannt. Für einen eigenen Client nötig, sofern das Gerät sie prüft.
5. **Sende-Seite:** ARQ/Retransmit-Timing und Fensterlogik nachbauen.

## 8. Artefakte

- `tools/p2p_decode.py` — konsolidierter Dekoder (pcap → H.264 + JSON + Türöffnen-Erkennung), verifiziert
- `downloads/p2p-capture/session.pcap` — vollständiger Live-View-Mitschnitt
- `downloads/p2p-capture/decoded/stream.h264`, `session.mp4`, `frame120.jpg` — dekodiertes Video
- `downloads/p2p-capture/decoded/control.json` — entschlüsselter Steuerkanal
- `downloads/p2p-open/open.pcap` — Mitschnitt eines echten Türöffnen-Vorgangs
- `scratchpad/frida_aeskey.py`, `frida_mode.py` — AES-Key/IV/Modus (Herkunft des Keys)
