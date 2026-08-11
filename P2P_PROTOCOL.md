# P2P-Transportprotokoll (`C1EFABFF`) — Reverse-Engineering-Stand

Dokumentiert das proprietäre UDP-P2P-Protokoll der Balter-EVO-2 / Qualvision-Quvii-Plattform (native Libs `libqv-p2p-v2.so`, `liblive_player.so`), über das **Video UND Gerätebefehle (Türöffnen)** laufen. Die Cloud-HTTPS-API (`qvcloud.net`) macht nur Login/Geräteliste/Schlösser – siehe [`PROTOCOL.md`](PROTOCOL.md); Steuerung/Video gehen ausschließlich über diesen Tunnel.

> Stand 2026-08-12. Basis: ein vollständiger tcpdump-Mitschnitt einer echten Live-Session (`downloads/p2p-capture/session.pcap`, 2801 Pakete / 2756× `C1EFABFF`). „Bestätigt" = direkt aus dem Mitschnitt; „vermutet" = plausibel, aber nicht endgültig verifiziert.

## 1. Aufzeichnungsmethode

Frida-Hooks auf `sendto/recvfrom` scheitern: die native Lib nutzt vermutlich **direkte Syscalls** an libc vorbei. Zuverlässig ist **tcpdump auf dem Gerät** (root):

```
adb shell "su -c 'timeout 30 tcpdump -i any -s0 -w /sdcard/cap.pcap udp'"
```

Analyse dependency-frei in Python: `scratchpad/pcap_analyze.py`, `pcap_analyze2.py` (Linktype 276 = LINUX_SLL2).

## 2. Netzwerk-Topologie

| Rolle | Adresse (Beispiel-Session) | Bemerkung |
|---|---|---|
| Client (Telefon) | `192.168.0.184:56775` | dynamischer Quellport |
| Gerät (Klingel, Elternhaus) | `146.52.36.168:45269` | öffentliche IP + dyn. Port, per NAT-Hole-Punch direkt erreicht |
| Rendezvous-Server | `195.154.119.43:15017` | Scaleway Paris; nur für den Hole-Punch, **kein** Video-Relay |

Der gesamte **Video-Bulk (≈1,86 MB/30 s) läuft direkt Gerät→Telefon**, nicht über die Cloud. Bei fehlgeschlagenem Hole-Punch existiert vermutlich ein Relay-Fallback (nicht in diesem Mitschnitt).

## 3. Session-Ablauf (Zeitleiste aus dem Mitschnitt)

```
t=0.000  TX Telefon -> Rendezvous UND Gerät:  164-B INIT (identisch, parallel)   [Hole-Punch]
t=0.062  RX Gerät -> Telefon:                 164-B INIT (Echo)
t=0.106  RX Rendezvous -> Telefon:            164-B INIT (Echo)
t=1.104  RX Gerät -> Telefon:                 28-B  Kontrollpaket (Stream beginnt)
t=1.105  RX Gerät -> Telefon:                 1448-B Datenpakete (Byte-Stream, Offset 0x115…)
t=1.113  TX Telefon -> Gerät:                 28-B  ACKs (bestätigen empfangene Offsets)
…        bidirektionaler zuverlässiger Byte-Stream, Gerät sendet Video, Telefon ackt
```

## 4. Pakettypen

Alle Pakete beginnen mit dem 4-Byte-Magic **`C1 EF AB FF`** (als LE-uint32 gelesen: `0xFFABEFC1`).

### 4a. INIT / Hole-Punch (164 Byte) — *bestätigt*

Telefon sendet dies zu Session-Beginn **gleichzeitig** an Rendezvous und Geräte-IP; beide Gegenstellen echoen es zurück (NAT-Loch öffnen).

```
c1efabff  00000000 00000000 00000000 00000000 00000000 0000  a400  ffffffff  88 000000
          └─────────── Session-IDs = 0 (noch keine) ────────┘  └len┘  └no-sess┘ └typ┘
          … 00000000 00000000 00010000 02001200 00000000 88f6a602   (Body, ~variabel)
```

- `a400` = uint16 **0x00A4 = 164** (Gesamtlänge)
- `ffffffff` = „keine Session" (Handshake)
- `88` = **Pakettyp** (Connect/Login-Request); erscheint auch als App-Handshake-Typ im Stream (§6)
- Zwei aufeinanderfolgende INITs unterscheiden sich nur im letzten Wort (`…88f6a602` vs `…89f6a602`) → laufender Zähler/Nonce.

### 4b. Kontroll-/ACK-Paket (28 Byte) — *bestätigt*

Header = **7× LE-uint32**, kein Payload.

```
TX-ACK Telefon->Gerät:  [0]FFABEFC1 [1]7D000035 [2]05000002 [3]000001ED [4]<offset-ack> [5]<flags> [6]<misc>
RX-Ctrl Gerät->Telefon: [0]FFABEFC1 [1]05000002 [2]7D000035 [3]<offset>    [4]000001ED  [5]00001900 [6]<checksum>
```

### 4c. Datenpaket (bis 1448 Byte) — *bestätigt*

28-Byte-Header (wie oben) + **bis zu 1420 Byte Payload** (Video-/Tunnel-Daten).

```
[0]FFABEFC1 [1]05000002(src) [2]7D000035(dst) [3]<byte-offset> [4]000001ED(msg-id) [5]00001900 [6]<checksum> | <payload…>
```

## 5. Header-Felder (28 Byte)

| # | Offset | Beispiel | Bedeutung | Status |
|---|---|---|---|---|
| 0 | 0 | `0xFFABEFC1` | Magic (Bytes `C1 EF AB FF`) | bestätigt |
| 1 | 4 | `0x05000002` / `0x7D000035` | **src-Verbindungs-ID** (Sender) | bestätigt |
| 2 | 8 | `0x7D000035` / `0x05000002` | **dst-Verbindungs-ID** (Empfänger) | bestätigt |
| 3 | 12 | `0x115, 0x6a1, 0xc2d…` (Daten) | **Byte-Offset** im Stream (+1420/Paket); bei ACK steht hier die msg-id | bestätigt |
| 4 | 16 | `0x1ED` | **Message-/Stream-ID** (konstant je Stream); bei ACK der bestätigte Offset | bestätigt |
| 5 | 20 | Daten `0x1900`; ACK `0xffff0d00`… | Länge/Empfangsfenster (Daten) bzw. Flags (ACK) | vermutet |
| 6 | 24 | variabel | Prüfsumme / Per-Paket-Nonce | vermutet |

- Die IDs in Feld 1/2 (`0x05000002`, `0x7D000035`) **tauschen je Richtung** → es sind (src-id, dst-id) der jeweiligen Verbindungshälfte, im Handshake ausgehandelt.
- **Zuverlässigkeit:** Datenpakete tragen einen fortlaufenden **Byte-Offset** (Schrittweite = Payload-Größe 1420). Der Empfänger schickt für jeden empfangenen Offset ein 28-Byte-ACK mit genau diesem Offset in Feld 4 → offset-basiertes ARQ (custom-TCP-über-UDP), kein reines Paket-Sequencing.

## 6. Anwendungsschicht IM Byte-Stream — *teilweise entschlüsselt*

Reassembliert man den Downstream nach Offset, beginnt er mit einem **App-Handshake** (Typ `88`, wie im INIT) und enthält früh einen **40-Zeichen-Token**:

```
…88… 01010002 0012…  ff63a702 00000000 60000000
767674 33646a68726573637078767675646f797961657569386f776b6d77696778706e6c676d6a
= "vvt3djhrescpxvvudoyyaeui8owkmwigxpnlgmj"
```

- Dieser Token ist mit hoher Wahrscheinlichkeit der **Stream-Key / die Session-Kennung** (entspricht dem CGI `get.device.streamkey`).
- Danach folgt der eigentliche Medien-/CGI-Tunnel. Aus früherer Analyse (siehe `PROTOCOL.md`/Notes):
  - **Steuer-/CGI-Teil** (u.a. `/tdkcgi` `set.device.opendoor`, RTSP-Setup) ist **AES-256-CBC**-verschlüsselt: Key = `<data-encode-key>` aus der Cloud-Geräteliste (32 ASCII-Bytes), IV = `"0000000000000000"`.
  - **Medien-Payload** ist **unverschlüsseltes H.264 (Annex-B)** (verifiziert: 352×280, Main, via `avcodec_send_packet` gedumpt).

## 7. Bestätigt vs. offen

**Bestätigt:** UDP-Transport (Magic, 28-B-Header, src/dst-ID, offset-basiertes ARQ mit ACK), Hole-Punch-Ablauf über Rendezvous+Gerät, INIT-Paket-Grundstruktur, App-Handshake mit Token, Krypto (AES-256-CBC-Steuerkanal, Key/IV bekannt; Video-Payload H.264 im Klartext).

**Offen / nächste Schritte für die Reimplementierung:**
1. **Verbindungs-IDs aushandeln:** Wie werden `0x05000002` / `0x7D000035` im INIT/App-Handshake vergeben? (Token → ID-Zuweisung dekodieren.)
2. **Rendezvous ansprechen:** Wie erfährt der Client Geräte-IP:Port und Rendezvous-Adresse? (Vermutlich Cloud-Call vor dem Hole-Punch, z. B. `get.device.streamkey`/Location — noch mitzuschneiden.)
3. **Feld 5/6 klären:** Fenster/Flags und Prüfsummen-Algorithmus.
4. **Stream-Anforderung:** genaues Kommando im (AES-)Steuerkanal, um „live" (Kanal 1) zu starten.
5. **Reassembly → Medien-Demux:** RTSP/RTP-Rahmen im Byte-Stream isolieren, H.264 extrahieren.

## 8. Artefakte

- `downloads/p2p-capture/session.pcap` — vollständiger Session-Mitschnitt
- `scratchpad/pcap_analyze.py`, `pcap_analyze2.py` — Parser/Analyse (dependency-frei)
- `scratchpad/frida_dumpvideo.py` — H.264-Dump am Decoder (Beleg: Payload = Klartext-H.264)
- `scratchpad/frida_aeskey.py`, `frida_mode.py` — AES-Key/IV/Modus des Steuerkanals
