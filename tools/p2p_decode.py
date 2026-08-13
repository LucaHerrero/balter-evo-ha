#!/usr/bin/env python3
"""
p2p_decode.py - Balter EVO 2 / Quvii C1EFABFF-P2P-Mitschnitt dekodieren.

Nimmt einen tcpdump-Mitschnitt einer Live-Session und rekonstruiert daraus
offline den Videostrom und die Steuerkanal-Nachrichten:

  pcap -> UDP-Frames -> C1EFABFF-Transport (ARQ-Reassembly)
       -> App-Frames -> AES-Entschluesselung der ersten 64 B -> H.264 + JSON

Verifiziert gegen downloads/p2p-capture/session.pcap: 505 Frames, 352x280,
H.264 Main -> reales Kamerabild der Tuerstation.

Abhaengigkeiten: nur `cryptography` (pip install cryptography).
ffmpeg wird nur fuer den optionalen Render-Schritt gebraucht.

Der Key ist der `data-encode-key` aus der Cloud-Geraeteliste (32 ASCII-Zeichen,
NICHT base64-dekodieren). Er ist geraetespezifisch und gehoert nicht ins Repo.

Beispiel:
    python p2p_decode.py session.pcap --key "$DATA_ENCODE_KEY" -o out/
"""
import argparse
import collections
import json
import os
import re
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = bytes.fromhex("c1efabff")
TRANSPORT_HDR = 28          # 7x LE-uint32
APP_HDR = 56                # App-Frame-Kopf vor dem Body
ENC_LEN = 64                # nur die ersten 64 B des Bodys sind AES-CBC
IV = b"0" * 16              # ASCII-Nullen, konstant


# --------------------------------------------------------------------------
# pcap
# --------------------------------------------------------------------------
def read_pcap(path):
    """Liefert [(t, src, sport, dst, dport, udp_payload)] - ohne externe Libs."""
    data = open(path, "rb").read()
    if len(data) < 24:
        raise ValueError("keine pcap-Datei")
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        raise ValueError(f"unbekanntes pcap-Magic {magic:#x} (pcapng wird nicht unterstuetzt)")
    linktype = struct.unpack("<I", data[20:24])[0]
    off, out = 24, []
    while off + 16 <= len(data):
        ts_s, ts_us, incl, _orig = struct.unpack("<IIII", data[off:off + 16])
        off += 16
        raw, off = data[off:off + incl], off + incl
        # LINUX_SLL2 = 276, LINUX_SLL = 113, Ethernet = 1
        ip = {276: raw[20:], 113: raw[16:], 1: raw[14:]}.get(linktype, raw)
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:   # IPv4 + UDP
            continue
        ihl = (ip[0] & 0x0F) * 4
        udp = ip[ihl:]
        if len(udp) < 8:
            continue
        sport, dport = struct.unpack(">HH", udp[0:4])
        out.append((ts_s + ts_us / 1e6, ".".join(map(str, ip[12:16])), sport,
                    ".".join(map(str, ip[16:20])), dport, udp[8:]))
    return out


# --------------------------------------------------------------------------
# Transportschicht
# --------------------------------------------------------------------------
def parse_header(pl):
    """(magic, src_id, dst_id, seq, ack, window, csum_len)"""
    return struct.unpack("<7I", pl[:TRANSPORT_HDR])


def find_connections(packets):
    """Zaehlt die (src-id, dst-id)-Paare; das haeufigste ist der Medienkanal."""
    conns = collections.Counter()
    for _t, _s, _sp, _d, _dp, pl in packets:
        if pl[:4] != MAGIC or len(pl) < TRANSPORT_HDR:
            continue
        f = parse_header(pl)
        if f[1]:                      # id 0 = Handshake, kein Datenkanal
            conns[(f[1], f[2])] += 1
    return conns


def reassemble(packets, src_id, dst_id):
    """Offset-basiertes ARQ zusammensetzen. Liefert (bytes, isn, luecken)."""
    segs = {}
    for _t, _s, _sp, _d, _dp, pl in packets:
        if pl[:4] != MAGIC or len(pl) <= TRANSPORT_HDR:
            continue
        f = parse_header(pl)
        if (f[1], f[2]) != (src_id, dst_id):
            continue
        segs.setdefault(f[3], pl[TRANSPORT_HDR:])     # Retransmits ignorieren
    if not segs:
        return b"", 0, []
    isn = min(segs)
    buf, gaps, pos = bytearray(), [], isn
    for o in sorted(segs):
        if o < pos:                   # ueberlappendes Retransmit
            continue
        if o > pos:                   # echte Luecke -> mit Nullen fuellen
            gaps.append((pos, o - pos))
            buf.extend(b"\x00" * (o - pos))
        buf.extend(segs[o])
        pos = o + len(segs[o])
    return bytes(buf), isn, gaps


# --------------------------------------------------------------------------
# App-Schicht
# --------------------------------------------------------------------------
def app_frames(buf):
    """App-Frames: ff ff ff ff | uint32 gesamtlaenge | 48 B Kopf | Body."""
    pos, out = 0, []
    while True:
        p = buf.find(b"\xff\xff\xff\xff", pos)
        if p < 0 or p + 8 > len(buf):
            break
        ln = struct.unpack("<I", buf[p + 4:p + 8])[0]
        if APP_HDR <= ln <= 65535 and p + ln <= len(buf):
            out.append((p, buf[p:p + ln]))
            pos = p + ln
        else:
            pos = p + 4
    return out


def iter_control_frames(packets, key):
    """Steuerframes robust je EINZELPAKET extrahieren (statt per Stream-Reassembly).

    Steuerframes (LOGIN, Setup, Tueroeffnen, close) passen in ein UDP-Paket. Der
    Bandbreitentest (0xBB-Filler) belegt auf demselben Kanal ueberlappende seq-
    Bereiche, an denen reassemble() den echten App-Frame faelschlich als Retransmit
    verwirft (so verschwand frueher der LOGIN bei om=1/seq=165). Dieser Scan sucht
    daher in jedem Paket direkt nach eingebetteten `ffffffff`-App-Frames.

    Liefert je Fund ein dict: channel (src_id,dst_id), seq, outer_msg, sess (hex),
    typ, bmsg, clen, plen, trailer_ok, payload. Dedupliziert nach (channel,outer_msg)
    -- der Trailer-korrekte Treffer gewinnt gegenueber Bandbreitentest-Rauschen.
    """
    best = {}
    for _t, _s, _sp, _d, _dp, pl in packets:
        if pl[:4] != MAGIC or len(pl) < TRANSPORT_HDR:
            continue
        f = parse_header(pl)
        if f[1] == 0:
            continue
        i = pl.find(b"\xff\xff\xff\xff", TRANSPORT_HDR)
        while i >= 0 and i + APP_HDR <= len(pl):
            total = struct.unpack("<I", pl[i + 4:i + 8])[0]
            if APP_HDR <= total <= 2000 and i + total <= len(pl):
                fr = pl[i:i + total]
                head, pay = decrypt_control(fr[APP_HDR:], key)
                if len(head) >= 14:
                    ok, payload, _tr = verify_trailer(head, pay)
                    rec = {
                        "channel": (f[1], f[2]),
                        "seq": f[3] + (i - TRANSPORT_HDR),
                        "outer_msg": struct.unpack("<I", fr[0x18:0x1c])[0],
                        "sess": fr[0x2a:0x2d].hex(),
                        "typ": head[0], "bmsg": head[13],
                        "clen": head[11], "plen": head[9],
                        "trailer_ok": ok, "payload": payload,
                    }
                    k = (rec["channel"], rec["outer_msg"])
                    if k not in best or (ok and not best[k]["trailer_ok"]):
                        best[k] = rec
            i = pl.find(b"\xff\xff\xff\xff", i + 4)
    return sorted(best.values(), key=lambda r: (r["channel"], r["outer_msg"]))


def _cbc(buf, key):
    n = (len(buf) // 16) * 16
    if n < 16:
        return b""
    d = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    return d.update(buf[:n]) + d.finalize()


def _cbc_enc(buf, key):
    n = (len(buf) // 16) * 16
    if n < 16:
        return b""
    e = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()
    return e.update(buf[:n]) + e.finalize()


def decrypt_head(body, key):
    """Nur die ersten ENC_LEN Bytes sind AES-256-CBC; der Rest ist Klartext.

    Das ist die schnelle Naeherung fuer Medien-Frames (Kopf 32 B + 32 B Nutzteil
    = 64 B verschluesselt, danach Klartext-H.264). Fuer Steuerframes mit laengerem
    Nutzteil siehe decrypt_control().
    """
    n = min(ENC_LEN, (len(body) // 16) * 16)
    if n < 16:
        return body
    d = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    return d.update(body[:n]) + d.finalize() + body[n:]


def decrypt_control(body, key):
    """Vollstaendige Frame-Entschluesselung nach der byte9-Regel.

    Der Body besteht aus zwei separaten AES-256-CBC-Segmenten (je IV = "0"*16):
      - Kopf:     Bytes 0..32  (Typ, Zeitstempel, Laengen)
      - Nutzteil: Bytes 32..32+plen, wobei plen = Kopf[9]
    Bei Medien-Frames ist plen = 32 (=> 64 B insgesamt, wie decrypt_head).
    Bei Steuerframes (z.B. Tueroeffnen) ist plen groesser.

    Liefert (kopf, nutzteil) als entschluesselte Bytes.
    """
    head = _cbc(body[:32], key)
    if len(head) < 32:
        return head, b""
    plen = head[9]
    payct = body[32:32 + plen]
    return head, _cbc(payct, key)


def frame_trailer(head, payload):
    """Integritaets-Trailer eines Steuerframes: SHA256(Kopf[32] ++ Payload).

    Der Trailer ist KEINE geheime Signatur, sondern eine schlichte Pruefsumme
    ueber die (entschluesselten) Frame-Daten. Er ist damit ohne Geheimnis
    berechenbar -- Voraussetzung fuer einen eigenstaendigen Client.
    """
    import hashlib
    return hashlib.sha256(bytes(head[:32]) + bytes(payload)).digest()


def verify_trailer(head, nutzteil):
    """Prueft den Trailer eines entschluesselten Steuerframe-Nutzteils.

    Nutzteil = payload[:clen] ++ trailer[32], clen = Kopf[11].
    Liefert (ok, payload, trailer).
    """
    clen = head[11]
    payload = nutzteil[:clen]
    trailer = nutzteil[clen:clen + 32]
    return frame_trailer(head, payload) == trailer, payload, trailer


def build_control_frame(ftype, timestamp, msg_id, payload, key, flag15=0, flag16=0):
    """Baut einen kompletten (verschluesselten) Steuerframe-Body.

    Gegenstueck zu decrypt_control(): Kopf-Segment (32 B) + Nutzteil-Segment
    (payload ++ SHA256-Trailer, auf 16 gepaddet), beide AES-256-CBC (IV="0"*16).
    Verifiziert: reproduziert den aufgezeichneten Tueroeffnen-Frame bit-genau.

    payload = Kommando-Bytes OHNE Trailer.
    plen (Kopf[9]) = auf 16 aufgerundete Nutzteillaenge (payload + 32-B-Trailer).
    flag15/flag16 (Kopf[15]/[16]) = beide 1 nur beim LOGIN (typ=0x01), sonst 0.
    """
    clen = len(payload)
    nutzlen = clen + 32
    plen = nutzlen + ((16 - nutzlen % 16) % 16)   # auf 16 aufgerundet
    head = bytearray(32)
    head[0] = ftype                              # 0xFE = Steuerung, 0x01 = Login
    struct.pack_into("<I", head, 1, timestamp)   # Unix-Sekunden
    head[9] = plen                               # verschluesselte Nutzteillaenge
    head[11] = clen                              # Payload ohne Trailer
    head[13] = msg_id                            # Kommando-Nummer
    head[15] = flag15
    head[16] = flag16
    trailer = frame_trailer(head, payload)
    nutzteil = bytes(payload) + trailer
    if len(nutzteil) % 16:
        nutzteil += b"\x00" * (16 - len(nutzteil) % 16)
    return _cbc_enc(bytes(head), key) + _cbc_enc(nutzteil, key)


def build_login_payload(dynamic_password, clientid, oem="G0028G0126"):
    """Nutzteil des App-Session-LOGIN (typ=0x01), der die Steuersession
    authentifiziert. Ohne diesen Frame verwirft das Geraet spaetere Kommandos
    (z.B. Tueroeffnen) trotz gueltiger Transport-/KCP-Session.

    Aufbau: 'adminapp&&' + dynamic_password + \\0 + oem + \\0 + 'clientid=' + id + \\0
    dynamic_password stammt aus der Cloud-Geraeteliste (rotiert ~woechentlich).
    """
    if isinstance(dynamic_password, bytes):
        dynamic_password = dynamic_password.decode("ascii")
    return (b"adminapp&&" + dynamic_password.encode("ascii") + b"\x00"
            + oem.encode("ascii") + b"\x00"
            + b"clientid=" + clientid.encode("ascii") + b"\x00")


APP_FRAME_CONST_10 = bytes.fromhex("0001000003011200")   # @0x10..0x18, konstant


def build_app_frame(outer_msg, body, sess):
    """Umhuellt einen (verschluesselten) Steuerframe-Body mit dem aeusseren
    56-B-App-Frame-Kopf. Alle Laengenfelder sind aus body-len ableitbar; nur
    outer_msg und sess sind frei.

    outer_msg ist ein PRO-KANAL-UND-RICHTUNG fortlaufender App-Frame-Zaehler ab 1
    (msg1 = LOGIN, msg2 = erstes Setup, ...). In open.pcap/punch.pcap beginnt der
    sichtbare Upstream bei msg=3, weil der tcpdump erst NACH dem Login-Handshake
    (msg1/2 je Richtung) startete -- nicht weil LOGIN ueber einen anderen Kanal
    laeuft.

    sess (3 B @0x2a) ist eine CLIENT-gewaehlte Verbindungs-ID: der Client sendet
    seine App-Frames nachweislich VOR dem Geraet (open.pcap +59 ms, punch.pcap
    +104 ms), waehlt sess also selbst. Das Geraet spiegelt sie NICHT zurueck --
    seine Downstream-Frames tragen an @0x2a konstant `00 04 00`. Ob das Geraet
    sess ueberhaupt prueft (und ob ein frischer Zufallswert noetig ist) ist offen.
    """
    if isinstance(sess, str):
        sess = bytes.fromhex(sess)
    assert len(sess) == 3
    body_len = len(body)
    hdr = bytearray(56)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 56 + body_len)      # total-len
    hdr[0x10:0x18] = APP_FRAME_CONST_10
    struct.pack_into("<I", hdr, 0x18, outer_msg)          # sequenzielle msg-id
    struct.pack_into("<I", hdr, 0x24, body_len + 16)      # body+16
    hdr[0x2a:0x2d] = sess                                 # Verbindungs-ID
    hdr[0x2d:0x30] = bytes.fromhex("000004")
    struct.pack_into("<I", hdr, 0x30, body_len)           # body-len
    return bytes(hdr) + body


def build_open_payload(door, locknumber, pin_sha256_hex):
    """Nutzteil-Payload des Tueroeffnen-Kommandos (16 B Parameter + 64 B PIN-Hash).

    door/locknumber wie im Cloud-CGI set.device.opendoor; pin_sha256_hex ist
    SHA256(Tuer-PIN) als 64 Hex-Zeichen (= out-auth-code der Cloud-Geraeteliste).
    """
    p = bytearray(16)
    p[0] = door
    p[2] = locknumber
    p[3] = 1                                     # Aktion = entriegeln
    return bytes(p) + pin_sha256_hex.encode("ascii")


def media_info(plain):
    """Kopf eines entschluesselten Medien-Frames deuten."""
    if len(plain) < 52:
        return None
    return {
        "type": plain[0],                                  # 0xa0 Medien, 0xfe Steuerung
        "timestamp": struct.unpack("<I", plain[1:5])[0],
        "width": struct.unpack("<H", plain[48:50])[0],
        "height": struct.unpack("<H", plain[50:52])[0],
    }


# --------------------------------------------------------------------------
# Ausgabe
# --------------------------------------------------------------------------
NAL_NAMES = {1: "non-IDR", 5: "IDR", 6: "SEI", 7: "SPS", 8: "PPS", 9: "AUD"}


def extract_h264(plain):
    """Ab dem ersten Parametersatz schneiden; nur gueltige NAL-Typen behalten."""
    for pat in (b"\x00\x00\x00\x01\x27", b"\x00\x00\x00\x01\x67",
                b"\x00\x00\x00\x01\x28", b"\x00\x00\x00\x01\x25"):
        p = plain.find(pat)
        if p >= 0:
            return plain[p:]
    return b""


def nal_stats(buf):
    stats, p = collections.Counter(), 0
    while True:
        p = buf.find(b"\x00\x00\x00\x01", p)
        if p < 0:
            break
        if p + 4 < len(buf):
            stats[buf[p + 4] & 0x1F] += 1
        p += 4
    return stats


def extract_json(plain):
    """JSON-Objekte aus dem Steuerkanal herausziehen (laengster Treffer je Start)."""
    found, seen = [], set()
    for m in re.finditer(rb'\{"[a-zA-Z_-]', plain):
        seg = plain[m.start():m.start() + 20000]
        end = seg.find(b"\x00")
        txt = (seg[:end] if end > 0 else seg).decode("utf-8", "replace")
        # groesste balancierte Klammerstruktur ab hier
        depth, cut = 0, None
        for i, ch in enumerate(txt):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    cut = i + 1
                    break
        if cut:
            cand = txt[:cut]
            try:
                obj = json.loads(cand)
            except ValueError:
                continue
            k = cand[:80]
            if k not in seen:
                seen.add(k)
                found.append(obj)
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--key", required=True,
                    help="data-encode-key aus der Cloud-Geraeteliste (32 ASCII-Zeichen)")
    ap.add_argument("-o", "--outdir", default=".")
    args = ap.parse_args()

    key = args.key.encode()
    if len(key) != 32:
        sys.exit(f"Key muss 32 Bytes sein, ist {len(key)}")
    os.makedirs(args.outdir, exist_ok=True)

    packets = read_pcap(args.pcap)
    print(f"pcap: {len(packets)} UDP-Pakete, "
          f"{sum(1 for p in packets if p[5][:4] == MAGIC)} davon C1EFABFF")

    conns = find_connections(packets)
    if not conns:
        sys.exit("kein C1EFABFF-Datenkanal gefunden")
    print("\nVerbindungen (src-id -> dst-id):")
    for (s, d), n in conns.most_common(6):
        print(f"  {s:08x} -> {d:08x}: {n} Pakete")

    (src_id, dst_id), _ = conns.most_common(1)[0]
    stream, isn, gaps = reassemble(packets, src_id, dst_id)
    print(f"\nDownstream {src_id:08x} -> {dst_id:08x}: {len(stream)} B "
          f"(ISN {isn}), {len(gaps)} Luecken ({sum(g[1] for g in gaps)} B fehlend)")
    if gaps:
        print("  ACHTUNG: Luecken wurden mit Nullen gefuellt -> Dekodierfehler moeglich")

    frames = app_frames(stream)
    covered = sum(len(f) for _, f in frames)
    print(f"App-Frames: {len(frames)} ({100 * covered / max(1, len(stream)):.1f} % abgedeckt)")

    plain = bytearray()
    kinds = collections.Counter()
    dims = collections.Counter()
    for _pos, f in frames:
        p = decrypt_head(f[APP_HDR:], key)
        plain.extend(p)
        info = media_info(p)
        if info:
            kinds[info["type"]] += 1
            if 0 < info["width"] <= 4096 and 0 < info["height"] <= 4096:
                dims[(info["width"], info["height"])] += 1
    print(f"Frame-Typen: " + ", ".join(
        f"{'Medien' if k == 0xa0 else 'Steuerung' if k == 0xfe else hex(k)}={n}"
        for k, n in kinds.most_common(4)))
    if dims:
        (w, h), n = dims.most_common(1)[0]
        print(f"Aufloesung: {w}x{h} (in {n} Frames)")

    h264 = extract_h264(bytes(plain))
    vpath = os.path.join(args.outdir, "stream.h264")
    open(vpath, "wb").write(h264)
    stats = nal_stats(h264)
    print(f"\nH.264: {len(h264)} B -> {vpath}")
    print("  NAL-Typen: " + ", ".join(
        f"{NAL_NAMES.get(t, t)}={n}" for t, n in sorted(stats.items()) if t in NAL_NAMES))

    objs = extract_json(bytes(plain))
    if objs:
        jpath = os.path.join(args.outdir, "control.json")
        with open(jpath, "w", encoding="utf-8") as fh:
            json.dump(objs, fh, ensure_ascii=False, indent=2)
        print(f"\nSteuerkanal: {len(objs)} JSON-Objekte -> {jpath}")

    # Upstream (Telefon->Geraet): Steuerkommandos, u.a. Tueroeffnen
    up_id = (dst_id, src_id)
    upstream, _, _ = reassemble(packets, *up_id)
    upframes = app_frames(upstream)
    if upframes:
        print(f"\nUpstream {up_id[0]:08x} -> {up_id[1]:08x}: "
              f"{len(upframes)} Steuerframes")
        for pos, f in upframes:
            head, pay = decrypt_control(f[APP_HDR:], key)
            if len(head) < 14:
                continue
            ok, payload, _tr = verify_trailer(head, pay)
            chk = "Trailer OK" if ok else "Trailer FEHLER"
            hexpay = re.search(rb'[0-9a-f]{64}', payload)   # SHA256 als Hex-ASCII
            tag = ""
            if hexpay:
                door, lock = payload[0], payload[2]
                tag = (f"  <== TUEROEFFNEN door={door} locknumber={lock} "
                       f"pin_sha256={hexpay.group().decode()}")
            print(f"  @{pos} typ={head[0]:#04x} plen={head[9]} [{chk}]{tag}")

    print(f"\nRendern:  ffmpeg -f h264 -r 17 -i {vpath} -c:v libx264 -pix_fmt yuv420p out.mp4")


if __name__ == "__main__":
    main()
