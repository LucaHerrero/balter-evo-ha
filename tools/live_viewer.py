#!/usr/bin/env python3
"""
live_viewer.py - Hochstabiler Balter EVO 2 Live-Video & Snapshot-Extraktor (v11).

Stabilitäts-Features:
- Dynamisches Peer-Tracking & Relay/Direct Auto-Switching
- Automatisches ARQ-Retransmit bei UDP-Paketverlust (HELLO76, a9, LOGIN)
- Robuste Cloud-P2P Verbindung mit automatischen Retries
- Direkte H.264 MP4-Videoclip- und JPEG-Snapshot-Erzeugung
"""

import sys, os, time, socket, struct, hashlib, threading, subprocess, shutil

sys.path.insert(0, os.path.dirname(__file__))
import p2p_decode as p2p
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "downloads", "opener-wip"))
from opener9 import natcheck_query, P2PSession

# Geraetedaten & Keys.
#
# dynamic_password UND data_encode_key rotieren (~woechentlich) und muessen
# frisch aus der Cloud-Geraeteliste kommen. Datei (Standard: creds.json neben
# diesem Skript, oder Pfad in $BALTER_CREDS) mit den Feldern der Geraeteliste:
#   {"dynamic_password": "...", "data_encode_key": "..."}
# Ctrl-Key == Media-Key == data_encode_key (auf diesem Geraet).
import json

OEM      = "G0028G0126"          # byte-verifiziert aus dem App-LOGIN
CLIENTID = "e4d73be5e26e9a83"    # dito -- NICHT hex("android")


def load_creds():
    path = os.environ.get("BALTER_CREDS") or os.path.join(os.path.dirname(__file__), "creds.json")
    if not os.path.exists(path):
        sys.exit(f"[FEHLER] Keine Zugangsdaten: {path} fehlt.\n"
                 f"         Erwartet JSON mit dynamic_password + data_encode_key\n"
                 f"         (frisch aus der Cloud-Geraeteliste -- beide rotieren).")
    d = json.load(open(path, encoding="utf-8"))
    dynpw, key = d.get("dynamic_password"), d.get("data_encode_key")
    if not dynpw or not key:
        sys.exit(f"[FEHLER] {path}: dynamic_password/data_encode_key fehlen.")
    return dynpw, key.encode("ascii")


DYNPW, KEY_CTRL = load_creds()
KEY_MEDIA = KEY_CTRL

CH0 = 0x01000000
CH1 = 0x02000001

WIN_ACK  = 0xffff0900
WIN_DATA = 0x00001900
WIN_BB   = 0x00000500
MAGIC    = b"\xc1\xef\xab\xff"


def inet_cksum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += struct.unpack("<H", data[i:i + 2])[0]
    if len(data) % 2:
        s += data[-1]
    s = (s >> 16) + (s & 0xffff); s = s + (s >> 16)
    return (~s) & 0xffff


def th(src_id, dst_id, seq, ack, payload=b"", win=None):
    if win is None:
        win = WIN_DATA if payload else 0xffff4100
    hdr = bytearray(struct.pack("<7I", 0xFFABEFC1, src_id, dst_id, seq, ack, win,
                                ((28 + len(payload)) << 16) & 0xFFFF0000))
    struct.pack_into("<H", hdr, 24, inet_cksum(bytes(hdr)))
    return bytes(hdr) + payload


def ctrl_frame(ftype, ts, payload, msg13=0, b14=0, f15=0, f16=0, b17=0):
    clen = len(payload)
    nutzlen = clen + 32
    plen = nutzlen + ((16 - nutzlen % 16) % 16)
    head = bytearray(32)
    head[0] = ftype
    struct.pack_into("<I", head, 1, ts)
    head[9] = plen
    head[11] = clen
    head[13] = msg13
    head[14] = b14
    head[15] = f15
    head[16] = f16
    if b17:
        head[17] = b17
    trailer = hashlib.sha256(bytes(head) + bytes(payload)).digest()
    nutz = bytes(payload) + trailer
    if len(nutz) % 16:
        nutz += b"\x00" * (16 - len(nutz) % 16)
    e1 = p2p._cbc_enc(bytes(head), KEY_CTRL)
    e2 = p2p._cbc_enc(nutz, KEY_CTRL)
    return e1 + e2


def build_app_frame(outer_msg, body, ch_idx, sess_bytes):
    """56-B-Kopf + Body -- byte-genau wie die App (siehe tools/verify_frames.py).

    Der Kopf traegt die Bodylaenge zweimal: als body+16 @0x24 und roh @0x30.
    Die frueheren 48-B-Koepfe schoben den Body 8 B nach vorn -> das Geraet las
    Muell als Laenge, ackte transportseitig, verwarf den Frame aber im App-Layer.
    """
    body_len = len(body)
    hdr = bytearray(56)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 56 + body_len)
    hdr[0x10:0x18] = bytes.fromhex("0001000003011200")
    struct.pack_into("<I", hdr, 0x18, outer_msg)
    struct.pack_into("<I", hdr, 0x24, body_len + 16)
    struct.pack_into("<H", hdr, 0x28, ch_idx)
    hdr[0x2a:0x2d] = sess_bytes
    hdr[0x2d:0x30] = bytes.fromhex("000004")
    struct.pack_into("<I", hdr, 0x30, body_len)
    return bytes(hdr) + body


def build_hello76(slot_id, ch_idx):
    """76 B = 56-B-Kopf + 20-B-Body. Alles ab 0x2c ist in der App Heap-Muell
    und wird vom Geraet ignoriert."""
    hdr = bytearray(56)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 76)
    hdr[0x10:0x18] = bytes.fromhex("0001000001011200")
    struct.pack_into("<I", hdr, 0x24, 20 + 16)
    struct.pack_into("<I", hdr, 0x28, slot_id | 0x04000000)
    return bytes(hdr) + b"\x00" * 20


def build_a9_body(ch_idx):
    """32-B-Klartext-Setupbody: [0]=0xa9, [9]=Stromtyp (0=Video, 2=Audio)."""
    b = bytearray(32)
    b[0] = 0xa9
    if ch_idx:
        b[9] = 0x02
    return bytes(b)


def build_mtu_probe(session_flag, testid, aval):
    b = bytearray(164)
    b[0:4] = MAGIC
    struct.pack_into("<I", b, 4, 136)
    b[0x20] = 0x88
    struct.pack_into("<I", b, 0x38, testid & 0xffffffff)
    sf = session_flag.encode()[:63]
    b[0x44:0x44 + len(sf)] = sf
    struct.pack_into("<I", b, 0xa0, aval & 0xffffffff)
    b[0x2e] = 0
    return bytes(b)


def build_punch(session_flag, rip, rport, cid=2, tid=1):
    b = bytearray(164)
    b[0:4] = MAGIC
    struct.pack_into("<I", b, 4, 136)
    b[0x20] = 0x88
    b[0x2a:0x2c] = struct.pack("<H", 0x1234)
    b[0x2e] = 0
    struct.pack_into("<I", b, 0x38, cid)
    struct.pack_into("<I", b, 0x3c, tid)
    ip_b = socket.inet_aton(rip)
    b[0x40:0x44] = ip_b
    sf = session_flag.encode()[:63]
    b[0x44:0x44 + len(sf)] = sf
    struct.pack_into("<H", b, 0x84, rport)
    return bytes(b)


def capture_live(duration=6.0):
    print("================================================================")
    print("  BALTER EVO 2 LIVE-STREAM & SNAPSHOT VIEWER (v11 STABILITY)   ")
    print("================================================================")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    lport = sock.getsockname()[1]
    
    print("\n[1/5] Cloud P2P NAT-Lookup & Relay...")
    mp_ip, mp_port = natcheck_query(sock)
    lip = sock.getsockname()[0]
    
    p2p_sess = P2PSession()
    for attempt in range(3):
        try:
            p2p_sess.connect()
            time.sleep(1.2)
            p2p_sess.p2pconnect()
            if p2p_sess.got_addr.wait(timeout=12):
                break
        except Exception as e:
            print(f"  P2P Verbindungsversuch {attempt+1} fehlgeschlagen: {e}")
            time.sleep(1.0)
            
    if not p2p_sess.got_addr.is_set():
        print("  [FEHLER] Timeout bei Cloud-Verbindung nach Retries.")
        p2p_sess.close(); sock.close(); return None
        
    relay = p2p_sess.utd
    sf = p2p_sess.session_flag
    p2p_sess.update_netinfo(mp_ip, mp_port, lip, lport)
    sock.settimeout(0.15)
    
    ch = {
        CH0: {"myid": None, "slot_id": 0x07, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1, "last_tx": 0},
        CH1: {"myid": None, "slot_id": 0x08, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1, "last_tx": 0}
    }
    
    ts = int(time.time())
    dynpw = DYNPW
    stop = threading.Event()
    peer_addr = [relay]
    rx_stream_segments = {} # seq -> payload
    logged_in = threading.Event()
    
    def send_ack(conv):
        peer = peer_addr[0]
        c = ch[conv]
        wnd = (0xffff - ((c["rcv"] - 1) & 0xffff)) & 0xffff
        if wnd < 0x1000: wnd = 0xffff
        field5 = (wnd << 16) | 0x0900
        sock.sendto(th(c["myid"], conv, c["sent_pos"], c["rcv"], win=field5), peer)

    def send_bb(conv):
        peer = peer_addr[0]
        c = ch[conv]
        size = min(c["bb"], 1420)
        sock.sendto(th(c["myid"], conv, c["sent_pos"], c["rcv"], b"\xbb" * size, win=WIN_BB), peer)
        c["bb"] = min(c["bb"] + 100, 1420)

    def send_frame(conv, fr_bytes, new_state=None):
        peer = peer_addr[0]
        c = ch[conv]
        sock.sendto(th(c["myid"], conv, c["sent_pos"], c["rcv"], fr_bytes, win=WIN_DATA), peer)
        c["sent_pos"] += len(fr_bytes)
        c["last_tx"] = time.time()
        if new_state:
            c["state"] = new_state

    def rx_loop():
        while not stop.is_set():
            try:
                data, src = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            if data[:4] != MAGIC or len(data) < 28:
                continue
                
            if len(data) == 164:
                rf = data[0x2e]
                if rf == 0:
                    echo = bytearray(data); echo[0x2e] = 1
                    sock.sendto(bytes(echo), src)
                elif rf == 1:
                    peer_addr[0] = src
                continue
                
            f = p2p.parse_header(data)
            conv = f[1]
            if conv not in ch or f[2] in (0, conv):
                continue
            c = ch[conv]
            if not c["myid"]:
                c["myid"] = f[2]
                peer_addr[0] = src
                print(f"  [SYN-ACK] Kanal {conv:#x} verbunden! (myid={f[2]:#x})")
                
            if f[4] != c["ack"]:
                c["ack"] = f[4]
                
            payl = len(data) - 28
            if payl <= 0:
                continue
                
            pay = data[28:]
            if f[5] == WIN_BB or pay[:4] == b"\xbb\xbb\xbb\xbb":
                send_bb(conv)
                send_ack(conv)
                continue
                
            # Alle Datenpakete auf CH0 erfassen
            if conv == CH0 and (f[5] & 0xffff) == 0x1900:
                rx_stream_segments[f[3]] = pay
                
            if pay[:4] == b"\xff\xff\xff\xff":
                tot = struct.unpack("<I", pay[4:8])[0] if len(pay) >= 8 else 0
                om = pay[0x18] if len(pay) >= 0x1c else 0
                end = f[3] + payl
                if end > c["rcv"]:
                    c["rcv"] = end
                send_ack(conv)
                
                # 1. HELLO76 -> Session-Basis
                if tot == 76 and c["state"] in ("SENT_HELLO", "INIT"):
                    # Session-Basis = die letzten 2 B des Geraete-HELLO (absolut 74..76).
                    # Das Slot-Byte ist unser eigenes (0x07/0x08), nicht aus dem Echo.
                    sess_base = pay[74:76]
                    slot = c["slot_id"]
                    sess_bytes = sess_base + bytes([slot])
                    ch[conv]["sess"] = sess_bytes
                    print(f"  [DEVICE-HELLO] Kanal {conv:#x}: Session-Basis = {sess_base.hex()} | Slot = {slot:#02x} | Sess = {sess_bytes.hex()}")
                    ch_idx = 0 if conv == CH0 else 1
                    a9_frame = build_app_frame(0, build_a9_body(ch_idx), ch_idx, sess_bytes)
                    send_frame(conv, a9_frame, new_state="SENT_A9")
                    
                # 2. a9-Echo (om=0) -> LOGIN
                elif (tot == 56 or payl == 144) and om == 0 and c["state"] == "SENT_A9":
                    print(f"  [144B STUFE 2] Geraet hat a9 bestaetigt auf Kanal {conv:#x}!")
                    sess_bytes = ch[conv]["sess"]
                    ch_idx = 0 if conv == CH0 else 1
                    lp = p2p.build_login_payload(dynpw, CLIENTID, OEM)
                    if conv == CH0:
                        login_body = ctrl_frame(0x01, ts, lp, msg13=1, f15=1, f16=1)
                    else:
                        login_body = ctrl_frame(0x0b, ts, lp, msg13=0xff, b14=0xff)
                    login_frame = build_app_frame(1, login_body, ch_idx, sess_bytes)
                    send_frame(conv, login_frame, new_state="SENT_LOGIN")
                    
                # 3. LOGIN OK (om=1) -> Stream Start
                elif (tot == 56 or tot > 50) and om == 1 and c["state"] == "SENT_LOGIN":
                    c["state"] = "LOGGED_IN"
                    print(f"  [LOGIN OK] Kanal {conv:#x} eingeloggt!")
                    if conv == CH0:
                        sess_bytes = ch[CH0]["sess"]
                        # Es gibt KEIN Stream-Start-Kommando: das Geraet schickt den
                        # Videostrom nach akzeptiertem CH0-LOGIN von selbst (in
                        # live_real.pcap ~2,2 s nach dem LOGIN, direkt nach seinem
                        # 0xFE msg13=2 mit Payload 00 01). Die App antwortet danach
                        # nur noch mit msg13=5, 6, 2 -- genau das hier.
                        print("  [LOGIN OK] Warte auf Geraete-Konfig (0xFE msg13=2)...")
                        for om_num, m in ((2, 5), (3, 6), (4, 2)):
                            s_fr = build_app_frame(om_num, ctrl_frame(0xFE, ts, b"\x00", msg13=m), 0, sess_bytes)
                            send_frame(CH0, s_fr)
                            time.sleep(0.02)
                        logged_in.set()

    threading.Thread(target=rx_loop, daemon=True).start()
    
    print("\n[2/5] Verbinde P2P-Transport & SYN...")
    t0 = time.time()
    while time.time() - t0 < 25 and not (ch[CH0]["myid"] and ch[CH1]["myid"]):
        sock.sendto(build_punch(sf, relay[0], relay[1], 2, 1), peer_addr[0])
        sock.sendto(th(0, CH0, 0, 0), peer_addr[0])
        sock.sendto(th(0, CH1, 0, 0), peer_addr[0])
        time.sleep(0.15)
        
    if not (ch[CH0]["myid"] and ch[CH1]["myid"]):
        print("  [FEHLER] P2P-Verbindung fehlgeschlagen.")
        stop.set(); sock.close(); p2p_sess.close(); return None
        
    print(f"\n[3/5] Sende Authentifizierung...")
    for conv in (CH0, CH1):
        sock.sendto(th(ch[conv]["myid"], conv, 1, 1, win=WIN_ACK), peer_addr[0])
        send_bb(conv)
        send_frame(conv, build_hello76(ch[conv]["slot_id"], 0 if conv == CH0 else 1), new_state="SENT_HELLO")
        
    testid = int.from_bytes(os.urandom(4), "little")
    mtu_vals = [200, 101, 200, 101, 60, 200]
    t0 = time.time(); ai = 0; last_probe = 0; last_arq = 0
    
    print("\n[4/5] Warte auf Stream-Freigabe...")
    while time.time() - t0 < 10 and not logged_in.is_set():
        now = time.time()
        if now - last_probe > 0.12:
            sock.sendto(build_mtu_probe(sf, testid, mtu_vals[ai % len(mtu_vals)]), peer_addr[0])
            ai += 1
            last_probe = now
        if now - last_arq > 0.35:
            for conv in (CH0, CH1):
                c = ch[conv]
                if c["state"] == "SENT_HELLO" and (now - c["last_tx"] > 0.4):
                    send_frame(conv, build_hello76(c["slot_id"], 0 if conv == CH0 else 1))
                elif c["state"] == "SENT_A9" and c["sess"] and (now - c["last_tx"] > 0.4):
                    ch_idx = 0 if conv == CH0 else 1
                    send_frame(conv, build_app_frame(0, build_a9_body(ch_idx), ch_idx, c["sess"]))
                elif c["state"] == "SENT_LOGIN" and c["sess"] and (now - c["last_tx"] > 0.4):
                    ch_idx = 0 if conv == CH0 else 1
                    lp = p2p.build_login_payload(dynpw, CLIENTID, OEM)
                    lb = (ctrl_frame(0x01, ts, lp, msg13=1, f15=1, f16=1) if conv == CH0
                          else ctrl_frame(0x0b, ts, lp, msg13=0xff, b14=0xff))
                    send_frame(conv, build_app_frame(1, lb, ch_idx, c["sess"]))
            last_arq = now
        time.sleep(0.01)
        
    print(f"  [STREAM ACTIVE] Zeichne Live-Videostrom auf ({duration:.1f}s)...")
    t_start = time.time()
    while time.time() - t_start < duration:
        now = time.time()
        if now - last_probe > 0.12:
            sock.sendto(build_mtu_probe(sf, testid, mtu_vals[ai % len(mtu_vals)]), peer_addr[0])
            ai += 1
            last_probe = now
        time.sleep(0.01)
        
    # Sende Teardown/Close frame
    if ch[CH0]["sess"]:
        send_frame(CH0, build_app_frame(7, ctrl_frame(0x07, ts, b""), 0, ch[CH0]["sess"]))
        
    stop.set()
    sock.close()
    p2p_sess.close()
    
    print(f"\n[5/5] Verarbeite Video-Frames ({len(rx_stream_segments)} Segmente empfangen)...")
    
    # Reassemble Byte Stream
    if rx_stream_segments:
        sorted_seqs = sorted(rx_stream_segments.keys())
        isn = sorted_seqs[0]
        buf, pos = bytearray(), isn
        for seq in sorted_seqs:
            if seq < pos: continue
            if seq > pos: buf.extend(b"\x00" * (seq - pos))
            buf.extend(rx_stream_segments[seq])
            pos = seq + len(rx_stream_segments[seq])
        raw_stream = bytes(buf)
    else:
        raw_stream = b""
        
    print(f"  Stream-Gesamtgroesse: {len(raw_stream)} Bytes")
    
    h264_candidates = []
    if raw_stream:
        frames = p2p.app_frames(raw_stream)
        for key in (KEY_MEDIA, KEY_CTRL):
            plain = bytearray()
            for _, f in frames:
                p = p2p.decrypt_head(f[56:], key)
                plain.extend(p)
            h = p2p.extract_h264(bytes(plain))
            if len(h) > 500: h264_candidates.append(h)
        h_raw = p2p.extract_h264(raw_stream)
        if len(h_raw) > 500: h264_candidates.append(h_raw)
        
    if not h264_candidates:
        print(f"  [FEHLER] Kein dekodierbares Live-H.264 im Stream "
              f"({len(rx_stream_segments)} Segmente, {len(raw_stream)} Bytes empfangen).")
        print("  -> Der Live-Empfang lieferte keine gueltigen Videodaten. Es wird")
        print("     bewusst KEIN Konserven-Bild mehr geschrieben (frueherer Fallback).")
        return None
    # Ersten Kandidaten mit SPS UND IDR nehmen, nicht den laengsten: der
    # unentschluesselte Rohstrom ist immer am laengsten und trotzdem unbrauchbar.
    def _decodable(buf):
        kinds, p = set(), buf.find(b"\x00\x00\x00\x01")
        while p >= 0:
            if p + 4 < len(buf):
                kinds.add(buf[p + 4] & 0x1f)
            p = buf.find(b"\x00\x00\x00\x01", p + 4)
        return 7 in kinds and 5 in kinds

    h264_best = next((h for h in h264_candidates if _decodable(h)),
                     max(h264_candidates, key=len))


    h264_path = os.path.abspath("live_feed.h264")
    jpg_path  = os.path.abspath("live_snapshot.jpg")
    mp4_path  = os.path.abspath("live_video.mp4")
    
    with open(h264_path, "wb") as fh:
        fh.write(h264_best)
        
    # 1. Snapshot JPG generieren
    subprocess.run(["ffmpeg", "-y", "-i", h264_path, "-vframes", "1", jpg_path], capture_output=True)
    
    # 2. MP4 Video generieren
    subprocess.run(["ffmpeg", "-y", "-f", "h264", "-r", "20", "-i", h264_path, "-c:v", "libx264", "-pix_fmt", "yuv420p", mp4_path], capture_output=True)
    
    if os.path.exists(jpg_path) and os.path.getsize(jpg_path) > 0:
        print(f"\n  >>> [ERFOLG] SNAPSHOT ERZEUGT: {jpg_path} ({os.path.getsize(jpg_path)} Bytes) <<<")
    if os.path.exists(mp4_path) and os.path.getsize(mp4_path) > 0:
        print(f"  >>> [ERFOLG] VIDEO-CLIP ERZEUGT: {mp4_path} ({os.path.getsize(mp4_path)} Bytes) <<<")
        
    return jpg_path, mp4_path


if __name__ == "__main__":
    capture_live(duration=6.0)
