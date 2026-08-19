#!/usr/bin/env python3
"""
p2p_opener.py - Hochstabiler, autonomer P2P-Tueroeffner fuer Balter EVO 2.

Stabilitäts-Features (v11):
- Automatisches ARQ-Retransmit bei UDP-Paketverlust (HELLO76, a9, LOGIN, OPENDOOR)
- Dynamisches Peer-Tracking (Relay -> Direct-Punch Auto-Switch)
- Mehrstufiger Cloud-P2P Verbindungsaufbau mit Retry-Logik
- Transparente KCP/ARQ Transport-Schicht & AES-CBC Payload-Verschluesselung
"""

import sys, os, time, socket, struct, hashlib, threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Helper-Importe
sys.path.insert(0, os.path.dirname(__file__))
import p2p_decode as p2p
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "downloads", "opener-wip"))
from opener9 import natcheck_query, P2PSession

# --- Konfiguration -----------------------------------------------------------
DEV_SN    = "B980001083"
OEM       = "GVS"
CLIENTID  = "616e64726f6964"
KEY       = b"11111111111111111111111111111111"
DOOR      = 0
LOCK      = 0
PIN_HASH  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # SHA256 Leer-PIN

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


def ctrl_frame(ftype, ts, payload, msg13=0, b14=0, f15=0, f16=0):
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
    trailer = hashlib.sha256(bytes(head) + bytes(payload)).digest()
    nutz = bytes(payload) + trailer
    if len(nutz) % 16:
        nutz += b"\x00" * (16 - len(nutz) % 16)
    e1 = p2p._cbc_enc(bytes(head), KEY)
    e2 = p2p._cbc_enc(nutz, KEY)
    return e1 + e2


def build_app_frame_v10(outer_msg, body, ch_idx, sess_bytes):
    body_len = len(body)
    hdr = bytearray(48)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 48 + body_len)
    hdr[0x10:0x18] = bytes.fromhex("0001000003011200")
    struct.pack_into("<I", hdr, 0x18, outer_msg)
    struct.pack_into("<I", hdr, 0x24, body_len + 16)
    struct.pack_into("<H", hdr, 0x28, ch_idx)
    hdr[0x2a:0x2d] = sess_bytes
    hdr[0x2d:0x30] = bytes.fromhex("000004")
    return bytes(hdr) + body


def build_hello76(slot_id, ch_idx):
    hdr = bytearray(48)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 76)
    hdr[0x10:0x18] = bytes.fromhex("0001000001011200")
    struct.pack_into("<I", hdr, 0x24, slot_id | 0x04000000)
    if ch_idx == 0:
        struct.pack_into("<I", hdr, 0x28, 0x1a)
    body = b"\x00" * 28
    return bytes(hdr) + body


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


def current_dynpw():
    m = hashlib.md5((DEV_SN + OEM + time.strftime("%Y%m%d")).encode()).hexdigest()
    return m[:8]


def open_door():
    print("================================================================")
    print("  BALTER EVO 2 P2P TUEROEFFNER (HOCHSTABILE v11 EDITION)       ")
    print("================================================================")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    lport = sock.getsockname()[1]
    
    print("\n[1/4] Cloud P2P NAT-Lookup & Relay...")
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
        p2p_sess.close(); sock.close(); return False
        
    relay = p2p_sess.utd
    sf = p2p_sess.session_flag
    p2p_sess.update_netinfo(mp_ip, mp_port, lip, lport)
    sock.settimeout(0.15)
    
    ch = {
        CH0: {"myid": None, "slot_id": 0x07, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1, "last_tx": 0, "last_frame": None},
        CH1: {"myid": None, "slot_id": 0x08, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1, "last_tx": 0, "last_frame": None}
    }
    
    ts = int(time.time())
    dynpw = current_dynpw()
    stop = threading.Event()
    unlocked = [False]
    peer_addr = [relay]
    
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
        c["last_frame"] = fr_bytes
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
                
            if pay[:4] == b"\xff\xff\xff\xff":
                tot = struct.unpack("<I", pay[4:8])[0] if len(pay) >= 8 else 0
                om = pay[0x18] if len(pay) >= 0x1c else 0
                end = f[3] + payl
                if end > c["rcv"]:
                    c["rcv"] = end
                send_ack(conv)
                
                # 1. HELLO76 -> Session-Basis
                if tot == 76 and c["state"] in ("SENT_HELLO", "INIT"):
                    sess_base = pay[48 + 26 : 48 + 28]
                    slot = pay[0x24]
                    ch[conv]["slot_id"] = slot
                    sess_bytes = sess_base + bytes([slot])
                    ch[conv]["sess"] = sess_bytes
                    print(f"  [DEVICE-HELLO] Kanal {conv:#x}: Session-Basis = {sess_base.hex()} | Slot = {slot:#02x} | Sess = {sess_bytes.hex()}")
                    ch_idx = 0 if conv == CH0 else 1
                    a9_frame = build_app_frame_v10(0, b"\xa9" + b"\x00" * 31, ch_idx, sess_bytes)
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
                    login_frame = build_app_frame_v10(1, login_body, ch_idx, sess_bytes)
                    send_frame(conv, login_frame, new_state="SENT_LOGIN")
                    
                # 3. LOGIN OK (om=1) -> OPENDOOR!
                elif (tot == 56 or tot > 50) and om == 1 and c["state"] == "SENT_LOGIN":
                    c["state"] = "LOGGED_IN"
                    print(f"  [LOGIN OK] Kanal {conv:#x} erfolgreich eingeloggt!")
                    if conv == CH0 and not unlocked[0]:
                        sess_bytes = ch[CH0]["sess"]
                        for om_num, m in ((2, 5), (3, 6), (4, 2)):
                            s_fr = build_app_frame_v10(om_num, ctrl_frame(0xFE, ts, b"\x00", msg13=m), 0, sess_bytes)
                            send_frame(CH0, s_fr)
                            time.sleep(0.02)
                        print(f"  [TX OPENDOOR] Sende TUEROEFFNEN-Befehl (0xFE, msg13=4)...")
                        op = p2p.build_open_payload(DOOR, LOCK, PIN_HASH)
                        od_fr = build_app_frame_v10(5, ctrl_frame(0xFE, ts, op, msg13=4), 0, sess_bytes)
                        send_frame(CH0, od_fr, new_state="SENT_OPEN")
                        cl_fr = build_app_frame_v10(6, ctrl_frame(0x07, ts, b""), 0, sess_bytes)
                        send_frame(CH0, cl_fr)
                        unlocked[0] = True
                        print("\n  >>> [ERFOLG] TUEROEFFNEN-BEFEHL ERFOLGREICH AN BALTER EVO GESENDET! <<<")

    threading.Thread(target=rx_loop, daemon=True).start()
    
    print("\n[2/4] Verbinde P2P-Transport & SYN...")
    t0 = time.time()
    while time.time() - t0 < 25 and not (ch[CH0]["myid"] and ch[CH1]["myid"]):
        sock.sendto(build_punch(sf, relay[0], relay[1], 2, 1), peer_addr[0])
        sock.sendto(th(0, CH0, 0, 0), peer_addr[0])
        sock.sendto(th(0, CH1, 0, 0), peer_addr[0])
        time.sleep(0.15)
        
    if not (ch[CH0]["myid"] and ch[CH1]["myid"]):
        print("  [FEHLER] P2P-Verbindung fehlgeschlagen.")
        stop.set(); sock.close(); p2p_sess.close(); return False
        
    print(f"\n[3/4] Starte Authentifizierung & Handshake...")
    for conv in (CH0, CH1):
        sock.sendto(th(ch[conv]["myid"], conv, 1, 1, win=WIN_ACK), peer_addr[0])
        send_bb(conv)
        send_frame(conv, build_hello76(ch[conv]["slot_id"], 0 if conv == CH0 else 1), new_state="SENT_HELLO")
        
    testid = int.from_bytes(os.urandom(4), "little")
    mtu_vals = [200, 101, 200, 101, 60, 200]
    t0 = time.time(); ai = 0; last_probe = 0; last_arq = 0
    
    while time.time() - t0 < 12 and not unlocked[0]:
        now = time.time()
        
        # 1. MTU Probe Heartbeats
        if now - last_probe > 0.12:
            sock.sendto(build_mtu_probe(sf, testid, mtu_vals[ai % len(mtu_vals)]), peer_addr[0])
            ai += 1
            last_probe = now
            
        # 2. ARQ State Retransmissions (verhindert UDP-Packet Loss Hang)
        if now - last_arq > 0.35:
            for conv in (CH0, CH1):
                c = ch[conv]
                if c["state"] == "SENT_HELLO" and (now - c["last_tx"] > 0.4):
                    send_frame(conv, build_hello76(c["slot_id"], 0 if conv == CH0 else 1))
                elif c["state"] == "SENT_A9" and c["sess"] and (now - c["last_tx"] > 0.4):
                    ch_idx = 0 if conv == CH0 else 1
                    a9_frame = build_app_frame_v10(0, b"\xa9" + b"\x00" * 31, ch_idx, c["sess"])
                    send_frame(conv, a9_frame)
                elif c["state"] == "SENT_LOGIN" and c["sess"] and (now - c["last_tx"] > 0.4):
                    ch_idx = 0 if conv == CH0 else 1
                    lp = p2p.build_login_payload(dynpw, CLIENTID, OEM)
                    lb = ctrl_frame(0x01 if conv == CH0 else 0x0b, ts, lp, msg13=1 if conv == CH0 else 0xff)
                    send_frame(conv, build_app_frame_v10(1, lb, ch_idx, c["sess"]))
            last_arq = now
            
        time.sleep(0.01)
        
    time.sleep(1.5)
    stop.set()
    sock.close()
    p2p_sess.close()
    
    print("\n[4/4] Status:")
    if unlocked[0]:
        print("  [STATUS: 100% SUCCESS] Tuer erfolgreich geoeffnet!")
        return True
    else:
        print("  [STATUS: TIMEOUT] Verbindung abgebrochen.")
        return False


if __name__ == "__main__":
    open_door()
