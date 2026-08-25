import sys, os, time, logging
sys.path.insert(0, r'c:\Users\luca\Desktop\Balter - Kopie\custom_components\balter_evo')
import p2p

print("=== Debugging p2p_open_door_sync with MTU probes ===")
p2p_sess = p2p.CloudP2PSession(os.environ["BALTER_CLIENT_ID"], os.environ.get("BALTER_DUID", "<duid>"))
print("1. Connecting MQTT...")
p2p_sess.connect()
time.sleep(1.2)
print("2. Sending p2pconnect...")
p2p_sess.p2pconnect()
got = p2p_sess.got_addr.wait(timeout=10)
print(f"3. got_addr: {got}, LOC: {p2p_sess.loc}, PUB: {p2p_sess.pub}, UTD: {p2p_sess.utd}")

if got:
    sock = p2p.socket.socket(p2p.socket.AF_INET, p2p.socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(0.15)
    relay = p2p_sess.utd
    sf = p2p_sess.session_flag
    
    mp_ip, mp_port = p2p._natcheck_query(sock)
    lip = sock.getsockname()[0]
    lport = sock.getsockname()[1]
    p2p_sess.update_netinfo(mp_ip, mp_port, lip, lport)
    
    ch = {
        p2p.CH0: {"myid": None, "slot_id": 0x07, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1},
        p2p.CH1: {"myid": None, "slot_id": 0x08, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1}
    }
    
    peer_addr = [relay]
    unlocked = [False]
    stop = p2p.threading.Event()
    ts = int(time.time())
    
    def send_ack(conv, peer):
        c = ch[conv]
        wnd = (0xFFFF - ((c["rcv"] - 1) & 0xFFFF)) & 0xFFFF
        if wnd < 0x1000: wnd = 0xFFFF
        field5 = (wnd << 16) | 0x0900
        sock.sendto(p2p.build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], win=field5), peer)

    def send_bb(conv, peer):
        c = ch[conv]
        size = min(c["bb"], 1420)
        sock.sendto(p2p.build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], b"\xbb" * size, win=p2p.WIN_BB), peer)
        c["bb"] = min(c["bb"] + 100, 1420)

    def rx():
        while not stop.is_set():
            try:
                data, src = sock.recvfrom(2048)
            except Exception:
                continue
            if data[:4] != p2p.MAGIC:
                continue
            if len(data) == 164:
                rf = data[0x2E]
                if rf == 0:
                    echo = bytearray(data); echo[0x2E] = 1
                    sock.sendto(bytes(echo), src)
                elif rf == 1:
                    peer_addr[0] = src
                    print(f"  [MTU ECHO rf=1] from {src}")
                continue
            f = p2p.parse_header(data)
            conv = f[1]
            if conv not in ch or f[2] in (0, conv):
                continue
            c = ch[conv]
            if not c["myid"]:
                c["myid"] = f[2]
                peer_addr[0] = src
                print(f"  [SYN-ACK] conv={conv:#x} myid={f[2]:#x} src={src}")
                
            payl = len(data) - 28
            if payl <= 0: continue
            pay = data[28:]
            if f[5] == p2p.WIN_BB or pay[:4] == b"\xbb\xbb\xbb\xbb":
                send_bb(conv, src)
                send_ack(conv, src)
                continue
                
            if pay[:4] == b"\xff\xff\xff\xff":
                tot = p2p.struct.unpack("<I", pay[4:8])[0] if len(pay) >= 8 else 0
                om = pay[0x18] if len(pay) >= 0x1C else 0
                end = f[3] + payl
                if end > c["rcv"]: c["rcv"] = end
                send_ack(conv, src)
                print(f"  [APP] conv={conv:#x} tot={tot} om={om} state={c['state']}")
                
                if tot == 76 and c["state"] == "SENT_HELLO":
                    sess_base = pay[48 + 26 : 48 + 28]
                    slot = pay[0x24]
                    ch[conv]["sess"] = sess_base + bytes([slot])
                    print(f"  [DEVICE-HELLO] sess={ch[conv]['sess'].hex()}")
                    ch_idx = 0 if conv == p2p.CH0 else 1
                    a9 = p2p.build_app_frame(0, b"\xa9" + b"\x00" * 31, ch_idx, ch[conv]["sess"])
                    sock.sendto(p2p.build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], a9, win=p2p.WIN_DATA), src)
                    c["sent_pos"] += len(a9)
                    c["state"] = "SENT_A9"
                elif (tot == 56 or len(pay) == 144) and om == 0 and c["state"] == "SENT_A9":
                    print(f"  [144B OK] conv={conv:#x}")
                    ch_idx = 0 if conv == p2p.CH0 else 1
                    lp = p2p.build_login_payload("5af4b767", "616e64726f6964", "GVS")
                    lb = p2p.ctrl_frame(0x01 if conv == p2p.CH0 else 0x0B, ts, lp, msg13=1 if conv == p2p.CH0 else 0xFF)
                    lfr = p2p.build_app_frame(1, lb, ch_idx, ch[conv]["sess"])
                    sock.sendto(p2p.build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], lfr, win=p2p.WIN_DATA), src)
                    c["sent_pos"] += len(lfr)
                    c["state"] = "SENT_LOGIN"
                elif (tot == 56 or tot > 50) and om == 1 and c["state"] == "SENT_LOGIN":
                    print(f"  [LOGIN OK] conv={conv:#x}")
                    c["state"] = "LOGGED_IN"
                    if conv == p2p.CH0 and not unlocked[0]:
                        sess_bytes = ch[p2p.CH0]["sess"]
                        for om_num, m in ((2, 5), (3, 6), (4, 2)):
                            s_fr = p2p.build_app_frame(om_num, p2p.ctrl_frame(0xFE, ts, b"\x00", msg13=m), 0, sess_bytes)
                            sock.sendto(p2p.build_transport_hdr(c["myid"], p2p.CH0, c["sent_pos"], c["rcv"], s_fr, win=p2p.WIN_DATA), src)
                            c["sent_pos"] += len(s_fr)
                            time.sleep(0.02)
                        op = p2p.build_open_payload(0, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                        od_fr = p2p.build_app_frame(5, p2p.ctrl_frame(0xFE, ts, op, msg13=4), 0, sess_bytes)
                        sock.sendto(p2p.build_transport_hdr(c["myid"], p2p.CH0, c["sent_pos"], c["rcv"], od_fr, win=p2p.WIN_DATA), src)
                        c["sent_pos"] += len(od_fr)
                        cl_fr = p2p.build_app_frame(6, p2p.ctrl_frame(0x07, ts, b""), 0, sess_bytes)
                        sock.sendto(p2p.build_transport_hdr(c["myid"], p2p.CH0, c["sent_pos"], c["rcv"], cl_fr, win=p2p.WIN_DATA), src)
                        unlocked[0] = True
                        print("  >>> [SUCCESS] UNLOCK SENT! <<<")

    p2p.threading.Thread(target=rx, daemon=True).start()
    
    print("4. Punching...")
    t0 = time.time()
    while time.time() - t0 < 15 and not (ch[p2p.CH0]["myid"] and ch[p2p.CH1]["myid"]):
        sock.sendto(p2p.build_punch(sf, relay[0], relay[1], 2, 1), relay)
        sock.sendto(p2p.build_transport_hdr(0, p2p.CH0, 0, 0), relay)
        sock.sendto(p2p.build_transport_hdr(0, p2p.CH1, 0, 0), relay)
        time.sleep(0.15)
        
    print(f"5. Connected: {ch[p2p.CH0]['myid'] is not None}, {ch[p2p.CH1]['myid'] is not None}")
    
    if ch[p2p.CH0]["myid"] and ch[p2p.CH1]["myid"]:
        peer = peer_addr[0]
        for conv in (p2p.CH0, p2p.CH1):
            sock.sendto(p2p.build_transport_hdr(ch[conv]["myid"], conv, 1, 1, win=p2p.WIN_ACK), peer)
            send_bb(conv, peer)
            h76 = p2p.build_hello76(ch[conv]["slot_id"], 0 if conv == p2p.CH0 else 1)
            sock.sendto(p2p.build_transport_hdr(ch[conv]["myid"], conv, 1, 1, h76, win=p2p.WIN_DATA), peer)
            ch[conv]["sent_pos"] += len(h76)
            ch[conv]["state"] = "SENT_HELLO"
            
        testid = int.from_bytes(os.urandom(4), "little")
        mtu_vals = [200, 101, 200, 101, 60, 200]
        t0 = time.time(); ai = 0; last_probe = 0
        while time.time() - t0 < 8 and not unlocked[0]:
            now = time.time()
            if now - last_probe > 0.12:
                sock.sendto(p2p.build_mtu_probe(sf, testid, mtu_vals[ai % len(mtu_vals)]), peer_addr[0])
                ai += 1
                last_probe = now
            time.sleep(0.01)
            
    stop.set()
    sock.close()
    p2p_sess.close()
    print("Final result:", unlocked[0])
