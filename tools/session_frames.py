#!/usr/bin/env python3
"""
session_frames.py - Vollstaendige App-Frame-Sequenz eines P2P-Mitschnitts.

Ergaenzung zu p2p_decode.py: geht ALLE C1EFABFF-Kanal-ID-Paare beider Richtungen
durch, reassembled je Stream, extrahiert die App-Frames und entschluesselt die
Steuerframe-Koepfe (byte9-Regel). Zeigt pro Frame Kanal, Richtung, outer_msg,
sess (@0x2a), Frame-Typ und den Klartext-Anfang -- und hebt LOGIN (typ=0x01,
'adminapp&&') sowie Tueroeffnen (typ=0xfe mit PIN-SHA256) hervor.

Gedacht fuer einen KALTSTART-Mitschnitt (tcpdump VOR dem App-Start), der den
Login-Handshake (outer_msg=1/2) mit einfaengt -- den open.pcap/punch.pcap fehlen,
weil dort erst nach dem Login mitgeschnitten wurde.

    python session_frames.py cold.pcap --key "$DATA_ENCODE_KEY"
"""
import argparse
import struct
import sys

import p2p_decode as p2p


def channel_pairs(packets):
    pairs = {}
    for pk in packets:
        pl = pk[5]
        if pl[:4] != p2p.MAGIC or len(pl) < p2p.TRANSPORT_HDR:
            continue
        f = p2p.parse_header(pl)
        if f[1] == 0:                      # id 0 = INIT/Handshake
            continue
        pairs[(f[1], f[2])] = pairs.get((f[1], f[2]), 0) + 1
    return pairs


def frame_row(fr, key):
    om = struct.unpack("<I", fr[0x18:0x1c])[0] if len(fr) > 0x1c else -1
    sess = fr[0x2a:0x2d].hex() if len(fr) > 0x2d else "??"
    body = fr[p2p.APP_HDR:]
    try:
        head, pay = p2p.decrypt_control(body, key)
    except Exception as e:
        return om, sess, None, f"<decrypt {e}>", None
    if len(head) < 14:
        return om, sess, None, "<kurz>", None
    typ = head[0]
    ok, payload, _tr = p2p.verify_trailer(head, pay)
    asc = payload[:48].decode("latin1", "replace").replace("\x00", ".")
    tag = ""
    if typ == 0x01 or payload[:10] == b"adminapp&&":
        tag = "  <<< LOGIN"
    elif typ == 0xfe and head[11] == 80:
        door, lock = payload[0], payload[2]
        tag = f"  <<< TUEROEFFNEN door={door} lock={lock}"
    trailer = "ok" if ok else "FEHLER"
    return om, sess, (typ, head[13], head[11], head[9]), asc, (trailer, tag)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--key", required=True, help="data-encode-key (32 ASCII-Zeichen)")
    ap.add_argument("--max", type=int, default=16, help="max Frames pro Kanal")
    args = ap.parse_args()
    key = args.key.encode()
    if len(key) != 32:
        sys.exit(f"Key muss 32 Bytes sein, ist {len(key)}")

    packets = [p for p in p2p.read_pcap(args.pcap) if p[5][:4] == p2p.MAGIC]
    pairs = channel_pairs(packets)
    print(f"{len(packets)} C1EFABFF-Pakete, {len(pairs)} Kanal-Paare\n")

    for (src, dst), n in sorted(pairs.items(), key=lambda x: -x[1]):
        stream, isn, gaps = p2p.reassemble(packets, src, dst)
        frames = p2p.app_frames(stream)
        if not frames:
            continue
        rows = [frame_row(fr, key) for _, fr in frames]
        has_login = any(r[4] and "LOGIN" in r[4][1] for r in rows)
        is_video = len(frames) > 60 and not has_login
        label = "VIDEO-Downstream" if is_video else "STEUERKANAL"
        mark = "   <<<<< LOGIN-KANAL" if has_login else ""
        print(f"[{src:#010x} -> {dst:#010x}] {len(frames)} App-Frames "
              f"({label}), isn={isn}, gaps={len(gaps)}{mark}")
        if is_video:
            print()
            continue
        for (pos, _fr), (om, sess, hd, asc, extra) in list(zip(frames, rows))[:args.max]:
            if hd is None:
                print(f"    @{pos:6} om={om:3} sess={sess}  {asc}")
                continue
            typ, bmsg, clen, plen = hd
            trailer, tag = extra
            print(f"    @{pos:6} om={om:3} sess={sess} typ=0x{typ:02x} bmsg={bmsg:2} "
                  f"clen={clen:3} plen={plen:3} trailer={trailer} | {asc!r}{tag}")
        print()


if __name__ == "__main__":
    main()
