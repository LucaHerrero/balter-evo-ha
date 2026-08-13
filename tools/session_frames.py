#!/usr/bin/env python3
"""
session_frames.py - Vollstaendige Steuer-Frame-Sequenz eines P2P-Mitschnitts.

Ergaenzung zu p2p_decode.py: extrahiert die Steuerframes (LOGIN, Setup,
Tueroeffnen, close) robust JE EINZELPAKET (p2p_decode.iter_control_frames),
statt sich auf die Stream-Reassembly zu verlassen -- der Bandbreitentest
(0xBB-Filler) belegt ueberlappende seq-Bereiche, an denen reassemble() den
echten App-Frame verwirft (so verschwand frueher der LOGIN bei om=1).

Zeigt pro Kanal die Frames mit outer_msg, sess (@0x2a), Typ und Klartext-Anfang
und hebt LOGIN (typ=0x01/0x0b, 'adminapp&&') sowie Tueroeffnen (clen=80) hervor.

    python session_frames.py cold.pcap --key "$DATA_ENCODE_KEY"
"""
import argparse
import collections
import sys

import p2p_decode as p2p


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--key", required=True, help="data-encode-key (32 ASCII-Zeichen)")
    args = ap.parse_args()
    key = args.key.encode()
    if len(key) != 32:
        sys.exit(f"Key muss 32 Bytes sein, ist {len(key)}")

    packets = [p for p in p2p.read_pcap(args.pcap) if p[5][:4] == p2p.MAGIC]
    print(f"{len(packets)} C1EFABFF-Pakete\n")

    frames = p2p.iter_control_frames(packets, key)
    by_chan = collections.OrderedDict()
    for r in frames:
        by_chan.setdefault(r["channel"], []).append(r)

    for (src, dst), rows in by_chan.items():
        has_login = any(r["typ"] in (0x01, 0x0b) or r["payload"][:10] == b"adminapp&&"
                        for r in rows)
        # nur Frames mit gueltigem Trailer sind echte Steuerframes; der Rest ist
        # Bandbreitentest-/Handshake-Rauschen (om=0, typ zufaellig)
        real = [r for r in rows if r["trailer_ok"]]
        if not real:
            continue
        mark = "   <<<<< LOGIN-KANAL" if has_login else ""
        print(f"[{src:#010x} -> {dst:#010x}] {len(real)} Steuerframes{mark}")
        for r in sorted(real, key=lambda r: r["outer_msg"]):
            asc = r["payload"][:44].decode("latin1", "replace").replace("\x00", ".")
            tag = ""
            if r["typ"] in (0x01, 0x0b) or r["payload"][:10] == b"adminapp&&":
                tag = "  <<< LOGIN"
            elif r["typ"] == 0xfe and r["clen"] == 80:
                p = r["payload"]
                tag = f"  <<< TUEROEFFNEN door={p[0]} lock={p[2]}"
            print(f"    om={r['outer_msg']:2} seq={r['seq']:5} sess={r['sess']} "
                  f"typ=0x{r['typ']:02x} bmsg={r['bmsg']:2} clen={r['clen']:3} "
                  f"plen={r['plen']:3} | {asc!r}{tag}")
        print()


if __name__ == "__main__":
    main()
