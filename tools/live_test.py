#!/usr/bin/env python3
"""live_test.py - Scharfer Test der P2P-Schicht gegen das echte Geraet.

Faehrt exakt den Codepfad der HA-Integration (custom_components/balter_evo/p2p.py)
mit frischen Cloud-Zugangsdaten aus tools/creds.json (siehe fetch_creds.py).

    python tools/live_test.py                 # Video/Snapshot -- oeffnet NICHTS
    python tools/live_test.py --seconds 8     # laenger mitschneiden
    python tools/live_test.py --open-door --yes-really-open-the-door

Der Videotest ist harmlos: er baut die P2P-Session auf, loggt sich ein und
empfaengt den Strom. Der Tueroeffner-Test entriegelt die Tuer PHYSISCH und
verlangt deshalb beide Flags.

Erwartetes Verhalten nach dem Frameformat-Fix (P2P_PROTOCOL.md Abschnitt 9):
  CH.. device HELLO, sess=...  -> a9
  CH.. a9 acknowledged         -> LOGIN
  CH.. LOGIN accepted
  video stream is flowing      (kommt ~2 s nach dem LOGIN von selbst)
Bleibt es bei "a9 acknowledged" ohne "LOGIN accepted", verwirft das Geraet den
LOGIN weiterhin app-seitig -- dann sind die Zugangsdaten alt (beide rotieren)
oder es liegt eine weitere Frame-Abweichung vor.
"""
from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import sys
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PKG_DIR = os.path.join(REPO, "custom_components", "balter_evo")

_pkg = types.ModuleType("balter_evo")
_pkg.__path__ = [PKG_DIR]
sys.modules["balter_evo"] = _pkg
p2p = importlib.import_module("balter_evo.p2p")


def load_creds(path: str) -> dict:
    if not os.path.exists(path):
        sys.exit(f"[FEHLER] {path} fehlt -- erst 'python tools/fetch_creds.py' laufen lassen.")
    d = json.load(open(path, encoding="utf-8"))
    for k in ("duid", "dynamic_password", "data_encode_key"):
        if not d.get(k):
            sys.exit(f"[FEHLER] {path}: Feld {k} fehlt.")
    return d


def count_slices(h264: bytes) -> int:
    """Anzahl der Bild-NALs (IDR + P) -- entspricht den Videobildern."""
    n, p = 0, h264.find(b"\x00\x00\x00\x01")
    while p >= 0:
        if p + 4 < len(h264) and (h264[p + 4] & 0x1F) in (1, 5):
            n += 1
        p = h264.find(b"\x00\x00\x00\x01", p + 4)
    return n


def write_video(captured: list[bytes], args) -> None:
    """Bestes dekodierbares H.264 aus dem Lauf als MP4 schreiben."""
    import subprocess

    best = next((h for h in captured if p2p.h264_is_decodable(h)), None)
    if best is None:
        print("  [Video] kein dekodierbarer H.264-Kandidat -- kein MP4 geschrieben")
        return

    frames = count_slices(best)
    # Der Strom laeuft erst ~2 s nach dem LOGIN an; daraus die Bildrate schaetzen,
    # damit der Clip in Echtzeit statt in Zeitlupe/Zeitraffer laeuft.
    window = max(1.0, args.seconds - 2.0)
    fps = max(5.0, min(30.0, frames / window))
    raw = os.path.splitext(args.video)[0] + ".h264"
    with open(raw, "wb") as fh:
        fh.write(best)

    cmd = ["ffmpeg", "-y", "-f", "h264", "-r", f"{fps:.2f}", "-i", raw]
    if args.clip > 0:
        cmd += ["-t", str(args.clip)]
    cmd += ["-c:v", "libx264", "-pix_fmt", "yuv420p", args.video]
    r = subprocess.run(cmd, capture_output=True, timeout=60)
    if r.returncode == 0 and os.path.exists(args.video) and os.path.getsize(args.video) > 0:
        print(f"  [Video] {frames} Bilder, ~{fps:.1f} fps -> {args.video} "
              f"({os.path.getsize(args.video)} B)")
    else:
        print(f"  [Video] ffmpeg fehlgeschlagen: {r.stderr.decode('utf-8', 'replace')[-300:]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--creds", default=os.path.join(HERE, "creds.json"))
    ap.add_argument("--seconds", type=float, default=6.0, help="Aufnahmedauer (Videotest)")
    ap.add_argument("--out", default=os.path.join(HERE, "live_snapshot.jpg"))
    ap.add_argument("--open-door", action="store_true", help="TUER PHYSISCH OEFFNEN")
    ap.add_argument("--yes-really-open-the-door", action="store_true",
                    help="Sicherheitsbestaetigung fuer --open-door")
    ap.add_argument("--pin", default="", help="Tuer-PIN (sonst out_auth_code aus creds.json)")
    ap.add_argument("--dump", metavar="DIR",
                    help="Rohstrom + H.264 zur Fehlersuche in DIR ablegen")
    ap.add_argument("--video", metavar="PATH", nargs="?", const="",
                    help="zusaetzlich einen MP4-Clip schreiben (Standard: tools/live_video.mp4)")
    ap.add_argument("--clip", type=float, default=0.0,
                    help="MP4 auf diese Laenge in Sekunden kuerzen (0 = alles)")
    args = ap.parse_args()
    if args.video == "":
        args.video = os.path.join(HERE, "live_video.mp4")

    # force=True: paho/ssl koennen den root-Logger schon bestueckt haben, dann
    # waere basicConfig() ein stiller No-Op und wir saehen die Zustandsmeldungen nicht.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S", stream=sys.stdout, force=True)
    logging.getLogger("balter_evo").setLevel(logging.INFO)
    c = load_creds(args.creds)
    duid = c["duid"]
    locks = c.get("locks") or []
    door = locks[0]["door"] if locks else 1
    lock = locks[0]["locknumber"] if locks else 1

    print("=" * 68)
    print(f"  Geraet {duid} ({c.get('name','?')})   door={door} lock={lock}")
    print(f"  dynpw {len(c['dynamic_password'])} Z. | key {len(c['data_encode_key'])} Z. "
          f"| client_id {c.get('client_id')} | oem {c.get('oem')}")
    print("=" * 68)

    if not c.get("client_id"):
        sys.exit("[FEHLER] creds.json enthaelt keine client_id -- fetch_creds.py neu laufen lassen.")
    kwargs = dict(client_id=c["client_id"],
                  oem=c.get("oem") or p2p.DEFAULT_OEM)

    if args.open_door:
        if not args.yes_really_open_the_door:
            sys.exit("[ABBRUCH] --open-door entriegelt die Tuer physisch. "
                     "Zusaetzlich --yes-really-open-the-door setzen.")
        pin = args.pin
        pin_hash = None
        if not pin:
            pin_hash = c.get("out_auth_code")
            if not pin_hash:
                sys.exit("[FEHLER] Weder --pin noch out_auth_code in creds.json.")
            print("  (nutze out_auth_code aus creds.json als PIN-Hash)")
        print("\n>>> TUEROEFFNEN in 3 s -- Strg+C bricht ab ...")
        time.sleep(3)
        t0 = time.time()
        ok = p2p.p2p_open_door_sync(duid, c["dynamic_password"], pin,
                                    door=door, locknumber=lock,
                                    data_encode_key=c["data_encode_key"],
                                    pin_sha256=pin_hash, **kwargs)
        print(f"\nErgebnis: {'OK' if ok else 'FEHLGESCHLAGEN'}  ({time.time()-t0:.1f} s)")
        return 0 if ok else 1

    if args.dump:
        os.makedirs(args.dump, exist_ok=True)
        _orig_frames, _orig_h264 = p2p.extract_app_frames, p2p.extract_h264

        def _spy_frames(data):
            path = os.path.join(args.dump, "raw_stream.bin")
            with open(path, "wb") as fh:
                fh.write(data)
            frames = _orig_frames(data)
            covered = sum(len(f) for _, f in frames)
            print(f"  [dump] Rohstrom {len(data)} B -> {path}")
            print(f"  [dump] App-Frames: {len(frames)} "
                  f"({100 * covered / max(1, len(data)):.1f} % abgedeckt)")
            return frames

        def _spy_h264(plain):
            h = _orig_h264(plain)
            with open(os.path.join(args.dump, "plain.bin"), "wb") as fh:
                fh.write(plain)
            print(f"  [dump] entschluesselt {len(plain)} B -> H.264 {len(h)} B")
            return h

        p2p.extract_app_frames, p2p.extract_h264 = _spy_frames, _spy_h264

    # Den fertig dekodierten H.264-Strom mitnehmen, um daraus ein MP4 zu bauen.
    captured: list[bytes] = []
    if args.video:
        _h264_orig = p2p.extract_h264

        def _keep(plain):
            h = _h264_orig(plain)
            if h:
                captured.append(h)
            return h

        p2p.extract_h264 = _keep

    print(f"\n[Videotest] {args.seconds:.0f} s mitschneiden -- es wird nichts geschaltet.\n")
    t0 = time.time()
    jpg = p2p.p2p_get_snapshot_sync(duid, c["dynamic_password"],
                                    data_encode_key=c["data_encode_key"],
                                    duration=args.seconds, **kwargs)
    dt = time.time() - t0
    if jpg:
        with open(args.out, "wb") as fh:
            fh.write(jpg)
        print(f"\nERFOLG: Standbild {len(jpg)} B -> {args.out}  ({dt:.1f} s)")
        if args.video:
            write_video(captured, args)
        return 0
    print(f"\nFEHLGESCHLAGEN: kein dekodierbares Bild ({dt:.1f} s). "
          f"Siehe die Zustandsmeldungen oben.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
