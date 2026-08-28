"""verify_media.py - Regressionstest fuer die Medienkette des Livestreams.

Schickt synthetisches H.264 durch genau die beiden ffmpeg-Prozesse, die auch im
Betrieb laufen, und prueft beide Ausgaenge:

  * den **MJPEG-Weg** (Einzelbilder fuer die Kamera-Entity)
  * den **MPEG-TS-Weg** auf einen lokalen UDP-Port -- das ist die Quelle, aus der
    die stream-Integration von Home Assistant HLS/WebRTC macht

Faengt genau den Fehler ab, der beide Ausgaenge still totlegen kann: fehlen
ffmpeg die Stromparameter (z. B. durch ``-fflags nobuffer``), laesst sich der
Encoder nicht oeffnen und es kommt einfach nichts heraus -- ohne Fehlermeldung
an der Oberflaeche. Ab ffmpeg 9 ist das reproduzierbar.

Braucht ffmpeg und ffprobe im PATH, aber weder Netz noch Tuerstation.

    python tools/verify_media.py     # Exit 0 = beide Ausgaenge liefern
"""
from __future__ import annotations

import importlib.util
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPONENT = ROOT / "custom_components" / "balter_evo"


def _load_p2p():
    """Import p2p.py without pulling in Home Assistant or paho."""
    for name in ("homeassistant", "homeassistant.core"):
        sys.modules.setdefault(name, types.ModuleType(name))
    sys.modules["homeassistant.core"].HomeAssistant = object
    sys.modules["homeassistant"].core = sys.modules["homeassistant.core"]
    if "paho.mqtt.client" not in sys.modules:
        paho = types.ModuleType("paho")
        mqtt = types.ModuleType("paho.mqtt")
        client = types.ModuleType("paho.mqtt.client")
        client.Client = object
        client.MQTTv31 = 3
        client.CallbackAPIVersion = types.SimpleNamespace(VERSION2=2)
        paho.mqtt = mqtt
        mqtt.client = client
        sys.modules.update({"paho": paho, "paho.mqtt": mqtt, "paho.mqtt.client": client})

    pkg_name = "balter_evo_media"
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = [str(COMPONENT)]
    sys.modules[pkg_name] = pkg
    spec = importlib.util.spec_from_file_location(f"{pkg_name}.p2p", COMPONENT / "p2p.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"{pkg_name}.p2p"] = module
    spec.loader.exec_module(module)
    return module


p2p = _load_p2p()


def make_h264(seconds: int = 3) -> bytes:
    """Build a synthetic H.264 Annex B stream, like the station sends."""
    result = subprocess.run(
        ["ffmpeg", "-hide_banner", "-loglevel", "error",
         "-f", "lavfi", "-i", f"testsrc=size=320x240:rate=10:duration={seconds}",
         "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
         "-g", "10", "-pix_fmt", "yuv420p", "-f", "h264", "-"],
        capture_output=True, check=True,
    )
    return result.stdout


def free_port() -> int:
    """Return a currently free loopback UDP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def main() -> int:
    """Push a stream through both outputs and check what comes out."""
    try:
        h264 = make_h264()
    except (OSError, subprocess.CalledProcessError) as err:
        print(f"ffmpeg wird gebraucht, ist aber nicht benutzbar: {err}")
        return 1
    assert h264.startswith(b"\x00\x00\x00\x01"), "kein Annex-B-Strom"
    print(f"Testmaterial: {len(h264)} B H.264, {p2p._count_pictures(h264)} Bilder")

    # Den UDP-Port binden -- genau das macht sonst die stream-Integration.
    port = free_port()
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", port))
    receiver.settimeout(0.5)
    received = bytearray()

    def receive() -> None:
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                received.extend(receiver.recv(4096))
            except TimeoutError:
                if received:
                    return

    rx = threading.Thread(target=receive, daemon=True)
    rx.start()

    mjpeg = p2p._start_mjpeg_transcoder()
    assert mjpeg is not None, "MJPEG-Transcoder startete nicht"
    remuxer = p2p._start_ts_remuxer(f"udp://127.0.0.1:{port}?pkt_size=1316")
    assert remuxer is not None, "MPEG-TS-Remuxer startete nicht"

    stop = threading.Event()
    frames = [0]
    reader = threading.Thread(
        target=p2p._jpeg_reader, args=(mjpeg, stop, lambda jpg: None, frames), daemon=True
    )
    reader.start()

    feeding = True
    for offset in range(0, len(h264), 4096):
        chunk = h264[offset:offset + 4096]
        if feeding and not p2p._feed(remuxer, chunk):
            feeding = False
        assert p2p._feed(mjpeg, chunk), "die MJPEG-Pipe brach ab"
        time.sleep(0.005)

    p2p._stop_ffmpeg(mjpeg)
    p2p._stop_ffmpeg(remuxer)
    time.sleep(0.5)
    stop.set()
    rx.join(timeout=13)
    receiver.close()

    assert frames[0] > 5, f"nur {frames[0]} Einzelbilder -- der MJPEG-Weg ist tot"
    print(f"  ok: MJPEG-Weg liefert Einzelbilder ({frames[0]})")

    assert received, "auf dem UDP-Port kam nichts an -- die stream-Quelle ist tot"
    assert received[0] == 0x47, f"kein MPEG-TS-Sync-Byte, sondern 0x{received[0]:02x}"
    assert len(received) % 188 == 0, f"keine ganzen TS-Pakete ({len(received)} B)"
    print(f"  ok: {len(received) // 188} MPEG-TS-Pakete auf dem Loopback-Port")

    with tempfile.TemporaryDirectory(prefix="balter_media_") as tmp:
        ts_file = pathlib.Path(tmp) / "stream.ts"
        ts_file.write_bytes(bytes(received))
        probe = subprocess.run(
            ["ffprobe", "-hide_banner", "-loglevel", "error", "-of", "csv=p=0",
             "-show_entries", "stream=codec_name,width,height", str(ts_file)],
            capture_output=True, text=True, check=False,
        )
        info = " ".join(probe.stdout.split())
        assert "h264" in info, f"ffprobe erkennt kein H.264: {info!r}"
        jpg = pathlib.Path(tmp) / "frame.jpg"
        subprocess.run(
            ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
             "-i", str(ts_file), "-vframes", "1", str(jpg)],
            capture_output=True, check=False,
        )
        assert jpg.exists() and jpg.stat().st_size > 0, "aus dem TS kam kein Bild heraus"
    print(f"  ok: gueltiges H.264 in MPEG-TS ({info}) und dekodierbar")

    assert p2p._start_ts_remuxer(None) is None
    assert p2p._feed(None, b"x") is False
    print("  ok: ohne ts_url laeuft alles wie bisher, nur ohne Container-Ausgang")

    print("\n4 Pruefungen bestanden")
    return 0


if __name__ == "__main__":
    sys.exit(main())
