"""verify_frames.py - Regressionstest fuer das App-Frame-Format.

Baut alle 12 Frame-Typen einer echten App-Sitzung mit den Funktionen der
HA-Integration (custom_components/balter_evo/p2p.py) nach und vergleicht sie
byte-weise gegen den Mitschnitt. Faengt genau den Fehler ab, der Login, Video
und Tueroeffnen monatelang blockiert hat: einen 48- statt 56-Byte-Frame-Kopf
(siehe P2P_PROTOCOL.md Abschnitt 9).

Braucht downloads/live-capture/live_real.pcap und den dazu passenden
data-encode-key (per $BALTER_KEY ueberschreibbar).

    python tools/verify_frames.py     # Exit 0 = alle Frames byte-identisch
"""
import sys, os, struct, types, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ROOT = os.path.dirname(REPO)
PCAP = os.path.join(ROOT, "downloads", "live-capture", "live_real.pcap")
INTEGRATION = os.path.join(REPO, "custom_components", "balter_evo", "p2p.py")

sys.path.insert(0, HERE)
import p2p_decode as pd
sys.modules.setdefault("paho", types.ModuleType("paho"))
sys.modules.setdefault("paho.mqtt", types.ModuleType("paho.mqtt"))
_c = types.ModuleType("paho.mqtt.client"); _c.Client = object; _c.CallbackAPIVersion = None
sys.modules.setdefault("paho.mqtt.client", _c)
# homeassistant.core steuert nur die Typannotation der async-Fassaden bei; fuer
# den reinen Frame-Test genuegt ein Platzhalter, damit der Test auch ohne
# installiertes Home Assistant laeuft.
_ha = types.ModuleType("homeassistant"); _ha.__path__ = []
_ha_core = types.ModuleType("homeassistant.core"); _ha_core.HomeAssistant = object
sys.modules.setdefault("homeassistant", _ha)
sys.modules.setdefault("homeassistant.core", _ha_core)
# p2p.py als Teil des balter_evo-Pakets laden (es importiert .qv_kdf relativ)
_pkg = types.ModuleType("balter_evo")
_pkg.__path__ = [os.path.join(REPO, "custom_components", "balter_evo")]
sys.modules["balter_evo"] = _pkg
bp2p = importlib.import_module("balter_evo.p2p")


def _load_creds():
    """Geraetegeheimnisse aus tools/creds.json bzw. $BALTER_CREDS lesen.

    Sie gehoeren NICHT ins Repo: dynamic_password und data_encode_key rotieren
    woechentlich und sind geraetespezifisch. Holen mit tools/fetch_creds.py.
    """
    import json
    path = os.environ.get("BALTER_CREDS") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "creds.json")
    if not os.path.exists(path):
        raise SystemExit(
            f"[FEHLER] {path} fehlt -- erst 'python tools/fetch_creds.py' laufen lassen.")
    return json.load(open(path, encoding="utf-8"))


_CREDS = _load_creds()
KEY = _CREDS["data_encode_key"].encode()

DYNPW = _CREDS["dynamic_password"]
MAGIC=pd.MAGIC; THDR=28
real={}
for t,s,sp,d,dp,pl in pd.read_pcap(PCAP):
    if pl[:4]!=MAGIC or len(pl)<THDR: continue
    f=struct.unpack("<7I",pl[:THDR])
    if f[1] not in (0x07000003,0x08000004): continue
    i=pl.find(b"\xff\xff\xff\xff",THDR)
    while i>=0 and i+56<=len(pl):
        tot=struct.unpack("<I",pl[i+4:i+8])[0]
        if 56<=tot<=4000 and i+tot<=len(pl):
            fr=pl[i:i+tot]; om=struct.unpack("<I",fr[0x18:0x1c])[0]
            real.setdefault((f[1],om,tot),fr)
        i=pl.find(b"\xff\xff\xff\xff",i+4)

def norm(b, hello=False):
    """Uninitialisierten App-Heap ausblenden (0x08..0x10; bei HELLO auch 0x20..0x24
    und alles ab 0x2C -- in cold2/open stehen dort Logtexte, das Geraet ignoriert sie)."""
    b=bytearray(b); b[0x08:0x10]=b"\x00"*8
    if hello:
        b[0x20:0x24]=b"\x00"*4; b[0x2C:]=b"\x00"*(len(b)-0x2C)
    return bytes(b)

fails=[]
def chk(name, built, key, hello=False):
    r=norm(real[key], hello); bb=norm(built, hello)
    ok = bb==r
    print(f"  {name:34s} {'IDENTISCH' if ok else 'ABWEICHUNG'}")
    if not ok:
        fails.append(name)
        for i in range(min(len(bb),len(r))):
            if bb[i]!=r[i]:
                print(f"      erste Abweichung @{i:#04x}: echt {r[i:i+8].hex(' ')} / gebaut {bb[i:i+8].hex(' ')}")
                break
    return ok

def ts_of(key):
    return struct.unpack("<I", pd._cbc(real[key][56:88],KEY)[1:5])[0]

chk("HELLO76 CH0", bp2p.build_hello76(0x07), (0x07000003,0,76), hello=True)
chk("HELLO76 CH1", bp2p.build_hello76(0x08), (0x08000004,0,76), hello=True)
sess0=real[(0x07000003,0,88)][0x2a:0x2d]; sess1=real[(0x08000004,0,88)][0x2a:0x2d]
chk("a9 CH0 (Video)", bp2p.build_app_frame(0,bp2p.build_a9_body(0),0,sess0), (0x07000003,0,88))
chk("a9 CH1 (Audio)", bp2p.build_app_frame(0,bp2p.build_a9_body(1),1,sess1), (0x08000004,0,88))
lp=bp2p.build_login_payload(DYNPW, _CREDS["client_id"])
chk("LOGIN CH0 (0x01,m13=1,f15=f16=1)",
    bp2p.build_app_frame(1, bp2p.ctrl_frame(0x01,ts_of((0x07000003,1,328)),lp,key=KEY,msg13=1,f15=1,f16=1),0,sess0),
    (0x07000003,1,328))
chk("LOGIN CH1 (0x0b,m13=b14=0xff)",
    bp2p.build_app_frame(1, bp2p.ctrl_frame(0x0B,ts_of((0x08000004,1,328)),lp,key=KEY,msg13=0xFF,b14=0xFF),1,sess1),
    (0x08000004,1,328))
for om,m in ((2,5),(3,6),(4,2)):
    chk(f"Setup 0xFE m13={m} (outer={om})",
        bp2p.build_app_frame(om, bp2p.ctrl_frame(0xFE,ts_of((0x07000003,om,136)),b"\x00",key=KEY,msg13=m),0,sess0),
        (0x07000003,om,136))
op=bp2p.build_open_payload(1,1,_CREDS["out_auth_code"])
chk("OPENDOOR 0xFE m13=4 door=1 lock=1",
    bp2p.build_app_frame(8, bp2p.ctrl_frame(0xFE,ts_of((0x07000003,8,200)),op,key=KEY,msg13=4),0,sess0),
    (0x07000003,8,200))
chk("Keepalive 0x00",
    bp2p.build_app_frame(5, bp2p.ctrl_frame(0x00,ts_of((0x07000003,5,120)),b"",key=KEY),0,sess0),
    (0x07000003,5,120))
chk("CLOSE 0x07",
    bp2p.build_app_frame(11, bp2p.ctrl_frame(0x07,ts_of((0x07000003,11,120)),b"",key=KEY),0,sess0),
    (0x07000003,11,120))
print("\nERGEBNIS:", "alle Frames byte-identisch zur echten App" if not fails else f"Abweichungen: {fails}")
sys.exit(1 if fails else 0)
