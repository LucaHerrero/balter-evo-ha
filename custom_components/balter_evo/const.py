"""Constants for the Balter EVO (Quvii Cloud) integration.

Protocol reverse-engineered from the "Balter EVO 2" Android app (de.balter.evo.two v1.8)
via dynamic instrumentation (Frida SSL_write/SSL_read hooks) and a synchronous
plain-HTTP replay. See REVERSE_ENGINEERING_NOTES.md for the full capture and verification.
"""

DOMAIN = "balter_evo"

CONF_DOOR_PIN = "door_pin"
CONF_CLIENT_ID = "client_id"
CONF_WARM_IDLE = "warm_idle"
# Altlast: frueher konnte hier die client-id der Balter-App hinterlegt werden, weil
# vermutet wurde, die P2P-Signalisierung akzeptiere nur registrierte ids. Live
# widerlegt -- eine selbst erzeugte 16-Hex-ID funktioniert durchgaengig, die
# MQTT-Credentials dafuer leitet die Integration ueber qv_kdf selbst ab. Der Key
# wird nur noch benutzt, um ihn aus bestehenden Eintraegen zu entfernen.
CONF_SIGNALLING_ID = "signalling_id"

# A door-release relay is momentary: after unlocking it buzzes open and re-locks on its
# own. We surface it as a lock and optimistically flip back to "locked" after this delay.
# Kept comfortably long so the "unlocked" state stays visible in the UI -- important for
# remote users who cannot hear the relay and rely purely on the on-screen feedback.
RELOCK_DELAY = 8

# Schloss, das angelegt wird, wenn die Cloud fuer ein Geraet keine sub-devices
# meldet. door=1/lock=1 ist der Tueroeffner jeder EVO-2-Station (live verifiziert).
DEFAULT_LOCK = {"code": "door1-lock1", "name": "Türöffner", "door": 1, "locknumber": 1}

# Entity-Service der Kamera: kurzen MP4-Clip aufnehmen und wegschreiben.
SERVICE_RECORD_CLIP = "record_clip"

# Maximale Dauer eines Live-Streams. Die Tuerstation vertraegt keine dauerhaft
# offene Sitzung (sie blockiert sonst fuer andere Bewohner/Klingel), darum
# begrenzen wir jeden Livestream und geben den P2P-Slot danach wieder frei.
STREAM_DURATION = 90.0

# Wie lange beim Entfernen der Entity auf das saubere Ende eines Livestreams
# gewartet wird, bevor er hart abgebrochen wird.
STREAM_STOP_TIMEOUT = 5.0

# Waehrend eines Livestreams wird der unveraenderte H.264-Strom zusaetzlich als
# MPEG-TS auf einen lokalen UDP-Port geschickt; von dort holt ihn die
# stream-Integration von Home Assistant ab (HLS/WebRTC statt Einzelbilder).
# Nur ueber das Loopback-Interface -- der Strom verlaesst den Host nicht.
STREAM_TS_HOST = "127.0.0.1"

# Leseoptionen der stream-Integration: ein grosser Empfangspuffer gegen Ruckler,
# und ein Timeout (in Mikrosekunden), damit das Lesen nach dem Ende der Sitzung
# aufhoert, statt haengen zu bleiben.
STREAM_TS_INPUT_OPTIONS = "fifo_size=5000000&overrun_nonfatal=1&timeout=8000000"

# Die Tuerstation bedient immer nur EINE P2P-Sitzung und braucht danach Erholung:
# ein Versuch, der startet, waehrend sie noch belegt ist, verlaengert die Belegung.
# Snapshot, Livestream und Tueroeffnen teilen sich deshalb einen Slot und halten
# diesen Mindestabstand ein (live beobachtet, siehe P2P_PROTOCOL.md §10.3).
P2P_MIN_GAP = 30.0

# Wie lange eine Sitzung nach einem Kommando offen gehalten wird. Ihr Neuaufbau
# kostet je nach Netz 5-8 s (NAT-Check, Cloud-Discovery, MQTT-Signalisierung,
# Punch, LOGIN) -- genau deshalb oeffnet die offizielle App beim zweiten Druck
# sofort: sie haelt die Sitzung offen und schickt nur noch den Befehl. Wir machen
# es genauso; danach wird die Sitzung geschlossen, damit Klingel und App den
# einzigen Slot der Station wiederbekommen.
#
# Der Wert ist die Abwaegung zwischen "zweites Oeffnen sofort" und "Station
# moeglichst schnell wieder frei" und deshalb in den Optionen einstellbar.
# 10 s decken das Nacheinander-Oeffnen ab (zweite Tuer, noch mal draufdruecken),
# ohne die Station spuerbar zu blockieren. 0 schaltet das Offenhalten ab.
DEFAULT_WARM_IDLE = 10.0
WARM_IDLE_MAX = 60.0

# Zwischenspeicher fuer die rotierenden Geraetegeheimnisse. Sie wechseln nur
# woechentlich; haeufiger abzufragen belastet die Cloud ohne Nutzen.
CREDENTIAL_MAX_AGE = 900.0

# Alter, bis zu dem ein zwischengespeichertes Paar ohne Rueckfrage bei der Cloud
# benutzt wird. Auf dem Weg zum Tueroeffnen darf eine langsame oder gestoerte
# Cloud-Verbindung den Befehl nicht aufhalten: die Geheimnisse rotieren
# woechentlich, ein Paar von heute morgen ist praktisch immer noch gueltig.
# Aufgefrischt wird dann im Hintergrund.
CREDENTIAL_STALE_AGE = 12 * 3600.0

# Wie lange ein Tueroeffnen hoechstens auf frische Geheimnisse wartet, bevor es
# mit dem zwischengespeicherten Paar losgeht. Die Cloud antwortet normalerweise
# in ~300 ms; so bekommt der haeufige Fall die frischen Werte (wichtig genau in
# der Woche, in der sie rotieren), waehrend eine haengende Cloud das Oeffnen
# nicht mehr aufhaelt.
CREDENTIAL_REFRESH_WAIT = 1.5

# Mindestalter, ab dem ein neues Standbild geholt wird. Muss ueber dem
# Slot-Zyklus liegen (P2P_MIN_GAP + Dauer eines Snapshots, zusammen rund 40 s):
# ein kuerzerer Wert laesst ein offenes Dashboard die Tuerstation dauerhaft
# belegen, sodass Klingel, App und Tueroeffner keinen Slot mehr bekommen.
SNAPSHOT_CACHE_TTL = 60.0


# Fixed client identity constants captured from the real app's login request.
# These identify the app/OEM to the backend, not the individual user.
APP_ID = "4028"
OEM_ID = "G0028,G0126"
# Der P2P-LOGIN traegt dieselbe OEM-Kennung, aber ohne Komma (byte-genau gegen
# live_real.pcap verifiziert) -- nur an EINER Stelle ableiten, nicht an dreien.
OEM_ID_COMPACT = OEM_ID.replace(",", "")
CLIENT_TYPE = "3"
CLIENT_VERSION = "v1.13"
IP_REGION_ID = "1"


# The userapp REST host is not fixed: it is announced per-account by the discovery service
# (mst/query -> server-type "userapp", e.g. r1-2.qvcloud.net/auth/user). We resolve it at
# login time (see api.BalterCloudClient._discover_userapp) and only fall back to HOST/BASE_PATH
# if discovery fails. NOTE: the previously hardcoded r1-8.qvcloud.net/tdk returns HTTP 404.
DISCOVERY_HOST = "global.qvcloud.net"
DISCOVERY_PATH = "/mst/query"
HOST = "r1-2.qvcloud.net"
BASE_PATH = "/auth/user"

# The real app presents an OkHttp User-Agent; sent for parity (not strictly required).
USER_AGENT = "okhttp/4.9.0"

REQUEST_TIMEOUT = 15
