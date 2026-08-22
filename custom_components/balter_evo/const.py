"""Constants for the Balter EVO (Quvii Cloud) integration.

Protocol reverse-engineered from the "Balter EVO 2" Android app (de.balter.evo.two v1.8)
via dynamic instrumentation (Frida SSL_write/SSL_read hooks) and a synchronous
plain-HTTP replay. See REVERSE_ENGINEERING_NOTES.md for the full capture and verification.
"""

DOMAIN = "balter_evo"

CONF_DOOR_PIN = "door_pin"
CONF_CLIENT_ID = "client_id"
# Die P2P-Signalisierung (MQTT: register + p2pconnect) beantwortet nur client-ids,
# die beim ust-Server registriert sind. Eine selbst erzeugte ID wird dort
# stillschweigend ignoriert -- Cloud-Login und der P2P-LOGIN am Geraet akzeptieren
# dagegen jede 16-stellige Hex-ID (beides live verifiziert). Wer keine eigene
# registrierte ID hat, traegt hier die client-id der Balter-App ein.
CONF_SIGNALLING_ID = "signalling_id"

# A door-release relay is momentary: after unlocking it buzzes open and re-locks on its
# own. We surface it as a lock and optimistically flip back to "locked" after this delay.
RELOCK_DELAY = 3

# Entity-Service der Kamera: kurzen MP4-Clip aufnehmen und wegschreiben.
SERVICE_RECORD_CLIP = "record_clip"


# Fixed client identity constants captured from the real app's login request.
# These identify the app/OEM to the backend, not the individual user.
APP_ID = "4028"
OEM_ID = "G0028,G0126"
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
USER_AGENT = "okhttp/3.12.1"

REQUEST_TIMEOUT = 15
