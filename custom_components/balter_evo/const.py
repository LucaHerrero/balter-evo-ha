"""Constants for the Balter EVO (Quvii Cloud) integration.

Protocol reverse-engineered from the "Balter EVO 2" Android app (de.balter.evo.two v1.8)
via dynamic instrumentation (Frida SSL_write/SSL_read hooks) and a synchronous
plain-HTTP replay. See REVERSE_ENGINEERING_NOTES.md for the full capture and verification.
"""

DOMAIN = "balter_evo"

CONF_DOOR_PIN = "door_pin"
CONF_CLIENT_ID = "client_id"

# A door-release relay is momentary: after unlocking it buzzes open and re-locks on its
# own. We surface it as a lock and optimistically flip back to "locked" after this delay.
RELOCK_DELAY = 3

# Fixed client identity constants captured from the real app's login request.
# These identify the app/OEM to the backend, not the individual user.
APP_ID = "4028"
OEM_ID = "G0028,G0126"
CLIENT_TYPE = "3"
CLIENT_VERSION = "v1.13"
IP_REGION_ID = "1"

# The r1-* nodes are behind a load balancer with a shared session store; a single node
# handles login + device list + sub-device list + /tdkcgi unlock for one servlet session.
# We keep one host for the whole session so the jsessionid cookie stays valid.
HOST = "r1-8.qvcloud.net"

# The real app presents an OkHttp User-Agent; sent for parity (not strictly required).
USER_AGENT = "okhttp/3.12.1"

REQUEST_TIMEOUT = 15
