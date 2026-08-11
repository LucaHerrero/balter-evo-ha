"""Constants for the Balter EVO (Quvii Cloud) integration.

Protocol reverse-engineered from the "Balter EVO 2" Android app (de.balter.evo.two v1.8)
via dynamic instrumentation (Frida SSL_write/SSL_read hooks). See REVERSE_ENGINEERING_NOTES.md
for the full capture and verification.
"""

DOMAIN = "balter_evo"

CONF_DOOR_PIN = "door_pin"

# Fixed client identity constants captured from the real app's login request.
# These identify the app/OEM to the backend, not the individual user.
APP_ID = "4028"
OEM_ID = "G0028,G0126"
CLIENT_TYPE = "3"
CLIENT_VERSION = "v1.13"
IP_REGION_ID = "1"

# Hosts observed in captured traffic. Login and subsequent "tdkcloud" calls landed on
# different regional nodes in our capture; both are used as observed rather than assumed
# interchangeable.
LOGIN_HOST = "r1-8.qvcloud.net"
API_HOST = "r1-2.qvcloud.net"

REQUEST_TIMEOUT = 15
