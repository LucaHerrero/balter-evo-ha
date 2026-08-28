"""Autonomous P2P engine for Balter EVO 2 door stations (Homaxi / Quvii protocol).

Everything the integration does directly with a door station goes through here:

* NAT traversal (vendor STUN check + cloud-signalled UDP hole punching)
* the C1EFABFF transport with its TCP-like byte stream and ARQ retransmits
* the application handshake HELLO76 -> a9 -> LOGIN -> "session ready"
* the three things we actually want: unlocking a door (:func:`p2p_open_door_sync`),
  grabbing a still image (:func:`p2p_get_snapshot_sync`) and live video
  (:func:`p2p_stream_video_sync`).

All three share one :class:`_P2PTransport`; only what happens after the login
differs. The frame builders are byte-exact against captures of the official app
(see P2P_PROTOCOL.md) -- do not "tidy them up" without a fresh capture.

No personal data is hardcoded: device password, encryption key and identity are
passed in by the caller and come from the cloud at runtime.
"""
from __future__ import annotations

import contextlib
import functools
import hashlib
import http.client
import json
import logging
import os
import random
import re
import socket
import ssl
import string
import struct
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from homeassistant.core import HomeAssistant

from .const import (
    APP_ID,
    CLIENT_TYPE,
    OEM_ID,
    OEM_ID_COMPACT,
    DEFAULT_WARM_IDLE,
    P2P_MIN_GAP,
)
from .qv_kdf import decode_cred

_LOGGER = logging.getLogger(__name__)


class P2PError(RuntimeError):
    """A P2P session with the door station could not be established or used."""


class P2PDoorBusyError(RuntimeError):
    """The door station never released the app session before OPENDOOR.

    Raised when the attempt stalled *before* the command left the client --
    typically because a previous P2P session (snapshot or a prior unlock) is
    still being torn down. The command was provably never sent, so it is safe
    to tell the user to simply try again in a few seconds.
    """


# --- Protokollkonstanten (byte-genau gegen die App-Mitschnitte verifiziert) ---

CH0 = 0x01000000        # Video- und Steuerkanal
CH1 = 0x02000001        # Audiokanal

WIN_ACK = 0xFFFF0900
WIN_DATA = 0x00001900
WIN_BB = 0x00000500
MAGIC = b"\xc1\xef\xab\xff"
IV_ZERO = b"0" * 16
APP_HDR = 56            # Laenge des aeusseren App-Frame-Kopfes

# Notnagel, falls kein data-encode-key durchgereicht wird. Der echte Key ist
# geraetespezifisch, rotiert woechentlich und gehoert NICHT ins Repo -- er kommt
# zur Laufzeit aus der Cloud-Geraeteliste (api.get_device_credentials).
FALLBACK_KEY = b"1" * 32

# Der LOGIN-Payload lautet "adminapp&&<dynpw>\0<oem>\0clientid=<id>\0" (byte-genau
# gegen live_real.pcap verifiziert). Die client-id gehoert NICHT ins Repo: sie ist
# die Identitaet der jeweiligen Installation und wird von der Integration erzeugt.
DEFAULT_OEM = OEM_ID_COMPACT

SHA256_OF_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

NATCHECK_SERVER = ("8.211.5.8", 8300)
NATCHECK_TIMEOUT = 0.6
RX_POLL_TIMEOUT = 0.15

# Zeitbudgets einer Sitzung. Jede Sekunde laenger blockiert den einzigen
# P2P-Slot der Station fuer alle anderen (Klingel, App, Tueroeffner).
RELAY_TIMEOUT = 10.0
PUNCH_TIMEOUT = 15.0
LOGIN_TIMEOUT = 8.0
DOOR_SESSION_TIMEOUT = 20.0
OPENDOOR_MAX_SENDS = 3
OPENDOOR_RESEND_AFTER = 1.2
CLOSE_LINGER = 0.3

# Die echte App laesst zwischen Quittung und Sitzungsende ~1,7 s vergehen. Bleibt
# die Sitzung ohnehin offen, ergibt sich diese Nachlaufzeit von selbst -- wird sie
# dagegen sofort geschlossen (warm_idle=0), muss sie ausdruecklich abgewartet
# werden, damit das Geraet den Befehl noch ausfuehren kann.
POST_UNLOCK_SETTLE = 0.6

# Wie lange auf die Transport-Quittung des Pruef-Frames gewartet wird, mit dem
# eine warm gehaltene Sitzung vor dem naechsten Befehl abgeklopft wird -- inkl.
# einer Wiederholung, denn ein einzelnes verlorenes UDP-Paket darf eine gesunde
# Sitzung nicht als tot erscheinen lassen.
WARM_PROBE_TIMEOUT = 1.6
WARM_PROBE_RESEND = 0.5

# Die Discovery-Antwort nennt nur Serveradressen und die (mit der client-id
# verschluesselten) MQTT-Zugangsdaten. Zwischen zwei Tueroeffnungen aendert sich
# daran nichts, also nicht jedes Mal TLS-Handshake und Round-Trip bezahlen.
DISCOVERY_TTL = 1800.0

KCP_PARAM = {
    "mode": "custom",
    "sndwnd": 175,
    "rcvwnd": 175,
    "nodelay": 2,
    "interval": 10,
    "resend": 2,
    "nc": 1,
    "rto": 10,
    "fastresend": 1,
    "mtu": 1200,
    "appCtrl": 0,
    "kcpVersion": "v1.0",
}


# --- Serialisierung der P2P-Sitzungen ---------------------------------------
#
# Das Geraet vertraegt keine parallelen oder dicht aufeinanderfolgenden Sitzungen:
# es haelt die alte Session noch, der Handshake bleibt dann bei SENT_A9 stehen
# (live beobachtet, siehe P2P_PROTOCOL.md §10.3). Kamera-Snapshot und Tueroeffnen
# muessen sich deshalb einen einzigen Slot teilen und Abstand halten.
_P2P_GATE = threading.Lock()

# Der Erholungsabstand gilt der Station, nicht dem Prozess: ein Schnappschuss von
# Tuerstation A darf das Oeffnen an Tuerstation B nicht ausbremsen.
_P2P_LAST_END: dict[str, float] = {}

# Tueroeffnen geht vor Videobild. Der haeufigste Ablauf ist: es klingelt, man
# schaut das Kamerabild an und oeffnet dann -- genau dann haelt der Livestream
# aber den einzigen P2P-Slot der Station, bis zu STREAM_DURATION Sekunden lang.
# Ein angefordertes Oeffnen setzt darum dieses Signal; laufende Streams und
# Schnappschuesse raeumen den Slot daraufhin von sich aus und reichen ihre
# bereits eingeloggte Sitzung sogar direkt weiter.
_UNLOCK_WANTED = threading.Event()

# Nach einem Kommando offen gehaltene Sitzungen, je Geraet hoechstens eine.
_WARM: dict[str, _WarmSession] = {}
_WARM_LOCK = threading.Lock()

# Was eine Sitzung wiederverwendbar macht: dieselben Geheimnisse, dieselbe
# Identitaet. Rotiert die Cloud den Schluessel, passt die Signatur nicht mehr und
# die alte Sitzung wird verworfen, statt mit totem Schluessel weiterbenutzt.
type _Signature = tuple[str, str, str, bytes]


def _mark_session_end(duid: str) -> None:
    """Note that the station just lost its P2P session and needs recovery time."""
    _P2P_LAST_END[duid] = time.monotonic()


class _WarmSession:
    """Eine nach dem Befehl offen gehaltene Sitzung samt Keepalive-Thread.

    Der Thread uebernimmt genau die Pflege, die sonst der Aufrufer betreibt
    (Heartbeat-Proben und ARQ-Wiederholungen). Ohne ihn liefe die Sitzung binnen
    Sekunden aus -- mit ihm bedient sie das naechste Kommando in Millisekunden.
    """

    def __init__(
        self, duid: str, transport: _P2PTransport, signature: _Signature, idle: float
    ) -> None:
        """Start keeping ``transport`` alive for at most ``idle`` seconds."""
        self.duid = duid
        self.transport = transport
        self.signature = signature
        self._stop = threading.Event()
        self._expiry = time.monotonic() + idle
        # Wer die Sitzung am Ende schliesst. Solange False, raeumt der Thread
        # selbst auf -- auch dann, wenn ein Aufrufer die Verantwortung abgibt,
        # weil der Thread haengt. Genau ein Schliessen, nie zwei, nie keins.
        self._handover = threading.Lock()
        self._caller_owns = False
        self._thread = threading.Thread(
            target=self._run, name=f"balter-p2p-warm-{duid}", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(0.01):
            if time.monotonic() < self._expiry:
                self.transport.maintain()
                continue
            # Abgelaufen. Nur schliessen, wenn uns nicht gerade jemand uebernimmt --
            # sonst bekaeme der Uebernehmer eine geschlossene Sitzung in die Hand.
            with _WARM_LOCK:
                if _WARM.get(self.duid) is not self:
                    return
                del _WARM[self.duid]
            self._close("expired")
            return
        with self._handover:
            orphaned = not self._caller_owns
        if orphaned:
            # Der Aufrufer hat nicht auf uns gewartet -- die Sitzung gehoert sonst
            # niemandem mehr und wuerde die Station endlos belegen.
            self._close("handover gave up")

    def _close(self, why: str) -> None:
        _LOGGER.debug("Warm P2P session with %s %s -- releasing the station", self.duid, why)
        self.transport.close()
        _mark_session_end(self.duid)

    def _halt(self) -> bool:
        """Stop the keepalive thread and take ownership; False if it did not stop.

        Ownership is what keeps the session from being closed twice (or not at
        all): the thread only cleans up while it still owns the session.
        """
        with self._handover:
            self._caller_owns = True
        self._stop.set()
        self._thread.join(timeout=1.0)
        if not self._thread.is_alive():
            return True
        # Der Thread haengt (blockierendes sendto). Ihm die Sitzung zurueckgeben,
        # statt parallel auf demselben Socket zu arbeiten.
        with self._handover:
            self._caller_owns = False
        _LOGGER.warning(
            "The keepalive thread for %s did not stop in time -- leaving the session to it",
            self.duid,
        )
        return False

    def take(self) -> _P2PTransport | None:
        """Stop the keepalive and hand the still-open session to the caller."""
        return self.transport if self._halt() else None

    def discard(self) -> None:
        """Stop the keepalive and close the session."""
        if self._halt():
            self._close("released")


def _take_warm(duid: str | None, signature: _Signature | None) -> _P2PTransport | None:
    """Adopt the warm session of ``duid`` and release every other one.

    Only ONE station session may be open at a time, so anything held for another
    device (or with outdated secrets) is closed here rather than left to expire.
    """
    wanted: _WarmSession | None = None
    stale: list[_WarmSession] = []
    with _WARM_LOCK:
        for key in list(_WARM):
            if duid is not None and key == duid and _WARM[key].signature == signature:
                wanted = _WARM.pop(key)
            else:
                stale.append(_WARM.pop(key))
    for warm in stale:
        _LOGGER.debug("Closing the warm P2P session with %s -- its slot is needed", warm.duid)
        warm.discard()
    return wanted.take() if wanted is not None else None


def release_all_sessions() -> None:
    """Close every session kept open, so the station is free again.

    Called when the integration unloads: the keepalive threads are daemons and
    would otherwise keep pinging -- and keep the station busy for the doorbell
    and the phone app -- until their hold time runs out.
    """
    _take_warm(None, None)


def _store_warm(
    duid: str, transport: _P2PTransport, signature: _Signature | None, idle: float
) -> None:
    """Keep ``transport`` open so the next command needs no handshake at all."""
    if signature is None or idle <= 0:
        transport.close()
        _mark_session_end(duid)
        return
    with _WARM_LOCK:
        _WARM[duid] = _WarmSession(duid, transport, signature, idle)
    _LOGGER.debug("Keeping the P2P session with %s warm for %.0fs", duid, idle)


class _P2PSlot:
    """Kontextmanager: exklusiver Zugriff aufs Geraet + Mindestabstand.

    Der Slot besitzt die Sitzung: er reicht eine noch offene Sitzung des
    vorherigen Kommandos herein (``transport``) und nimmt sie am Ende wieder
    entgegen -- um sie ``warm_idle`` Sekunden offen zu halten (``keep_warm``)
    oder zu schliessen. ``warm_idle=0`` schaltet das Offenhalten ab.
    """

    def __init__(
        self,
        purpose: str,
        duid: str,
        signature: _Signature | None = None,
        reuse: bool = False,
        warm_idle: float = DEFAULT_WARM_IDLE,
    ) -> None:
        """Name the kind of session, so the log says who is holding the slot."""
        self._purpose = purpose
        self._duid = duid
        self._signature = signature
        self._reuse = reuse
        self._warm_idle = warm_idle
        self.transport: _P2PTransport | None = None
        self.keep_warm = False
        # Nachlaufzeit, die dem Geraet vor einem Close noch bleiben muss.
        self.settle = 0.0

    def __enter__(self) -> _P2PSlot:
        started = time.monotonic()
        _P2P_GATE.acquire()
        blocked = time.monotonic() - started
        # Ein laufender Livestream haelt den Slot bis zu STREAM_DURATION Sekunden.
        # Ohne diese Meldung wartet z.B. ein Tueroeffnen minutenlang stumm und
        # scheitert dann scheinbar grundlos an einer "besetzten" Station.
        if blocked > 1.0:
            _LOGGER.info(
                "%s waited %.0fs for another P2P session to finish", self._purpose, blocked
            )
        self.transport = _take_warm(self._duid if self._reuse else None, self._signature)
        if self.transport is not None:
            # Die Sitzung steht bereits -- weder Handshake noch Erholungsabstand.
            _LOGGER.debug("%s reuses the open P2P session with %s", self._purpose, self._duid)
            return self
        # Ohne Eintrag ist die Station nachweislich frei -- der Vorgabewert muss
        # den Abstand daher immer als erfuellt ausweisen, auch kurz nach dem Start
        # des Hosts, wo time.monotonic() noch kleiner als P2P_MIN_GAP sein kann.
        last_end = _P2P_LAST_END.get(self._duid, time.monotonic() - P2P_MIN_GAP)
        wait = P2P_MIN_GAP - (time.monotonic() - last_end)
        if wait > 0:
            _LOGGER.debug(
                "%s waits another %.1fs so the station can recover", self._purpose, wait
            )
            time.sleep(wait)
        return self

    @property
    def warm_idle(self) -> float:
        """Return how long a session may be kept open after the command."""
        return self._warm_idle

    def drop_transport(self) -> None:
        """Close the session held here -- it turned out to be unusable."""
        transport = self.transport
        self.transport = None
        self.keep_warm = False
        if transport is not None:
            transport.close()
            _mark_session_end(self._duid)

    def __exit__(self, *exc: object) -> None:
        transport = self.transport
        self.transport = None
        if transport is not None and self.keep_warm and exc[0] is None and self._warm_idle > 0:
            _store_warm(self._duid, transport, self._signature, self._warm_idle)
        else:
            if transport is not None:
                # Die Sitzung bleibt nicht stehen, also die Nachlaufzeit hier
                # abwarten -- sonst raeumt der Close den Befehl weg, den das
                # Geraet gerade erst ausfuehrt.
                if self.settle > 0:
                    time.sleep(self.settle)
                transport.close()
            _mark_session_end(self._duid)
        _P2P_GATE.release()


# --- Rahmenbau ---------------------------------------------------------------

def rand_token(n: int) -> str:
    """Generate a random alphanumeric token."""
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def inet_cksum(data: bytes) -> int:
    """Compute the standard Internet checksum."""
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += struct.unpack("<H", data[i : i + 2])[0]
    if len(data) % 2:
        s += data[-1]
    s = (s >> 16) + (s & 0xFFFF)
    s = s + (s >> 16)
    return (~s) & 0xFFFF


def build_transport_hdr(
    src_id: int, dst_id: int, seq: int, ack: int, payload: bytes = b"", win: int | None = None
) -> bytes:
    """Build the 28-byte C1EFABFF transport header."""
    if win is None:
        win = WIN_DATA if payload else 0xFFFF4100
    hdr = bytearray(
        struct.pack(
            "<7I",
            0xFFABEFC1,
            src_id,
            dst_id,
            seq,
            ack,
            win,
            ((28 + len(payload)) << 16) & 0xFFFF0000,
        )
    )
    struct.pack_into("<H", hdr, 24, inet_cksum(bytes(hdr)))
    return bytes(hdr) + payload


def cbc_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC encryption with a zero IV."""
    n = len(data) - (len(data) % 16)
    if n == 0:
        return b""
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV_ZERO)).encryptor()
    return cipher.update(data[:n]) + cipher.finalize()


def cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC decryption with a zero IV (trailing partial block kept)."""
    n = len(data) - (len(data) % 16)
    if n == 0:
        return data
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV_ZERO)).decryptor()
    return cipher.update(data[:n]) + cipher.finalize() + data[n:]


def ctrl_frame(
    ftype: int,
    ts: int,
    payload: bytes,
    key: bytes = FALLBACK_KEY,
    msg13: int = 0,
    b14: int = 0,
    f15: int = 0,
    f16: int = 0,
    b17: int = 0,
) -> bytes:
    """Build and encrypt an application control frame."""
    clen = len(payload)
    nutzlen = clen + 32
    plen = nutzlen + ((16 - nutzlen % 16) % 16)
    head = bytearray(32)
    head[0] = ftype
    struct.pack_into("<I", head, 1, ts)
    head[9] = plen
    head[11] = clen
    head[13] = msg13
    head[14] = b14
    head[15] = f15
    head[16] = f16
    if b17:
        head[17] = b17
    trailer = hashlib.sha256(bytes(head) + bytes(payload)).digest()
    nutz = bytes(payload) + trailer
    if len(nutz) % 16:
        nutz += b"\x00" * (16 - len(nutz) % 16)
    return cbc_encrypt(bytes(head), key) + cbc_encrypt(nutz, key)


def build_app_frame(outer_msg: int, body: bytes, ch_idx: int, sess_bytes: bytes) -> bytes:
    """Build the 56-byte outer header plus body.

    Byte-exact against live_real.pcap / open.pcap / cold2.pcap / session.pcap:
    the header is 56 bytes and carries the body length TWICE -- once as
    ``body_len + 16`` @0x24 and once plain @0x30. A 48-byte header (used up to
    v11) shifts the body 8 bytes forward, so the device reads garbage as the
    body length: the transport layer still ACKs the frame, but the application
    layer silently drops it -- no LOGIN, no config, no video.
    """
    body_len = len(body)
    hdr = bytearray(APP_HDR)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, APP_HDR + body_len)
    hdr[0x10:0x18] = bytes.fromhex("0001000003011200")
    struct.pack_into("<I", hdr, 0x18, outer_msg)
    struct.pack_into("<I", hdr, 0x24, body_len + 16)
    struct.pack_into("<H", hdr, 0x28, ch_idx)
    hdr[0x2A:0x2D] = sess_bytes
    hdr[0x2D:0x30] = bytes.fromhex("000004")
    struct.pack_into("<I", hdr, 0x30, body_len)
    return bytes(hdr) + body


def build_hello76(slot_id: int) -> bytes:
    """Build the 76-byte client HELLO frame (56-byte header + 20-byte body).

    Only the fields up to 0x2C carry meaning; everything after is uninitialised
    heap in the real app (cold2.pcap/open.pcap show log strings and floats
    there, live_real.pcap zeros) and the device ignores it. The device echoes
    the frame and appends the 2-byte session base at absolute offset 74..76.
    """
    hdr = bytearray(APP_HDR)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 76)
    hdr[0x10:0x18] = bytes.fromhex("0001000001011200")
    struct.pack_into("<I", hdr, 0x24, 20 + 16)
    struct.pack_into("<I", hdr, 0x28, slot_id | 0x04000000)
    return bytes(hdr) + (b"\x00" * 20)


def build_a9_body(ch_idx: int) -> bytes:
    """Build the 32-byte plaintext setup body sent right after the HELLO exchange.

    Byte 0 = 0xA9; byte 9 = stream type: 0 = video (CH0), 2 = audio (CH1).
    Identical in live_real.pcap, cold2.pcap and open.pcap.
    """
    body = bytearray(32)
    body[0] = 0xA9
    if ch_idx:
        body[9] = 0x02
    return bytes(body)


def build_login_payload(dynpw: str, client_id: str, oem: str = DEFAULT_OEM) -> bytes:
    """Build the payload of the LOGIN (cmd=0x01) frame."""
    return (
        b"adminapp&&"
        + dynpw.encode("ascii")
        + b"\x00"
        + oem.encode("ascii")
        + b"\x00clientid="
        + client_id.encode("ascii")
        + b"\x00"
    )


def build_open_payload(door: int, locknumber: int, pin_sha256: str) -> bytes:
    """Build the payload of the OPENDOOR (cmd=0xFE, msg13=4) frame."""
    payload = bytearray(16)
    payload[0] = door
    payload[2] = locknumber
    payload[3] = 1
    return bytes(payload) + pin_sha256.encode("ascii")


def build_mtu_probe(session_flag: str, testid: int, aval: int) -> bytes:
    """Build the 0x88 MTU probe packet (also serves as session heartbeat)."""
    b = bytearray(164)
    b[0:4] = MAGIC
    struct.pack_into("<I", b, 4, 136)
    b[0x20] = 0x88
    struct.pack_into("<I", b, 0x38, testid & 0xFFFFFFFF)
    flag = session_flag.encode()[:63]
    b[0x44 : 0x44 + len(flag)] = flag
    struct.pack_into("<I", b, 0xA0, aval & 0xFFFFFFFF)
    return bytes(b)


def build_punch(session_flag: str, rip: str, rport: int, cid: int = 2, tid: int = 1) -> bytes:
    """Build the initial NAT punch packet."""
    b = bytearray(164)
    b[0:4] = MAGIC
    struct.pack_into("<I", b, 4, 136)
    b[0x20] = 0x88
    b[0x2A:0x2C] = struct.pack("<H", 0x1234)
    struct.pack_into("<I", b, 0x38, cid)
    struct.pack_into("<I", b, 0x3C, tid)
    b[0x40:0x44] = socket.inet_aton(rip)
    flag = session_flag.encode()[:63]
    b[0x44 : 0x44 + len(flag)] = flag
    struct.pack_into("<H", b, 0x84, rport)
    return bytes(b)


def build_natcheck(nonce: int = 0xEB95D55A) -> bytes:
    """Build the verified 112-byte NAT check request."""
    b = bytearray(112)
    struct.pack_into("<I", b, 0, 0xFFABEFC1)
    struct.pack_into("<H", b, 0x1A, 112)
    b[0x1C:0x20] = b"\xff\xff\xff\xff"
    b[0x20] = 0x54
    b[0x2C:0x34] = bytes.fromhex("0001000001001100")
    struct.pack_into("<I", b, 0x40, 0x2C)
    struct.pack_into("<I", b, 0x44, nonce)
    return bytes(b)


def parse_header(data: bytes) -> tuple[int, int, int, int, int, int, int]:
    """Parse a 28-byte transport packet header."""
    return struct.unpack("<7I", data[:28])


def split_app_frames(data: bytes) -> tuple[list[bytes], int]:
    """Split a byte stream into whole application frames.

    Returns the complete frames and how many bytes of ``data`` they used, so a
    caller streaming the device can drop what it has consumed and keep only the
    incomplete tail. That is what keeps the live stream O(new bytes) instead of
    re-parsing the whole session every time.
    """
    frames: list[bytes] = []
    i = 0
    consumed = 0
    while i <= len(data) - APP_HDR:
        if data[i : i + 4] == b"\xff\xff\xff\xff":
            total = struct.unpack("<I", data[i + 4 : i + 8])[0]
            if APP_HDR <= total <= len(data) - i:
                frames.append(data[i : i + total])
                i += total
                consumed = i
                continue
            # Angefangener Frame am Ende (oder Zufallstreffer): nicht verbrauchen.
        i += 1
    return frames, consumed


def extract_app_frames(data: bytes) -> list[tuple[int, bytes]]:
    """Extract ``(outer_msg, frame)`` pairs from a reassembled byte stream."""
    return [
        (struct.unpack("<I", frame[0x18:0x1C])[0], frame)
        for frame in split_app_frames(data)[0]
    ]


def decrypt_head(payload: bytes, key: bytes) -> bytes:
    """Decrypt the 64-byte media header, returning the full plaintext frame."""
    if len(payload) < 64:
        return payload
    return cbc_decrypt(payload[:64], key) + payload[64:]


def h264_is_decodable(buf: bytes) -> bool:
    """Return True if the buffer carries a parameter set (SPS) and a keyframe (IDR).

    Used to pick between decrypt candidates. Length is a misleading criterion: the
    undecrypted raw stream is always the longest one because it still carries every
    56-byte frame header and the encrypted 64-byte block of each media frame -- it
    scans as "H.264" but no decoder can use it.
    """
    kinds = set()
    p = buf.find(b"\x00\x00\x00\x01")
    while p >= 0:
        if p + 4 < len(buf):
            kinds.add(buf[p + 4] & 0x1F)
        p = buf.find(b"\x00\x00\x00\x01", p + 4)
    return 7 in kinds and 5 in kinds


def first_nal_offset(buf: bytes) -> int:
    """Return the offset of the first usable H.264 NAL start code, or -1."""
    for pattern in (
        b"\x00\x00\x00\x01\x67", b"\x00\x00\x00\x01\x27",  # SPS
        b"\x00\x00\x00\x01\x68", b"\x00\x00\x00\x01\x28",  # PPS
        b"\x00\x00\x00\x01\x65", b"\x00\x00\x00\x01\x25",  # IDR
    ):
        offset = buf.find(pattern)
        if offset >= 0:
            return offset
    return -1


def extract_h264(plain: bytes) -> bytes:
    """Return the decrypted stream from its first valid H.264 NAL unit onwards."""
    offset = first_nal_offset(plain)
    return plain[offset:] if offset >= 0 else b""


# --- Netz-Hilfen -------------------------------------------------------------

def _natcheck_query(sock: socket.socket, tries: int = 5) -> tuple[str, int]:
    """Ask the vendor's NAT check server for our public UDP address."""
    request = build_natcheck()
    previous_timeout = sock.gettimeout()
    try:
        sock.settimeout(NATCHECK_TIMEOUT)
        for _ in range(tries):
            sock.sendto(request, NATCHECK_SERVER)
            try:
                data, _ = sock.recvfrom(512)
            except TimeoutError:
                continue
            if len(data) >= 0x60 and data[0x20] == 0x54 and data[0x2E] == 1:
                ip = data[0x4C : data.find(b"\x00", 0x4C)].decode("ascii", "replace")
                port = struct.unpack("<H", data[0x5C:0x5E])[0]
                return ip, port
    finally:
        # Der Socket wird gleich vom Empfangs-Thread benutzt -- dessen Taktung
        # haengt an diesem Timeout, also nicht veraendert zuruecklassen.
        sock.settimeout(previous_timeout)
    return "0.0.0.0", 0


def _local_ip_towards(peer_ip: str) -> str:
    """Return the LAN address this host would use to reach ``peer_ip``.

    ``getsockname()`` on our own P2P socket answers 0.0.0.0: it is bound to every
    interface and never connected. Publishing that as our local address hides the
    LAN route from the door station, so all traffic has to take the relay detour.
    A connected throwaway socket asks the routing table instead -- no packet is
    sent by ``connect()`` on UDP.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect((peer_ip, 9))
            return str(probe.getsockname()[0])
        except OSError:
            return "0.0.0.0"


# --- Cloud-Discovery & MQTT-Signalisierung -----------------------------------

def _mst_query(client_id: str) -> str:
    """Query the vendor discovery service for the current server addresses."""
    body = (
        '<?xml version="1.0" encoding="UTF-8"?><envelope><header>'
        "<flag>tdkcloud</flag><command>query-hlrv2</command><seq>1</seq></header>"
        "<content><server-type>userapp,alarmapp,p2papp,natcheck,appinfo,oauth2,log,openapi"
        f"</server-type><oem>{OEM_ID}</oem><devid></devid><public-ip></public-ip>"
        f"<client-id>{client_id}</client-id><regionid>0</regionid><version>4456</version>"
        "</content></envelope>"
    )
    # Der Dienst praesentiert ein Zertifikat, das nicht zum Hostnamen passt; die
    # App prueft es ebenfalls nicht. Uebertragen werden nur oeffentliche
    # Serveradressen -- die eigentlichen Credentials sind zusaetzlich mit dem aus
    # der client-id abgeleiteten Schluessel verschluesselt (qv_kdf).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection("global.qvcloud.net", 443, context=ctx, timeout=12)
    try:
        conn.request(
            "GET",
            "/mst/query",
            body=body.encode(),
            headers={"Host": "global.qvcloud.net", "Content-Type": "application/xml;charset=utf-8"},
        )
        resp = conn.getresponse()
        return resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


# Antworten des Discovery-Dienstes je client-id, siehe DISCOVERY_TTL.
_DISCOVERY_CACHE: dict[str, tuple[float, str]] = {}
_DISCOVERY_LOCK = threading.Lock()


def _mst_query_cached(client_id: str) -> str:
    """Return the discovery answer, reusing a recent one.

    Saves a TLS handshake and a round trip to global.qvcloud.net on every single
    session -- half a second that the user waits in front of the door for
    addresses that have not changed since the last unlock.
    """
    with _DISCOVERY_LOCK:
        cached = _DISCOVERY_CACHE.get(client_id)
        if cached and time.monotonic() - cached[0] < DISCOVERY_TTL:
            return cached[1]
    answer = _mst_query(client_id)
    with _DISCOVERY_LOCK:
        _DISCOVERY_CACHE[client_id] = (time.monotonic(), answer)
    return answer


def _discovery_forget(client_id: str) -> None:
    """Drop a cached discovery answer that turned out to be unusable."""
    with _DISCOVERY_LOCK:
        _DISCOVERY_CACHE.pop(client_id, None)


def _parse_param(param: str) -> dict[str, str]:
    """Parse a ``key=value&key=value`` parameter string."""
    out = {}
    for kv in param.split("&"):
        if "=" in kv:
            key, value = kv.split("=", 1)
            out[key] = value
    return out


def _parse_servers(xml: str) -> dict[str, dict[str, str]]:
    """Parse the discovery answer into ``server-type -> {url, uri, param}``."""
    root = ET.fromstring(xml)
    return {
        (srv.findtext("server-type") or ""): {
            "url": srv.findtext("url") or "",
            "uri": srv.findtext("uri") or "",
            "param": srv.findtext("param") or "",
        }
        for srv in root.findall(".//server")
    }


class CloudP2PSession:
    """MQTT signalling session that brokers the P2P addresses of one device."""

    REGISTER_TIMEOUT = 3.0

    def __init__(self, client_id: str, duid: str) -> None:
        """Prepare a signalling session for one device.

        The client id must be 16 hex characters. It does NOT have to be
        registered with the vendor: the MQTT credentials for a self-generated
        id are derived locally via qv_kdf (verified live).
        """
        if not re.fullmatch(r"[0-9a-f]{16}", client_id or ""):
            raise ValueError(
                f"Ungueltige P2P-Signalisierungs-ID {client_id!r}: "
                "erwartet werden 16 Hex-Zeichen."
            )
        self.client_id = client_id
        self.duid = duid
        self.registered = threading.Event()
        self.userid = str(random.randint(10**9, 9 * 10**9))
        self.session_flag = rand_token(43)
        self.requ_id = random.randint(-(2**31), -1)
        self.loc: tuple[str, int] | None = None
        self.pub: tuple[str, int] | None = None
        self.relay: tuple[str, int] | None = None
        self.got_addr = threading.Event()
        self.cli: mqtt.Client | None = None
        self._sub = f"{self.client_id}/ust/json"
        self._pub = f"app/ust/json/{self.client_id}"

    def _hdr(self, cmd: str) -> dict[str, Any]:
        return {
            "flag": "tdkcloud",
            "version": "v3.2.c",
            "command": cmd,
            "userdata": self.userid,
            "client": {
                "id": self.client_id,
                "type": CLIENT_TYPE,
                "oem": OEM_ID,
                "app": APP_ID,
            },
        }

    def connect(self) -> None:
        """Resolve the MQTT broker, connect and wait for the register ack.

        The signalling server ignores a ``p2pconnect`` from a client it has not
        acked a ``register`` for, so callers must not skip ahead.
        """
        try:
            servers = _parse_servers(_mst_query_cached(self.client_id))
        except ET.ParseError:
            _discovery_forget(self.client_id)
            raise
        p2p = servers.get("p2papp")
        if not p2p or ":" not in p2p["url"]:
            _discovery_forget(self.client_id)
            raise P2PError("Discovery lieferte keinen p2papp-Server")
        host = p2p["url"].replace("mqtts://", "").split(":")[0]
        port = int(p2p["url"].rsplit(":", 1)[1])
        params = _parse_param(p2p["param"])
        # Der Discovery-Dienst verschluesselt username/password mit einem
        # client-id-spezifischen Schluessel (qv_kdf). Damit funktioniert JEDE
        # selbst erzeugte 16-hex-id -- keine Registrierung, keine geliehene
        # App-Identitaet noetig (live verifiziert).
        try:
            username = decode_cred(self.client_id, params["username"])
            password = decode_cred(self.client_id, params["password"])
        except KeyError as err:
            _discovery_forget(self.client_id)
            raise P2PError("Discovery lieferte keine MQTT-Zugangsdaten") from err

        self.cli = self._new_client()
        self.cli.username_pw_set(username, password)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.cli.tls_set_context(ctx)
        self.cli.on_connect = self._on_connect
        self.cli.on_message = self._on_message
        try:
            self.cli.connect(host, port, keepalive=30)
        except OSError:
            # Die Adresse kam aus dem Discovery-Zwischenspeicher. Bleibt sie dort
            # stehen, scheitert jede Sitzung bis zum Ablauf der TTL -- obwohl eine
            # frische Abfrage den umgezogenen Broker sofort liefern wuerde.
            _discovery_forget(self.client_id)
            raise
        self.cli.loop_start()

        if not self.registered.wait(self.REGISTER_TIMEOUT):
            _LOGGER.debug(
                "Signalling server did not ack the registration of %s -- continuing anyway",
                self.client_id,
            )

    def _new_client(self) -> mqtt.Client:
        """Create a paho client across the v1 and v2 callback APIs."""
        client_id = f"app_{self.client_id}_{self.userid}_"
        try:
            return mqtt.Client(
                client_id=client_id,
                protocol=mqtt.MQTTv31,
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            )
        except (AttributeError, TypeError):
            return mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv31)

    def _on_connect(self, *args: Any, **kwargs: Any) -> None:
        cli = args[0] if args else self.cli
        # Argument 3 ist je nach paho-Version rc (int) oder ReasonCode; beide
        # vergleichen sich sinnvoll mit 0 bzw. sind "is_failure"-faehig.
        reason = args[3] if len(args) >= 4 else None
        if reason is not None and getattr(reason, "is_failure", bool(reason)):
            _LOGGER.error("P2P signalling broker refused the connection: %s", reason)
            return
        if cli:
            cli.subscribe(self._sub, qos=1)
            cli.publish(
                self._pub, json.dumps({"header": self._hdr("register"), "content": {}}), qos=1
            )

    def request_addresses(self) -> None:
        """Ask the cloud for the device's P2P addresses (local, public, relay)."""
        content = {
            "devid": self.duid,
            "session-flag": self.session_flag,
            "requ-session-id": self.requ_id,
            "force-trans": 0,
            "devType": "normal",
            "devSubState": "awakened",
            "kcpParam": KCP_PARAM,
            "devTrans": {"monChn": -1},
        }
        self._publish("p2pconnect", content)

    def wait_for_relay(self, timeout: float) -> tuple[str, int] | None:
        """Wait for the relay address the device can be punched through."""
        if not self.got_addr.wait(timeout):
            return None
        return self.relay

    def update_netinfo(self, pub_ip: str, pub_port: int, loc_ip: str, loc_port: int) -> None:
        """Publish our own NAT addresses so the device can punch back."""
        self._publish(
            "update-netinfo",
            {
                "nettype": 4,
                "netsubtype": 0,
                "pub-ip": pub_ip,
                "pub-udpport": pub_port,
                "loc-ip": [loc_ip],
                "loc-udp-port": loc_port,
            },
        )

    def _publish(self, command: str, content: dict[str, Any]) -> None:
        if self.cli:
            self.cli.publish(
                self._pub,
                json.dumps({"header": self._hdr(command), "content": content}),
                qos=1,
            )

    def _on_message(self, *args: Any, **kwargs: Any) -> None:
        msg = args[2] if len(args) >= 3 else kwargs.get("message")
        if msg is None:
            return
        try:
            payload = json.loads(msg.payload.decode("utf-8", "replace"))
        except (ValueError, AttributeError):
            return
        command = payload.get("header", {}).get("command")
        if command == "register":
            self.registered.set()
        elif command == "p2pconnect":
            self._read_addresses(payload.get("content", {}))

    def _read_addresses(self, content: dict[str, Any]) -> None:
        loc_ip = content.get("loc-ip") or [None]
        if loc_ip[0]:
            self.loc = (loc_ip[0], content.get("loc-udpport", 58367))
        if content.get("pub-ip"):
            self.pub = (content["pub-ip"], content.get("pub-udpport", 58367))
        if content.get("utd-pub-ip"):
            self.relay = (content["utd-pub-ip"], content.get("utd-pub-udpport"))
        self.got_addr.set()

    def close(self) -> None:
        """Disconnect from the signalling broker."""
        if self.cli:
            self.cli.loop_stop()
            with contextlib.suppress(OSError):
                self.cli.disconnect()
            self.cli = None


# --- Transport ---------------------------------------------------------------

@dataclass
class _Channel:
    """State of one logical channel: CH0 = video/control, CH1 = audio."""

    conv: int
    slot_id: int
    index: int
    myid: int | None = None
    sess: bytes | None = None
    rcv: int = 1              # naechstes von uns erwartetes Byte des Geraets
    sent_pos: int = 1         # naechster Byte-Offset unseres Stroms
    peer_ack: int = 0         # hoechster vom Geraet quittierter Offset
    state: str = "INIT"       # INIT -> SENT_HELLO -> SENT_A9 -> SENT_LOGIN -> LOGGED_IN
    bb_size: int = 520
    last_pos: int = 1         # Byte-Offset des zuletzt gesendeten App-Frames
    last_frame: bytes | None = None
    last_tx: float = 0.0


class _P2PTransport:
    """One live P2P session with a door station.

    Covers NAT traversal, the C1EFABFF transport and the application handshake
    up to the point where the device accepts commands. What happens afterwards --
    unlock, snapshot, live video -- is up to the caller.

    The station serves only ONE session at a time, so callers must hold the
    :class:`_P2PSlot` for the whole lifetime of an instance and always call
    :meth:`close`.
    """

    PROBE_INTERVAL = 0.12
    ARQ_INTERVAL = 0.40
    ARQ_IDLE = 0.50
    _MTU_PROBE_VALUES = (200, 101, 200, 101, 60, 200)
    _HANDSHAKE_STATES = frozenset({"SENT_HELLO", "SENT_A9", "SENT_LOGIN"})

    def __init__(
        self,
        duid: str,
        dynamic_password: str,
        client_id: str,
        key: bytes,
        oem: str = DEFAULT_OEM,
        on_media: Callable[[int, bytes], None] | None = None,
    ) -> None:
        """Prepare (but do not open) a session; see :meth:`connect`."""
        self._duid = duid
        self._dynamic_password = dynamic_password
        self._client_id = client_id
        self._oem = oem
        self._key = key
        self._on_media = on_media
        self._ts = int(time.time())
        self._sock: socket.socket | None = None
        self._cloud: CloudP2PSession | None = None
        self._stop = threading.Event()
        self._send_lock = threading.Lock()
        self._session_flag = ""
        self._probe_id = int.from_bytes(os.urandom(4), "little")
        self._probe_index = 0
        self._last_probe = 0.0
        self._last_arq = 0.0
        self.peer: tuple[str, int] | None = None
        self.channels = {CH0: _Channel(CH0, 0x07, 0), CH1: _Channel(CH1, 0x08, 1)}
        self.logged_in = threading.Event()      # CH0-LOGIN transportseitig quittiert
        self.device_ready = threading.Event()   # App-Session frei (0xFE msg13=2)

    @property
    def duid(self) -> str:
        """Return the device this session belongs to."""
        return self._duid

    def set_media_sink(self, on_media: Callable[[int, bytes], None] | None) -> None:
        """Redirect -- or switch off -- the media callback of a running session.

        A session handed on to another command must stop feeding the previous
        command's assembler, otherwise it keeps buffering video nobody reads.
        """
        self._on_media = on_media

    # ------------------------------------------------------------- Aufbau

    def connect(self) -> bool:
        """Bring the session up to "device accepted our LOGIN".

        Returns False with an explanatory log line if the station could not be
        reached. :meth:`close` must be called either way.
        """
        try:
            return self._connect()
        except (OSError, ValueError, P2PError, ET.ParseError) as err:
            _LOGGER.error("P2P session with %s could not be established: %s", self._duid, err)
            return False

    def _connect(self) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        sock.settimeout(RX_POLL_TIMEOUT)
        self._sock = sock
        local_port = sock.getsockname()[1]

        # NAT-Check und Cloud-Signalisierung haengen nicht voneinander ab und
        # kosten jeweils bis zu ein paar Sekunden. Nebeneinander gestartet zahlt
        # der Nutzer vor der Tuer nur die laengere der beiden Wartezeiten. Der
        # Empfangs-Thread laeuft noch nicht, der Socket gehoert also solange
        # allein dem NAT-Check.
        natcheck: list[tuple[str, int]] = []
        nat_thread = threading.Thread(
            target=self._natcheck_worker, args=(sock, natcheck),
            name=f"balter-p2p-nat-{self._duid}", daemon=True,
        )
        nat_thread.start()

        cloud = CloudP2PSession(self._client_id, self._duid)
        self._cloud = cloud
        cloud.connect()
        cloud.request_addresses()
        relay = cloud.wait_for_relay(RELAY_TIMEOUT)

        nat_thread.join(timeout=NATCHECK_TIMEOUT * 5 + 1.0)
        if nat_thread.is_alive():
            # Ab hier teilen Empfangsschleife und Punch sich den Socket. Ein noch
            # laufender NAT-Check wuerde ihnen Pakete wegfangen und das Timeout
            # unter den Fuessen wegziehen -- lieber sauber scheitern.
            _LOGGER.error(
                "NAT check for %s did not finish -- aborting this session instead of "
                "sharing the socket with it", self._duid,
            )
            return False
        public_ip, public_port = natcheck[0] if natcheck else ("0.0.0.0", 0)
        if public_port:
            _LOGGER.debug(
                "NAT check resolved public address %s:%d (local port %d)",
                public_ip, public_port, local_port,
            )
        else:
            _LOGGER.debug("NAT check got no answer -- relying on the cloud relay")

        if relay is None:
            _LOGGER.error(
                "P2P relay discovery timed out for %s (device offline, or a previous "
                "session is still held -- leave a gap between runs)",
                self._duid,
            )
            return False

        self.peer = relay
        self._session_flag = cloud.session_flag
        _LOGGER.debug(
            "Discovered P2P relay %s, device local=%s public=%s", relay, cloud.loc, cloud.pub
        )
        cloud.update_netinfo(
            public_ip, public_port, _local_ip_towards(relay[0]), local_port
        )

        threading.Thread(
            target=self._rx_loop, name=f"balter-p2p-rx-{self._duid}", daemon=True
        ).start()

        if not self._punch(relay):
            _LOGGER.error(
                "P2P punch/handshake failed for %s (no channel ids received)", self._duid
            )
            return False
        self._send_hello()
        return True

    @staticmethod
    def _natcheck_worker(sock: socket.socket, out: list[tuple[str, int]]) -> None:
        """Run the NAT check in a side thread, tolerating a socket closed under it."""
        with contextlib.suppress(OSError):
            out.append(_natcheck_query(sock))

    def _punch(self, relay: tuple[str, int]) -> bool:
        """Hole-punch until the device answers on both channels."""
        deadline = time.monotonic() + PUNCH_TIMEOUT
        while time.monotonic() < deadline and not self._channels_up():
            self._send(build_punch(self._session_flag, relay[0], relay[1]), relay)
            for conv in self.channels:
                self._send(build_transport_hdr(0, conv, 0, 0), relay)
            time.sleep(0.15)
        return self._channels_up()

    def _channels_up(self) -> bool:
        return all(chan.myid for chan in self.channels.values())

    def _send_hello(self) -> None:
        """Open both channels with the 76-byte client HELLO."""
        for chan in self.channels.values():
            self._send(build_transport_hdr(chan.myid, chan.conv, 1, 1, win=WIN_ACK))
            self._send_bb(chan)
            self._send_frame(chan, build_hello76(chan.slot_id))
            chan.state = "SENT_HELLO"

    # ------------------------------------------------------------- Senden

    def _send(self, data: bytes, peer: tuple[str, int] | None = None) -> None:
        """Send one raw datagram; silently ignores a socket closed underneath us."""
        sock = self._sock
        target = peer or self.peer
        if sock is None or target is None:
            return
        with contextlib.suppress(OSError):
            sock.sendto(data, target)

    def _send_frame(
        self, chan: _Channel, frame: bytes, peer: tuple[str, int] | None = None
    ) -> tuple[int, int]:
        """Append one application frame to our byte stream and send it.

        Returns the ``(start, end)`` byte offsets of the frame -- the device
        acknowledges receipt by raising its ack field to ``end``.
        """
        with self._send_lock:
            start = chan.sent_pos
            chan.sent_pos += len(frame)
            end = chan.sent_pos
        chan.last_pos = start
        chan.last_frame = frame
        chan.last_tx = time.monotonic()
        self._send(
            build_transport_hdr(chan.myid, chan.conv, start, chan.rcv, frame, win=WIN_DATA),
            peer,
        )
        return start, end

    def _send_ack(self, chan: _Channel, peer: tuple[str, int] | None = None) -> None:
        window = (0xFFFF - ((chan.rcv - 1) & 0xFFFF)) & 0xFFFF
        if window < 0x1000:
            window = 0xFFFF
        self._send(
            build_transport_hdr(
                chan.myid, chan.conv, chan.sent_pos, chan.rcv, win=(window << 16) | 0x0900
            ),
            peer,
        )

    def _send_bb(self, chan: _Channel, peer: tuple[str, int] | None = None) -> None:
        """Answer the device's 0xBB bandwidth probe with one of our own."""
        size = min(chan.bb_size, 1420)
        self._send(
            build_transport_hdr(
                chan.myid, chan.conv, chan.sent_pos, chan.rcv, b"\xbb" * size, win=WIN_BB
            ),
            peer,
        )
        chan.bb_size = min(chan.bb_size + 100, 1420)

    def send_ctrl(
        self, outer_msg: int, ftype: int, payload: bytes = b"", conv: int = CH0, **fields: int
    ) -> tuple[int, int]:
        """Send an encrypted control frame and return its ``(start, end)`` offsets."""
        chan = self.channels[conv]
        if chan.sess is None:
            raise P2PError(f"CH{conv:x} has no session yet")
        body = ctrl_frame(ftype, self._ts, payload, key=self._key, **fields)
        return self._send_frame(chan, build_app_frame(outer_msg, body, chan.index, chan.sess))

    def send_session_setup(self) -> None:
        """Send the three post-login frames the real app always sends (om 2..4)."""
        for outer_msg, msg13 in ((2, 5), (3, 6), (4, 2)):
            self.send_ctrl(outer_msg, 0xFE, b"\x00", msg13=msg13)
            time.sleep(0.02)

    def resend_last(self, conv: int = CH0) -> None:
        """Repeat the last frame of a channel at its ORIGINAL byte offset.

        A retransmit must not advance the stream: appending the same bytes at a
        new position makes the device see a second, differently placed command --
        for an unlock that would mean opening the door twice.
        """
        chan = self.channels[conv]
        if chan.last_frame is None:
            return
        self._send(
            build_transport_hdr(
                chan.myid, chan.conv, chan.last_pos, chan.rcv, chan.last_frame, win=WIN_DATA
            )
        )

    # ------------------------------------------------------------ Empfangen

    def _rx_loop(self) -> None:
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                return
            try:
                data, src = sock.recvfrom(2048)
            except (TimeoutError, OSError):
                continue
            if len(data) < 28 or data[:4] != MAGIC:
                continue
            if len(data) == 164:
                self._handle_probe(data, src)
            else:
                self._handle_packet(data, src)

    def _handle_probe(self, data: bytes, src: tuple[str, int]) -> None:
        """Mirror the peer's NAT probe back, or adopt the address it punched from."""
        role = data[0x2E]
        if role == 0:
            echo = bytearray(data)
            echo[0x2E] = 1
            self._send(bytes(echo), src)
        elif role == 1:
            self.peer = src

    def _handle_packet(self, data: bytes, src: tuple[str, int]) -> None:
        _, conv, dst_id, seq, ack, win, _ = parse_header(data)
        chan = self.channels.get(conv)
        if chan is None or dst_id in (0, conv):
            return
        if not chan.myid:
            chan.myid = dst_id
            self.peer = src
        # Quittung des Geraets: der Byte-Offset unseres Stroms, den es bestaetigt
        # hat (TCP-artig, exklusiv). Einzige Empfangsbestaetigung, die es fuer das
        # Tueroeffnen gibt -- eine App-Layer-Antwort darauf existiert nicht.
        chan.peer_ack = max(chan.peer_ack, ack)

        payload = data[28:]
        if not payload:
            return
        if win == WIN_BB or payload[:4] == b"\xbb\xbb\xbb\xbb":
            self._send_bb(chan, src)
            self._send_ack(chan, src)
            return

        if conv == CH0 and (win & 0xFFFF) == 0x1900 and self._on_media is not None:
            self._on_media(seq, payload)

        # JEDES Datenpaket quittieren, nicht nur die mit App-Frame-Marker: ein
        # Medien-Frame ist bis zu 1,2 kB gross und wird auf mehrere UDP-Pakete
        # verteilt, deren Fortsetzungen kein ffffffff tragen. Ohne Quittung laeuft
        # das Sendefenster des Geraets nach ~8 kB voll und der Strom steht.
        end = seq + len(payload)
        if seq <= chan.rcv:
            chan.rcv = max(chan.rcv, end)
        elif chan.rcv <= 1:          # ISN != 1 -> uebernehmen
            chan.rcv = end
        self._send_ack(chan, src)

        if payload[:4] == b"\xff\xff\xff\xff":
            self._handle_app_frame(chan, payload, src)

    def _handle_app_frame(
        self, chan: _Channel, payload: bytes, src: tuple[str, int]
    ) -> None:
        total = struct.unpack("<I", payload[4:8])[0] if len(payload) >= 8 else 0
        outer_msg = payload[0x18] if len(payload) >= 0x1C else 0

        if chan.conv == CH0 and not self.device_ready.is_set():
            self._scan_session_ready(payload)

        if total == 76 and chan.state == "SENT_HELLO":
            self._start_session(chan, payload, src)
        elif (total == 56 or len(payload) == 144) and outer_msg == 0 and chan.state == "SENT_A9":
            self._send_login(chan, src)
        elif (total == 56 or total > 50) and outer_msg == 1 and chan.state == "SENT_LOGIN":
            # Transportseitige Quittung des LOGIN. Das ist NOCH NICHT die Freigabe
            # der App-Session -- die meldet das Geraet ~2 s spaeter mit 0xFE msg13=2.
            chan.state = "LOGGED_IN"
            _LOGGER.debug("CH%x LOGIN acknowledged", chan.conv)
            if chan.conv == CH0:
                self.logged_in.set()

    def _scan_session_ready(self, payload: bytes) -> None:
        """Look for the device's "session open" frame (0xFE msg13=2).

        The device bundles several application frames into one UDP packet, so
        every embedded frame has to be checked, not just the first. Waiting for
        the OPENDOOR frame (msg13=4) to come back would be futile: that one only
        ever travels client -> device (verified against open.pcap).
        """
        i = 0
        while i >= 0 and i + 88 <= len(payload):
            total = struct.unpack("<I", payload[i + 4 : i + 8])[0]
            if 88 <= total <= 2000:
                head = cbc_decrypt(payload[i + 56 : i + 88], self._key)
                if len(head) >= 14 and head[0] == 0xFE and head[13] == 2:
                    self.device_ready.set()
                    _LOGGER.debug("Device signalled session ready (0xFE msg13=2)")
                    return
            i = payload.find(b"\xff\xff\xff\xff", i + 4)

    def _start_session(
        self, chan: _Channel, payload: bytes, src: tuple[str, int]
    ) -> None:
        """Answer the device HELLO with the plaintext a9 setup frame.

        Session base = the last 2 bytes of the device HELLO (absolute 74..76);
        the slot byte is our own (0x07 for CH0, 0x08 for CH1) and is not read
        back from the echo.
        """
        chan.sess = payload[74:76] + bytes([chan.slot_id])
        self._send_frame(
            chan, build_app_frame(0, build_a9_body(chan.index), chan.index, chan.sess), src
        )
        chan.state = "SENT_A9"
        _LOGGER.debug(
            "CH%x got device HELLO76, sess=%s, sending a9", chan.conv, chan.sess.hex()
        )

    def _send_login(self, chan: _Channel, src: tuple[str, int]) -> None:
        """Log in on one channel once the device echoed our a9 frame."""
        if chan.sess is None:
            return
        payload = build_login_payload(self._dynamic_password, self._client_id, self._oem)
        # CH0 (Video/Steuerung) verlangt f15=1 und f16=1, CH1 (Audio) b14=0xFF.
        # Beides byte-genau gegen open.pcap verifiziert (§5q der RE-Notizen).
        if chan.conv == CH0:
            body = ctrl_frame(0x01, self._ts, payload, key=self._key, msg13=1, f15=1, f16=1)
        else:
            body = ctrl_frame(0x0B, self._ts, payload, key=self._key, msg13=0xFF, b14=0xFF)
        self._send_frame(chan, build_app_frame(1, body, chan.index, chan.sess), src)
        chan.state = "SENT_LOGIN"
        _LOGGER.debug("CH%x got 144B echo, sending LOGIN", chan.conv)

    # ------------------------------------------------------- Sitzungspflege

    def maintain(self) -> None:
        """Keep the session alive: heartbeat probes and ARQ retransmits."""
        now = time.monotonic()
        if now - self._last_probe > self.PROBE_INTERVAL:
            value = self._MTU_PROBE_VALUES[self._probe_index % len(self._MTU_PROBE_VALUES)]
            self._send(build_mtu_probe(self._session_flag, self._probe_id, value))
            self._probe_index += 1
            self._last_probe = now
        if now - self._last_arq > self.ARQ_INTERVAL:
            self._retransmit_stalled(now)
            self._last_arq = now

    def _retransmit_stalled(self, now: float) -> None:
        """Repeat handshake frames the device has not answered (UDP loss)."""
        for chan in self.channels.values():
            if (
                chan.myid is not None
                and chan.state in self._HANDSHAKE_STATES
                and now - chan.last_tx > self.ARQ_IDLE
            ):
                self.resend_last(chan.conv)
                chan.last_tx = now

    def run_until(self, deadline: float, until: Callable[[], bool] | None = None) -> None:
        """Service the session until ``deadline`` or until ``until()`` is true."""
        while time.monotonic() < deadline:
            self.maintain()
            if until is not None and until():
                return
            time.sleep(0.01)

    def run_for(self, seconds: float, until: Callable[[], bool] | None = None) -> None:
        """Service the session for ``seconds`` (see :meth:`run_until`)."""
        self.run_until(time.monotonic() + seconds, until)

    def wait_until(self, event: threading.Event, deadline: float) -> bool:
        """Wait for ``event`` while keeping the session alive."""
        self.run_until(deadline, event.is_set)
        return event.is_set()

    def wait(self, event: threading.Event, timeout: float) -> bool:
        """Wait ``timeout`` seconds for ``event`` while keeping the session alive."""
        return self.wait_until(event, time.monotonic() + timeout)

    def close(self, outer_msg: int = 6) -> None:
        """Say goodbye and release the station's single P2P slot.

        Doing this promptly matters: while the session stands, the station turns
        down every other connection attempt -- including the doorbell's own.
        """
        chan = self.channels[CH0]
        if chan.sess is not None:
            body = ctrl_frame(0x07, self._ts, b"", key=self._key)
            frame = build_app_frame(outer_msg, body, chan.index, chan.sess)
            self._send(
                build_transport_hdr(chan.myid, chan.conv, chan.sent_pos, chan.rcv, frame)
            )
            time.sleep(CLOSE_LINGER)
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        if self._cloud is not None:
            self._cloud.close()
            self._cloud = None

    def __enter__(self) -> _P2PTransport:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def handshake_states(self) -> str:
        """Return a short "CH0=..., CH1=..." progress summary for error logs."""
        return ", ".join(f"CH{chan.conv:x}={chan.state}" for chan in self.channels.values())


class _StreamAssembler:
    """Reassembles the device's CH0 byte stream in arrival order.

    The device numbers its bytes like TCP, and UDP delivers them out of order,
    so segments are buffered until the missing bytes turn up. A gap still open
    after ``GAP_TIMEOUT`` is zero-filled, otherwise a single lost packet would
    stall the video for good. Consumed segments are dropped, which keeps the
    cost of :meth:`read` proportional to the new data rather than to the whole
    session -- the difference between a smooth 90-second stream and one that
    slows down the longer it runs.
    """

    GAP_TIMEOUT = 1.0

    def __init__(self) -> None:
        """Start an empty reassembly buffer."""
        self._lock = threading.Lock()
        self._segments: dict[int, bytes] = {}
        self._next: int | None = None
        self._gap_since: float | None = None
        self._delivered = False
        self.total = 0

    def add(self, seq: int, data: bytes) -> None:
        """Take one received segment (called from the receive thread)."""
        with self._lock:
            if self._next is None:
                self._next = seq
            elif seq < self._next:
                if self._delivered:
                    # Liegt hinter dem bereits Ausgelieferten -> Wiederholung.
                    return
                # Noch nichts ausgeliefert: das Geraet faengt nicht zwingend bei
                # 1 an, und das erste Paket kann verspaetet eintreffen. Die
                # kleinste bisher gesehene Nummer ist die Startnummer.
                self._next = seq
            if seq not in self._segments:
                self._segments[seq] = data
                self.total += len(data)

    def read(self, flush: bool = False) -> bytes:
        """Return the next contiguous bytes; ``flush`` closes all gaps at once."""
        out = bytearray()
        with self._lock:
            while self._next is not None:
                segment = self._segments.pop(self._next, None)
                if segment is not None:
                    out += segment
                    self._next += len(segment)
                    self._gap_since = None
                    continue
                ahead = [seq for seq in self._segments if seq > self._next]
                if not ahead:
                    break
                if not flush and not self._gap_expired():
                    break
                # Verlorene Bytes auffuellen, damit der Decoder wieder aufsetzt.
                following = min(ahead)
                out += bytes(following - self._next)
                self._next = following
                self._gap_since = None
            if out:
                self._delivered = True
        return bytes(out)

    def _gap_expired(self) -> bool:
        now = time.monotonic()
        if self._gap_since is None:
            self._gap_since = now
            return False
        return now - self._gap_since >= self.GAP_TIMEOUT


# --- Gemeinsame Bausteine der Abläufe ----------------------------------------

def _session_key(data_encode_key: str | None) -> bytes:
    """Return the AES key of the session (device key, or the family default)."""
    return data_encode_key.encode("ascii") if data_encode_key else FALLBACK_KEY


def _require_password(duid: str, dynamic_password: str) -> bool:
    """Refuse to touch the station without the rotating device password.

    A made-up password is indistinguishable from a correct one at the transport
    layer: the station acks such a LOGIN and then lets the session expire in
    silence, which looks exactly like a busy station and keeps its only P2P slot
    occupied for nothing.
    """
    if dynamic_password:
        return True
    _LOGGER.error(
        "No dynamic_password available for %s -- not opening a P2P session. "
        "Check the cloud credentials of the integration.",
        duid,
    )
    return False


def _decode_media(frames: list[bytes], keys: tuple[bytes, ...]) -> bytes | None:
    """Decrypt the captured media frames and return the best H.264 stream."""
    candidates = []
    for key in dict.fromkeys(keys):          # doppelte Schluessel ueberspringen
        plain = bytearray()
        for frame in frames:
            plain += decrypt_head(frame[APP_HDR:], key)
        stream = extract_h264(bytes(plain))
        if len(stream) > 500:
            candidates.append(stream)
    if not candidates:
        return None
    # Den ersten Kandidaten nehmen, der SPS UND IDR enthaelt -- NICHT den
    # laengsten: ein falsch entschluesselter Strom ist meist der laengste (er
    # traegt die Frame-Koepfe mit) und trotzdem nicht dekodierbar.
    return next(
        (stream for stream in candidates if h264_is_decodable(stream)),
        max(candidates, key=len),
    )


def _run_ffmpeg(args: list[str], timeout: float) -> bool:
    """Run ffmpeg, reporting whether it could be started at all."""
    try:
        subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", *args],
                       capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        _LOGGER.error("FFmpeg not found -- it is required on the Home Assistant host")
        return False
    except (OSError, subprocess.SubprocessError) as err:
        _LOGGER.warning("FFmpeg failed: %s", err)
        return False
    return True


# --- Tueroeffnen -------------------------------------------------------------

@dataclass
class UnlockResult:
    """How far one unlock attempt got.

    Truthy exactly when the device acknowledged the command, so callers can
    simply write ``if not result:``. The individual flags tell apart the two
    failure modes that need different handling: a stalled handshake means the
    command was never sent (safe to retry), a missing ack means it may well have
    opened the door (must not be retried).
    """

    ready: bool = False   # Geraet hat die App-Session freigegeben
    sent: bool = False    # OPENDOOR hat den Client verlassen
    acked: bool = False   # Geraet hat die Bytes quittiert

    def __bool__(self) -> bool:
        """Report whether the door station confirmed the unlock."""
        return self.acked


def _open_door(
    slot: _P2PSlot,
    duid: str,
    dynamic_password: str,
    pin: str,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    door: int = 0,
    locknumber: int = 0,
    key: bytes = FALLBACK_KEY,
    pin_sha256: str | None = None,
) -> UnlockResult:
    """Unlock one door-release relay over UDP/KCP (verified flow).

    ``slot`` owns the session. It hands in a session that is still open from a
    previous command -- then the unlock is just one frame and takes milliseconds
    instead of the five to eight seconds a fresh handshake costs -- and takes the
    session back afterwards, to keep it warm or to close it.

    ``pin_sha256`` short-circuits hashing the PIN: the cloud device list already
    carries the same value as ``out-auth-code`` (verified: SHA256(PIN) ==
    out-auth-code), so callers that have the device list but not the PIN can
    pass it directly.
    """
    _LOGGER.debug("Initiating P2P unlock for duid=%s, door=%d, lock=%d", duid, door, locknumber)
    result = UnlockResult()
    if not _require_password(duid, dynamic_password):
        return result

    pin_hash = (
        pin_sha256
        or (hashlib.sha256(pin.encode("utf-8")).hexdigest() if pin else None)
        or SHA256_OF_EMPTY
    )

    # Ein Zeitbudget fuer die ganze Sitzung: jede Sekunde laenger blockiert
    # den P2P-Slot der Station fuer den naechsten Versuch.
    deadline = time.monotonic() + DOOR_SESSION_TIMEOUT
    transport = slot.transport
    if transport is not None and not _warm_session_alive(transport, deadline):
        # Die weitergereichte Sitzung antwortet nicht mehr. Sofort neu aufbauen und
        # NICHT den Erholungsabstand abwarten: die Station hat die Verbindung ja
        # selbst schon fallen lassen, sie ist damit frei.
        slot.drop_transport()
        transport = None

    if transport is None:
        transport = _P2PTransport(duid, dynamic_password, client_id, key, oem)
        slot.transport = transport
        if not transport.connect():
            return result
        deadline = time.monotonic() + DOOR_SESSION_TIMEOUT
        if not transport.wait_until(transport.device_ready, deadline):
            # Ohne diese Meldung waere nicht zu sehen, WIE WEIT der Handshake kam --
            # genau das unterscheidet "Station belegt" von einem echten Fehler.
            _LOGGER.error(
                "Device never signalled session ready (0xFE msg13=2) -- OPENDOOR was not "
                "sent at all. Handshake got to %s. The station serves only one P2P session "
                "at a time: a running camera stream, a live view in the phone app or a "
                "ringing call will block it.",
                transport.handshake_states(),
            )
            return result
        # Erst die drei Setup-Frames, dann der Tueroeffner -- genau in der
        # Reihenfolge der echten App. Auf einer schon laufenden Sitzung entfallen
        # sie, dort ist der Tueroeffner-Frame das einzige, was noch fehlt.
        transport.send_session_setup()

    result.ready = True
    _, end_pos = transport.send_ctrl(
        5, 0xFE, build_open_payload(door, locknumber, pin_hash), msg13=4
    )
    result.sent = True
    _LOGGER.debug("OPENDOOR sent (door=%d lock=%d), waiting for device ack", door, locknumber)
    result.acked = _await_opendoor_ack(transport, end_pos, deadline)

    if result.acked:
        # Die Sitzung bleibt stehen. Das gibt dem Geraet dieselbe Nachlaufzeit,
        # die sich auch die echte App nimmt (~1,7 s zwischen Quittung und
        # Sitzungsende), kostet den Nutzer aber keine Wartezeit mehr -- und das
        # naechste Oeffnen kommt ohne jeden Neuaufbau aus. Wird sie doch sofort
        # geschlossen (warm_idle=0), muss die Nachlaufzeit abgewartet werden.
        slot.keep_warm = True
        slot.settle = POST_UNLOCK_SETTLE
        _LOGGER.debug("Door unlock confirmed by device")
    elif result.sent:
        _LOGGER.error(
            "OPENDOOR was sent but the device never acknowledged the bytes "
            "(transport ack stopped at %d, expected >= %d). The door may or may not "
            "have opened.",
            transport.channels[CH0].peer_ack, end_pos,
        )
    return result


def _warm_session_alive(transport: _P2PTransport, deadline: float) -> bool:
    """Check a session that was kept open before a command is sent on it.

    One harmless session frame -- the same one the app sends after its login --
    goes out and we wait for the transport to acknowledge it. Only then is it
    proven that the station is still listening. The unlock frame itself must not
    be used for that test: a second attempt would open the door twice.
    """
    chan = transport.channels[CH0]
    try:
        _, end = transport.send_ctrl(4, 0xFE, b"\x00", msg13=2)
    except (P2PError, OSError):
        return False
    sent_at = time.monotonic()
    resent = False
    probe_deadline = min(deadline, sent_at + WARM_PROBE_TIMEOUT)
    while time.monotonic() < probe_deadline:
        transport.maintain()
        if chan.peer_ack >= end:
            return True
        # Ein einzelnes verlorenes Datagramm darf eine gesunde Sitzung nicht als
        # tot erscheinen lassen: der Neuaufbau ueberspringt danach den
        # Erholungsabstand und laeuft der noch belegten Station ins Messer.
        # Wiederholung am ORIGINAL-Offset, damit das Geraet sie als Dublette sieht.
        if not resent and time.monotonic() - sent_at > WARM_PROBE_RESEND:
            transport.resend_last(CH0)
            resent = True
        time.sleep(0.01)
    _LOGGER.debug(
        "The session kept open with %s went stale -- reconnecting", transport.duid
    )
    return False


def _await_opendoor_ack(transport: _P2PTransport, end_pos: int, deadline: float) -> bool:
    """Wait for the device to acknowledge the OPENDOOR bytes, resending if needed.

    There is no application-level reply to an unlock: in open.pcap not a single
    0xFE frame with msg13=4 comes back, and the msg13=5/7/8 frames that do also
    appear in a pure live-view capture without any unlock. The proof of delivery
    is therefore the transport, which acks the byte offset just behind the frame.

    Retransmits repeat the SAME bytes at the SAME offset: the device recognises
    them as a duplicate and does not open a second time.
    """
    chan = transport.channels[CH0]
    sends = 1
    last_send = time.monotonic()
    while time.monotonic() < deadline:
        transport.maintain()
        if chan.peer_ack >= end_pos:
            _LOGGER.debug("Device acknowledged OPENDOOR (transport ack=%d)", chan.peer_ack)
            return True
        now = time.monotonic()
        if sends >= OPENDOOR_MAX_SENDS:
            # Nach der letzten Wiederholung nicht bis zum vollen Timeout
            # weiterlaufen -- es ist keine Quittung mehr zu erwarten und der
            # naechste Versuch braucht den Slot.
            if now - last_send > 2.0:
                break
        elif now - last_send > OPENDOOR_RESEND_AFTER:
            sends += 1
            transport.resend_last(CH0)
            last_send = now
            _LOGGER.debug(
                "OPENDOOR not acknowledged yet, resending the same frame at offset %d (%d/%d)",
                chan.last_pos, sends, OPENDOOR_MAX_SENDS,
            )
        time.sleep(0.01)
    return False


# --- Standbild / Clip --------------------------------------------------------

def _grab_video(
    slot: _P2PSlot,
    duid: str,
    dynamic_password: str,
    key: bytes,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    duration: float = 8.0,
    return_h264: bool = False,
) -> bytes | None:
    """Fetch live video from the door station.

    Returns a JPEG still by default, or the raw H.264 elementary stream when
    ``return_h264`` is set (used by the clip recorder).

    ``duration`` is the recording window AFTER the login. The device needs about
    two seconds before it starts pushing video, so anything below ~5 s yields
    very little material. The window ends early when someone wants to unlock a
    door -- that always has priority over a picture.
    """
    if not _require_password(duid, dynamic_password):
        return None

    assembler = _StreamAssembler()
    transport = _video_session(
        slot, duid, dynamic_password, key, client_id, oem, assembler.add
    )
    if transport is None:
        slot.drop_transport()
        return None
    try:
        transport.run_for(duration, until=_UNLOCK_WANTED.is_set)
    finally:
        _release_or_hand_over(slot, transport, "snapshot")

    _LOGGER.debug("Received %d B of media on CH0 from %s", assembler.total, duid)
    frames = [frame for _, frame in extract_app_frames(assembler.read(flush=True))]
    h264 = _decode_media(frames, (key, FALLBACK_KEY)) if frames else None
    if not h264:
        _LOGGER.debug("No H.264 NAL units recovered from the P2P stream for %s", duid)
        return None
    if return_h264:
        return h264
    return _still_image(h264)


def _still_image(h264: bytes) -> bytes | None:
    """Decode the first frame of an H.264 stream into a JPEG."""
    with tempfile.TemporaryDirectory(prefix="balter_snapshot_") as tmp_dir:
        raw = os.path.join(tmp_dir, "frame.h264")
        jpg = os.path.join(tmp_dir, "frame.jpg")
        with open(raw, "wb") as handle:
            handle.write(h264)
        if not _run_ffmpeg(["-y", "-i", raw, "-vframes", "1", jpg], timeout=15):
            return None
        if not os.path.exists(jpg) or os.path.getsize(jpg) == 0:
            return None
        with open(jpg, "rb") as handle:
            return handle.read()


def _record_clip(
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    seconds: float = 5.0,
    warm_idle: float = DEFAULT_WARM_IDLE,
) -> bytes | None:
    """Record a short MP4 clip.

    ``seconds`` is the desired clip length; the recording window is longer
    because the device only starts sending about two seconds after the login.
    The frame rate is estimated from the number of picture NALs and the actual
    stream time so the clip plays back in real time.
    """
    window = seconds + 4.0
    h264 = p2p_get_snapshot_sync(
        duid, dynamic_password, data_encode_key=data_encode_key,
        client_id=client_id, oem=oem, duration=window, return_h264=True,
        warm_idle=warm_idle,
    )
    if not h264:
        return None

    fps = max(5.0, min(30.0, _count_pictures(h264) / max(1.0, window - 2.0)))
    with tempfile.TemporaryDirectory(prefix="balter_clip_") as tmp_dir:
        raw = os.path.join(tmp_dir, "clip.h264")
        mp4 = os.path.join(tmp_dir, "clip.mp4")
        with open(raw, "wb") as handle:
            handle.write(h264)
        ok = _run_ffmpeg(
            ["-y", "-f", "h264", "-r", f"{fps:.2f}", "-i", raw, "-t", str(seconds),
             "-c:v", "libx264", "-pix_fmt", "yuv420p", mp4],
            timeout=120,
        )
        if ok and os.path.exists(mp4) and os.path.getsize(mp4) > 0:
            with open(mp4, "rb") as handle:
                return handle.read()
    _LOGGER.warning("FFmpeg produced no clip for %s", duid)
    return None


def _count_pictures(h264: bytes) -> int:
    """Count the coded picture NAL units (types 1 and 5) in a stream."""
    count, pos = 0, h264.find(b"\x00\x00\x00\x01")
    while pos >= 0:
        if pos + 4 < len(h264) and (h264[pos + 4] & 0x1F) in (1, 5):
            count += 1
        pos = h264.find(b"\x00\x00\x00\x01", pos + 4)
    return count


# --- Livestream --------------------------------------------------------------

def _stream_video(
    slot: _P2PSlot,
    duid: str,
    dynamic_password: str,
    key: bytes,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    duration: float = 90.0,
    on_jpeg: Callable[[bytes], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> int:
    """Open a P2P video session and transcode the live H.264 stream to JPEGs.

    Calls ``on_jpeg(jpeg_bytes)`` for every decoded frame until ``duration``
    seconds elapse or ``should_stop()`` returns True. Returns the number of
    frames emitted. The decrypted door-station stream is a clean multi-frame
    H.264 elementary stream (verified: SPS/PPS/IDR/P), so it is piped straight
    into ffmpeg (``-f h264 -> -f mjpeg``); a reader thread splits the JPEGs.
    """
    if on_jpeg is None:
        return 0
    if not _require_password(duid, dynamic_password):
        return 0

    assembler = _StreamAssembler()
    ffmpeg = _start_mjpeg_transcoder()
    if ffmpeg is None:
        return 0

    stop = threading.Event()
    frames_out = [0]
    workers = [
        threading.Thread(target=_jpeg_reader, args=(ffmpeg, stop, on_jpeg, frames_out),
                         name=f"balter-mjpeg-{duid}", daemon=True),
        threading.Thread(target=_decrypt_pump, args=(ffmpeg, stop, assembler, key),
                         name=f"balter-decrypt-{duid}", daemon=True),
    ]
    transport = _video_session(
        slot, duid, dynamic_password, key, client_id, oem, assembler.add
    )
    if transport is None:
        slot.drop_transport()
        _stop_ffmpeg(ffmpeg)
        return 0
    try:
        for worker in workers:
            worker.start()

        _LOGGER.debug("Live stream started for %s (max %.0fs)", duid, duration)
        transport.run_for(duration, until=lambda: _stream_should_end(should_stop))
    finally:
        stop.set()
        _release_or_hand_over(slot, transport, "live stream")
        _stop_ffmpeg(ffmpeg)

    _LOGGER.debug("Live stream ended for %s (%d frames)", duid, frames_out[0])
    return frames_out[0]


def _video_session(
    slot: _P2PSlot,
    duid: str,
    dynamic_password: str,
    key: bytes,
    client_id: str,
    oem: str,
    on_media: Callable[[int, bytes], None],
) -> _P2PTransport | None:
    """Return a logged-in session for a video command, or None if none came up.

    Reuses a session the slot still holds open from a previous command. Joining
    a running stream means the first frames arrive mid-picture, but both decoders
    only start at the next parameter set anyway -- and it saves the whole
    handshake plus the station's recovery gap.
    """
    transport = slot.transport
    if transport is not None:
        if _warm_session_alive(transport, time.monotonic() + WARM_PROBE_TIMEOUT):
            transport.set_media_sink(on_media)
            transport.send_session_setup()
            return transport
        slot.drop_transport()

    transport = _P2PTransport(
        duid, dynamic_password, client_id, key, oem, on_media=on_media
    )
    slot.transport = transport
    if not transport.connect():
        return None
    if transport.wait(transport.logged_in, LOGIN_TIMEOUT):
        # Es gibt kein Play-Kommando: das Geraet sendet den Videostrom von
        # selbst, sobald der CH0-LOGIN app-seitig akzeptiert ist. Die
        # Setup-Frames folgen dem Video, sie starten es nicht.
        transport.send_session_setup()
    else:
        _LOGGER.warning("Login not confirmed for %s -- device busy?", duid)
    return transport


def _release_or_hand_over(slot: _P2PSlot, transport: _P2PTransport, what: str) -> None:
    """End a camera session -- by handing it to a waiting unlock, or by closing it.

    An unlock that had to interrupt us would otherwise pay for the whole
    handshake AGAIN, plus the station's recovery gap: half a minute in front of
    the door for a session that is already logged in and ready to take commands.
    """
    # Der Assembler dieses Kommandos wird gleich nicht mehr gelesen -- ohne dies
    # wuerde die uebergebene Sitzung weiter Video hineinpuffern.
    transport.set_media_sink(None)
    if slot.warm_idle > 0 and _UNLOCK_WANTED.is_set() and transport.device_ready.is_set():
        _LOGGER.info("Handing the open P2P session over from the %s to the door unlock", what)
        slot.keep_warm = True
        return
    slot.drop_transport()


def _stream_should_end(should_stop: Callable[[], bool] | None) -> bool:
    """Report whether the live stream has to give up the P2P slot now."""
    if _UNLOCK_WANTED.is_set():
        _LOGGER.info("Ending the live stream early -- a door unlock is waiting")
        return True
    return bool(should_stop and should_stop())


def _start_mjpeg_transcoder() -> subprocess.Popen[bytes] | None:
    """Start ffmpeg as an H.264 -> MJPEG pipe, or None if it is unavailable."""
    try:
        return subprocess.Popen(
            ["ffmpeg", "-hide_banner", "-loglevel", "error", "-fflags", "nobuffer",
             "-flags", "low_delay", "-f", "h264", "-i", "pipe:0",
             "-f", "mjpeg", "-q:v", "6", "pipe:1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as err:
        _LOGGER.error(
            "FFmpeg could not be started -- the live stream needs ffmpeg on the "
            "Home Assistant host: %s", err,
        )
        return None


def _stop_ffmpeg(ffmpeg: subprocess.Popen[bytes]) -> None:
    """Close the pipe and make sure the transcoder is gone."""
    if ffmpeg.stdin is not None:
        with contextlib.suppress(OSError):
            ffmpeg.stdin.close()
    try:
        ffmpeg.wait(timeout=3)
    except subprocess.TimeoutExpired:
        ffmpeg.terminate()


def _jpeg_reader(
    ffmpeg: subprocess.Popen[bytes],
    stop: threading.Event,
    on_jpeg: Callable[[bytes], None],
    frames_out: list[int],
) -> None:
    """Cut whole JPEGs (SOI ffd8 ... EOI ffd9) out of the ffmpeg output."""
    if ffmpeg.stdout is None:
        return
    buf = bytearray()
    while not stop.is_set():
        chunk = ffmpeg.stdout.read(4096)
        if not chunk:
            return
        buf.extend(chunk)
        while True:
            start = buf.find(b"\xff\xd8")
            if start < 0:
                break
            end = buf.find(b"\xff\xd9", start + 2)
            if end < 0:
                del buf[:start]
                break
            jpeg = bytes(buf[start : end + 2])
            del buf[: end + 2]
            frames_out[0] += 1
            # Ein fehlerhafter Konsument darf den Stream nicht abwuergen.
            with contextlib.suppress(Exception):
                on_jpeg(jpeg)


def _decrypt_pump(
    ffmpeg: subprocess.Popen[bytes],
    stop: threading.Event,
    assembler: _StreamAssembler,
    key: bytes,
) -> None:
    """Decrypt arriving media frames and feed them to ffmpeg.

    Everything before the first parameter set is dropped: ffmpeg cannot start on
    a half frame. Only the unsynchronised head is buffered, so memory stays flat
    however long the stream runs.
    """
    if ffmpeg.stdin is None:
        return
    tail = bytearray()      # angefangener App-Frame
    presync = bytearray()   # entschluesselte Bytes vor dem ersten NAL
    synced = False
    while not stop.is_set():
        time.sleep(0.2)
        tail += assembler.read()
        frames, consumed = split_app_frames(bytes(tail))
        del tail[:consumed]
        if not frames:
            continue

        chunk = bytearray()
        for frame in frames:
            chunk += decrypt_head(frame[APP_HDR:], key)
        if not synced:
            presync += chunk
            offset = first_nal_offset(presync)
            if offset < 0:
                # Nur das Ende behalten -- ein Startcode kann an der Grenze liegen.
                del presync[:-8]
                continue
            chunk = presync[offset:]
            presync.clear()
            synced = True
        try:
            ffmpeg.stdin.write(bytes(chunk))
            ffmpeg.stdin.flush()
        except (BrokenPipeError, OSError):
            return


# --- Öffentliche, serialisierte Einstiegspunkte ------------------------------

def p2p_open_door_sync(
    duid: str,
    dynamic_password: str,
    pin: str,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    door: int = 0,
    locknumber: int = 0,
    data_encode_key: str | None = None,
    pin_sha256: str | None = None,
    warm_idle: float = DEFAULT_WARM_IDLE,
) -> UnlockResult:
    """Tueroeffnen -- serialisiert gegen jede andere P2P-Sitzung dieses Prozesses.

    Setzt vorher das Vorrangsignal, damit Livestream und Standbild den Slot
    sofort raeumen, statt ihn bis zu STREAM_DURATION Sekunden zu blockieren --
    und uebernimmt deren bereits eingeloggte Sitzung gleich mit. Ebenso wird eine
    vom vorherigen Oeffnen noch offene Sitzung wiederverwendet: genau das macht
    das zweite Oeffnen kurz nach dem ersten so schnell wie in der echten App.
    """
    _UNLOCK_WANTED.set()
    key = _session_key(data_encode_key)
    try:
        with _P2PSlot(
            "Door unlock", duid, (dynamic_password, client_id, oem, key),
            reuse=True, warm_idle=warm_idle,
        ) as slot:
            return _open_door(
                slot, duid, dynamic_password, pin, client_id, oem, door, locknumber,
                key, pin_sha256,
            )
    finally:
        _UNLOCK_WANTED.clear()


def p2p_get_snapshot_sync(
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    duration: float = 8.0,
    return_h264: bool = False,
    warm_idle: float = DEFAULT_WARM_IDLE,
) -> bytes | None:
    """Standbild/Video holen -- serialisiert gegen jede andere P2P-Sitzung."""
    key = _session_key(data_encode_key)
    with _P2PSlot(
        "Snapshot", duid, (dynamic_password, client_id, oem, key),
        reuse=True, warm_idle=warm_idle,
    ) as slot:
        return _grab_video(
            slot, duid, dynamic_password, key, client_id, oem, duration, return_h264
        )


def p2p_record_clip_sync(*args: Any, **kwargs: Any) -> bytes | None:
    """Kurzen MP4-Clip aufnehmen (nutzt intern den Snapshot-Slot)."""
    return _record_clip(*args, **kwargs)


def p2p_stream_video_sync(
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    duration: float = 90.0,
    on_jpeg: Callable[[bytes], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    warm_idle: float = DEFAULT_WARM_IDLE,
) -> int:
    """Live-Videostream -- serialisiert gegen jede andere P2P-Sitzung."""
    key = _session_key(data_encode_key)
    with _P2PSlot(
        "Live stream", duid, (dynamic_password, client_id, oem, key),
        reuse=True, warm_idle=warm_idle,
    ) as slot:
        return _stream_video(
            slot, duid, dynamic_password, key, client_id, oem, duration, on_jpeg,
            should_stop,
        )


# --- Async-Fassaden für Home Assistant ---------------------------------------

async def async_p2p_open_door(
    hass: HomeAssistant,
    duid: str,
    dynamic_password: str,
    pin: str,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    door: int = 0,
    locknumber: int = 0,
    data_encode_key: str | None = None,
    pin_sha256: str | None = None,
    warm_idle: float = DEFAULT_WARM_IDLE,
) -> bool:
    """Unlock a door without blocking the event loop.

    Reuses a session that is still open from the previous command whenever there
    is one, so unlocking twice in a row costs one frame instead of a whole
    handshake -- the same reason it feels instant in the official app.

    A handshake, when one is needed, is deliberately attempted exactly ONCE per
    call. Live captures show the door station serves only a single P2P session
    and needs time to recover: every fresh attempt made while it is still busy
    *extends* the busy period, so hammering it with internal retries lowers the
    success rate instead of raising it. One clean attempt, then -- if the
    handshake stalled before the command left the client -- we raise
    P2PDoorBusyError so the UI can ask the user to wait ~30 s. If OPENDOOR did go
    out but was not acknowledged, that is a real failure (returned as False); a
    retry could open the door twice.
    """
    result = await hass.async_add_executor_job(
        functools.partial(
            p2p_open_door_sync, duid, dynamic_password, pin, client_id, oem, door,
            locknumber, data_encode_key, pin_sha256, warm_idle,
        )
    )
    if result.acked:
        return True
    if result.sent:
        # Befehl ist raus, nur die Quittung fehlt -> NICHT wiederholen.
        return False
    # Handshake blieb vor dem Senden haengen -> Station war belegt. Der Befehl
    # ging nachweislich nie raus, daher als "belegt" statt als "keine Quittung"
    # melden, damit die UI zum erneuten Versuch (nach kurzer Pause) auffordert.
    raise P2PDoorBusyError(
        "Die Türstation hat die P2P-Sitzung nicht freigegeben (vermutlich noch "
        "mit einer vorherigen Sitzung beschäftigt)."
    )


async def async_p2p_get_snapshot(
    hass: HomeAssistant,
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    duration: float = 8.0,
    attempts: int = 2,
    warm_idle: float = DEFAULT_WARM_IDLE,
) -> bytes | None:
    """Fetch a still image without blocking the event loop.

    A snapshot has no side effects, so a stalled handshake is simply retried.
    """
    for attempt in range(1, attempts + 1):
        image = await hass.async_add_executor_job(
            functools.partial(
                p2p_get_snapshot_sync, duid, dynamic_password,
                data_encode_key=data_encode_key, client_id=client_id, oem=oem,
                duration=duration, warm_idle=warm_idle,
            )
        )
        if image:
            return image
        if attempt < attempts:
            _LOGGER.debug("Snapshot attempt %d/%d failed, retrying", attempt, attempts)
    return None


async def async_p2p_record_clip(
    hass: HomeAssistant,
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    seconds: float = 5.0,
    warm_idle: float = DEFAULT_WARM_IDLE,
) -> bytes | None:
    """Record a short MP4 clip without blocking the event loop."""
    return await hass.async_add_executor_job(
        functools.partial(
            p2p_record_clip_sync, duid, dynamic_password,
            data_encode_key=data_encode_key, client_id=client_id, oem=oem,
            seconds=seconds, warm_idle=warm_idle,
        )
    )


async def async_p2p_stream_video(
    hass: HomeAssistant,
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = "",
    oem: str = DEFAULT_OEM,
    duration: float = 90.0,
    on_jpeg: Callable[[bytes], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    warm_idle: float = DEFAULT_WARM_IDLE,
) -> int:
    """Run a live MJPEG stream in the executor.

    ``on_jpeg(bytes)`` is called from a worker thread for every decoded frame;
    keep it cheap and thread-safe (a plain attribute assignment is fine).
    ``should_stop()`` lets the caller end the stream early.
    """
    return await hass.async_add_executor_job(
        functools.partial(
            p2p_stream_video_sync, duid, dynamic_password, data_encode_key,
            client_id, oem, duration, on_jpeg, should_stop, warm_idle,
        )
    )
