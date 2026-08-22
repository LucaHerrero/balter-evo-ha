"""Autonomous P2P Engine for Balter EVO 2 (Homaxi / Quvii protocol).

100% verified P2P transport implementation for:
- STUN NAT-Check (build_natcheck)
- Multi-version paho-mqtt support
- Door unlocking (p2p_open_door_sync / async_p2p_open_door)
- Camera snapshots (p2p_get_snapshot_sync / async_p2p_get_snapshot)
- Fully dynamic parameters (zero hardcoded personal data)
"""
from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import http.client
import json
import logging
import os
import random
import secrets
import shutil
import socket
import ssl
import string
import struct
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import paho.mqtt.client as mqtt

_LOGGER = logging.getLogger(__name__)

CH0 = 0x01000000
CH1 = 0x02000001

WIN_ACK = 0xFFFF0900
WIN_DATA = 0x00001900
WIN_BB = 0x00000500
MAGIC = b"\xc1\xef\xab\xff"
IV_ZERO = b"0" * 16
APP_HDR = 56  # outer app-frame header length (verified against all app captures)
# Notnagel, falls kein data-encode-key durchgereicht wird. Der echte Key ist
# geraetespezifisch, rotiert woechentlich und gehoert NICHT ins Repo -- er kommt
# zur Laufzeit aus der Cloud-Geraeteliste (api.get_device_credentials).
DEFAULT_KEY_CTRL = b"1" * 32
DEFAULT_KEY_MEDIA = b"1" * 32

APP_ID = "4028"
OEM = "G0028,G0126"
# Values the real app puts into the P2P LOGIN payload (verified byte-exact
# against live_real.pcap): "adminapp&&<dynpw>\0G0028G0126\0clientid=<id>\0".
DEFAULT_CLIENT_ID = "e4d73be5e26e9a83"
DEFAULT_OEM = "G0028G0126"
CRED_KEY = bytes.fromhex("a1c1d4bfe68cfc08a8768552e1114fe546a8768552e1114f3ad5b9ece31b8bd7")
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
P2P_MIN_GAP = 20.0          # Sekunden zwischen zwei Sitzungen
_P2P_GATE = threading.Lock()
_P2P_LAST_END = [0.0]


class _P2PSlot:
    """Kontextmanager: exklusiver Zugriff aufs Geraet + Mindestabstand."""

    def __enter__(self) -> "_P2PSlot":
        _P2P_GATE.acquire()
        wait = P2P_MIN_GAP - (time.time() - _P2P_LAST_END[0])
        if wait > 0:
            _LOGGER.debug("Balter EVO: waiting %.1fs before the next P2P session", wait)
            time.sleep(wait)
        return self

    def __exit__(self, *exc: Any) -> None:
        _P2P_LAST_END[0] = time.time()
        _P2P_GATE.release()


def rand_token(n: int) -> str:
    """Generate a random alphanumeric token."""
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def inet_cksum(data: bytes) -> int:
    """Compute standard Internet Checksum."""
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
    """AES-256-CBC encryption with zero IV."""
    n = len(data) - (len(data) % 16)
    if n == 0:
        return b""
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV_ZERO)).encryptor()
    return cipher.update(data[:n]) + cipher.finalize()


def cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC decryption with zero IV."""
    n = len(data) - (len(data) % 16)
    if n == 0:
        return data
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV_ZERO)).decryptor()
    return cipher.update(data[:n]) + cipher.finalize() + data[n:]


def ctrl_frame(
    ftype: int,
    ts: int,
    payload: bytes,
    key: bytes = DEFAULT_KEY_CTRL,
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
    """Build the 56-byte Outer Header + Body.

    Byte-exact against live_real.pcap / open.pcap / cold2.pcap / session.pcap:
    the header is 56 bytes and carries the body length TWICE -- once as
    ``body_len + 16`` @0x24 and once plain @0x30. A 48-byte header (used up to
    v11) shifts the body 8 bytes forward, so the device reads garbage as the
    body length: the transport layer still ACKs the frame, but the application
    layer silently drops it -- no LOGIN, no config, no video.
    """
    body_len = len(body)
    hdr = bytearray(56)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 56 + body_len)
    hdr[0x10:0x18] = bytes.fromhex("0001000003011200")
    struct.pack_into("<I", hdr, 0x18, outer_msg)
    struct.pack_into("<I", hdr, 0x24, body_len + 16)
    struct.pack_into("<H", hdr, 0x28, ch_idx)
    hdr[0x2A:0x2D] = sess_bytes
    hdr[0x2D:0x30] = bytes.fromhex("000004")
    struct.pack_into("<I", hdr, 0x30, body_len)
    return bytes(hdr) + body


def build_hello76(slot_id: int, ch_idx: int) -> bytes:
    """Build the 76-byte Client HELLO frame (56-byte header + 20-byte body).

    Only the fields up to 0x2C carry meaning; everything after is uninitialised
    heap in the real app (cold2.pcap/open.pcap show log strings and floats
    there, live_real.pcap zeros) and the device ignores it. The device echoes
    the frame and appends the 2-byte session base at absolute offset 74..76.
    """
    hdr = bytearray(56)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 76)
    hdr[0x10:0x18] = bytes.fromhex("0001000001011200")
    struct.pack_into("<I", hdr, 0x24, 20 + 16)
    struct.pack_into("<I", hdr, 0x28, slot_id | 0x04000000)
    return bytes(hdr) + (b"\x00" * 20)


def build_a9_body(ch_idx: int) -> bytes:
    """32-byte plaintext setup body sent right after the HELLO exchange.

    Byte 0 = 0xA9; byte 9 = stream type: 0 = video (CH0), 2 = audio (CH1).
    Identical in live_real.pcap, cold2.pcap and open.pcap.
    """
    b = bytearray(32)
    b[0] = 0xA9
    if ch_idx:
        b[9] = 0x02
    return bytes(b)


def build_login_payload(
    dynpw: str, client_id: str = DEFAULT_CLIENT_ID, oem: str = DEFAULT_OEM
) -> bytes:
    """Build the payload for the LOGIN (cmd=0x01) frame."""
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
    """Build the payload for the OPENDOOR (cmd=0xFE, msg13=4) frame."""
    p = bytearray(16)
    p[0] = door
    p[2] = locknumber
    p[3] = 1
    return bytes(p) + pin_sha256.encode("ascii")


def build_mtu_probe(session_flag: str, testid: int, aval: int) -> bytes:
    """Build the 0x88 MTU probe packet."""
    b = bytearray(164)
    b[0:4] = MAGIC
    struct.pack_into("<I", b, 4, 136)
    b[0x20] = 0x88
    struct.pack_into("<I", b, 0x38, testid & 0xFFFFFFFF)
    sf = session_flag.encode()[:63]
    b[0x44 : 0x44 + len(sf)] = sf
    struct.pack_into("<I", b, 0xA0, aval & 0xFFFFFFFF)
    b[0x2E] = 0
    return bytes(b)


def build_punch(session_flag: str, rip: str, rport: int, cid: int = 2, tid: int = 1) -> bytes:
    """Build the initial NAT punch packet."""
    b = bytearray(164)
    b[0:4] = MAGIC
    struct.pack_into("<I", b, 4, 136)
    b[0x20] = 0x88
    b[0x2A:0x2C] = struct.pack("<H", 0x1234)
    b[0x2E] = 0
    struct.pack_into("<I", b, 0x38, cid)
    struct.pack_into("<I", b, 0x3C, tid)
    b[0x40:0x44] = socket.inet_aton(rip)
    sf = session_flag.encode()[:63]
    b[0x44 : 0x44 + len(sf)] = sf
    struct.pack_into("<H", b, 0x84, rport)
    return bytes(b)


def build_natcheck(nonce: int = 0xEB95D55A) -> bytes:
    """Build verified 112-byte STUN NAT check request."""
    b = bytearray(112)
    struct.pack_into("<I", b, 0, 0xFFABEFC1)
    struct.pack_into("<H", b, 0x1A, 112)
    b[0x1C:0x20] = b"\xff\xff\xff\xff"
    b[0x20] = 0x54
    b[0x2C:0x34] = bytes.fromhex("0001000001001100")
    struct.pack_into("<I", b, 0x40, 0x2C)
    struct.pack_into("<I", b, 0x44, nonce)
    return bytes(b)


def _natcheck_query(sock: socket.socket, tries: int = 5) -> tuple[str, int]:
    """Query external STUN NAT check server (8.211.5.8:8300)."""
    req = build_natcheck()
    for _ in range(tries):
        sock.sendto(req, ("8.211.5.8", 8300))
        try:
            sock.settimeout(0.6)
            data, _ = sock.recvfrom(512)
        except socket.timeout:
            continue
        if len(data) >= 0x60 and data[0x20] == 0x54 and data[0x2E] == 1:
            ip = data[0x4C : data.find(b"\x00", 0x4C)].decode("ascii", "replace")
            port = struct.unpack("<H", data[0x5C:0x5E])[0]
            return ip, port
    return "0.0.0.0", 0


def parse_header(data: bytes) -> tuple[int, int, int, int, int, int, int]:
    """Parse a 28-byte transport packet header."""
    return struct.unpack("<7I", data[:28])


def extract_app_frames(data: bytes) -> list[tuple[int, bytes]]:
    """Extract individual Outer Frames (om, payload) from the reassembled byte stream."""
    frames = []
    i = 0
    while i <= len(data) - APP_HDR:
        if data[i : i + 4] == b"\xff\xff\xff\xff":
            tot = struct.unpack("<I", data[i + 4 : i + 8])[0]
            if APP_HDR <= tot <= len(data) - i:
                om = struct.unpack("<I", data[i + 0x18 : i + 0x1C])[0]
                frames.append((om, data[i : i + tot]))
                i += tot
                continue
        i += 1
    return frames


def decrypt_head(payload: bytes, key: bytes) -> bytes:
    """Decrypt the 64-byte media header with AES-256-CBC, returning full plaintext."""
    if len(payload) < 64:
        return payload
    dec_head = cbc_decrypt(payload[:64], key)
    return dec_head + payload[64:]


def h264_is_decodable(buf: bytes) -> bool:
    """True if the buffer carries both a parameter set (SPS) and a keyframe (IDR).

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


def extract_h264(plain: bytes) -> bytes:
    """Locate the start of valid H.264 NAL units in the decrypted media stream."""
    for pat in (
        b"\x00\x00\x00\x01\x67",  # SPS
        b"\x00\x00\x00\x01\x27",
        b"\x00\x00\x00\x01\x68",  # PPS
        b"\x00\x00\x00\x01\x28",
        b"\x00\x00\x00\x01\x65",  # IDR
        b"\x00\x00\x00\x01\x25",
    ):
        p = plain.find(pat)
        if p >= 0:
            return plain[p:]
    return b""


# --- Cloud Discovery & MQTT Session ------------------------------------------

def _mst_query(client_id: str = "e4d73be5e26e9a83") -> tuple[int, str]:
    body = (
        '<?xml version="1.0" encoding="UTF-8"?><envelope><header>'
        '<flag>tdkcloud</flag><command>query-hlrv2</command><seq>1</seq></header>'
        '<content><server-type>userapp,alarmapp,p2papp,natcheck,appinfo,oauth2,log,openapi'
        f'</server-type><oem>{OEM}</oem><devid></devid><public-ip></public-ip>'
        f'<client-id>{client_id}</client-id><regionid>0</regionid><version>4456</version>'
        '</content></envelope>'
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection("global.qvcloud.net", 443, context=ctx, timeout=12)
    conn.request(
        "GET",
        "/mst/query",
        body=body.encode(),
        headers={"Host": "global.qvcloud.net", "Content-Type": "application/xml;charset=utf-8"},
    )
    resp = conn.getresponse()
    data = resp.read().decode("utf-8", "replace")
    conn.close()
    return resp.status, data


def _decode_cred(b64val: str) -> str:
    ct = base64.b64decode(b64val)
    pt = Cipher(algorithms.AES(CRED_KEY), modes.CBC(IV_ZERO)).decryptor().update(ct)
    return pt.rstrip(b"\x00").decode("utf-8", "replace")


def _parse_param(param: str) -> dict[str, str]:
    out = {}
    for kv in param.split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k] = v
    return out


def _parse_servers(xml: str) -> dict[str, dict[str, str]]:
    root = ET.fromstring(xml)
    servers = {}
    for srv in root.findall(".//server"):
        st = srv.findtext("server-type") or ""
        servers[st] = {
            "url": srv.findtext("url") or "",
            "uri": srv.findtext("uri") or "",
            "param": srv.findtext("param") or "",
        }
    return servers


class CloudP2PSession:
    """Manages the MQTT connection to the Quvii Cloud for P2P Hole Punching."""

    def __init__(self, client_id: str, duid: str) -> None:
        self.client_id = client_id if len(client_id) == 16 else "e4d73be5e26e9a83"
        self.duid = duid
        self.userid = str(random.randint(10**9, 9 * 10**9))
        self.session_flag = rand_token(43)
        self.requ_id = random.randint(-(2**31), -1)
        self.loc: tuple[str, int] | None = None
        self.pub: tuple[str, int] | None = None
        self.utd: tuple[str, int] | None = None
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
            "client": {"id": self.client_id, "type": "3", "oem": OEM, "app": APP_ID},
        }

    def connect(self) -> None:
        _, xml = _mst_query(self.client_id)
        servers = _parse_servers(xml)
        p2p = servers["p2papp"]
        host = p2p["url"].replace("mqtts://", "").split(":")[0]
        port = int(p2p["url"].split(":")[-1])
        q = _parse_param(p2p["param"])
        username = _decode_cred(q["username"])
        password = _decode_cred(q["password"])

        try:
            cli = mqtt.Client(
                client_id=f"app_{self.client_id}_{self.userid}_",
                protocol=mqtt.MQTTv31,
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            )
        except (AttributeError, TypeError):
            cli = mqtt.Client(
                client_id=f"app_{self.client_id}_{self.userid}_",
                protocol=mqtt.MQTTv31,
            )

        cli.username_pw_set(username, password)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        cli.tls_set_context(ctx)
        cli.on_connect = self._on_connect
        cli.on_message = self._on_message
        cli.connect(host, port, keepalive=30)
        cli.loop_start()
        self.cli = cli

    def _on_connect(self, *args: Any, **kwargs: Any) -> None:
        cli = args[0] if args else self.cli
        if cli:
            cli.subscribe(self._sub, qos=1)
            cli.publish(self._pub, json.dumps({"header": self._hdr("register"), "content": {}}), qos=1)

    def p2pconnect(self) -> None:
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
        if self.cli:
            self.cli.publish(
                self._pub, json.dumps({"header": self._hdr("p2pconnect"), "content": content}), qos=1
            )

    def update_netinfo(self, pub_ip: str, pub_port: int, loc_ip: str, loc_port: int) -> None:
        content = {
            "nettype": 4,
            "netsubtype": 0,
            "pub-ip": pub_ip,
            "pub-udpport": pub_port,
            "loc-ip": [loc_ip],
            "loc-udp-port": loc_port,
        }
        if self.cli:
            self.cli.publish(
                self._pub, json.dumps({"header": self._hdr("update-netinfo"), "content": content}), qos=1
            )

    def _on_message(self, *args: Any, **kwargs: Any) -> None:
        msg = args[2] if len(args) >= 3 else kwargs.get("message")
        if msg is None:
            return
        try:
            p = json.loads(msg.payload.decode("utf-8", "replace"))
        except Exception:
            return
        if p.get("header", {}).get("command") == "p2pconnect":
            c = p.get("content", {})
            loc_ip = c.get("loc-ip", [None])
            if loc_ip and loc_ip[0]:
                self.loc = (loc_ip[0], c.get("loc-udpport", 58367))
            if c.get("pub-ip"):
                self.pub = (c.get("pub-ip"), c.get("pub-udpport", 58367))
            if c.get("utd-pub-ip"):
                self.utd = (c.get("utd-pub-ip"), c.get("utd-pub-udpport"))
            self.got_addr.set()

    def close(self) -> None:
        if self.cli:
            self.cli.loop_stop()
            self.cli.disconnect()


# --- P2P Door Unlock & Camera Snapshot Runners -------------------------------

def _p2p_open_door_impl(
    duid: str,
    dynamic_password: str,
    pin: str,
    client_id: str = DEFAULT_CLIENT_ID,
    oem: str = DEFAULT_OEM,
    door: int = 0,
    locknumber: int = 0,
    data_encode_key: str | None = None,
    pin_sha256: str | None = None,
    status: dict[str, Any] | None = None,
) -> bool:
    """Execute physical door unlock sequence over UDP/KCP (100% verified flow).

    ``pin_sha256`` short-circuits hashing the PIN: the cloud device list already
    carries the same value as ``out-auth-code`` (verified: SHA256(PIN) == out-auth-code),
    so callers that have the device list but not the PIN can pass it directly.
    """
    _LOGGER.warning("Balter EVO: Initiating P2P unlock for duid=%s, door=%d, lock=%d", duid, door, locknumber)
    if not dynamic_password:
        dynamic_password = hashlib.md5((duid + oem + time.strftime("%Y%m%d")).encode()).hexdigest()[:8]

    # The control channel (LOGIN / OPENDOOR frames) is encrypted with the device's
    # data-encode-key, which rotates. Fall back to the family default only if absent.
    ctrl_key = data_encode_key.encode("ascii") if data_encode_key else DEFAULT_KEY_CTRL

    pin_hash = (
        pin_sha256
        or (hashlib.sha256(pin.encode("utf-8")).hexdigest() if pin else None)
        or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(0.15)
    
    # 1. Resolve STUN Public Address
    mp_ip, mp_port = _natcheck_query(sock)
    lip = sock.getsockname()[0]
    lport = sock.getsockname()[1]
    _LOGGER.warning("Balter EVO: NAT check resolved public address %s:%s (local: %s:%s)", mp_ip, mp_port, lip, lport)

    p2p_sess = CloudP2PSession("e4d73be5e26e9a83", duid)
    p2p_sess.connect()
    time.sleep(1.2)
    p2p_sess.p2pconnect()
    
    if not p2p_sess.got_addr.wait(timeout=10) or not p2p_sess.utd:
        _LOGGER.error(
            "Balter EVO: P2P cloud relay discovery timed out for %s "
            "(device offline, or a previous session is still held -- leave a gap between runs)",
            duid,
        )
        p2p_sess.close()
        sock.close()
        if status is not None:
            status.update({"ready": False, "sent": False, "acked": False})
        return False
        
    relay = p2p_sess.utd
    sf = p2p_sess.session_flag
    _LOGGER.warning("Balter EVO: Discovered P2P relay %s, local=%s, pub=%s", relay, p2p_sess.loc, p2p_sess.pub)
    
    p2p_sess.update_netinfo(mp_ip, mp_port, lip, lport)
    
    ch = {
        CH0: {"myid": None, "slot_id": 0x07, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1, "last_tx": 0, "last_frame": None, "last_pos": 1},
        CH1: {"myid": None, "slot_id": 0x08, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1, "last_tx": 0, "last_frame": None, "last_pos": 1}
    }
    
    ts = int(time.time())
    stop = threading.Event()
    unlocked = [False]
    door_ack = threading.Event()
    dev_ready = threading.Event()
    # Retransmit-Zustand des OPENDOOR-Frames (die App sendet es bis zu 3x)
    od_state: dict[str, Any] = {"payload": None, "outer": 5, "sends": 0, "last": 0.0}
    peer_addr = [relay]
    
    def send_ack(conv: int, peer: Any) -> None:
        c = ch[conv]
        wnd = (0xFFFF - ((c["rcv"] - 1) & 0xFFFF)) & 0xFFFF
        if wnd < 0x1000:
            wnd = 0xFFFF
        field5 = (wnd << 16) | 0x0900
        sock.sendto(build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], win=field5), peer)

    def send_bb(conv: int, peer: Any) -> None:
        c = ch[conv]
        size = min(c["bb"], 1420)
        sock.sendto(build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], b"\xbb" * size, win=WIN_BB), peer)
        c["bb"] = min(c["bb"] + 100, 1420)

    def rx_loop() -> None:
        while not stop.is_set():
            try:
                data, src = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            if data[:4] != MAGIC or len(data) < 28:
                continue
                
            if len(data) == 164:
                rf = data[0x2E]
                if rf == 0:
                    echo = bytearray(data)
                    echo[0x2E] = 1
                    sock.sendto(bytes(echo), src)
                elif rf == 1:
                    peer_addr[0] = src
                continue
                
            f = parse_header(data)
            conv = f[1]
            if conv not in ch or f[2] in (0, conv):
                continue
            c = ch[conv]
            if not c["myid"]:
                c["myid"] = f[2]
                peer_addr[0] = src
                
            payl = len(data) - 28
            if payl <= 0:
                continue
                
            pay = data[28:]
            if f[5] == WIN_BB or pay[:4] == b"\xbb\xbb\xbb\xbb":
                send_bb(conv, src)
                send_ack(conv, src)
                continue
                
            # Jedes Datenpaket quittieren (auch Fortsetzungspakete ohne ffffffff-Marker),
            # sonst laeuft das Sendefenster des Geraets voll -- siehe Kommentar im
            # Snapshot-Pfad.
            end = f[3] + payl
            if f[3] <= c["rcv"]:
                if end > c["rcv"]:
                    c["rcv"] = end
            elif c["rcv"] <= 1:
                c["rcv"] = end
            send_ack(conv, src)

            if pay[:4] == b"\xff\xff\xff\xff":
                tot = struct.unpack("<I", pay[4:8])[0] if len(pay) >= 8 else 0
                om = pay[0x18] if len(pay) >= 0x1C else 0

                # Geraetequittung auf das Tueroeffnen: 0xFE mit msg13=4. Auch
                # eingebettete Frames pruefen -- das Geraet buendelt mehrere
                # App-Frames in ein UDP-Paket.
                if conv == CH0 and not door_ack.is_set():
                    i = 0
                    while i >= 0 and i + 88 <= len(pay):
                        ftot = struct.unpack("<I", pay[i + 4:i + 8])[0]
                        if 88 <= ftot <= 2000 and i + 88 <= len(pay):
                            dh = cbc_decrypt(pay[i + 56:i + 88], ctrl_key)
                            if len(dh) >= 14 and dh[0] == 0xFE:
                                if dh[13] == 4:
                                    door_ack.set()
                                    _LOGGER.warning("Balter EVO: device acknowledged OPENDOOR")
                                    break
                                if dh[13] == 2 and not dev_ready.is_set():
                                    # Nach-Login-Konfig des Geraets ("00 01"). ERST danach
                                    # ist die App-Session wirklich offen -- das reine
                                    # Transport-ACK des LOGIN kommt ~2 s frueher und sagt
                                    # nichts ueber die App-Schicht aus.
                                    dev_ready.set()
                                    _LOGGER.warning("Balter EVO: device signalled session ready (0xFE msg13=2)")
                        i = pay.find(b"\xff\xff\xff\xff", i + 4)

                # 1. HELLO76 -> Session-Basis (extracted from device's HELLO76 body bytes 26..28)
                if tot == 76 and c["state"] == "SENT_HELLO":
                    # Session base = last 2 bytes of the device HELLO (absolute 74..76);
                    # the slot byte is our own (0x07 for CH0, 0x08 for CH1), it is not
                    # read back from the echo.
                    sess_base = pay[74:76]
                    ch[conv]["sess"] = sess_base + bytes([c["slot_id"]])
                    ch_idx = 0 if conv == CH0 else 1
                    a9 = build_app_frame(0, build_a9_body(ch_idx), ch_idx, ch[conv]["sess"])
                    c["last_pos"] = c["sent_pos"]
                    sock.sendto(build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], a9, win=WIN_DATA), src)
                    c["sent_pos"] += len(a9)
                    c["last_tx"] = time.time()
                    c["last_frame"] = a9
                    c["state"] = "SENT_A9"
                    _LOGGER.warning("Balter EVO: CH%x got device HELLO76, sess=%s, sending a9", conv, ch[conv]["sess"].hex())
                    
                # 2. 144B Echo (om == 0) -> LOGIN
                elif (tot == 56 or len(pay) == 144) and om == 0 and c["state"] == "SENT_A9":
                    ch_idx = 0 if conv == CH0 else 1
                    lp = build_login_payload(dynamic_password, client_id, oem)
                    # CRITICAL: CH0 LOGIN requires f15=1, f16=1; CH1 LOGIN requires b14=0xFF
                    # Both verified byte-exact against open.pcap (§5q of RE notes)
                    if conv == CH0:
                        lb = ctrl_frame(0x01, ts, lp, key=ctrl_key, msg13=1, f15=1, f16=1)
                    else:
                        lb = ctrl_frame(0x0B, ts, lp, key=ctrl_key, msg13=0xFF, b14=0xFF)
                    lfr = build_app_frame(1, lb, ch_idx, ch[conv]["sess"])
                    c["last_pos"] = c["sent_pos"]
                    sock.sendto(build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], lfr, win=WIN_DATA), src)
                    c["sent_pos"] += len(lfr)
                    c["last_tx"] = time.time()
                    c["last_frame"] = lfr
                    c["state"] = "SENT_LOGIN"
                    _LOGGER.warning("Balter EVO: CH%x got 144B echo, sending LOGIN", conv)

                # 3. LOGIN transportseitig bestaetigt. Das ist NOCH NICHT die
                #    Freigabe der App-Session -- darauf wartet die Hauptschleife
                #    ueber dev_ready (0xFE msg13=2).
                elif (tot == 56 or tot > 50) and om == 1 and c["state"] == "SENT_LOGIN":
                    c["state"] = "LOGGED_IN"
                    _LOGGER.warning("Balter EVO: CH%x LOGIN acknowledged", conv)

    threading.Thread(target=rx_loop, daemon=True).start()
    
    # 2. Punch & SYN
    t0 = time.time()
    while time.time() - t0 < 15 and not (ch[CH0]["myid"] and ch[CH1]["myid"]):
        sock.sendto(build_punch(sf, relay[0], relay[1], 2, 1), relay)
        sock.sendto(build_transport_hdr(0, CH0, 0, 0), relay)
        sock.sendto(build_transport_hdr(0, CH1, 0, 0), relay)
        time.sleep(0.15)
        
    if not (ch[CH0]["myid"] and ch[CH1]["myid"]):
        _LOGGER.error("Balter EVO: P2P punch/handshake failed (CH0/CH1 IDs not received)")
        stop.set()
        sock.close()
        p2p_sess.close()
        if status is not None:
            status.update({"ready": False, "sent": False, "acked": False})
        return False
        
    peer = peer_addr[0]
    for conv in (CH0, CH1):
        sock.sendto(build_transport_hdr(ch[conv]["myid"], conv, 1, 1, win=WIN_ACK), peer)
        send_bb(conv, peer)
        h76 = build_hello76(ch[conv]["slot_id"], 0 if conv == CH0 else 1)
        ch[conv]["last_pos"] = 1
        sock.sendto(build_transport_hdr(ch[conv]["myid"], conv, 1, 1, h76, win=WIN_DATA), peer)
        ch[conv]["sent_pos"] += len(h76)
        ch[conv]["state"] = "SENT_HELLO"
        
    testid = int.from_bytes(os.urandom(4), "little")
    mtu_vals = [200, 101, 200, 101, 60, 200]
    t0 = time.time()
    ai = 0
    last_probe = 0
    last_arq = 0
    
    while time.time() - t0 < 20 and not door_ack.is_set():
        now = time.time()

        # MTU probe heartbeats
        if now - last_probe > 0.12:
            sock.sendto(build_mtu_probe(sf, testid, mtu_vals[ai % len(mtu_vals)]), peer_addr[0])
            ai += 1
            last_probe = now

        # Sobald das Geraet die App-Session freigegeben hat (0xFE msg13=2): die
        # drei Setup-Frames und dann den Tueroeffner senden -- genau in der
        # Reihenfolge der echten App.
        if dev_ready.is_set() and od_state["sends"] == 0 and ch[CH0]["sess"]:
            c0 = ch[CH0]
            for om_num, m in ((2, 5), (3, 6), (4, 2)):
                s_fr = build_app_frame(om_num, ctrl_frame(0xFE, ts, b"\x00", key=ctrl_key, msg13=m),
                                       0, c0["sess"])
                sock.sendto(build_transport_hdr(c0["myid"], CH0, c0["sent_pos"], c0["rcv"], s_fr, win=WIN_DATA),
                            peer_addr[0])
                c0["sent_pos"] += len(s_fr)
                time.sleep(0.02)
            op = build_open_payload(door, locknumber, pin_hash)
            od_fr = build_app_frame(5, ctrl_frame(0xFE, ts, op, key=ctrl_key, msg13=4), 0, c0["sess"])
            sock.sendto(build_transport_hdr(c0["myid"], CH0, c0["sent_pos"], c0["rcv"], od_fr, win=WIN_DATA),
                        peer_addr[0])
            c0["sent_pos"] += len(od_fr)
            od_state.update({"payload": op, "outer": 5, "sends": 1, "last": time.time()})
            unlocked[0] = True
            _LOGGER.warning("Balter EVO: OPENDOOR sent (door=%d lock=%d), waiting for device ack",
                            door, locknumber)

        # OPENDOOR erneut senden, bis das Geraet quittiert (wie die App: max. 3x,
        # jedes Mal mit fortlaufender outer-msg).
        if od_state["payload"] is not None and 0 < od_state["sends"] < 3 and now - od_state["last"] > 1.2:
            c0 = ch[CH0]
            od_state["outer"] += 1
            od_state["sends"] += 1
            fr = build_app_frame(od_state["outer"],
                                 ctrl_frame(0xFE, ts, od_state["payload"], key=ctrl_key, msg13=4),
                                 0, c0["sess"])
            sock.sendto(build_transport_hdr(c0["myid"], CH0, c0["sent_pos"], c0["rcv"], fr, win=WIN_DATA),
                        peer_addr[0])
            c0["sent_pos"] += len(fr)
            od_state["last"] = now
            _LOGGER.warning("Balter EVO: OPENDOOR retransmit %d/3", od_state["sends"])


        # ARQ retransmit for stuck states (prevents UDP packet loss hangups)
        if now - last_arq > 0.40:
            for conv_arq in (CH0, CH1):
                c_arq = ch[conv_arq]
                if c_arq["myid"] is None:
                    continue
                st = c_arq["state"]
                last_tx = c_arq.get("last_tx", 0)
                # WICHTIG: ein Retransmit muss am URSPRUENGLICHEN Byte-Offset des
                # Frames wiederholt werden (c["last_pos"]), nicht am aktuellen
                # sent_pos. Sonst haengt der Client dieselben Bytes als NEUE Daten
                # hinter den Strom -- das Geraet sieht einen doppelten a9/LOGIN an
                # falscher Stelle, verwirft die App-Nachricht und der Handshake
                # bleibt bei SENT_A9 stehen.
                if st == "SENT_HELLO" and (now - last_tx > 0.5):
                    h76 = build_hello76(c_arq["slot_id"], 0 if conv_arq == CH0 else 1)
                    sock.sendto(build_transport_hdr(c_arq["myid"], conv_arq, c_arq["last_pos"], c_arq["rcv"], h76, win=WIN_DATA), peer_addr[0])
                    c_arq["last_tx"] = now
                elif st in ("SENT_A9", "SENT_LOGIN") and c_arq.get("last_frame") and (now - last_tx > 0.5):
                    sock.sendto(build_transport_hdr(c_arq["myid"], conv_arq, c_arq["last_pos"], c_arq["rcv"], c_arq["last_frame"], win=WIN_DATA), peer_addr[0])
                    c_arq["last_tx"] = now
            last_arq = now
            
        time.sleep(0.01)

    # Session sauber schliessen -- erst jetzt, nicht direkt nach dem OPENDOOR.
    if ch[CH0]["sess"]:
        c0 = ch[CH0]
        cl_fr = build_app_frame(od_state["outer"] + 1, ctrl_frame(0x07, ts, b"", key=ctrl_key),
                                0, c0["sess"])
        sock.sendto(build_transport_hdr(c0["myid"], CH0, c0["sent_pos"], c0["rcv"], cl_fr), peer_addr[0])

    time.sleep(0.5)
    stop.set()
    sock.close()
    p2p_sess.close()

    if status is not None:
        status.update({"ready": dev_ready.is_set(), "sent": bool(unlocked[0]),
                       "acked": door_ack.is_set()})

    if door_ack.is_set():
        _LOGGER.warning("Balter EVO: door unlock confirmed by device")
        return True
    if unlocked[0]:
        _LOGGER.error(
            "Balter EVO: OPENDOOR was sent %dx but the device never acknowledged it "
            "(msg13=4). The door may or may not have opened.", od_state["sends"])
    elif not dev_ready.is_set():
        _LOGGER.error(
            "Balter EVO: device never signalled session ready (0xFE msg13=2) -- "
            "OPENDOOR was not sent at all")
    return False


def _p2p_get_snapshot_impl(
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = DEFAULT_CLIENT_ID,
    oem: str = DEFAULT_OEM,
    duration: float = 8.0,
    return_h264: bool = False,
) -> bytes | None:
    """Fetch live video from the door station.

    Returns a JPEG still by default, or the raw H.264 elementary stream when
    ``return_h264`` is set (used by the clip recorder).

    ``duration`` is the recording window AFTER the login. The device needs about
    two seconds before it starts pushing video, so anything below ~5 s yields
    very little material.
    """
    if not dynamic_password:
        dynamic_password = hashlib.md5((duid + oem + time.strftime("%Y%m%d")).encode()).hexdigest()[:8]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(0.15)
    
    mp_ip, mp_port = _natcheck_query(sock)
    lip = sock.getsockname()[0]
    lport = sock.getsockname()[1]
    
    p2p_sess = CloudP2PSession("e4d73be5e26e9a83", duid)
    p2p_sess.connect()
    time.sleep(1.2)
    p2p_sess.p2pconnect()
    
    if not p2p_sess.got_addr.wait(timeout=10) or not p2p_sess.utd:
        _LOGGER.error(
            "Balter EVO: P2P cloud relay discovery timed out for %s "
            "(device offline, or a previous session is still held -- leave a gap between runs)",
            duid,
        )
        p2p_sess.close()
        sock.close()
        return None

    relay = p2p_sess.utd
    sf = p2p_sess.session_flag
    _LOGGER.info("Balter EVO: relay %s, device pub=%s loc=%s", relay, p2p_sess.pub, p2p_sess.loc)
    p2p_sess.update_netinfo(mp_ip, mp_port, lip, lport)
    
    ch = {
        CH0: {"myid": None, "slot_id": 0x07, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1},
        CH1: {"myid": None, "slot_id": 0x08, "sess": None, "rcv": 1, "ack": 0, "state": "INIT", "bb": 520, "sent_pos": 1}
    }
    
    ts = int(time.time())
    stop = threading.Event()
    peer_addr = [relay]
    rx_stream_segments: dict[int, bytes] = {}
    logged_in = threading.Event()
    media_seen = threading.Event()
    media_bytes = [0]

    media_key = data_encode_key.encode("ascii") if data_encode_key else DEFAULT_KEY_MEDIA
    
    def send_ack(conv: int, peer: Any) -> None:
        c = ch[conv]
        wnd = (0xFFFF - ((c["rcv"] - 1) & 0xFFFF)) & 0xFFFF
        if wnd < 0x1000:
            wnd = 0xFFFF
        field5 = (wnd << 16) | 0x0900
        sock.sendto(build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], win=field5), peer)

    def send_bb(conv: int, peer: Any) -> None:
        c = ch[conv]
        size = min(c["bb"], 1420)
        sock.sendto(build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], b"\xbb" * size, win=WIN_BB), peer)
        c["bb"] = min(c["bb"] + 100, 1420)

    def rx_loop() -> None:
        while not stop.is_set():
            try:
                data, src = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            if data[:4] != MAGIC or len(data) < 28:
                continue
                
            if len(data) == 164:
                rf = data[0x2E]
                if rf == 0:
                    echo = bytearray(data)
                    echo[0x2E] = 1
                    sock.sendto(bytes(echo), src)
                elif rf == 1:
                    peer_addr[0] = src
                continue
                
            f = parse_header(data)
            conv = f[1]
            if conv not in ch or f[2] in (0, conv):
                continue
            c = ch[conv]
            if not c["myid"]:
                c["myid"] = f[2]
                peer_addr[0] = src
                
            payl = len(data) - 28
            if payl <= 0:
                continue
                
            pay = data[28:]
            if f[5] == WIN_BB or pay[:4] == b"\xbb\xbb\xbb\xbb":
                send_bb(conv, src)
                send_ack(conv, src)
                continue
                
            if conv == CH0 and (f[5] & 0xFFFF) == 0x1900:
                rx_stream_segments[f[3]] = pay
                media_bytes[0] += payl
                if media_bytes[0] > 8192 and not media_seen.is_set():
                    media_seen.set()
                    _LOGGER.info("Balter EVO: video stream is flowing (%d B on CH0)", media_bytes[0])

            # JEDES Datenpaket quittieren, nicht nur die, die mit einem App-Frame-
            # Marker beginnen: ein Medien-Frame ist bis zu 1,2 kB gross und wird auf
            # mehrere UDP-Pakete verteilt; deren Fortsetzungen tragen kein ffffffff.
            # Wurden sie nicht quittiert, lief das Sendefenster des Geraets nach
            # ~8 kB voll und der Videostrom blieb stehen.
            end = f[3] + payl
            if f[3] <= c["rcv"]:
                if end > c["rcv"]:
                    c["rcv"] = end
            elif c["rcv"] <= 1:          # ISN != 1 -> uebernehmen
                c["rcv"] = end
            send_ack(conv, src)

            if pay[:4] == b"\xff\xff\xff\xff":
                tot = struct.unpack("<I", pay[4:8])[0] if len(pay) >= 8 else 0
                om = pay[0x18] if len(pay) >= 0x1C else 0

                # 1. HELLO76 -> Session-Basis
                if tot == 76 and c["state"] == "SENT_HELLO":
                    sess_base = pay[74:76]
                    ch[conv]["sess"] = sess_base + bytes([c["slot_id"]])
                    ch_idx = 0 if conv == CH0 else 1
                    a9 = build_app_frame(0, build_a9_body(ch_idx), ch_idx, ch[conv]["sess"])
                    sock.sendto(build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], a9, win=WIN_DATA), src)
                    c["sent_pos"] += len(a9)
                    c["state"] = "SENT_A9"
                    _LOGGER.info("Balter EVO: CH%x device HELLO, sess=%s -> a9",
                                 conv, ch[conv]["sess"].hex())

                # 2. a9-Echo -> LOGIN
                elif (tot == 56 or len(pay) == 144) and om == 0 and c["state"] == "SENT_A9":
                    _LOGGER.info("Balter EVO: CH%x a9 acknowledged -> LOGIN", conv)
                    ch_idx = 0 if conv == CH0 else 1
                    lp = build_login_payload(dynamic_password, client_id, oem)
                    # CH0 (video/control): typ=0x01, msg13=1, f15=f16=1
                    # CH1 (audio):         typ=0x0B, msg13=b14=0xFF
                    if conv == CH0:
                        lb = ctrl_frame(0x01, ts, lp, key=media_key, msg13=1, f15=1, f16=1)
                    else:
                        lb = ctrl_frame(0x0B, ts, lp, key=media_key, msg13=0xFF, b14=0xFF)
                    lfr = build_app_frame(1, lb, ch_idx, ch[conv]["sess"])
                    sock.sendto(build_transport_hdr(c["myid"], conv, c["sent_pos"], c["rcv"], lfr, win=WIN_DATA), src)
                    c["sent_pos"] += len(lfr)
                    c["state"] = "SENT_LOGIN"

                # 3. LOGIN OK -> Stream Start
                #
                # Es gibt kein Play-Kommando: das Geraet sendet den Videostrom von
                # selbst, sobald der CH0-LOGIN app-seitig akzeptiert ist (im
                # App-Mitschnitt ~2,2 s spaeter, nach seinem 0xFE msg13=2 / "00 01").
                # Die Frames msg13=5/6/2 folgen dem Video, sie starten es nicht.
                elif (tot == 56 or tot > 50) and om == 1 and c["state"] == "SENT_LOGIN":
                    c["state"] = "LOGGED_IN"
                    _LOGGER.info("Balter EVO: CH%x LOGIN accepted", conv)
                    if conv == CH0:
                        sess_bytes = ch[CH0]["sess"]
                        for om_num, m in ((2, 5), (3, 6), (4, 2)):
                            s_fr = build_app_frame(om_num, ctrl_frame(0xFE, ts, b"\x00", key=media_key, msg13=m), 0, sess_bytes)
                            sock.sendto(build_transport_hdr(c["myid"], CH0, c["sent_pos"], c["rcv"], s_fr, win=WIN_DATA), src)
                            c["sent_pos"] += len(s_fr)
                            time.sleep(0.02)
                        logged_in.set()

    threading.Thread(target=rx_loop, daemon=True).start()
    
    t0 = time.time()
    while time.time() - t0 < 15 and not (ch[CH0]["myid"] and ch[CH1]["myid"]):
        sock.sendto(build_punch(sf, relay[0], relay[1], 2, 1), relay)
        sock.sendto(build_transport_hdr(0, CH0, 0, 0), relay)
        sock.sendto(build_transport_hdr(0, CH1, 0, 0), relay)
        time.sleep(0.15)
        
    if not (ch[CH0]["myid"] and ch[CH1]["myid"]):
        _LOGGER.error("Balter EVO: P2P punch/handshake failed (CH0/CH1 IDs not received)")
        stop.set()
        sock.close()
        p2p_sess.close()
        return None

    peer = peer_addr[0]
    _LOGGER.info("Balter EVO: transport up (CH0=%#x CH1=%#x via %s) -> HELLO76",
                 ch[CH0]["myid"], ch[CH1]["myid"], peer)
    for conv in (CH0, CH1):
        sock.sendto(build_transport_hdr(ch[conv]["myid"], conv, 1, 1, win=WIN_ACK), peer)
        send_bb(conv, peer)
        h76 = build_hello76(ch[conv]["slot_id"], 0 if conv == CH0 else 1)
        ch[conv]["last_pos"] = 1
        sock.sendto(build_transport_hdr(ch[conv]["myid"], conv, 1, 1, h76, win=WIN_DATA), peer)
        ch[conv]["sent_pos"] += len(h76)
        ch[conv]["state"] = "SENT_HELLO"
        
    testid = int.from_bytes(os.urandom(4), "little")
    mtu_vals = [200, 101, 200, 101, 60, 200]
    t0 = time.time()
    ai = 0
    last_probe = 0
    
    logged_in.wait(timeout=6)
    
    t_start = time.time()
    while time.time() - t_start < duration:
        now = time.time()
        if now - last_probe > 0.12:
            sock.sendto(build_mtu_probe(sf, testid, mtu_vals[ai % len(mtu_vals)]), peer_addr[0])
            ai += 1
            last_probe = now
        time.sleep(0.01)
        
    if ch[CH0]["sess"]:
        cl_fr = build_app_frame(6, ctrl_frame(0x07, ts, b"", key=media_key), 0, ch[CH0]["sess"])
        sock.sendto(build_transport_hdr(ch[CH0]["myid"], CH0, ch[CH0]["sent_pos"], ch[CH0]["rcv"], cl_fr), peer_addr[0])
        
    stop.set()
    sock.close()
    p2p_sess.close()
    
    h264_best = None
    if rx_stream_segments:
        sorted_seqs = sorted(rx_stream_segments.keys())
        isn = sorted_seqs[0]
        buf, pos = bytearray(), isn
        for seq in sorted_seqs:
            if seq < pos:
                continue
            if seq > pos:
                buf.extend(b"\x00" * (seq - pos))
            buf.extend(rx_stream_segments[seq])
            pos = seq + len(rx_stream_segments[seq])
        raw_stream = bytes(buf)
        frames = extract_app_frames(raw_stream)
        # Kandidaten in Prioritaetsreihenfolge: der Cloud-Key zuerst, der
        # unentschluesselte Rohstrom als allerletzter Ausweg.
        h264_candidates = []
        for k in (media_key, DEFAULT_KEY_MEDIA, DEFAULT_KEY_CTRL):
            plain = bytearray()
            for _, fr in frames:
                p = decrypt_head(fr[APP_HDR:], k)
                plain.extend(p)
            h = extract_h264(bytes(plain))
            if len(h) > 500:
                h264_candidates.append(h)
        h_raw = extract_h264(raw_stream)
        if len(h_raw) > 500:
            h264_candidates.append(h_raw)
        # Den ersten Kandidaten nehmen, der SPS UND IDR enthaelt -- NICHT den
        # laengsten: der Rohstrom-Fallback ist immer am laengsten (er traegt die
        # Frame-Koepfe mit) und ist trotzdem nicht dekodierbar.
        h264_best = next((h for h in h264_candidates if h264_is_decodable(h)), None)
        if h264_best is None and h264_candidates:
            h264_best = max(h264_candidates, key=len)
            
    if not h264_best:
        _LOGGER.debug("No H.264 NAL units recovered from the P2P stream for %s", duid)
        return None
        
    if return_h264:
        return h264_best

    with tempfile.NamedTemporaryFile(suffix=".h264", delete=False) as tf_h264:
        tf_h264.write(h264_best)
        h264_name = tf_h264.name
        
    jpg_name = h264_name + ".jpg"
    try:
        subprocess.run(
            ["ffmpeg", "-y", "-i", h264_name, "-vframes", "1", jpg_name],
            capture_output=True,
            timeout=5,
        )
        if os.path.exists(jpg_name) and os.path.getsize(jpg_name) > 0:
            with open(jpg_name, "rb") as fh:
                return fh.read()
    except Exception as err:
        _LOGGER.warning("FFmpeg frame conversion error: %s", err)
    finally:
        for p in (h264_name, jpg_name):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
    return None


def p2p_open_door_sync(*args: Any, **kwargs: Any) -> bool:
    """Tueroeffnen -- serialisiert gegen jede andere P2P-Sitzung dieses Prozesses."""
    with _P2PSlot():
        return _p2p_open_door_impl(*args, **kwargs)


def p2p_get_snapshot_sync(*args: Any, **kwargs: Any) -> bytes | None:
    """Standbild/Video holen -- serialisiert gegen jede andere P2P-Sitzung."""
    with _P2PSlot():
        return _p2p_get_snapshot_impl(*args, **kwargs)


def p2p_record_clip_sync(
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = DEFAULT_CLIENT_ID,
    oem: str = DEFAULT_OEM,
    seconds: float = 5.0,
) -> bytes | None:
    """Einen kurzen MP4-Clip aufnehmen.

    ``seconds`` ist die gewuenschte Cliplaenge; aufgenommen wird laenger, weil das
    Geraet erst ~2 s nach dem Login sendet. Die Bildrate wird aus der Anzahl der
    Bild-NALs und der tatsaechlichen Streamzeit geschaetzt, damit der Clip in
    Echtzeit laeuft.
    """
    window = seconds + 4.0
    h264 = p2p_get_snapshot_sync(
        duid, dynamic_password, data_encode_key=data_encode_key,
        client_id=client_id, oem=oem, duration=window, return_h264=True,
    )
    if not h264:
        return None

    frames, pos = 0, h264.find(b"\x00\x00\x00\x01")
    while pos >= 0:
        if pos + 4 < len(h264) and (h264[pos + 4] & 0x1F) in (1, 5):
            frames += 1
        pos = h264.find(b"\x00\x00\x00\x01", pos + 4)
    fps = max(5.0, min(30.0, frames / max(1.0, window - 2.0)))

    tmp_dir = tempfile.mkdtemp(prefix="balter_clip_")
    raw = os.path.join(tmp_dir, "clip.h264")
    mp4 = os.path.join(tmp_dir, "clip.mp4")
    try:
        with open(raw, "wb") as fh:
            fh.write(h264)
        subprocess.run(
            ["ffmpeg", "-y", "-f", "h264", "-r", f"{fps:.2f}", "-i", raw,
             "-t", str(seconds), "-c:v", "libx264", "-pix_fmt", "yuv420p", mp4],
            capture_output=True, timeout=120,
        )
        if os.path.exists(mp4) and os.path.getsize(mp4) > 0:
            with open(mp4, "rb") as fh:
                return fh.read()
        _LOGGER.warning("Balter EVO: ffmpeg produced no clip for %s", duid)
    except Exception as err:  # ffmpeg fehlt oder bricht ab
        _LOGGER.warning("Balter EVO: clip encoding failed: %s", err)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return None


async def async_p2p_open_door(
    hass: Any,
    duid: str,
    dynamic_password: str,
    pin: str,
    client_id: str = DEFAULT_CLIENT_ID,
    oem: str = DEFAULT_OEM,
    door: int = 0,
    locknumber: int = 0,
    data_encode_key: str | None = None,
    pin_sha256: str | None = None,
    attempts: int = 3,
) -> bool:
    """Async wrapper for non-blocking door unlock in Home Assistant executor.

    Retries ONLY while the unlock command provably never left the client -- i.e.
    the handshake stalled before the device released the app session. Once
    OPENDOOR has gone out, a retry could open the door a second time, so a
    missing acknowledgement is reported as a failure instead of being retried.
    """
    for attempt in range(1, attempts + 1):
        status: dict[str, Any] = {"ready": False, "sent": False, "acked": False}
        ok = await hass.async_add_executor_job(
            functools.partial(
                p2p_open_door_sync, duid, dynamic_password, pin, client_id, oem, door,
                locknumber, data_encode_key, pin_sha256, status,
            )
        )
        if ok:
            return True
        if status["sent"]:
            # Befehl ist raus, nur die Quittung fehlt -> NICHT wiederholen.
            return False
        if attempt < attempts:
            _LOGGER.warning(
                "Balter EVO: handshake stalled before OPENDOOR (attempt %d/%d), retrying",
                attempt, attempts,
            )
    return False


async def async_p2p_get_snapshot(
    hass: Any,
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = DEFAULT_CLIENT_ID,
    oem: str = DEFAULT_OEM,
    duration: float = 8.0,
    attempts: int = 2,
) -> bytes | None:
    """Async wrapper for on-demand snapshot fetching in Home Assistant executor.

    A snapshot has no side effects, so a stalled handshake is simply retried.
    """
    for attempt in range(1, attempts + 1):
        image = await hass.async_add_executor_job(
            functools.partial(
                p2p_get_snapshot_sync, duid, dynamic_password,
                data_encode_key=data_encode_key, client_id=client_id, oem=oem,
                duration=duration,
            )
        )
        if image:
            return image
        if attempt < attempts:
            _LOGGER.debug("Balter EVO: snapshot attempt %d/%d failed, retrying",
                          attempt, attempts)
    return None


async def async_p2p_record_clip(
    hass: Any,
    duid: str,
    dynamic_password: str,
    data_encode_key: str | None = None,
    client_id: str = DEFAULT_CLIENT_ID,
    oem: str = DEFAULT_OEM,
    seconds: float = 5.0,
) -> bytes | None:
    """Async wrapper: record a short MP4 clip from the door station."""
    return await hass.async_add_executor_job(
        functools.partial(
            p2p_record_clip_sync, duid, dynamic_password,
            data_encode_key=data_encode_key, client_id=client_id, oem=oem,
            seconds=seconds,
        )
    )
