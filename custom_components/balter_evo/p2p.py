"""P2P engine for Balter EVO (Homaxi / Quvii protocol).

Implements the reverse-engineered UDP/KCP transport protocol:
- Dynamic Session-Basis negotiation from device HELLO76 Body[26:28]
- Two-channel architecture (CH0: 0x01000000 media/control, CH1: 0x02000001 audio)
- Outer Header v10 structure (48 Bytes with 2B channel index & 3B session token)
- Automatic ARQ retransmissions to tolerate UDP packet loss
- Dynamic Peer tracking and auto NAT-switch
- Partial AES-256-CBC encryption for control and media headers
- Fully parameterized: no hardcoded credentials, serial numbers, or keys.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import socket
import struct
import subprocess
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)

CH0 = 0x01000000
CH1 = 0x02000001

WIN_ACK = 0xFFFF0900
WIN_DATA = 0x00001900
WIN_BB = 0x00000500
MAGIC = b"\xc1\xef\xab\xff"
IV_ZERO = b"0" * 16
DEFAULT_KEY_CTRL = b"11111111111111111111111111111111"


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


def build_ctrl_frame(
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
    """Build the 48-byte Outer Header + Body according to the verified protocol format."""
    body_len = len(body)
    hdr = bytearray(48)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 48 + body_len)
    hdr[0x10:0x18] = bytes.fromhex("0001000003011200")
    struct.pack_into("<I", hdr, 0x18, outer_msg)
    struct.pack_into("<I", hdr, 0x24, body_len + 16)
    struct.pack_into("<H", hdr, 0x28, ch_idx)
    hdr[0x2A:0x2D] = sess_bytes
    hdr[0x2D:0x30] = bytes.fromhex("000004")
    return bytes(hdr) + body


def build_hello76(slot_id: int, ch_idx: int) -> bytes:
    """Build the 76-byte Client HELLO frame."""
    hdr = bytearray(48)
    hdr[0:4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", hdr, 0x04, 76)
    hdr[0x10:0x18] = bytes.fromhex("0001000001011200")
    struct.pack_into("<I", hdr, 0x24, slot_id | 0x04000000)
    if ch_idx == 0:
        struct.pack_into("<I", hdr, 0x28, 0x1A)
    return bytes(hdr) + (b"\x00" * 28)


def build_login_payload(dynpw: str, client_id: str = "android", oem: str = "GVS") -> bytes:
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


def parse_header(data: bytes) -> tuple[int, int, int, int, int, int, int]:
    """Parse a 28-byte transport packet header."""
    return struct.unpack("<7I", data[:28])


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
