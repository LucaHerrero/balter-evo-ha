"""qv_kdf.py - Ableitung des mst/query-Credential-Schluessels aus der client-id.

Vollstaendig aus libqv-p2p-v2.so reverse-engineert (tdkcloud::MstEncrypt +
AESSecret::GenerateKey/GenerateSeedKeyAndBox/GenerateExpansionKey) und byte-genau
verifiziert: der abgeleitete Schluessel entschluesselt die vom Discovery-Dienst
(mst/query, server-type p2papp) gelieferten username/password-Felder.

Die Cloud verschluesselt diese Felder mit einem client-id-spezifischen Schluessel;
nur wer ihn ableiten kann, bekommt gueltige MQTT-Zugangsdaten fuer die eigene
client-id. Damit kann die Integration eine SELBST erzeugte Identitaet nutzen
statt einer geliehenen.

Ablauf (alles Byte-Arithmetik mod 256):
  seed  = client_id rechts mit '0' auf 32 Zeichen aufgefuellt
  box[0]      = B[0xF1];  box[i] = B[(box[i-1] % 16) * box[i-1]]     (i = 1..31)
  box[i]     += seed[i]                                              (i = 0..31)
  sbox[0]     = A[box[0]]; sbox[j] = A[(sbox[j-1] % 16) * sbox[j-1]] (j = 1..255)
  danach AES-256-Key-Schedule um zwei Woerter erweitert (RotWord/SubWord ueber
  die dynamische sbox, Rcon), key = box[8:32] ++ w8 ++ w9  (32 Byte)
  Entschluesselung: AES-256-CBC, IV = b"0" * 16.

A und B sind feste, geraeteunabhaengige Tabellen (aus GenerateSourceData); sie
liegen komprimiert in _KDF_BLOB.
"""
from __future__ import annotations

import base64
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_KDF_BLOB = (
    "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"
)
_tables = zlib.decompress(base64.b64decode(_KDF_BLOB))
_A = _tables[:4096]
_B = _tables[4096:8192]
_C1 = 0xF1
_RCON = (0x40, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B)
_IV = b"0" * 16


def _seed_key_box(seed: bytes) -> bytes:
    box = bytearray(32)
    box[0] = _B[_C1]
    for i in range(1, 32):
        x = box[i - 1]
        box[i] = _B[(x % 16) * x]
    for i in range(min(len(seed), 32)):
        box[i] = (box[i] + seed[i]) & 0xFF
    return bytes(box)


def _dyn_sbox(start: int) -> bytes:
    s = bytearray(256)
    s[0] = _A[start]
    for j in range(1, 256):
        x = s[j - 1]
        s[j] = _A[(x % 16) * x]
    return bytes(s)


def cred_key(client_id: str) -> bytes:
    """Return the 32-byte AES key for the given 16-hex client id."""
    seed = (client_id + "0" * 32)[:32].encode("ascii")
    box = _seed_key_box(seed)
    sbox = _dyn_sbox(box[0])
    w = [list(box[4 * i:4 * i + 4]) for i in range(8)]
    for i in (8, 9):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = t[1:] + t[:1]                     # RotWord
            t = [sbox[b] for b in t]              # SubWord (dynamic sbox)
            t[0] ^= _RCON[i // 8]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    return box[8:32] + bytes(w[8]) + bytes(w[9])


def decode_cred(client_id: str, b64_value: str) -> str:
    """Decrypt a base64 mst/query credential field (username/password)."""
    key = cred_key(client_id)
    ct = base64.b64decode(b64_value)
    n = (len(ct) // 16) * 16
    pt = Cipher(algorithms.AES(key), modes.CBC(_IV)).decryptor().update(ct[:n])
    return pt.rstrip(b"\x00").decode("utf-8", "replace")
