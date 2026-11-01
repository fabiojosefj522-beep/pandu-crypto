"""pandu-crypto for Python: the same format as src/pandu-crypto.js (see FORMAT.md).

Needs the `cryptography` package:  pip install cryptography
MIT License - Copyright (c) 2026 Fabio Jose dos Santos (Pandu SOS, https://usepandu.com.br)
"""
import base64
import hashlib
import json
import os
import re
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_LINK_RE = re.compile(r"#D=([A-Z2-7]{16})([A-Z2-7]{26}|[A-Z2-7]{52})$")


def b32(data: bytes) -> str:
    """Base32, RFC 4648 alphabet, no padding."""
    return base64.b32encode(data).decode("ascii").rstrip("=")


def unb32(text: str) -> bytes:
    return base64.b32decode(text + "=" * (-len(text) % 8))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_card(bits: int = 128) -> dict:
    """id and key go into the QR; tok (edit token) stays only with the owner."""
    if bits not in (128, 256):
        raise ValueError("bits must be 128 or 256")
    return {"id": b32(os.urandom(10)), "key": b32(os.urandom(bits // 8)), "tok": b64url(os.urandom(32))}


def make_link(base: str, card_id: str, key: str) -> str:
    if not re.fullmatch(r"[A-Z2-7]{16}", card_id) or not re.fullmatch(r"[A-Z2-7]{26}|[A-Z2-7]{52}", key):
        raise ValueError("bad id or key")
    return base.split("#", 1)[0] + "#D=" + card_id + key


def parse_link(link: str):
    m = _LINK_RE.search(link or "")
    return {"id": m.group(1), "key": m.group(2)} if m else None


def token_hash(tok: str) -> str:
    """What the server keeps instead of the edit token: hex SHA-256 of the token string."""
    return hashlib.sha256(tok.encode("ascii")).hexdigest()


def encrypt(data, key: str) -> dict:
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    flag = 0
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)  # raw DEFLATE, no zlib header
    packed = comp.compress(body) + comp.flush()
    if len(packed) < len(body):
        body, flag = packed, 1
    iv = os.urandom(12)
    ct = AESGCM(unb32(key)).encrypt(iv, bytes([flag]) + body, None)  # tag is appended, as in Web Crypto
    return {"ct": b64url(ct), "iv": b64url(iv)}


def decrypt(ct: str, iv: str, key: str):
    """Returns the data, or None if the key is wrong or the bytes were changed."""
    try:
        plain = AESGCM(unb32(key)).decrypt(unb64url(iv), unb64url(ct), None)
        body = plain[1:]
        if plain[0] == 1:
            body = zlib.decompress(body, -15)
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None
