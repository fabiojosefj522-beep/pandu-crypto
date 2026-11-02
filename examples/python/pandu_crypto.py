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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_LINK_RE = re.compile(r"#([DP])=([A-Z2-7]{16})([A-Z2-7]{26}|[A-Z2-7]{52})$")
_PIN_ITER = 100_000


def b32(data: bytes) -> str:
    """Base32, RFC 4648 alphabet, no padding."""
    return base64.b32encode(data).decode("ascii").rstrip("=")


def unb32(text: str) -> bytes:
    return base64.b32decode(text + "=" * (-len(text) % 8))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_card(bits: int = 128, pin: bool = False) -> dict:
    """id and key go into the QR; tok (edit token) stays only with the owner; share (QR + PIN) goes to the server."""
    if bits not in (128, 256):
        raise ValueError("bits must be 128 or 256")
    card = {"id": b32(os.urandom(10)), "key": b32(os.urandom(bits // 8)), "tok": b64url(os.urandom(32))}
    if pin:
        card["share"] = b64url(os.urandom(16))
    return card


def make_link(base: str, card_id: str, key: str, pin: bool = False) -> str:
    if not re.fullmatch(r"[A-Z2-7]{16}", card_id) or not re.fullmatch(r"[A-Z2-7]{26}|[A-Z2-7]{52}", key):
        raise ValueError("bad id or key")
    return base.split("#", 1)[0] + ("#P=" if pin else "#D=") + card_id + key


def parse_link(link: str):
    m = _LINK_RE.search(link or "")
    if not m:
        return None
    out = {"id": m.group(2), "key": m.group(3)}
    if m.group(1) == "P":
        out["pin"] = True
    return out


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


# ---------- QR + PIN (see FORMAT.md, section 8) ----------
def _hkdf(ikm: bytes, salt: bytes, info: str, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info.encode()).derive(ikm)


def pin_proof(card_id: str, key: str, pin: str) -> str:
    """What the reader sends to the server to get the share."""
    if not re.fullmatch(r"\d{4,12}", pin):
        raise ValueError("the PIN must be 4 to 12 digits")
    salt = _hkdf(unb32(key), unb32(card_id), "pandu-pin-v1/pin", 16)
    return b64url(hashlib.pbkdf2_hmac("sha256", pin.encode("ascii"), salt, _PIN_ITER, 32))


def _pin_data_key(card_id: str, key: str, share: str) -> bytes:
    k1 = unb32(key)
    return _hkdf(k1 + unb64url(share), unb32(card_id), "pandu-pin-v1/data", len(k1))


def encrypt_pin(data, card: dict, pin: str = None) -> dict:
    """Encrypts for a PIN card; with a PIN it also returns s (share) and ph (proof hash) for the server."""
    out = encrypt(data, b32(_pin_data_key(card["id"], card["key"], card["share"])))
    if pin is not None:
        out["s"] = card["share"]
        out["ph"] = token_hash(pin_proof(card["id"], card["key"], pin))
    return out


def decrypt_pin(ct: str, iv: str, card_id: str, key: str, share: str):
    try:
        return decrypt(ct, iv, b32(_pin_data_key(card_id, key, share)))
    except Exception:
        return None
