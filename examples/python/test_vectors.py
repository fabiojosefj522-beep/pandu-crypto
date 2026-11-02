"""Checks examples/python/pandu_crypto.py against test/vectors.json.
python examples/python/test_vectors.py   (needs: pip install cryptography)"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import pandu_crypto as pc  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

V = json.loads((pathlib.Path(__file__).parents[2] / "test" / "vectors.json").read_text(encoding="utf-8"))
passed = failed = 0


def ok(cond, name):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print("  FAIL", name)


ok(all(pc.b32(v["text"].encode()) == v["base32"] and pc.unb32(v["base32"]).decode() == v["text"] for v in V["base32"]), "base32")
ok(all(pc.b64url(bytes.fromhex(v["hex"])) == v["base64url"] for v in V["base64url"]), "base64url")
L = V["link"]
ok(pc.make_link(L["base"], L["id"], L["key"]) == L["link"] and pc.b32(bytes.fromhex(L["id_hex"])) == L["id"], "link")
ok(pc.parse_link(L["link"]) == {"id": L["id"], "key": L["key"]}, "parse link")
ok(pc.token_hash(V["token"]["tok"]) == V["token"]["sha256_hex"], "token hash")
for v in V["aes_gcm"]:
    ok(json.dumps(pc.decrypt(v["ct"], v["iv"], v["key"]), ensure_ascii=False, separators=(",", ":")) == v["json"], "decrypt " + v["name"])
    ct = AESGCM(pc.unb32(v["key"])).encrypt(pc.unb64url(v["iv"]), bytes.fromhex(v["plaintext_hex"]), None)
    ok(pc.b64url(ct) == v["ct"], "encrypt " + v["name"])

# QR + PIN
pv = V["pin"]
ok(pc.pin_proof(pv["id"], pv["key"], pv["pin"]) == pv["proof"] and pc.token_hash(pv["proof"]) == pv["ph"], "PIN proof")
ok(pc.make_link("https://example.com/r", pv["id"], pv["key"], pin=True) == pv["link"] and pc.parse_link(pv["link"]).get("pin") is True, "PIN link")
ok(pc._pin_data_key(pv["id"], pv["key"], pv["share"]).hex() == pv["data_key_hex"], "PIN data key")
ok(json.dumps(pc.decrypt_pin(pv["ct"], pv["iv"], pv["id"], pv["key"], pv["share"]), ensure_ascii=False, separators=(",", ":")) == pv["json"], "PIN decrypt")
card = pc.new_card(pin=True)
e = pc.encrypt_pin({"doc": "x"}, card, "1234")
ok(pc.decrypt_pin(e["ct"], e["iv"], card["id"], card["key"], e["s"]) == {"doc": "x"} and pc.decrypt(e["ct"], e["iv"], card["key"]) is None, "PIN round trip, QR key alone fails")

# round trip with fresh random cards, 128 and 256 bits
data = {"n": "Maria", "al": ["Dipirona"], "note": "á é í ó ú ç 🐼" * 20}
for bits in (128, 256):
    c = pc.new_card(bits)
    e = pc.encrypt(data, c["key"])
    ok(pc.decrypt(e["ct"], e["iv"], c["key"]) == data, f"round trip {bits}")
    ok(pc.decrypt(e["ct"], e["iv"], pc.new_card(bits)["key"]) is None, f"wrong key {bits}")
    ok(pc.parse_link(pc.make_link("https://e.com/", c["id"], c["key"])) == {"id": c["id"], "key": c["key"]}, f"link {bits}")

print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
