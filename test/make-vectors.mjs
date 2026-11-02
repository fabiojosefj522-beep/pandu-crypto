// Writes test/vectors.json: fixed inputs and the exact outputs, so any language can check it is compatible.
// node test/make-vectors.mjs   (the vectors are committed; run again only if the format changes)
import { writeFileSync } from 'node:fs';
import { deflateRawSync } from 'node:zlib';
import { b32, b64url, unb32, unb64url, makeLink, tokenHash, decrypt, pinProof, decryptPin } from '../src/pandu-crypto.js';

const seq = (n, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 255);
const hex = (u8) => Buffer.from(u8).toString('hex');
const enc = new TextEncoder();

async function aes(keyBytes, ivBytes, plain) {
  const k = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBytes }, k, plain));
}
async function vector(name, keyBytes, ivBytes, data, flag) {
  const json = JSON.stringify(data), raw = enc.encode(json);
  const body = flag === 1 ? new Uint8Array(deflateRawSync(raw)) : raw;
  const plain = new Uint8Array(body.length + 1); plain[0] = flag; plain.set(body, 1);
  const ct = await aes(keyBytes, ivBytes, plain), key = b32(keyBytes), iv = b64url(ivBytes);
  const back = await decrypt(b64url(ct), iv, key);
  if (JSON.stringify(back) !== json) throw new Error('round trip failed: ' + name);
  return { name, key, key_hex: hex(keyBytes), iv, iv_hex: hex(ivBytes), flag, json, plaintext_hex: hex(plain), ct: b64url(ct) };
}

const data = { n: 'Maria da Silva', bt: 'O+', al: ['Dipirona', 'Penicilina'], ct: [['Fábio', 'filho', '+55 31 99999-0000']], note: 'Diabética. Usa insulina. 🐼' };
const id = b32(seq(10, 0xa0)), key128 = b32(seq(16)), tok = b64url(seq(32, 0x40));
const out = {
  about: 'pandu-crypto test vectors. Base32: RFC 4648 alphabet, no padding. Base64url: no padding. AES-GCM with a 96-bit IV and a 128-bit tag appended to the ciphertext, no associated data. plaintext = 1 flag byte (0 = UTF-8 JSON, 1 = raw DEFLATE of the UTF-8 JSON) + body.',
  base32: [['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']].map(([text, b]) => ({ text, base32: b })),
  base64url: [{ hex: 'fbff', base64url: '-_8' }, { hex: hex(seq(32, 0x40)), base64url: tok }],
  link: { base: 'https://example.com/card?x=1#old', id, id_hex: hex(seq(10, 0xa0)), key: key128, link: makeLink('https://example.com/card?x=1#old', id, key128) },
  token: { tok, sha256_hex: await tokenHash(tok) },
  aes_gcm: [
    await vector('aes-128, plain JSON (flag 0)', seq(16), seq(12, 0xf0), data, 0),
    await vector('aes-128, deflate-raw (flag 1)', seq(16), seq(12, 0xe0), { ...data, note: data.note.repeat(6) }, 1),
    await vector('aes-256, plain JSON (flag 0)', seq(32, 0x80), seq(12, 0xd0), data, 0),
  ],
};
/* QR + PIN: every intermediate value, so another language can check each step */
async function hkdf(ikm, salt, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, k, len * 8));
}
{
  const id = b32(seq(10, 0x30)), key = b32(seq(16, 0x50)), share = b64url(seq(16, 0x70)), pin = '482913', ivB = seq(12, 0xc0);
  const salt = await hkdf(unb32(key), unb32(id), 'pandu-pin-v1/pin', 16), proof = await pinProof(id, key, pin);
  const ikm = new Uint8Array(32); ikm.set(unb32(key)); ikm.set(unb64url(share), 16);
  const dk = await hkdf(ikm, unb32(id), 'pandu-pin-v1/data', 16);
  const json = JSON.stringify({ doc: 'Laudo', text: 'Exame normal.' }), plain = new Uint8Array([0, ...enc.encode(json)]);
  const ct = b64url(await aes(dk, ivB, plain));
  if (JSON.stringify(await decryptPin(ct, b64url(ivB), id, key, share)) !== json) throw new Error('pin round trip failed');
  out.pin = { about: 'pin_salt = HKDF-SHA256(ikm = key bytes, salt = id bytes, info = "pandu-pin-v1/pin", 16 bytes); proof = base64url(PBKDF2-SHA256(PIN as ASCII digits, pin_salt, 100000 iterations, 32 bytes)); ph = hex SHA-256 of the proof string; data_key = HKDF-SHA256(ikm = key bytes || share bytes, salt = id bytes, info = "pandu-pin-v1/data", length of the key)',
    id, key, share, pin, link: makeLink('https://example.com/r', id, key, { pin: true }), pin_salt_hex: hex(salt), proof, ph: await tokenHash(proof), data_key_hex: hex(dk), iv: b64url(ivB), plaintext_hex: hex(plain), json, ct };
}
for (const v of out.base32) if (b32(enc.encode(v.text)) !== v.base32) throw new Error('base32 vector ' + v.text);
writeFileSync(new URL('./vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log('vectors.json written:', out.aes_gcm.length, 'AES vectors');
