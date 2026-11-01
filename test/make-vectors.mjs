// Writes test/vectors.json: fixed inputs and the exact outputs, so any language can check it is compatible.
// node test/make-vectors.mjs   (the vectors are committed; run again only if the format changes)
import { writeFileSync } from 'node:fs';
import { deflateRawSync } from 'node:zlib';
import { b32, b64url, makeLink, tokenHash, decrypt } from '../src/pandu-crypto.js';

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
for (const v of out.base32) if (b32(enc.encode(v.text)) !== v.base32) throw new Error('base32 vector ' + v.text);
writeFileSync(new URL('./vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log('vectors.json written:', out.aes_gcm.length, 'AES vectors');
