/* pandu-crypto — zero-knowledge QR links for sensitive data (health cards, emergency info, pet tags...).
   The same method Pandu SOS (https://usepandu.com.br) uses in production.

   How it works
   1. The data is encrypted on the user's own device with AES-GCM (Web Crypto), using a random 128-bit key
      created only for that QR, and a fresh random 96-bit IV on every save.
   2. The QR holds a link like  https://example.com/#D=<id><key> : a random 80-bit id and the key.
      Everything after "#" (the URL fragment) stays in the browser and is never sent to any server.
   3. The server stores only {id, ct, iv, date, sha256(edit token)}. It cannot read anything.
   4. Whoever scans fetches ct + iv by id and decrypts locally with the key from the link.
   Optional "QR + PIN" mode (#P= links): the QR alone is not enough; see pinProof() below.

   No dependencies. Runs in every modern browser, in Node 18+, Deno, Bun and Cloudflare Workers.
   MIT License — Copyright (c) 2026 Fábio José dos Santos */

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ID_LEN = 16;          /* 10 random bytes in base32 */
const KEY_LENS = [26, 52];  /* 16 random bytes (AES-128, the default) or 32 (AES-256) in base32 */
const LINK_RE = /#([DP])=([A-Z2-7]{16})([A-Z2-7]{26}|[A-Z2-7]{52})$/;
const PIN_RE = /^\d{4,12}$/;
const PIN_ITER = 100000;
const cryptoApi = () => { const c = globalThis.crypto; if (!c || !c.subtle) throw new Error('pandu-crypto: Web Crypto is not available (needs https or localhost)'); return c; };

/* ---------- encodings ---------- */
/* base32 (RFC 4648 alphabet, no padding): capitals and digits only, so a QR can store it in its compact "alphanumeric" mode */
export function b32(bytes) {
  let out = '', buf = 0, n = 0;
  for (let i = 0; i < bytes.length; i++) { buf = (buf << 8) | bytes[i]; n += 8; while (n >= 5) { out += B32[(buf >>> (n - 5)) & 31]; n -= 5; } buf &= (1 << n) - 1; }
  if (n > 0) out += B32[(buf << (5 - n)) & 31];
  return out;
}
export function unb32(s) {
  const out = []; let buf = 0, n = 0;
  for (let i = 0; i < s.length; i++) { const v = B32.indexOf(s[i]); if (v < 0) throw new Error('pandu-crypto: invalid base32'); buf = (buf << 5) | v; n += 5; if (n >= 8) { out.push((buf >>> (n - 8)) & 255); n -= 8; } buf &= (1 << n) - 1; }
  return new Uint8Array(out);
}
export function b64url(bytes) {
  let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64url(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}
async function stream(bytes, Ctor, fmt) {
  const s = new Blob([bytes]).stream().pipeThrough(new Ctor(fmt));
  return new Uint8Array(await new Response(s).arrayBuffer());
}

/* ---------- keys and links ---------- */
/* a new card: id and key go into the QR; tok (the edit token) stays only on the owner's device and is never put in the QR.
   Keys are 128-bit by default: NIST expects AES-128 to stay secure for decades even against quantum computers, and the
   QR stays small (version 4 for a typical link). { bits: 256 } is there for rules that require 256-bit keys (e.g. CNSA 2.0);
   it makes the QR one size bigger (version 5). */
export function newCard(opts = {}) {
  const c = cryptoApi(), rnd = (n) => c.getRandomValues(new Uint8Array(n)), bits = opts.bits === undefined ? 128 : opts.bits;
  if (bits !== 128 && bits !== 256) throw new Error('pandu-crypto: bits must be 128 or 256');
  const card = { id: b32(rnd(10)), key: b32(rnd(bits / 8)), tok: b64url(rnd(32)) };
  if (opts.pin) card.share = b64url(rnd(16)); /* QR + PIN: the server's half, handed out only to whoever proves the PIN */
  return card;
}
/* opts.pin: a "#P=" link, which tells the reader to ask for the PIN */
export function makeLink(base, id, key, opts = {}) {
  if (!/^[A-Z2-7]+$/.test(id) || id.length !== ID_LEN || !/^[A-Z2-7]+$/.test(key) || !KEY_LENS.includes(key.length)) throw new Error('pandu-crypto: bad id or key');
  return String(base).replace(/#.*$/, '') + (opts.pin ? '#P=' : '#D=') + id + key;
}
/* accepts a full link, a location.hash or just "#D=..." / "#P=..."; returns {id, key} (and pin: true for #P=) */
export function parseLink(link) {
  const m = LINK_RE.exec(String(link || ''));
  if (!m) return null;
  return m[1] === 'P' ? { id: m[2], key: m[3], pin: true } : { id: m[2], key: m[3] };
}
/* what the server keeps instead of the edit token (hex SHA-256) */
export async function tokenHash(tok) {
  const d = await cryptoApi().subtle.digest('SHA-256', new TextEncoder().encode(String(tok)));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/* ---------- encryption ----------
   plaintext = 1 flag byte (0 = JSON as is, 1 = JSON compressed with deflate-raw) + the bytes; the smaller one wins */
export async function encrypt(data, key) { return encryptRaw(data, unb32(key)); }
async function encryptRaw(data, keyBytes) {
  const c = cryptoApi();
  let body = new TextEncoder().encode(JSON.stringify(data)), flag = 0;
  if (typeof CompressionStream === 'function') { try { const z = await stream(body, CompressionStream, 'deflate-raw'); if (z.length < body.length) { body = z; flag = 1; } } catch (_) { /* plain is fine */ } }
  const plain = new Uint8Array(body.length + 1); plain[0] = flag; plain.set(body, 1);
  const iv = c.getRandomValues(new Uint8Array(12));
  const k = await c.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await c.subtle.encrypt({ name: 'AES-GCM', iv }, k, plain));
  return { ct: b64url(ct), iv: b64url(iv) };
}
/* returns the data, or null when the key is wrong or the bytes were changed (AES-GCM checks integrity) */
export async function decrypt(ct, iv, key) { try { return await decryptRaw(ct, iv, unb32(key)); } catch (_) { return null; } }
async function decryptRaw(ct, iv, keyBytes) {
  try {
    const c = cryptoApi();
    const k = await c.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const plain = new Uint8Array(await c.subtle.decrypt({ name: 'AES-GCM', iv: unb64url(iv) }, k, unb64url(ct)));
    let body = plain.slice(1);
    if (plain[0] === 1) body = await stream(body, DecompressionStream, 'deflate-raw');
    return JSON.parse(new TextDecoder().decode(body));
  } catch (_) { return null; }
}

/* ---------- QR + PIN ----------
   For data only the right person should open (a medical report for the doctor, a door code for a guest): a photo of the QR
   is not enough. The data key is derived from the key in the QR AND a share the server keeps, and the server hands the
   share out only to whoever proves the PIN, with a limit on wrong attempts. The server still cannot read anything: it never
   has the key in the QR, and it cannot even check PIN guesses on its own (the proof needs that key too).
   Limits: whoever has the QR AND a copy of the server's database does not need the PIN. Not for emergencies: a rescuer
   does not know the PIN. PIN: 4 to 12 digits. */
async function hkdf(ikm, salt, info, len) {
  const c = cryptoApi(), k = await c.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await c.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(info) }, k, len * 8));
}
/* what the reader sends to the server to get the share: PBKDF2-SHA256(PIN, salt from the QR key, 100,000 rounds) */
export async function pinProof(id, key, pin) {
  if (!PIN_RE.test(String(pin))) throw new Error('pandu-crypto: the PIN must be 4 to 12 digits');
  const c = cryptoApi(), salt = await hkdf(unb32(key), unb32(id), 'pandu-pin-v1/pin', 16);
  const k = await c.subtle.importKey('raw', new TextEncoder().encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
  return b64url(new Uint8Array(await c.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PIN_ITER }, k, 256)));
}
/* the AES key of a PIN card: HKDF-SHA256(key in the QR || server share), as long as the key in the QR */
async function pinDataKey(id, key, share) {
  const k1 = unb32(key), k2 = unb64url(share), ikm = new Uint8Array(k1.length + k2.length);
  ikm.set(k1); ikm.set(k2, k1.length);
  return hkdf(ikm, unb32(id), 'pandu-pin-v1/data', k1.length);
}
/* encrypts for a PIN card; with a PIN it also returns s (the share) and ph (the proof's hash) for the server */
export async function encryptPin(data, card, pin) {
  if (!card.share) throw new Error('pandu-crypto: this card has no share (create it with newCard({ pin: true }))');
  const out = await encryptRaw(data, await pinDataKey(card.id, card.key, card.share));
  if (pin !== undefined) { out.s = card.share; out.ph = await tokenHash(await pinProof(card.id, card.key, pin)); }
  return out;
}
export async function decryptPin(ct, iv, id, key, share) { try { return await decryptRaw(ct, iv, await pinDataKey(id, key, share)); } catch (_) { return null; } }

/* ---------- optional helpers for the reference server (server/cloudflare) ---------- */
/* saves (creates or updates) the encrypted card. Returns the HTTP status: 200 ok, 403 = this id belongs to someone else */
export async function save(api, card, data) {
  const body = Object.assign({ id: card.id, tok: card.tok }, await encrypt(data, card.key));
  const r = await fetch(api, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), cache: 'no-store' });
  return r.status;
}
/* saves a PIN card; pass the PIN to set or change it, leave it out to just update the data */
export async function savePin(api, card, data, pin) {
  const body = Object.assign({ id: card.id, tok: card.tok }, await encryptPin(data, card, pin));
  const r = await fetch(api, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), cache: 'no-store' });
  return r.status;
}
/* opens a PIN card: {data} | {error: 'wrong-pin', left} | {error: 'locked', wait (seconds)} | {error: 'not-found' | 'turned-off' | 'bad-link' | 'bad-key' | 'offline'} */
export async function openPin(api, link, pin) {
  const p = parseLink(link); if (!p) return { error: 'bad-link' };
  let r; try { r = await fetch(api, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ op: 'open', id: p.id, proof: await pinProof(p.id, p.key, pin) }), cache: 'no-store' }); } catch (e) { return { error: String(e.message).includes('PIN') ? 'bad-pin' : 'offline' }; }
  let j = {}; try { j = await r.json(); } catch (_) { j = {}; }
  if (r.status === 403) return { error: 'wrong-pin', left: j.left };
  if (r.status === 429) return { error: 'locked', wait: j.wait };
  if (r.status === 404) return { error: 'not-found' };
  if (r.status === 410) return { error: 'turned-off' };
  if (!r.ok) return { error: 'offline' };
  const data = await decryptPin(j.ct, j.iv, p.id, p.key, j.s);
  return data === null ? { error: 'bad-key' } : { data, updated: j.u };
}
/* opens a card from its link: {data} | {error: 'needs-pin' | 'not-found' | 'turned-off' | 'bad-link' | 'bad-key' | 'offline'} */
export async function load(api, link) {
  const p = parseLink(link); if (!p) return { error: 'bad-link' };
  if (p.pin) return { error: 'needs-pin' };
  let r; try { r = await fetch(api + (api.includes('?') ? '&' : '?') + 'id=' + p.id, { cache: 'no-store' }); } catch (_) { return { error: 'offline' }; }
  if (r.status === 404) return { error: 'not-found' };
  if (r.status === 410) return { error: 'turned-off' };
  if (!r.ok) return { error: 'offline' };
  const j = await r.json();
  if (j.pin) return { error: 'needs-pin' };
  const data = await decrypt(j.ct, j.iv, p.key);
  return data === null ? { error: 'bad-key' } : { data, updated: j.u };
}
/* turns the card off: the encrypted bytes are erased and the QR answers "turned off" from then on */
export async function remove(api, card) {
  const r = await fetch(api, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: card.id, tok: card.tok }), cache: 'no-store' });
  return r.status;
}
