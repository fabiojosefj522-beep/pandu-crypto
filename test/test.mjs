// node test/test.mjs — no dependencies (Node 18+)
import { newCard, encrypt, decrypt, makeLink, parseLink, tokenHash, b32, unb32, b64url, unb64url, save, load, remove, encryptPin, decryptPin, pinProof, savePin, openPin } from '../src/pandu-crypto.js';
import { onRequest } from '../server/cloudflare/functions/api/q.js';

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.log('  FAIL', m); } };

// encodings
const r = crypto.getRandomValues(new Uint8Array(37));
ok(unb32(b32(r)).join() === r.join(), 'base32 round trip');
ok(unb64url(b64url(r)).join() === r.join(), 'base64url round trip');

// keys
const c = newCard();
ok(/^[A-Z2-7]{16}$/.test(c.id) && /^[A-Z2-7]{26}$/.test(c.key) && /^[A-Za-z0-9_-]{43}$/.test(c.tok), 'newCard formats');
ok(unb32(c.key).length === 16 && unb32(c.id).length === 10, 'key is 128 bits, id is 80 bits');
ok(newCard().key !== c.key, 'keys are random');

// links: the key is only in the fragment
const link = makeLink('https://example.com/card?x=1#old', c.id, c.key);
ok(link === 'https://example.com/card?x=1#D=' + c.id + c.key, 'makeLink');
ok(new URL(link).search === '?x=1' && !new URL(link).search.includes(c.key), 'key never in the part sent to the server');
ok(JSON.stringify(parseLink(link)) === JSON.stringify({ id: c.id, key: c.key }), 'parseLink');
ok(parseLink('https://example.com/#D=SHORT') === null, 'parseLink rejects bad links');

// encryption
const data = { name: 'Maria', allergies: ['penicillin'], contact: '+55 11 99999-0000', note: 'á é í ó ú ç 🐼'.repeat(5) };
const e1 = await encrypt(data, c.key), e2 = await encrypt(data, c.key);
ok(JSON.stringify(await decrypt(e1.ct, e1.iv, c.key)) === JSON.stringify(data), 'decrypt gives the data back');
ok(e1.iv !== e2.iv && e1.ct !== e2.ct, 'a new IV on every save');
ok(!e1.ct.includes('Maria') && !Buffer.from(unb64url(e1.ct)).toString('latin1').includes('Maria'), 'ciphertext does not contain the data');
ok(await decrypt(e1.ct, e1.iv, newCard().key) === null, 'wrong key -> null');
const bad = unb64url(e1.ct); bad[3] ^= 1;
ok(await decrypt(b64url(bad), e1.iv, c.key) === null, 'changed bytes -> null (integrity)');
ok((await tokenHash(c.tok)).length === 64 && (await tokenHash(c.tok)) !== c.tok, 'token hash');

// 256-bit keys (optional) and 128-bit links keep working next to them
const c256 = newCard({ bits: 256 });
ok(c256.key.length === 52 && unb32(c256.key).length === 32, '256-bit key');
const l256 = makeLink('https://e.com/', c256.id, c256.key);
ok(JSON.stringify(parseLink(l256)) === JSON.stringify({ id: c256.id, key: c256.key }), 'parseLink 256');
const e256 = await encrypt(data, c256.key);
ok(JSON.stringify(await decrypt(e256.ct, e256.iv, c256.key)) === JSON.stringify(data), 'AES-256 round trip');
ok(await decrypt(e256.ct, e256.iv, c.key) === null && await decrypt(e1.ct, e1.iv, c256.key) === null, 'keys of different sizes do not mix');
ok(JSON.stringify(parseLink(link)) === JSON.stringify({ id: c.id, key: c.key }), '128-bit links still parse');
let threw = false; try { newCard({ bits: 192 }); } catch (_) { threw = true; } ok(threw, 'only 128 or 256');

// reference server on a real SQLite (like D1); skipped on Node versions without node:sqlite
let sqliteMod = null; try { sqliteMod = await import('node:sqlite'); } catch (_) { sqliteMod = null; }
if (!sqliteMod) console.log('  (server tests skipped: this Node has no node:sqlite)');
else {
  const sq = new sqliteMod.DatabaseSync(':memory:');
  const DB = { prepare(sql) { let a = []; const api = { bind(...x) { a = x; return api; }, async first() { const r = sq.prepare(sql).get(...a); return r === undefined ? null : { ...r }; }, async run() { sq.prepare(sql).run(...a); return { success: true }; }, async all() { return { results: sq.prepare(sql).all(...a).map((r) => ({ ...r })) }; } }; return api; } };
  let ip = 0;
  globalThis.fetch = async (url, opt = {}) => { const req = new Request(new URL(url, 'https://x.test/'), opt); if (opt.headers) req.headers.set('CF-Connecting-IP', '10.0.0.' + (ip++ % 250)); return onRequest({ request: req, env: { DB } }); };
  const API = 'https://x.test/api/q', row = (id) => sq.prepare('SELECT * FROM q WHERE id = ?').get(id);
  ok(await save(API, c, data) === 200, 'save');
  const got = await load(API, link);
  ok(JSON.stringify(got.data) === JSON.stringify(data), 'load + decrypt');
  const stored = row(c.id);
  ok(!JSON.stringify(stored).includes('Maria') && !JSON.stringify(stored).includes(c.key) && !JSON.stringify(stored).includes(c.tok), 'server keeps no data, no key, no token');
  ok(stored.h === await tokenHash(c.tok), 'server keeps only the token hash');
  ok(await save(API, { ...c, tok: newCard().tok }, { name: 'attacker' }) === 403, 'someone else cannot overwrite');
  ok(await remove(API, { ...c, tok: newCard().tok }) === 403, 'someone else cannot delete');
  ok((await load(API, makeLink('https://e.com/', c.id, newCard().key))).error === 'bad-key', 'wrong key in link');
  ok((await load(API, makeLink('https://e.com/', newCard().id, c.key))).error === 'not-found', 'unknown id -> not-found');
  ok(await remove(API, c) === 200 && (await load(API, link)).error === 'turned-off', 'delete -> turned off (410)');
  ok(row(c.id).ct === '', 'delete erases the encrypted bytes');

  // QR + PIN
  const pc = newCard({ pin: true }), plink = makeLink('https://e.com/r', pc.id, pc.key, { pin: true }), report = { doc: 'Laudo', text: 'Exame normal. 🐼'.repeat(10) };
  ok(/^[A-Za-z0-9_-]{22}$/.test(pc.share) && plink.includes('#P=') && parseLink(plink).pin === true, 'PIN card: share and #P= link');
  ok(await savePin(API, pc, report, '482913') === 200, 'save with PIN');
  const pr = row(pc.id);
  ok(pr.s === pc.share && pr.ph.length === 64 && !JSON.stringify(pr).includes('482913') && !JSON.stringify(pr).includes(pc.key), 'server keeps the share and a proof hash, never the PIN or the QR key');
  ok((await load(API, plink)).error === 'needs-pin', 'a #P= link asks for the PIN');
  const g = await (await fetch(API + '?id=' + pc.id)).json();
  ok(g.pin === true && !g.ct && !g.s, 'GET of a PIN card gives no bytes and no share');
  ok(await decrypt(pr.ct, pr.iv, pc.key) === null, 'the QR key alone does not open it (photo of the QR)');
  ok(await decryptPin(pr.ct, pr.iv, pc.id, newCard().key, pr.s) === null, 'the server share alone does not open it (database copy)');
  const o1 = await openPin(API, plink, '482913');
  ok(JSON.stringify(o1.data) === JSON.stringify(report), 'right PIN opens it');
  const w = []; for (let i = 0; i < 4; i++) w.push(await openPin(API, plink, '000000'));
  ok(w.map((x) => x.left).join() === '4,3,2,1' && w.every((x) => x.error === 'wrong-pin'), 'wrong PINs are counted', w);
  const ok1 = await openPin(API, plink, '482913');
  ok(ok1.data && row(pc.id).pf === 0, 'the right PIN resets the count');
  for (let i = 0; i < 4; i++) await openPin(API, plink, '111111');
  const lock = await openPin(API, plink, '111111');
  ok(lock.error === 'locked' && lock.wait > 800 && lock.wait <= 900, '5th wrong PIN: locked for 15 minutes', lock);
  ok((await openPin(API, plink, '482913')).error === 'locked', 'locked even with the right PIN');
  const nowReal = Date.now; Date.now = () => nowReal() + 16 * 60e3;
  const lock2 = await openPin(API, plink, '222222');
  ok(lock2.error === 'locked' && lock2.wait > 1700 && lock2.wait <= 1800, 'next wrong PIN after the lock: 30 minutes', lock2);
  Date.now = nowReal;
  ok(await savePin(API, pc, report) === 200 && (await openPin(API, plink, '482913')).data, 'the owner saving again unlocks it');
  ok(await savePin(API, pc, { ...report, text: 'novo' }) === 200 && row(pc.id).ph === pr.ph && (await openPin(API, plink, '482913')).data.text === 'novo', 'saving without a PIN keeps the PIN');
  ok(await savePin(API, pc, report, '7777') === 200 && (await openPin(API, plink, '482913')).error === 'wrong-pin' && (await openPin(API, plink, '7777')).data, 'the owner can change the PIN');
  ok(await savePin(API, { ...pc, tok: newCard().tok }, report, '1234') === 403, 'someone else cannot change the PIN');
  let threw = false; try { await pinProof(pc.id, pc.key, '12a4'); } catch (_) { threw = true; } ok(threw, 'the PIN must be digits');
  ok((await openPin(API, makeLink('https://e.com/', newCard().id, pc.key, { pin: true }), '1234')).error === 'not-found', 'unknown PIN card -> not-found');
  ok(await remove(API, pc) === 200 && row(pc.id).s === null && (await openPin(API, plink, '7777')).error === 'turned-off', 'delete erases the share too');
}


// official vectors (test/vectors.json): the same checks other languages run (examples/python, examples/java)
const V = JSON.parse(await (await import('node:fs/promises')).readFile(new URL('./vectors.json', import.meta.url), 'utf8'));
const fromHex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
ok(V.base32.every((v) => b32(new TextEncoder().encode(v.text)) === v.base32 && new TextDecoder().decode(unb32(v.base32)) === v.text), 'vectors: base32 (RFC 4648)');
ok(V.base64url.every((v) => b64url(fromHex(v.hex)) === v.base64url), 'vectors: base64url');
ok(makeLink(V.link.base, V.link.id, V.link.key) === V.link.link && b32(fromHex(V.link.id_hex)) === V.link.id, 'vectors: link');
ok(await tokenHash(V.token.tok) === V.token.sha256_hex, 'vectors: token hash');
for (const v of V.aes_gcm) {
  ok(JSON.stringify(await decrypt(v.ct, v.iv, v.key)) === v.json, 'vectors: decrypt ' + v.name);
  const k = await crypto.subtle.importKey('raw', unb32(v.key), 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: unb64url(v.iv) }, k, fromHex(v.plaintext_hex)));
  ok(b64url(ct) === v.ct && unb32(v.key).length * 8 === (v.key.length === 26 ? 128 : 256), 'vectors: encrypt ' + v.name);
}

{
  const pv = V.pin;
  ok(await pinProof(pv.id, pv.key, pv.pin) === pv.proof && await tokenHash(pv.proof) === pv.ph, 'vectors: PIN proof');
  ok(makeLink('https://example.com/r', pv.id, pv.key, { pin: true }) === pv.link, 'vectors: PIN link');
  ok(JSON.stringify(await decryptPin(pv.ct, pv.iv, pv.id, pv.key, pv.share)) === pv.json, 'vectors: PIN decrypt');
  const k = await crypto.subtle.importKey('raw', fromHex(pv.data_key_hex), 'AES-GCM', false, ['encrypt']);
  ok(b64url(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: unb64url(pv.iv) }, k, fromHex(pv.plaintext_hex)))) === pv.ct, 'vectors: PIN encrypt');
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
