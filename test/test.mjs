// node test/test.mjs — no dependencies (Node 18+)
import { newCard, encrypt, decrypt, makeLink, parseLink, tokenHash, b32, unb32, b64url, unb64url, save, load, remove } from '../src/pandu-crypto.js';
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

// reference server with an in-memory D1 stand-in
const rows = new Map();
const DB = { prepare(sql) { let a = []; const st = {
  bind(...x) { a = x; return st; },
  async first() { const r = rows.get(a[0]); if (!r) return null; return sql.startsWith('SELECT h') ? { h: r.h } : { ct: r.ct, iv: r.iv, u: r.u }; },
  async run() {
    if (sql.startsWith('CREATE')) return;
    if (sql.includes("VALUES (?1, '', ''")) { const [id, u, h] = a, o = rows.get(id); if (!o) rows.set(id, { ct: '', iv: '', u, h }); else if (o.h === h) Object.assign(o, { ct: '', iv: '', u }); return; }
    const [id, ct, iv, u, h] = a, o = rows.get(id); if (!o) rows.set(id, { ct, iv, u, h }); else if (o.h === h) Object.assign(o, { ct, iv, u });
  } }; return st; } };
globalThis.fetch = async (url, opt = {}) => onRequest({ request: new Request(new URL(url, 'https://x.test/'), opt), env: { DB } });
const API = 'https://x.test/api/q';
ok(await save(API, c, data) === 200, 'save');
const got = await load(API, link);
ok(JSON.stringify(got.data) === JSON.stringify(data), 'load + decrypt');
const stored = rows.get(c.id);
ok(!JSON.stringify(stored).includes('Maria') && !JSON.stringify(stored).includes(c.key) && !JSON.stringify(stored).includes(c.tok), 'server keeps no data, no key, no token');
ok(stored.h === await tokenHash(c.tok), 'server keeps only the token hash');
ok(await save(API, { ...c, tok: newCard().tok }, { name: 'attacker' }) === 403, 'someone else cannot overwrite');
ok(await remove(API, { ...c, tok: newCard().tok }) === 403, 'someone else cannot delete');
ok((await load(API, makeLink('https://e.com/', c.id, newCard().key))).error === 'bad-key', 'wrong key in link');
ok((await load(API, makeLink('https://e.com/', newCard().id, c.key))).error === 'not-found', 'unknown id -> not-found');
ok(await remove(API, c) === 200 && (await load(API, link)).error === 'turned-off', 'delete -> turned off (410)');
ok(rows.get(c.id).ct === '', 'delete erases the encrypted bytes');

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
