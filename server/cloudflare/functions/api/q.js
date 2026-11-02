/* pandu-crypto reference server: Cloudflare Pages Functions + D1.
   It only ever sees a random id, encrypted bytes, the IV, a date and the SHA-256 of the owner's edit token
   (and, for QR + PIN cards, the server's share and the SHA-256 of the PIN proof).
   The key lives only inside the QR (after "#"), so this server cannot read anyone's data.

   GET    /api/q?id=ID                     -> 200 {ct, iv, u} | 200 {pin: true, u} (QR + PIN card) | 404 | 410 (turned off)
   PUT    /api/q  {id, tok, ct, iv[, s, ph]} -> 200 {ok, u}     | 400 | 403 (not the owner) | 413 | 429
   POST   /api/q  {op: 'open', id, proof}   -> 200 {ct, iv, u, s} | 403 {left} (wrong PIN) | 429 {wait} (too many) | 400 | 404 | 410
   DELETE /api/q  {id, tok}                 -> 200 {ok}        | 403
   QR + PIN: s = the server's share, ph = SHA-256 of the proof (send s: '' and ph: '' to remove the PIN). After 5 wrong
   PINs the card is locked for 15 minutes, doubling at each further wrong PIN (up to 24 hours); the owner's next PUT unlocks it.
   Storage: the D1 database bound as "DB"; the table is created (and updated) on first use.
   MIT License — Copyright (c) 2026 Fábio José dos Santos */
const ID_RE = /^[A-Z2-7]{16}$/;
const TOK_RE = /^[A-Za-z0-9_-]{43}$/;
const B64_RE = /^[A-Za-z0-9_-]+$/;
const SHARE_RE = /^[A-Za-z0-9_-]{22}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const MAX_CT = 12000;        /* bytes of ciphertext (base64url) per card */
const WRITES_PER_MIN = 30;   /* per network address */
const PIN_FREE = 5;          /* wrong PINs before the first lock */

const json = (code, obj) => new Response(JSON.stringify(obj), { status: code, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha = async (s) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s))));
/* constant-time comparison of two hex strings */
const sameHash = (a, b) => { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; };

/* soft limit per address, kept only in this instance's memory, as a hash, for one minute */
const seen = new Map();
const tooMany = async (ip) => {
  const now = Date.now(), k = (await sha(ip)).slice(0, 16), r = seen.get(k);
  if (seen.size > 5000) for (const [kk, v] of seen) if (now - v.t > 60e3) seen.delete(kk);
  if (!r || now - r.t > 60e3) { seen.set(k, { t: now, n: 1 }); return false; }
  r.n += 1; return r.n > WRITES_PER_MIN;
};

let ready = false;
const setup = async (db) => {
  if (ready) return;
  await db.prepare('CREATE TABLE IF NOT EXISTS q (id TEXT PRIMARY KEY, ct TEXT NOT NULL, iv TEXT NOT NULL, u TEXT NOT NULL, h TEXT NOT NULL)').run();
  for (const col of ['s TEXT', 'ph TEXT', 'pf INTEGER', 'lk INTEGER']) { try { await db.prepare('ALTER TABLE q ADD COLUMN ' + col).run(); } catch (_) { /* already there */ } }
  ready = true;
};

export async function onRequest({ request, env }) {
  const db = env.DB;
  if (!db) return json(503, { error: 'storage not configured' });
  try {
    await setup(db);
    if (request.method === 'GET') {
      const id = new URL(request.url).searchParams.get('id') || '';
      if (!ID_RE.test(id)) return json(400, { error: 'id' });
      const rec = await db.prepare('SELECT ct, iv, u, s FROM q WHERE id = ?').bind(id).first();
      if (!rec) return json(404, { error: 'not found' });
      if (!rec.ct) return json(410, { error: 'turned off' });
      if (rec.s) return json(200, { pin: true, u: rec.u }); /* QR + PIN: the bytes come only with the right PIN */
      return json(200, { ct: rec.ct, iv: rec.iv, u: rec.u });
    }
    if (request.method === 'PUT' || request.method === 'DELETE' || request.method === 'POST') {
      const raw = await request.text();
      if (raw.length > 40000) return json(413, { error: 'too big' });
      let b = null; try { b = JSON.parse(raw); } catch (_) { b = null; }
      if (!b || !ID_RE.test(b.id || '')) return json(400, { error: 'bad request' });
      if (await tooMany(request.headers.get('CF-Connecting-IP') || '')) return json(429, { error: 'slow down', wait: 60 });
      /* QR + PIN: whoever proves the PIN gets the bytes and the share; wrong PINs are counted in the database */
      if (request.method === 'POST') {
        if (b.op !== 'open' || !TOK_RE.test(b.proof || '')) return json(400, { error: 'bad request' });
        const rec = await db.prepare('SELECT ct, iv, u, s, ph, pf, lk FROM q WHERE id = ?').bind(b.id).first();
        if (!rec) return json(404, { error: 'not found' });
        if (!rec.ct) return json(410, { error: 'turned off' });
        if (!rec.s) return json(400, { error: 'no pin on this card' });
        const now = Date.now();
        if (rec.lk && now < rec.lk) return json(429, { error: 'locked', wait: Math.ceil((rec.lk - now) / 1000) });
        if (!sameHash(await sha(b.proof), rec.ph)) {
          const pf = (rec.pf || 0) + 1, lk = pf >= PIN_FREE ? now + Math.min(15 * 60e3 * 2 ** (pf - PIN_FREE), 24 * 3600e3) : 0;
          await db.prepare('UPDATE q SET pf = ?1, lk = ?2 WHERE id = ?3').bind(pf, lk, b.id).run();
          return lk ? json(429, { error: 'locked', wait: Math.ceil((lk - now) / 1000) }) : json(403, { error: 'wrong pin', left: PIN_FREE - pf });
        }
        if (rec.pf) await db.prepare('UPDATE q SET pf = 0, lk = 0 WHERE id = ?').bind(b.id).run();
        return json(200, { ct: rec.ct, iv: rec.iv, u: rec.u, s: rec.s });
      }
      if (!TOK_RE.test(b.tok || '')) return json(400, { error: 'bad request' });
      const h = await sha(b.tok), old = await db.prepare('SELECT h FROM q WHERE id = ?').bind(b.id).first();
      if (old && !sameHash(old.h, h)) return json(403, { error: 'not the owner' });
      const u = new Date().toISOString();
      /* delete: the encrypted bytes (and the PIN share) are erased; the id and the owner's hash stay, so the QR can say it was turned off */
      if (request.method === 'DELETE') { await db.prepare("INSERT INTO q (id, ct, iv, u, h) VALUES (?1, '', '', ?2, ?3) ON CONFLICT(id) DO UPDATE SET ct = '', iv = '', u = ?2, s = NULL, ph = NULL WHERE h = ?3").bind(b.id, u, h).run(); return json(200, { ok: true }); }
      if (typeof b.ct !== 'string' || typeof b.iv !== 'string' || !B64_RE.test(b.ct) || !/^[A-Za-z0-9_-]{16}$/.test(b.iv)) return json(400, { error: 'bad data' });
      if (b.ct.length > MAX_CT) return json(413, { error: 'too big' });
      const pinSet = b.s !== undefined || b.ph !== undefined, pinOff = b.s === '' && b.ph === '';
      if (pinSet && !pinOff && !(SHARE_RE.test(b.s || '') && HEX64_RE.test(b.ph || ''))) return json(400, { error: 'bad pin data' });
      await db.prepare('INSERT INTO q (id, ct, iv, u, h) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO UPDATE SET ct = ?2, iv = ?3, u = ?4 WHERE h = ?5').bind(b.id, b.ct, b.iv, u, h).run();
      if (pinSet) await db.prepare('UPDATE q SET s = ?1, ph = ?2 WHERE id = ?3 AND h = ?4').bind(pinOff ? null : b.s, pinOff ? null : b.ph, b.id, h).run();
      await db.prepare('UPDATE q SET pf = 0, lk = 0 WHERE id = ? AND h = ?').bind(b.id, h).run(); /* the owner unlocks */
      return json(200, { ok: true, u });
    }
    return new Response(JSON.stringify({ error: 'method' }), { status: 405, headers: { Allow: 'GET, PUT, POST, DELETE', 'Content-Type': 'application/json' } });
  } catch (_) {
    return json(500, { error: 'server' });
  }
}
