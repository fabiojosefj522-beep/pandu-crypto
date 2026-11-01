/* pandu-crypto reference server: Cloudflare Pages Functions + D1.
   It only ever sees a random id, encrypted bytes, the IV, a date and the SHA-256 of the owner's edit token.
   The key lives only inside the QR (after "#"), so this server cannot read anyone's data.

   GET    /api/q?id=ID              -> 200 {ct, iv, u} | 404 (never saved) | 410 (turned off by the owner)
   PUT    /api/q  {id, tok, ct, iv}  -> 200 {ok, u}     | 400 | 403 (not the owner) | 413 | 429
   DELETE /api/q  {id, tok}          -> 200 {ok}        | 403
   Storage: the D1 database bound as "DB"; the table is created on first use.
   MIT License — Copyright (c) 2026 Fábio José dos Santos */
const ID_RE = /^[A-Z2-7]{16}$/;
const TOK_RE = /^[A-Za-z0-9_-]{43}$/;
const B64_RE = /^[A-Za-z0-9_-]+$/;
const MAX_CT = 12000;        /* bytes of ciphertext (base64url) per card */
const WRITES_PER_MIN = 30;   /* per network address */

const json = (code, obj) => new Response(JSON.stringify(obj), { status: code, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha = async (s) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s))));
/* constant-time comparison of two hex strings */
const sameHash = (a, b) => { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; };

/* soft write limit per address, kept only in this instance's memory, as a hash, for one minute */
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
      const rec = await db.prepare('SELECT ct, iv, u FROM q WHERE id = ?').bind(id).first();
      if (!rec) return json(404, { error: 'not found' });
      if (!rec.ct) return json(410, { error: 'turned off' });
      return json(200, { ct: rec.ct, iv: rec.iv, u: rec.u });
    }
    if (request.method === 'PUT' || request.method === 'DELETE') {
      const raw = await request.text();
      if (raw.length > 40000) return json(413, { error: 'too big' });
      let b = null; try { b = JSON.parse(raw); } catch (_) { b = null; }
      if (!b || !ID_RE.test(b.id || '') || !TOK_RE.test(b.tok || '')) return json(400, { error: 'bad request' });
      if (await tooMany(request.headers.get('CF-Connecting-IP') || '')) return json(429, { error: 'slow down' });
      const h = await sha(b.tok), old = await db.prepare('SELECT h FROM q WHERE id = ?').bind(b.id).first();
      if (old && !sameHash(old.h, h)) return json(403, { error: 'not the owner' });
      const u = new Date().toISOString();
      /* delete: the encrypted bytes are erased; the id and the owner's hash stay, so the QR can say it was turned off */
      if (request.method === 'DELETE') { await db.prepare("INSERT INTO q (id, ct, iv, u, h) VALUES (?1, '', '', ?2, ?3) ON CONFLICT(id) DO UPDATE SET ct = '', iv = '', u = ?2 WHERE h = ?3").bind(b.id, u, h).run(); return json(200, { ok: true }); }
      if (typeof b.ct !== 'string' || typeof b.iv !== 'string' || !B64_RE.test(b.ct) || !/^[A-Za-z0-9_-]{16}$/.test(b.iv)) return json(400, { error: 'bad data' });
      if (b.ct.length > MAX_CT) return json(413, { error: 'too big' });
      await db.prepare('INSERT INTO q (id, ct, iv, u, h) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO UPDATE SET ct = ?2, iv = ?3, u = ?4 WHERE h = ?5').bind(b.id, b.ct, b.iv, u, h).run();
      return json(200, { ok: true, u });
    }
    return new Response(JSON.stringify({ error: 'method' }), { status: 405, headers: { Allow: 'GET, PUT, DELETE', 'Content-Type': 'application/json' } });
  } catch (_) {
    return json(500, { error: 'server' });
  }
}
