// PBA data server — a drop-in replacement for the Firebase Realtime Database REST API,
// built to run on Railway (same approach as laurb5data-production.up.railway.app).
//
// Supports:  GET / PUT / PATCH / POST / DELETE on  /<any/path>.json
//            ?shallow=true, ?print=silent, X-Firebase-ETag + if-match conditional writes
// Storage:   one JSON file on a Railway Volume, written atomically, with a .bak copy.
// Security:  reads are public (like the old Firebase DB). Writes require a Discord token
//            belonging to an admin listed in data/adminAccess (or a SUPER_ADMIN id).
//            Only super admins may change data/adminAccess.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─────────────────────────── config ───────────────────────────
const PORT = process.env.PORT || 8080;
const DATA_DIR = process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const REQUIRE_AUTH = (process.env.REQUIRE_AUTH || 'true').toLowerCase() !== 'false';
const SUPER_ADMIN_IDS = (process.env.SUPER_ADMIN_DISCORD_IDS || '613513131741937684')
  .split(',').map(s => s.trim()).filter(Boolean);
const ADMIN_KEY = process.env.ADMIN_KEY || '';               // for curl backups/restores
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
const IMPORT_URL = process.env.FIREBASE_IMPORT_URL || '';    // one-time import when DB is empty
const MAX_BODY = 25 * 1024 * 1024;

// ─────────────────────────── storage ───────────────────────────
fs.mkdirSync(DATA_DIR, { recursive: true });
let root = null;
try {
  if (fs.existsSync(DB_FILE)) root = clean(JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
} catch (e) {
  console.error('db.json unreadable, trying backup:', e.message);
  try { root = clean(JSON.parse(fs.readFileSync(DB_FILE + '.bak', 'utf8'))); } catch { root = null; }
}

let saveTimer = null;
function scheduleSave() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveNow, 200);
}
function saveNow() {
  clearTimeout(saveTimer); saveTimer = null;
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(root ?? null));
  if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, DB_FILE + '.bak');
  fs.renameSync(tmp, DB_FILE);
}
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => { try { if (saveTimer) saveNow(); } finally { process.exit(0); } });
}

// ─────────────────────── Firebase-style tree ops ───────────────────────
// Internally everything is stored as plain objects (arrays become {"0":..,"1":..}),
// nulls and empty objects are pruned — exactly like Firebase.
function clean(v) {
  if (v === null || v === undefined) return null;
  if (Array.isArray(v)) v = Object.fromEntries(v.map((x, i) => [String(i), x]));
  if (typeof v !== 'object') return v;
  const out = {};
  for (const [k, x] of Object.entries(v)) {
    const c = clean(x);
    if (c !== null) out[k] = c;
  }
  return Object.keys(out).length ? out : null;
}
function getAt(node, segs) {
  for (const s of segs) {
    if (node === null || typeof node !== 'object' || !(s in node)) return null;
    node = node[s];
  }
  return node;
}
function setAt(node, segs, value) {
  if (!segs.length) return clean(value);
  const [k, ...rest] = segs;
  const obj = node && typeof node === 'object' ? { ...node } : {};
  const child = setAt(obj[k], rest, value);
  if (child === null) delete obj[k]; else obj[k] = child;
  return Object.keys(obj).length ? obj : null;
}
// On the way out, convert integer-keyed objects back to arrays the way Firebase does.
function shape(v) {
  if (v === null || typeof v !== 'object') return v;
  const keys = Object.keys(v);
  const out = {};
  for (const k of keys) out[k] = shape(v[k]);
  if (keys.length && keys.every(k => /^(0|[1-9]\d{0,8})$/.test(k))) {
    const max = Math.max(...keys.map(Number));
    if (max < keys.length * 2) {
      const arr = new Array(max + 1).fill(null);
      for (const k of keys) arr[Number(k)] = out[k];
      return arr;
    }
  }
  return out;
}
function etagOf(v) {
  if (v === null) return 'null_etag';
  return crypto.createHash('sha1').update(JSON.stringify(v)).digest('base64');
}
// Firebase-style push id (chronologically sortable)
const PUSH_CHARS = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz';
let lastPush = 0, lastRand = [];
function pushId() {
  let now = Date.now();
  const dup = now === lastPush; lastPush = now;
  let ts = '';
  for (let i = 0; i < 8; i++) { ts = PUSH_CHARS[now % 64] + ts; now = Math.floor(now / 64); }
  if (!dup) lastRand = Array.from({ length: 12 }, () => Math.floor(Math.random() * 64));
  else { let i = 11; while (i >= 0 && lastRand[i] === 63) lastRand[i--] = 0; if (i >= 0) lastRand[i]++; }
  return ts + lastRand.map(n => PUSH_CHARS[n]).join('');
}

// ─────────────────────────── auth ───────────────────────────
const tokenCache = new Map(); // sha(token) -> { id, exp }
async function discordIdFromToken(token) {
  const key = crypto.createHash('sha256').update(token).digest('hex');
  const hit = tokenCache.get(key);
  if (hit && hit.exp > Date.now()) return hit.id;
  const r = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + token }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) { tokenCache.delete(key); return null; }
  const u = await r.json();
  tokenCache.set(key, { id: u.id, exp: Date.now() + 10 * 60 * 1000 });
  if (tokenCache.size > 500) tokenCache.delete(tokenCache.keys().next().value);
  return u.id || null;
}
function roleOf(discordId) {
  if (!discordId) return null;
  if (SUPER_ADMIN_IDS.includes(discordId)) return 'super';
  const rec = getAt(root, ['data', 'adminAccess', discordId]);
  return rec && (rec.role === 'super' || rec.role === 'regular') ? rec.role : null;
}
// Does a write to `segs` touch data/adminAccess (itself, a parent, or a child)?
function touchesAdminAccess(segs) {
  const target = ['data', 'adminAccess'];
  const n = Math.min(segs.length, target.length);
  for (let i = 0; i < n; i++) if (segs[i] !== target[i]) return false;
  return true;
}
async function authorizeWrite(req, url, affectedPaths) {
  const keyGiven = req.headers['x-admin-key'] || url.searchParams.get('auth');
  if (ADMIN_KEY && keyGiven === ADMIN_KEY) return null; // full access
  if (!REQUIRE_AUTH) return null;
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  if (!m) return [401, 'Sign in required'];
  let id;
  try { id = await discordIdFromToken(m[1]); } catch { return [503, 'Could not reach Discord to verify login']; }
  const role = roleOf(id);
  if (!role) return [id ? 403 : 401, id ? 'Not an admin' : 'Login expired'];
  if (role !== 'super' && affectedPaths.some(touchesAdminAccess)) return [403, 'Super admin only'];
  return null;
}

// ─────────────────────────── http ───────────────────────────
function cors(req, res) {
  const origin = req.headers.origin;
  const allow = ALLOWED_ORIGINS.includes('*') ? '*' : (ALLOWED_ORIGINS.includes(origin) ? origin : '');
  if (allow) res.setHeader('Access-Control-Allow-Origin', allow);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,PUT,PATCH,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Firebase-ETag,If-Match,X-Admin-Key');
  res.setHeader('Access-Control-Expose-Headers', 'ETag');
  res.setHeader('Access-Control-Max-Age', '86400');
}
function send(res, status, body, extra = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra });
  res.end(body === undefined ? '' : JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(new Error('too_large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      const txt = Buffer.concat(chunks).toString('utf8');
      if (!txt.trim()) return resolve(null);
      try { resolve(JSON.parse(txt)); } catch { reject(new Error('bad_json')); }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  cors(req, res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/' || url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('PBA data server OK');
  }
  if (!url.pathname.endsWith('.json')) return send(res, 404, { error: 'Paths must end in .json' });

  let segs;
  try {
    segs = url.pathname.slice(0, -5).split('/').filter(Boolean).map(decodeURIComponent);
  } catch { return send(res, 400, { error: 'Bad path' }); }

  const silent = url.searchParams.get('print') === 'silent';
  const wantEtag = String(req.headers['x-firebase-etag'] || '').toLowerCase() === 'true';

  try {
    if (req.method === 'GET') {
      const current = shape(getAt(root, segs));
      let v = current;
      if (url.searchParams.get('shallow') === 'true' && v && typeof v === 'object') {
        v = Object.fromEntries(Object.keys(v).map(k => [k, true]));
      }
      return send(res, 200, v, wantEtag ? { ETag: etagOf(current) } : {});
    }

    if (!['PUT', 'PATCH', 'POST', 'DELETE'].includes(req.method)) return send(res, 405, { error: 'Method not allowed' });

    const body = req.method === 'DELETE' ? null : await readBody(req);
    let affected = [segs];
    let newKey = null;
    if (req.method === 'PATCH') {
      if (!body || typeof body !== 'object' || Array.isArray(body)) return send(res, 400, { error: 'PATCH body must be an object' });
      affected = Object.keys(body).map(k => segs.concat(k.split('/').filter(Boolean)));
    } else if (req.method === 'POST') {
      newKey = pushId();
      affected = [segs.concat(newKey)];
    }

    const denied = await authorizeWrite(req, url, affected);
    if (denied) return send(res, denied[0], { error: denied[1] });

    // conditional write (used for atomic "claim" operations)
    const ifMatch = req.headers['if-match'];
    if (ifMatch !== undefined && (req.method === 'PUT' || req.method === 'DELETE')) {
      const current = shape(getAt(root, segs));
      const tag = etagOf(current);
      if (ifMatch !== tag) return send(res, 412, current, { ETag: tag });
    }

    if (req.method === 'PUT') root = setAt(root, segs, body);
    else if (req.method === 'DELETE') root = setAt(root, segs, null);
    else if (req.method === 'POST') root = setAt(root, segs.concat(newKey), body);
    else for (const [k, v] of Object.entries(body)) root = setAt(root, segs.concat(k.split('/').filter(Boolean)), v);
    scheduleSave();

    if (silent) { res.writeHead(204); return res.end(); }
    if (req.method === 'POST') return send(res, 200, { name: newKey });
    if (req.method === 'DELETE') return send(res, 200, null);
    const extra = wantEtag || ifMatch !== undefined ? { ETag: etagOf(shape(getAt(root, segs))) } : {};
    return send(res, 200, req.method === 'PATCH' ? body : shape(getAt(root, segs)), extra);
  } catch (e) {
    if (e.message === 'too_large') return send(res, 413, { error: 'Body too large' });
    if (e.message === 'bad_json') return send(res, 400, { error: 'Invalid JSON' });
    console.error(e);
    return send(res, 500, { error: 'Server error' });
  }
});

// ─────────────────────── one-time import from Firebase ───────────────────────
async function maybeImport() {
  if (root !== null || !IMPORT_URL) return;
  const base = IMPORT_URL.replace(/\/+$/, '');
  const src = base.endsWith('.json') ? base : base + '/.json';
  console.log('DB is empty — importing from', src);
  try {
    const r = await fetch(src, { signal: AbortSignal.timeout(60000) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    root = clean(await r.json());
    saveNow();
    console.log('Import complete:', root ? Object.keys(root).join(', ') : '(source was empty)');
  } catch (e) { console.error('Import failed:', e.message); }
}

maybeImport().finally(() => {
  server.listen(PORT, () => {
    console.log(`PBA data server on :${PORT}  data=${DB_FILE}  auth=${REQUIRE_AUTH ? 'discord' : 'OFF'}`);
    if (!process.env.DATA_DIR && !process.env.RAILWAY_VOLUME_MOUNT_PATH && process.env.RAILWAY_ENVIRONMENT) {
      console.warn('WARNING: no Railway Volume attached — data will be lost on every redeploy!');
    }
  });
});
