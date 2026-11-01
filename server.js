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

// Roblox sign-in (OAuth 2.0). Set these in Railway → Variables.
const ROBLOX_CLIENT_ID = process.env.ROBLOX_CLIENT_ID || '';
const ROBLOX_CLIENT_SECRET = process.env.ROBLOX_CLIENT_SECRET || '';
// Where this server lives publicly (Railway sets RAILWAY_PUBLIC_DOMAIN automatically).
const PUBLIC_URL = (process.env.PUBLIC_URL ||
  (process.env.RAILWAY_PUBLIC_DOMAIN ? 'https://' + process.env.RAILWAY_PUBLIC_DOMAIN : '')).replace(/\/+$/, '');
// Websites allowed to receive a login (comma-separated). Logins are only ever sent back to these.
const SITE_ORIGINS = (process.env.SITE_ORIGINS || 'https://pbarblx.org,https://www.pbarblx.org')
  .split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 30);

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
// ─────────── Admin permissions (LAU-style: per-section grants) ───────────
// data/adminAccess/<discordId> = { name, sections: ['teams','stats',...] }
// Super admins (SUPER_ADMIN_DISCORD_IDS, or a legacy role:'super') can do everything,
// including managing access. Older role:'regular' records keep what they had before.
const ALL_SECTIONS = ['teams', 'stats', 'schedule', 'seasons', 'bracket', 'accolades'];
function permsOf(discordId) {
  if (!discordId) return null;
  if (SUPER_ADMIN_IDS.includes(discordId)) return { super: true, sections: ALL_SECTIONS };
  const rec = getAt(root, ['data', 'adminAccess', discordId]);
  if (!rec) return null;
  if (rec.role === 'super') return { super: true, sections: ALL_SECTIONS };
  let sections = rec.sections;
  if (sections && !Array.isArray(sections)) sections = Object.values(sections);
  if (!sections && rec.role === 'regular') sections = ['stats', 'seasons'];
  sections = (sections || []).filter(x => ALL_SECTIONS.includes(x));
  return sections.length ? { super: false, sections } : null;
}
// Which section(s) allow writing to a path. null = super admin only.
function sectionsForPath(segs) {
  const [a, b] = segs;
  if (a === 'data' && (b === 'teams' || b === 'structure')) return ['teams'];   // teams + conferences/divisions
  if (a === 'schedule') return ['schedule', 'stats'];   // matchups (Schedule) and scores (Stats & Score)
  // A season's week count and series layout can be edited from Schedule / Series too.
  if (a === 'seasons' && segs.length >= 3 && ['regWeeks', 'seriesConfig'].includes(segs[2])) return ['seasons', 'schedule'];
  if (a === 'seasons') return ['seasons'];
  if (a === 'bracket') return ['bracket'];
  if (a === 'accolades' || a === 'awards') return ['accolades'];   // Awards + Player of the Series
  if (a === 'boxscores') return ['stats'];                           // player box scores (Stats & Score)
  return null; // data/adminAccess, data/playerdb, accounts, the root, anything else
}
function allowed(perms, segs) {
  if (perms.super) return true;
  if (!segs.length) return false;
  const need = sectionsForPath(segs);
  return !!need && need.some(x => perms.sections.includes(x));
}
async function authorizeWrite(req, url, affectedPaths) {
  const keyGiven = req.headers['x-admin-key'] || url.searchParams.get('auth');
  if (ADMIN_KEY && keyGiven === ADMIN_KEY) return null; // full access
  if (!REQUIRE_AUTH) return null;
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  if (!m) return [401, 'Sign in required'];
  let id;
  try { id = await discordIdFromToken(m[1]); } catch { return [503, 'Could not reach Discord to verify login']; }
  const perms = permsOf(id);
  if (!perms) return [id ? 403 : 401, id ? 'Not an admin' : 'Login expired'];
  const blocked = affectedPaths.find(segs => !allowed(perms, segs));
  if (blocked) return [403, "You don't have permission to change that"];
  return null;
}

// ─────────────────────── Roblox sign-in ───────────────────────
// Sessions are kept in their own file (NOT in db.json, which anyone can read).
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
let sessions = {};
try { if (fs.existsSync(SESSIONS_FILE)) sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8')) || {}; } catch { sessions = {}; }
let sessTimer = null;
function saveSessions() {
  clearTimeout(sessTimer);
  sessTimer = setTimeout(() => {
    const now = Date.now();
    for (const [k, v] of Object.entries(sessions)) if (!v || v.exp < now) delete sessions[k];
    const tmp = SESSIONS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(sessions));
    fs.renameSync(tmp, SESSIONS_FILE);
  }, 200);
}
const pendingLogins = new Map(); // state -> { verifier, returnTo, exp }
function b64url(buf) { return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function safeReturn(raw) {
  try {
    const u = new URL(raw);
    const origin = u.origin;
    const local = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
    if (SITE_ORIGINS.includes(origin) || local) { u.hash = ''; return u.toString(); }
  } catch {}
  return SITE_ORIGINS[0] ? SITE_ORIGINS[0] + '/' : null;
}
function redirect(res, to) { res.writeHead(302, { Location: to, 'Cache-Control': 'no-store' }); res.end(); }
function callbackUrl(req) {
  return (PUBLIC_URL || ('https://' + req.headers.host)) + '/auth/roblox/callback';
}
function publicUser(rec) {
  return { robloxId: rec.robloxId, username: rec.username, displayName: rec.displayName, avatar: rec.avatar || '', createdAt: rec.createdAt || null };
}

async function handleAuth(req, res, url) {
  // 1) Send the player to Roblox's login / authorize page.
  if (url.pathname === '/auth/roblox/start' && req.method === 'GET') {
    const returnTo = safeReturn(url.searchParams.get('return') || '');
    if (!ROBLOX_CLIENT_ID || !ROBLOX_CLIENT_SECRET) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      return res.end('Roblox sign-in is not configured yet (missing ROBLOX_CLIENT_ID / ROBLOX_CLIENT_SECRET).');
    }
    if (!returnTo) { res.writeHead(400, { 'Content-Type': 'text/plain' }); return res.end('Unknown website. Add it to SITE_ORIGINS.'); }
    // The player must have accepted the Terms of Use and Privacy Policy on the site first.
    const agreed = (url.searchParams.get('agree') || '').split(',');
    const legalVersion = (url.searchParams.get('v') || '').slice(0, 20);
    if (!agreed.includes('terms') || !agreed.includes('privacy') || !legalVersion) {
      return redirect(res, returnTo + '#pba_auth_error=' + encodeURIComponent('Please accept the Terms of Use and Privacy Policy first'));
    }
    const state = b64url(crypto.randomBytes(24));
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
    pendingLogins.set(state, { verifier, returnTo, legalVersion, exp: Date.now() + 10 * 60 * 1000 });
    for (const [k, v] of pendingLogins) if (v.exp < Date.now()) pendingLogins.delete(k);
    const q = new URLSearchParams({
      client_id: ROBLOX_CLIENT_ID,
      redirect_uri: callbackUrl(req),
      scope: 'openid profile',
      response_type: 'code',
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    return redirect(res, 'https://apis.roblox.com/oauth/v1/authorize?' + q.toString());
  }

  // 2) Roblox sends the player back here with a one-time code.
  if (url.pathname === '/auth/roblox/callback' && req.method === 'GET') {
    const state = url.searchParams.get('state') || '';
    const pending = pendingLogins.get(state);
    pendingLogins.delete(state);
    if (!pending || pending.exp < Date.now()) {
      const back = SITE_ORIGINS[0] ? SITE_ORIGINS[0] + '/' : null;
      if (back) return redirect(res, back + '#pba_auth_error=' + encodeURIComponent('Login expired, please try again'));
      res.writeHead(400, { 'Content-Type': 'text/plain' }); return res.end('Login expired, please try again.');
    }
    const fail = msg => redirect(res, pending.returnTo + '#pba_auth_error=' + encodeURIComponent(msg));
    if (url.searchParams.get('error')) return fail('Roblox sign-in was cancelled');
    const code = url.searchParams.get('code');
    if (!code) return fail('Roblox did not return a login code');
    try {
      const tokRes = await fetch('https://apis.roblox.com/oauth/v1/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: ROBLOX_CLIENT_ID,
          client_secret: ROBLOX_CLIENT_SECRET,
          grant_type: 'authorization_code',
          code,
          redirect_uri: callbackUrl(req),
          code_verifier: pending.verifier,
        }).toString(),
        signal: AbortSignal.timeout(10000),
      });
      if (!tokRes.ok) { console.error('Roblox token error', tokRes.status, await tokRes.text()); return fail('Roblox sign-in failed'); }
      const tok = await tokRes.json();
      const infoRes = await fetch('https://apis.roblox.com/oauth/v1/userinfo', {
        headers: { Authorization: 'Bearer ' + tok.access_token },
        signal: AbortSignal.timeout(10000),
      });
      if (!infoRes.ok) { console.error('Roblox userinfo error', infoRes.status); return fail('Could not read your Roblox profile'); }
      const info = await infoRes.json();
      const robloxId = String(info.sub || '');
      if (!/^\d+$/.test(robloxId)) return fail('Roblox returned an invalid account');

      // Save / update the player's public account record.
      const prev = getAt(root, ['accounts', robloxId]) || {};
      const rec = {
        robloxId,
        username: info.preferred_username || info.nickname || prev.username || '',
        displayName: info.name || info.nickname || prev.displayName || '',
        avatar: info.picture || prev.avatar || '',
        createdAt: prev.createdAt || Date.now(),
        lastLogin: Date.now(),
        acceptedTermsVersion: pending.legalVersion,
        acceptedTermsAt: Date.now(),
      };
      root = setAt(root, ['accounts', robloxId], rec);
      ensurePlayerRecord(rec);
      scheduleSave();

      const token = b64url(crypto.randomBytes(32));
      sessions[crypto.createHash('sha256').update(token).digest('hex')] = { robloxId, exp: Date.now() + SESSION_DAYS * 86400000 };
      saveSessions();
      return redirect(res, pending.returnTo + '#pba_session=' + token);
    } catch (e) {
      console.error('Roblox sign-in error:', e.message);
      return fail('Could not reach Roblox, please try again');
    }
  }

  // 3) Who is signed in?   4) Sign out.
  if ((url.pathname === '/auth/me' && req.method === 'GET') || (url.pathname === '/auth/logout' && req.method === 'POST')) {
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
    const key = m ? crypto.createHash('sha256').update(m[1]).digest('hex') : '';
    const sess = key && sessions[key];
    if (url.pathname === '/auth/logout') {
      if (sess) { delete sessions[key]; saveSessions(); }
      return send(res, 200, { ok: true });
    }
    if (!sess || sess.exp < Date.now()) return send(res, 401, { error: 'Not signed in' });
    const rec = getAt(root, ['accounts', sess.robloxId]);
    if (!rec) return send(res, 401, { error: 'Account not found' });
    return send(res, 200, publicUser(rec));
  }

  return send(res, 404, { error: 'Not found' });
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
  if (url.pathname.startsWith('/auth/')) {
    try { return await handleAuth(req, res, url); }
    catch (e) { console.error(e); return send(res, 500, { error: 'Server error' }); }
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
// Every account gets a player record (so they appear on the Players page and admins can
// put them on a team). Linked by Roblox ID; starts as a Free Agent with no stats.
function ensurePlayerRecord(rec) {
  const db = getAt(root, ['data', 'playerdb']) || {};
  const key = Object.keys(db).find(k => String((db[k] || {}).robloxId || '') === String(rec.robloxId));
  const name = rec.displayName || rec.username;
  if (!key) {
    root = setAt(root, ['data', 'playerdb', 'rbx_' + rec.robloxId], {
      name, robloxId: rec.robloxId, username: rec.username, code: '', pos: '', num: '',
      fromAccount: true, createdAt: Date.now(),
    });
  } else if (db[key].fromAccount) {
    // Keep auto-created records in sync with the player's Roblox name.
    root = setAt(root, ['data', 'playerdb', key, 'name'], name);
    root = setAt(root, ['data', 'playerdb', key, 'username'], rec.username);
  }
  scheduleSave();
}

// One-time cleanup: remove the 36 sample players the admin panel used to seed.
const PLACEHOLDER_NAMES = new Set(["J. Marsh", "P. Ibrahim", "O. Castillo", "R. Calloway", "T. Okafor", "J. Farrow", "A. Whitlock", "D. Reyes", "K. Mbeki", "K. Voss", "E. Marchetti", "N. Halvorsen", "M. Solis", "R. Achterberg", "J. Delgado", "G. Prentiss", "C. Ferreira", "S. Renwick", "C. Danvers", "T. Osgood", "W. Kamau", "N. Osei", "H. Vaccaro", "A. Petrova", "L. Tran", "B. Adeyemi", "F. Nakamura", "S. Okonkwo", "D. Falkenrath", "Y. Marchetti", "V. Castellano", "R. Isherwood", "Q. Beaumont", "B. Larkspur", "E. Whitfield", "I. Solano"]);
function removePlaceholderPlayers() {
  if (getAt(root, ['meta', 'placeholdersRemoved'])) return;
  const db = getAt(root, ['data', 'playerdb']) || {};
  let removed = 0;
  for (const [k, p] of Object.entries(db)) {
    if (p && !p.robloxId && PLACEHOLDER_NAMES.has(p.name)) { root = setAt(root, ['data', 'playerdb', k], null); removed++; }
  }
  root = setAt(root, ['meta', 'placeholdersRemoved'], Date.now());
  // Make sure everyone who already signed in has a player record.
  Object.values(getAt(root, ['accounts']) || {}).forEach(a => { if (a && a.robloxId) ensurePlayerRecord(a); });
  saveNow();
  console.log('Removed ' + removed + ' placeholder players');
}

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
  try { removePlaceholderPlayers(); } catch (e) { console.error('Placeholder cleanup failed:', e.message); }
  server.listen(PORT, () => {
    console.log(`PBA data server on :${PORT}  data=${DB_FILE}  auth=${REQUIRE_AUTH ? 'discord' : 'OFF'}`);
    if (!process.env.DATA_DIR && !process.env.RAILWAY_VOLUME_MOUNT_PATH && process.env.RAILWAY_ENVIRONMENT) {
      console.warn('WARNING: no Railway Volume attached — data will be lost on every redeploy!');
    }
  });
});
