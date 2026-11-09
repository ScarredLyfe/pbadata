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
// Alt detection (alts.js): hashed networks/devices, VPN check and staff alerts, kept in alts.json.
const alts = require('./alts')(DATA_DIR);
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
const ALL_SECTIONS = ['teams', 'stats', 'schedule', 'seasons', 'bracket', 'accolades', 'applications'];
// Two leagues share this server. PBA lives at the top of the database (as before); PBCA lives under
// leagues/pbca/ with the same layout (data/teams, seasons, schedule, boxscores, …, its own admin list).
// Roblox/Discord accounts are shared; each league has its own player profiles (team, stats).
const LEAGUE_BASES = [[], ['leagues', 'pbca']];
const LEAGUE_IDS = ['pbca'];
function splitLeague(segs) {
  if (segs[0] === 'leagues' && LEAGUE_IDS.includes(segs[1])) return { base: segs.slice(0, 2), rest: segs.slice(2) };
  return { base: [], rest: segs };
}
function permsOf(discordId, base = []) {
  if (!discordId) return null;
  if (SUPER_ADMIN_IDS.includes(discordId)) return { super: true, sections: ALL_SECTIONS };
  const rec = getAt(root, [...base, 'data', 'adminAccess', discordId]);
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
  if (a === 'teams') return ['teams'];                   // each season's own team list: teams/<seasonId>/<code>
  if (a === 'schedule') return ['schedule', 'stats'];   // matchups (Schedule) and scores (Stats & Score)
  // Which season is active (the one the Discord bots update) is the super admin's call only.
  if (a === 'seasons' && segs.length >= 3 && segs[2] === 'active') return null;
  if (a === 'seasons' && segs.length >= 3 && segs[2] === 'playoffs') return ['seasons', 'schedule', 'stats', 'bracket'];
  // A season's week count and series layout can be edited from Schedule / Series too.
  if (a === 'seasons' && segs.length >= 3 && ['regWeeks', 'seriesConfig'].includes(segs[2])) return ['seasons', 'schedule'];
  if (a === 'seasons') return ['seasons'];
  if (a === 'bracket') return ['bracket'];
  if (a === 'accolades' || a === 'awards') return ['accolades'];   // Awards + Player of the Series
  if (a === 'boxscores') return ['stats'];                           // player box scores (Stats & Score)
  if (a === 'applications') return ['applications'];                // staff application forms (the Discord bot's panel)
  return null; // data/adminAccess, data/playerdb, accounts, the root, anything else
}
function allowed(perms, segs) {
  if (perms.super) return true;
  if (!segs.length) return false;
  const need = sectionsForPath(segs);
  return !!need && need.some(x => perms.sections.includes(x));
}
// ─────────── Active seasons ───────────
// seasons/<id>/active marks the season the Discord bots update (one per league). Seasons that
// aren't active are locked: only the super admin can change them or anything that belongs to
// them (scores, stats, bracket, awards, teams, rosters). Checked by comparing the data before
// and after a write, so it covers every way of writing (PUT, PATCH, whole-collection saves…).
const SEASON_OWNED = ['schedule', 'boxscores', 'bracket', 'awards', 'accolades', 'teams', 'rosters'];
const sameJSON = (a, b) => JSON.stringify(a == null ? null : a) === JSON.stringify(b == null ? null : b);
function seasonLockError(before, after, base) {
  const oS = getAt(before, [...base, 'seasons']) || {}, nS = getAt(after, [...base, 'seasons']) || {};
  for (const sid of new Set([...Object.keys(oS), ...Object.keys(nS)])) {
    const o = oS[sid], n = nS[sid];
    if (!!(o && o.active) !== !!(n && n.active)) return 'Only the super admin can change which season is active';
    if (o && !o.active) {
      const label = o.label || o.name || sid;
      if (!sameJSON(o, n)) return `${label} isn't the active season, so it's locked`;
      for (const c of SEASON_OWNED) {
        if (!sameJSON(getAt(before, [...base, c, sid]), getAt(after, [...base, c, sid]))) return `${label} isn't the active season, so it's locked`;
      }
    }
  }
  return null;
}

// Only the owner can make someone a super admin, change a super admin, or remove one.
// (Other super admins can still add, change and remove regular admins.)
const OWNER_ID = (process.env.OWNER_DISCORD_ID || '613513131741937684').trim();
function superAdminError(before, after, base, writerId) {
  if (writerId === OWNER_ID) return null;
  const o = getAt(before, [...base, 'data', 'adminAccess']) || {}, n = getAt(after, [...base, 'data', 'adminAccess']) || {};
  for (const id of new Set([...Object.keys(o), ...Object.keys(n)])) {
    const wasSuper = o[id] && o[id].role === 'super', isSuper = n[id] && n[id].role === 'super';
    if ((wasSuper || isSuper) && !sameJSON(o[id], n[id])) return 'Only the owner can add, change or remove a super admin';
  }
  return null;
}

// Locked games (schedule/<season>/<week>/<game>.locked, set by the super admin) can't be changed
// by anyone else: not the score, the stats, or the lock itself.
function gameLockError(before, after, base) {
  const oS = getAt(before, [...base, 'schedule']) || {}, nS = getAt(after, [...base, 'schedule']) || {};
  const keys = (a, b) => [...new Set([...Object.keys(a || {}), ...Object.keys(b || {})])];
  for (const sid of keys(oS, nS)) for (const wk of keys(oS[sid], nS[sid])) {
    const ow = (oS[sid] || {})[wk] || {}, nw = (nS[sid] || {})[wk] || {};
    for (const gid of keys(ow, nw)) {
      const o = ow[gid], n = nw[gid];
      if (!(o && o.locked) && !(n && n.locked)) continue;
      const box = r => getAt(r, [...base, 'boxscores', sid, wk, gid]);
      if (!sameJSON(o, n) || !sameJSON(box(before), box(after))) return 'That game is locked. Only the super admin can change it.';
    }
  }
  return null;
}

async function authorizeWrite(req, url, affectedPaths) {
  const keyGiven = req.headers['x-admin-key'] || url.searchParams.get('auth');
  if (ADMIN_KEY && keyGiven === ADMIN_KEY) return null; // full access
  if (!REQUIRE_AUTH) return null;
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  if (!m) return [401, 'Sign in required'];
  let id;
  if (m[1].startsWith('pba:')) {
    // Signed in on the website (Roblox) with a linked Discord: use that Discord ID, no second login.
    const sess = sessions[crypto.createHash('sha256').update(m[1].slice(4)).digest('hex')];
    const acct = sess && !sess.relink && sess.exp >= Date.now() && getAt(root, ['accounts', String(sess.robloxId)]);
    id = acct && acct.discordId ? String(acct.discordId) : null;
  } else {
    try { id = await discordIdFromToken(m[1]); } catch { return [503, 'Could not reach Discord to verify login']; }
  }
  if (!id) return [401, 'Login expired'];
  // Each league has its own admins: check the path against that league's admin list.
  req.writer = { id, limitedBases: [] };   // leagues where this person is NOT a super admin
  for (const segs of affectedPaths) {
    const { base, rest } = splitLeague(segs);
    const perms = permsOf(id, base);
    if (!perms) return [403, 'Not an admin' + (base.length ? ' for ' + base[1].toUpperCase() : '')];
    if (!allowed(perms, rest)) return [403, "You don't have permission to change that"];
    if (!perms.super && !req.writer.limitedBases.some(b => b.join('/') === base.join('/'))) req.writer.limitedBases.push(base);
  }
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
  return { robloxId: rec.robloxId, username: rec.username, displayName: rec.displayName, avatar: rec.avatar || '', createdAt: rec.createdAt || null,
    lastSyncAt: rec.lastSyncAt || null, nextSyncAt: rec.lastSyncAt ? rec.lastSyncAt + SYNC_COOLDOWN_MS : null,
    discordId: rec.discordId || null, discordUsername: rec.discordUsername || '', discordGlobalName: rec.discordGlobalName || '', discordAvatar: rec.discordAvatar || '' };
}
// The signed-in player's session from "Authorization: Bearer <session token>".
function fmtWait(ms) {
  const mins = Math.max(1, Math.ceil(ms / 60000)), h = Math.floor(mins / 60), m = mins % 60;
  return h ? h + 'h' + (m ? ' ' + m + 'm' : '') : m + 'm';
}
function sessionOf(req) {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  const key = m ? crypto.createHash('sha256').update(m[1]).digest('hex') : '';
  const sess = key && sessions[key];
  return sess && !sess.relink && sess.exp >= Date.now() ? sess : null;
}
// Roblox profile sync (username / display name / avatar): once per 24 hours per account.
// The cooldown is stored on the account on the server, so another browser or tab can't skip it.
const SYNC_COOLDOWN_MS = 24 * 60 * 60 * 1000;
async function fetchRobloxProfile(robloxId) {
  const id = encodeURIComponent(robloxId);
  const u = await fetch('https://users.roblox.com/v1/users/' + id, { signal: AbortSignal.timeout(8000) });
  if (!u.ok) throw new Error('Roblox user lookup failed (' + u.status + ')');
  const info = await u.json();
  let avatar = '';
  try {
    const t = await fetch('https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=' + id + '&size=150x150&format=Png&isCircular=false', { signal: AbortSignal.timeout(8000) });
    const tj = t.ok ? await t.json() : null;
    const d = tj && tj.data && tj.data[0];
    if (d && d.state === 'Completed' && d.imageUrl) avatar = d.imageUrl;
  } catch {}
  return { username: info.name || '', displayName: info.displayName || info.name || '', avatar };
}
// Apply a fresh Roblox username / display name / avatar to the account and its player profile.
function applyRobloxProfile(rid, prof) {
  const acct = getAt(root, ['accounts', rid]) || {};
  const next = Object.assign({}, acct, { lastSyncAt: Date.now() });
  if (prof.username) next.username = prof.username;
  if (prof.displayName) next.displayName = prof.displayName;
  if (prof.avatar) next.avatar = prof.avatar;
  root = setAt(root, ['accounts', rid], next);
  ensurePlayerRecord(next);   // keeps the profile's name and @username in step
  scheduleSave();
  return next;
}
const DISCORD_FIELDS = ['discordId', 'discordUsername', 'discordGlobalName', 'discordAvatar', 'discordLinkedAt'];
// Copy (or clear, with null) a player's Discord link onto their account and player profile.
function setDiscord(robloxId, d) {
  const rid = String(robloxId);
  DISCORD_FIELDS.forEach(f => { root = setAt(root, ['accounts', rid, f], d ? (d[f] ?? null) : null); });
  for (const B of LEAGUE_BASES) {
    const db = getAt(root, [...B, 'data', 'playerdb']) || {};
    const pkey = Object.keys(db).find(k => String((db[k] || {}).robloxId || '') === rid);
    if (pkey) ['discordId', 'discordUsername'].forEach(f => { root = setAt(root, [...B, 'data', 'playerdb', pkey, f], d ? (d[f] ?? null) : null); });
  }
  scheduleSave();
}

// Finish a Roblox sign-in / sign-up once we know the Roblox account (from Roblox's sign-in page,
// or from the backup "code in your About" check). info: { preferred_username, name, picture }.
// Returns { error } or { token, relinked, su }.
async function finishRobloxLogin(req, pending, robloxId, info, opts = {}) {
  const E = error => ({ error });
  // Save / update the player's public account record.
  const prev = getAt(root, ['accounts', robloxId]) || {};
  // Sign-up step 5 (Discord already linked in step 3, alt check passed in step 4).
  const su = pending.signup ? signupOf(pending.signup) : null;
  if (pending.signup && (!su || !su.checked)) return E('Your sign-up expired. Start again from Link Discord.');
  if (!su && !prev.robloxId) return E('New here? Start by linking your Discord account.');
  if (su && prev.discordId && String(prev.discordId) !== su.discord.discordId)
    return E('That Roblox account is already linked to a different Discord account. Sign in with that Discord instead.');
  if (su) {
    const accts = getAt(root, ['accounts']) || {};
    if (Object.keys(accts).some(k => k !== robloxId && String((accts[k] || {}).discordId || '') === su.discord.discordId))
      return E('That Discord account is already linked to another player.');
  }
  const ip = alts.clientIp(req);
  if (!prev.robloxId && (await alts.vpnCheck(ip)).vpn) return E(VPN_MSG);   // new accounts only
  // Signing in refreshes the Roblox name/avatar only for new accounts or when a sync is due,
  // so signing out and back in can't be used to skip the 24-hour sync cooldown.
  // (opts.fresh: the code-in-About check just read their profile from Roblox, so always use it.)
  const fresh = opts.fresh || !prev.robloxId || !prev.lastSyncAt || Date.now() - prev.lastSyncAt >= SYNC_COOLDOWN_MS;
  const rec = {
    robloxId,
    username: (fresh && (info.preferred_username || info.nickname)) || prev.username || '',
    displayName: (fresh && (info.name || info.nickname)) || prev.displayName || '',
    avatar: (fresh && info.picture) || prev.avatar || '',
    lastSyncAt: fresh ? Date.now() : prev.lastSyncAt,
    createdAt: prev.createdAt || Date.now(),
    lastLogin: Date.now(),
    acceptedTermsVersion: pending.legalVersion,
    acceptedTermsAt: Date.now(),
  };
  DISCORD_FIELDS.forEach(f => { if (prev[f] != null) rec[f] = prev[f]; });
  if (su && !prev.discordId) Object.assign(rec, su.discord);   // the Discord from step 3
  // Linking a new Roblox account after unlinking: move the existing player profile over
  // instead of creating a second one (avoids a stale duplicate under the old name).
  let relinked = false;
  if (pending.relink) {
    const r = relinkPlayer(pending.relink, rec);
    if (r.error) return E(r.error);
    relinked = r.ok;
  }
  root = setAt(root, ['accounts', robloxId], rec);
  ensurePlayerRecord(rec);
  if (su) {
    setDiscord(robloxId, su.discord);   // also puts it on the player profiles
    signups.delete(crypto.createHash('sha256').update(pending.signup).digest('hex'));
  }
  scheduleSave();
  alts.record(altKey(rec), ip, pending.device || (su && su.device), su && !prev.robloxId ? 'signup' : 'signin');

  const token = newSession(robloxId);
  return { token, relinked, su };
}

// ── Sign-up (Discord first) ──
// Step 3 links Discord (/auth/signup/discord), step 4 is the alt/VPN check (/auth/signup/check),
// step 5 links Roblox (/auth/roblox/start?signup=…). A Discord that already has an account signs
// straight in. Pending sign-ups live in memory for 30 minutes.
const signups = new Map();   // sha(token) -> { discord, checked, device, exp }
const codeLogins = new Map();   // sha(token) -> { robloxId, code, signup, relink, legalVersion, device, tries, exp } (backup Roblox link)
const altKey = acct => acct && acct.discordId ? 'd:' + acct.discordId : acct && acct.robloxId ? 'r:' + acct.robloxId : null;
function discordFields(d) {
  const avatar = d.avatar
    ? `https://cdn.discordapp.com/avatars/${d.id}/${d.avatar}.${String(d.avatar).startsWith('a_') ? 'gif' : 'png'}?size=256`
    : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(d.id) >> 22n) % 6}.png`;
  return { discordId: String(d.id), discordUsername: d.username || '', discordGlobalName: d.global_name || '', discordAvatar: avatar, discordLinkedAt: Date.now() };
}
async function discordUser(dtoken) {
  const r = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + dtoken }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) return null;
  const d = await r.json();
  return d && /^\d+$/.test(String(d.id || '')) ? d : null;
}
function newSession(robloxId) {
  const token = b64url(crypto.randomBytes(32));
  sessions[crypto.createHash('sha256').update(token).digest('hex')] = { robloxId, exp: Date.now() + SESSION_DAYS * 86400000 };
  saveSessions();
  return token;
}
const signupOf = t => { const s = t && signups.get(crypto.createHash('sha256').update(String(t)).digest('hex')); return s && s.exp >= Date.now() ? s : null; };
const VPN_MSG = 'It looks like you\'re using a VPN or proxy. Turn it off, then try again.';

async function handleAuth(req, res, url) {
  // Team card on the website: promote / demote (Owner), release (Owner or coach), lineup (Owner).
  // Saved for that league's Discord bot at <league>/bot/teamreq/<id>; the bot checks in Discord
  // that they really own the team, does it, and writes the result back on the request.
  if (url.pathname === '/auth/team/request' && req.method === 'POST') {
    const sess = sessionOf(req);
    if (!sess) return send(res, 401, { error: 'Sign in first.' });
    const acct = getAt(root, ['accounts', String(sess.robloxId)]);
    if (!acct || !acct.discordId) return send(res, 403, { error: 'Link your Discord account first.' });
    let body; try { body = (await readBody(req)) || {}; } catch { return send(res, 400, { error: 'Bad request' }); }
    const lg = body.league === 'pbca' ? 'pbca' : 'pba';
    const B = lg === 'pbca' ? ['leagues', 'pbca'] : [];
    const type = String(body.type || '');
    if (!['promote', 'demote', 'release', 'lineup'].includes(type)) return send(res, 400, { error: 'Unknown request' });
    const id_ = v => (typeof v === 'string' || typeof v === 'number') && /^[\w-]{1,64}$/.test(String(v)) ? String(v) : null;
    const reqRec = { status: 'pending', at: Date.now(), type, by: String(acct.discordId), byRoblox: String(sess.robloxId), teamCode: id_(body.teamCode) };
    if (type === 'promote' || type === 'demote' || type === 'release') {
      reqRec.target = id_(body.target);
      if (!reqRec.target) return send(res, 400, { error: 'Pick a player.' });
      if (type === 'promote') reqRec.position = ['coach_1', 'coach_2'].includes(body.position) ? body.position : 'coach_1';
    } else {
      const spots = ['PG', 'SG', 'SF', 'PF', 'C'];
      const part = o => { const out = {}; for (const k of spots) { const v = id_(o && o[k]); if (v) out[k] = v; } return out; };
      // Bench: a list of { player, pos } (as many spots as the roster has players beyond the 5 starters).
      const benchIn = Array.isArray(body.lineup && body.lineup.bench) ? body.lineup.bench.slice(0, 20) : [];
      const bench = benchIn.map(b => ({ player: id_(b && b.player), pos: spots.includes(b && b.pos) ? b.pos : null })).filter(b => b.player);
      reqRec.lineup = { starters: part(body.lineup && body.lineup.starters), bench };
    }
    // At most 5 waiting requests per person (stops spam).
    const waiting = Object.values(getAt(root, [...B, 'bot', 'teamreq']) || {}).filter(x => x && x.by === reqRec.by && x.status === 'pending').length;
    if (waiting >= 5) return send(res, 429, { error: 'Slow down: wait for your last changes to finish.' });
    const id = pushId();
    reqRec.id = id;
    root = setAt(root, [...B, 'bot', 'teamreq', id], reqRec);
    scheduleSave();
    return send(res, 200, { id });
  }
  // Sign-up step 3: Discord. Existing account → signed in. New → a sign-up token for steps 4 and 5.
  if (url.pathname === '/auth/signup/discord' && req.method === 'POST') {
    let body; try { body = await readBody(req); } catch { return send(res, 400, { error: 'Bad request' }); }
    const dtoken = body && String(body.discordToken || '');
    if (!dtoken) return send(res, 400, { error: 'Missing Discord token' });
    let d; try { d = await discordUser(dtoken); } catch { return send(res, 503, { error: 'Could not reach Discord, please try again' }); }
    if (!d) return send(res, 400, { error: 'Discord sign-in expired, please try again' });
    const device = alts.okDevice(body.device) ? body.device : null;
    const accts = getAt(root, ['accounts']) || {};
    const rid = Object.keys(accts).find(k => String((accts[k] || {}).discordId || '') === String(d.id));
    if (rid) {
      // Returning player: sign in with Discord.
      root = setAt(root, ['accounts', rid, 'lastLogin'], Date.now()); scheduleSave();
      alts.record('d:' + d.id, alts.clientIp(req), device, 'signin');
      return send(res, 200, { session: newSession(rid), user: publicUser(getAt(root, ['accounts', rid])) });
    }
    const token = b64url(crypto.randomBytes(24));
    signups.set(crypto.createHash('sha256').update(token).digest('hex'), { discord: discordFields(d), device, checked: false, exp: Date.now() + 30 * 60 * 1000 });
    for (const [k, v] of signups) if (v.exp < Date.now()) signups.delete(k);
    const f = discordFields(d);
    return send(res, 200, { signup: token, discord: { username: f.discordUsername, globalName: f.discordGlobalName, avatar: f.discordAvatar } });
  }
  // Sign-up step 4: alt detection. Refuses VPNs; flags shared networks/devices for staff (never shown here).
  if (url.pathname === '/auth/signup/check' && req.method === 'POST') {
    let body; try { body = await readBody(req); } catch { return send(res, 400, { error: 'Bad request' }); }
    const su = signupOf(body && body.signup);
    if (!su) return send(res, 401, { error: 'Your sign-up expired. Link Discord again.', expired: true });
    const ip = alts.clientIp(req);
    if ((await alts.vpnCheck(ip)).vpn) return send(res, 403, { error: VPN_MSG, vpn: true });
    if (alts.okDevice(body.device)) su.device = body.device;
    alts.record('d:' + su.discord.discordId, ip, su.device, 'signup');
    su.checked = true;
    return send(res, 200, { ok: true });
  }

  // Backup way to link Roblox, for players Roblox won't let use its sign-in page (under-13 accounts,
  // or a country's minimum age): put a code from the site in your Roblox profile's About, then
  // press Verify. Only the account's owner can edit its About, so that proves it's theirs.
  //   POST /auth/roblox/code/start { username, signup, relink, agree, v, device } → { token, code, user }
  //   POST /auth/roblox/code/check { token } → { session, relinked, isNew } once the code is in the About.
  if (url.pathname === '/auth/roblox/code/start' && req.method === 'POST') {
    let body; try { body = await readBody(req); } catch { return send(res, 400, { error: 'Bad request' }); }
    const username = String((body && body.username) || '').trim().replace(/^@/, '');
    if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) return send(res, 400, { error: 'Enter a valid Roblox username.' });
    const agreed = String(body.agree || '').split(',');
    const legalVersion = String(body.v || '').slice(0, 20);
    if (!agreed.includes('terms') || !agreed.includes('privacy') || !legalVersion) return send(res, 400, { error: 'Please accept the Terms of Use and Privacy Policy first.' });
    const signup = String(body.signup || '').slice(0, 100);
    const su = signup ? signupOf(signup) : null;
    if (signup && (!su || !su.checked)) return send(res, 401, { error: 'Your sign-up expired. Start again from Link Discord.', expired: true });
    let user;
    try {
      const r = await fetch('https://users.roblox.com/v1/usernames/users', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ usernames: [username], excludeBannedUsers: true }), signal: AbortSignal.timeout(8000) });
      const j = r.ok ? await r.json() : null;
      user = j && j.data && j.data[0];
    } catch { return send(res, 502, { error: 'Could not reach Roblox, please try again.' }); }
    if (!user || !user.id) return send(res, 404, { error: 'No Roblox account has that username.' });
    // Words only: Roblox's filter often hides numbers in an About with ####.
    const words = ['hoop', 'dunk', 'court', 'rim', 'swish', 'assist', 'rebound', 'layup', 'buzzer', 'jumper', 'crossover', 'baseline',
      'paint', 'arena', 'bench', 'tipoff', 'dribble', 'pivot', 'screen', 'triple', 'block', 'steal', 'pass', 'net'];
    const pick = () => words[crypto.randomInt(words.length)];
    const code = `${pick()} ${pick()} ${pick()} ${pick()} ${pick()}`;
    const token = b64url(crypto.randomBytes(24));
    codeLogins.set(crypto.createHash('sha256').update(token).digest('hex'), {
      robloxId: String(user.id), code, legalVersion, signup, relink: String(body.relink || '').slice(0, 100),
      device: alts.okDevice(body.device) ? body.device : null, tries: 0, exp: Date.now() + 20 * 60 * 1000,
    });
    for (const [k, v] of codeLogins) if (v.exp < Date.now()) codeLogins.delete(k);
    return send(res, 200, { token, code, user: { id: String(user.id), username: user.name, displayName: user.displayName || user.name } });
  }
  if (url.pathname === '/auth/roblox/code/check' && req.method === 'POST') {
    let body; try { body = await readBody(req); } catch { return send(res, 400, { error: 'Bad request' }); }
    const key = crypto.createHash('sha256').update(String((body && body.token) || '')).digest('hex');
    const pend = codeLogins.get(key);
    if (!pend || pend.exp < Date.now()) { codeLogins.delete(key); return send(res, 410, { error: 'This code expired. Get a new one.', expired: true }); }
    if (++pend.tries > 30) { codeLogins.delete(key); return send(res, 429, { error: 'Too many tries. Get a new code.', expired: true }); }
    let about = '';
    try {
      const r = await fetch('https://users.roblox.com/v1/users/' + encodeURIComponent(pend.robloxId), { signal: AbortSignal.timeout(8000) });
      if (!r.ok) throw new Error(String(r.status));
      about = String((await r.json()).description || '');
    } catch { return send(res, 502, { error: 'Could not reach Roblox, please try again.' }); }
    const norm = t => t.toLowerCase().replace(/\s+/g, ' ').trim();
    if (!norm(about).includes(norm(pend.code))) return send(res, 409, { error: 'The code isn\'t in your Roblox About yet. Paste it in, press Save on Roblox, wait a few seconds, then press Verify again. (Roblox sometimes hides text with #####: if that happens, get a new code.)' });
    let prof;
    try { prof = await fetchRobloxProfile(pend.robloxId); } catch { return send(res, 502, { error: 'Could not reach Roblox, please try again.' }); }
    const r = await finishRobloxLogin(req, pend, pend.robloxId, { preferred_username: prof.username, name: prof.displayName, picture: prof.avatar }, { fresh: true });
    if (r.error) return send(res, 400, { error: r.error });
    codeLogins.delete(key);
    return send(res, 200, { session: r.token, relinked: !!r.relinked, isNew: !!r.su });
  }

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
    const relink = (url.searchParams.get('relink') || '').slice(0, 100);
    const signup = (url.searchParams.get('signup') || '').slice(0, 100);
    const device = alts.okDevice(url.searchParams.get('device')) ? url.searchParams.get('device') : null;
    pendingLogins.set(state, { verifier, returnTo, legalVersion, relink, signup, device, exp: Date.now() + 10 * 60 * 1000 });
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

      const r = await finishRobloxLogin(req, pending, robloxId, info);
      if (r.error) return fail(r.error);
      return redirect(res, pending.returnTo + '#pba_session=' + r.token + (r.relinked ? '&pba_relinked=1' : '') + (r.su ? '&pba_new=1' : ''));
    } catch (e) {
      console.error('Roblox sign-in error:', e.message);
      return fail('Could not reach Roblox, please try again');
    }
  }

  // 7) Sync Roblox username / display name / avatar (24-hour cooldown, enforced here).
  if (url.pathname === '/auth/roblox/sync' && req.method === 'POST') {
    const sess = sessionOf(req);
    if (!sess) return send(res, 401, { error: 'Not signed in' });
    const rid = String(sess.robloxId);
    const acct = getAt(root, ['accounts', rid]);
    if (!acct) return send(res, 401, { error: 'Account not found' });
    const wait = (acct.lastSyncAt || 0) + SYNC_COOLDOWN_MS - Date.now();
    if (wait > 0) return send(res, 429, { error: 'You can sync again in ' + fmtWait(wait) + '.', nextSyncAt: acct.lastSyncAt + SYNC_COOLDOWN_MS });
    let prof;
    try { prof = await fetchRobloxProfile(rid); } catch (e) { console.error('Roblox sync failed:', e.message); return send(res, 503, { error: 'Could not reach Roblox, please try again' }); }
    return send(res, 200, publicUser(applyRobloxProfile(rid, prof)));
  }

  // 6) Link a Discord account to the signed-in player (step 2 of creating a profile).
  //    The site gets a Discord token from Discord's own sign-in and sends it here; we check it with Discord.
  if (url.pathname === '/auth/discord/link' && req.method === 'POST') {
    const sess = sessionOf(req);
    if (!sess) return send(res, 401, { error: 'Not signed in' });
    let body; try { body = await readBody(req); } catch { return send(res, 400, { error: 'Bad request' }); }
    const dtoken = body && String(body.discordToken || '');
    if (!dtoken) return send(res, 400, { error: 'Missing Discord token' });
    let d;
    try {
      const r = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + dtoken }, signal: AbortSignal.timeout(8000) });
      if (!r.ok) return send(res, 400, { error: 'Discord sign-in expired, please try again' });
      d = await r.json();
    } catch { return send(res, 503, { error: 'Could not reach Discord, please try again' }); }
    if (!d || !/^\d+$/.test(String(d.id || ''))) return send(res, 400, { error: 'Discord returned an invalid account' });
    const rid = String(sess.robloxId);
    if (!getAt(root, ['accounts', rid])) return send(res, 401, { error: 'Account not found' });
    // One Discord account per player.
    const accts = getAt(root, ['accounts']) || {};
    const taken = Object.keys(accts).find(k => k !== rid && String((accts[k] || {}).discordId || '') === String(d.id));
    if (taken) return send(res, 409, { error: 'That Discord account is already linked to another player. Unlink it there first.' });
    // Clear this Discord from any other profile still holding it (e.g. one set aside by a Roblox unlink),
    // so a Discord is only ever on one profile.
    for (const B of LEAGUE_BASES) {
      const pdb = getAt(root, [...B, 'data', 'playerdb']) || {};
      Object.keys(pdb).forEach(k => {
        const p = pdb[k] || {};
        if (String(p.discordId || '') === String(d.id) && String(p.robloxId || '') !== rid) {
          root = setAt(root, [...B, 'data', 'playerdb', k, 'discordId'], null);
          root = setAt(root, [...B, 'data', 'playerdb', k, 'discordUsername'], null);
        }
      });
    }
    const avatar = d.avatar
      ? `https://cdn.discordapp.com/avatars/${d.id}/${d.avatar}.${String(d.avatar).startsWith('a_') ? 'gif' : 'png'}?size=256`
      : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(d.id) >> 22n) % 6}.png`;
    setDiscord(rid, { discordId: String(d.id), discordUsername: d.username || '', discordGlobalName: d.global_name || '', discordAvatar: avatar, discordLinkedAt: Date.now() });
    return send(res, 200, publicUser(getAt(root, ['accounts', rid])));
  }
  if (url.pathname === '/auth/discord/unlink' && req.method === 'POST') {
    const sess = sessionOf(req);
    if (!sess) return send(res, 401, { error: 'Not signed in' });
    setDiscord(sess.robloxId, null);
    const rec = getAt(root, ['accounts', String(sess.robloxId)]);
    return rec ? send(res, 200, publicUser(rec)) : send(res, 401, { error: 'Account not found' });
  }

  // 5) Unlink this Roblox account. The player profile (stats, team, awards) is kept and set aside;
  //    the returned relink token moves it onto whichever Roblox account is linked next.
  if (url.pathname === '/auth/unlink' && req.method === 'POST') {
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
    const key = m ? crypto.createHash('sha256').update(m[1]).digest('hex') : '';
    const sess = key && sessions[key];
    if (!sess || sess.exp < Date.now()) return send(res, 401, { error: 'Not signed in' });
    const rid = String(sess.robloxId);
    const acct = getAt(root, ['accounts', rid]);
    if (acct) ensurePlayerRecord(acct);
    const playerKeys = {};
    for (const B of LEAGUE_BASES) {
      const db = getAt(root, [...B, 'data', 'playerdb']) || {};
      const pkey = Object.keys(db).find(k => String((db[k] || {}).robloxId || '') === rid);
      if (!pkey) continue;
      playerKeys[B.join('/')] = pkey;
      root = setAt(root, [...B, 'data', 'playerdb', pkey, 'unlinked'], true);
      root = setAt(root, [...B, 'data', 'playerdb', pkey, 'unlinkedAt'], Date.now());
    }
    root = setAt(root, ['accounts', rid], null);
    for (const [k, v] of Object.entries(sessions)) if (v && !v.relink && String(v.robloxId) === rid) delete sessions[k];
    let relinkToken = null;
    if (Object.keys(playerKeys).length) {
      relinkToken = b64url(crypto.randomBytes(24));
      sessions['relink:' + crypto.createHash('sha256').update(relinkToken).digest('hex')] =
        { relink: true, playerKeys, oldRobloxId: rid, exp: Date.now() + 30 * 86400000 };
    }
    saveSessions(); scheduleSave();
    return send(res, 200, { ok: true, relinkToken });
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
    alts.record(altKey(rec), alts.clientIp(req), String(req.headers['x-pba-device'] || ''), 'visit');   // at most once an hour
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Firebase-ETag,If-Match,X-Admin-Key,X-PBA-Device');
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
  // Alt alerts for the Discord bots (admin key only): queue, ack (posted), decide (Confirm Alt / Not an Alt).
  if (url.pathname.startsWith('/alts/')) {
    if (!ADMIN_KEY || req.headers['x-admin-key'] !== ADMIN_KEY) return send(res, 403, { error: 'Admin key required' });
    try {
      if (url.pathname === '/alts/queue' && req.method === 'GET') return send(res, 200, alts.queue(String(url.searchParams.get('league') || 'pba')));
      const body = req.method === 'POST' ? (await readBody(req)) || {} : {};
      if (url.pathname === '/alts/ack' && req.method === 'POST')
        return alts.ack(String(body.id), String(body.league || 'pba'), { channelId: body.channelId || null, messageId: body.messageId || null, rev: Number(body.rev) || 0, at: Date.now() })
          ? send(res, 200, { ok: true }) : send(res, 404, { error: 'Alert not found' });
      if (url.pathname === '/alts/decide' && req.method === 'POST') {
        const a = alts.decide(String(body.id), body.decision === 'alt' ? 'alt' : 'not', body.by ? String(body.by) : null);
        return a ? send(res, 200, a) : send(res, 404, { error: 'Alert not found' });
      }
      if (url.pathname === '/alts/confirm' && req.method === 'POST') {
        const a = alts.confirm(String(body.id), body.by ? String(body.by) : null);
        return a ? send(res, 200, a) : send(res, 404, { error: 'Alert not found' });
      }
      if (url.pathname === '/alts/reverse' && req.method === 'POST') {
        const a = alts.reverse(String(body.id), body.by ? String(body.by) : null);
        return a ? send(res, 200, a) : send(res, 404, { error: 'Alert not found' });
      }
      if (url.pathname === '/alts/check' && req.method === 'GET')
        return send(res, 200, alts.check(String(url.searchParams.get('keys') || '').split(',').map(k => k.trim()).filter(Boolean), url.searchParams.get('all') === '1'));
      if (url.pathname === '/alts/get' && req.method === 'GET') { const a = alts.get(String(url.searchParams.get('id'))); return a ? send(res, 200, a) : send(res, 404, { error: 'Alert not found' }); }
    } catch (e) { console.error(e); return send(res, 500, { error: 'Server error' }); }
    return send(res, 404, { error: 'Not found' });
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

    let next = root;
    if (req.method === 'PUT') next = setAt(next, segs, body);
    else if (req.method === 'DELETE') next = setAt(next, segs, null);
    else if (req.method === 'POST') next = setAt(next, segs.concat(newKey), body);
    else for (const [k, v] of Object.entries(body)) next = setAt(next, segs.concat(k.split('/').filter(Boolean)), v);
    // Admins who aren't the super admin can't touch seasons that aren't active.
    for (const base of (req.writer && req.writer.limitedBases) || []) {
      const err = seasonLockError(root, next, base) || gameLockError(root, next, base);
      if (err) return send(res, 403, { error: err });
    }
    // Super admin appointments are the owner's alone.
    if (req.writer) for (const base of LEAGUE_BASES) {
      const err = superAdminError(root, next, base, req.writer.id);
      if (err) return send(res, 403, { error: err });
    }
    root = next;
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
  for (const B of LEAGUE_BASES) ensurePlayerRecordIn(B, rec);
  scheduleSave();
}
function ensurePlayerRecordIn(B, rec) {
  const db = getAt(root, [...B, 'data', 'playerdb']) || {};
  const key = Object.keys(db).find(k => String((db[k] || {}).robloxId || '') === String(rec.robloxId));
  const name = rec.displayName || rec.username;
  if (!key) {
    // The usual key is rbx_<robloxId>, unless a relinked profile still uses that key.
    let newKey = 'rbx_' + rec.robloxId, n = 2;
    while (db[newKey]) newKey = 'rbx_' + rec.robloxId + '_' + n++;
    const p = { name, robloxId: rec.robloxId, username: rec.username, code: '', pos: '', num: '', fromAccount: true, createdAt: Date.now() };
    if (rec.discordId) { p.discordId = rec.discordId; p.discordUsername = rec.discordUsername || ''; }
    root = setAt(root, [...B, 'data', 'playerdb', newKey], p);
  } else if (db[key].fromAccount) {
    // Keep auto-created records in sync with the player's Roblox name.
    root = setAt(root, [...B, 'data', 'playerdb', key, 'name'], name);
    root = setAt(root, [...B, 'data', 'playerdb', key, 'username'], rec.username);
  }
}

// Does a player record have league history (box score lines or awards)? Used before merging.
function playerHasHistory(pid, B = []) {
  const box = getAt(root, [...B, 'boxscores']) || {};
  for (const sid of Object.keys(box)) for (const wk of Object.keys(box[sid] || {})) for (const gid of Object.keys(box[sid][wk] || {})) {
    const g = box[sid][wk][gid] || {};
    if ((g.teamA && g.teamA[pid]) || (g.teamB && g.teamB[pid])) return true;
  }
  const aw = getAt(root, [...B, 'awards']) || {};
  for (const sid of Object.keys(aw)) {
    const list = aw[sid] && aw[sid].list;
    if ((Array.isArray(list) ? list : Object.values(list || {})).some(a => a && a.playerId === pid)) return true;
  }
  return false;
}
// Move an unlinked player profile (in every league) onto a newly linked Roblox account.
function relinkPlayer(token, rec) {
  const skey = 'relink:' + crypto.createHash('sha256').update(String(token)).digest('hex');
  const rel = sessions[skey];
  if (!rel || !rel.relink || rel.exp < Date.now()) return { ok: false };
  const keys = rel.playerKeys || (rel.playerKey ? { '': rel.playerKey } : {});
  const newId = String(rec.robloxId);
  const plan = [];
  for (const B of LEAGUE_BASES) {
    const P = keys[B.join('/')], db = getAt(root, [...B, 'data', 'playerdb']) || {};
    if (!P || !db[P]) continue;
    const Q = Object.keys(db).find(k => k !== P && String((db[k] || {}).robloxId || '') === newId);
    // A profile the new Roblox account already has: fold it in if it's empty, refuse if it has history.
    if (Q && playerHasHistory(Q, B)) return { error: 'That Roblox account already has its own player profile with stats. Link a different account, or ask an admin to merge them.' };
    plan.push({ B, P, Q, db });
  }
  if (!plan.length) { delete sessions[skey]; saveSessions(); return { ok: false }; }
  // The Discord link travels with the profile, unless someone else has linked that Discord since.
  const first = plan[0].db[plan[0].P] || {};
  if (first.discordId && !rec.discordId) {
    const accts = getAt(root, ['accounts']) || {};
    const takenAcct = Object.values(accts).some(a => a && String(a.discordId || '') === String(first.discordId));
    const takenProfile = plan.some(({ db, P }) => Object.keys(db).some(k => k !== P && db[k] && String(db[k].discordId || '') === String(first.discordId)));
    if (!takenAcct && !takenProfile) { rec.discordId = first.discordId; rec.discordUsername = first.discordUsername || ''; rec.discordLinkedAt = Date.now(); }
  }
  for (const { B, P, Q, db } of plan) {
    if (Q) {
      if (!db[P].code && db[Q].code) root = setAt(root, [...B, 'data', 'playerdb', P, 'code'], db[Q].code);
      root = setAt(root, [...B, 'data', 'playerdb', Q], null);
    }
    const cur = getAt(root, [...B, 'data', 'playerdb', P]) || {};
    const next = Object.assign({}, cur, { robloxId: newId, username: rec.username, relinkedAt: Date.now(),
      previousRobloxIds: [...new Set([...(cur.previousRobloxIds || []), String(rel.oldRobloxId)])].filter(x => x !== newId) });
    if (cur.fromAccount !== false) next.name = rec.displayName || rec.username || cur.name;
    delete next.unlinked; delete next.unlinkedAt;
    // The profile's Discord always matches the account it now belongs to.
    if (rec.discordId) { next.discordId = rec.discordId; next.discordUsername = rec.discordUsername || ''; }
    else { delete next.discordId; delete next.discordUsername; }
    root = setAt(root, [...B, 'data', 'playerdb', P], next);
  }
  delete sessions[skey]; saveSessions(); scheduleSave();
  return { ok: true };
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

// One-time per league: give every existing season its own copy of the team list
// (teams/<seasonId>), and mark one season active (the default one, else the newest).
// After this, a brand-new season starts with no teams, and old seasons keep theirs.
function migrateSeasons() {
  for (const B of LEAGUE_BASES) {
    if (getAt(root, [...B, 'meta', 'perSeasonTeams'])) continue;
    const seasons = getAt(root, [...B, 'seasons']) || {};
    const ids = Object.keys(seasons);
    const teams = getAt(root, [...B, 'data', 'teams']);
    for (const sid of ids) if (teams && !getAt(root, [...B, 'teams', sid])) root = setAt(root, [...B, 'teams', sid], teams);
    if (ids.length && !ids.some(id => seasons[id] && seasons[id].active)) {
      const pick = ids.find(id => seasons[id] && seasons[id].isDefault) || ids[ids.length - 1];
      root = setAt(root, [...B, 'seasons', pick, 'active'], true);
    }
    root = setAt(root, [...B, 'meta', 'perSeasonTeams'], Date.now());
    console.log(`Seasons set up for ${B.length ? B[1].toUpperCase() : 'PBA'}: ${ids.length} season(s) got their own team list.`);
  }
  saveNow();
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
  try { if (root) migrateSeasons(); } catch (e) { console.error('Season setup failed:', e.message); }
  // Every account gets a player profile in each league (adds PBCA profiles for existing players).
  try {
    const accts = Object.values(getAt(root, ['accounts']) || {}).filter(a => a && a.robloxId);
    accts.forEach(a => ensurePlayerRecord(a));
    if (accts.length) saveNow();
  } catch (e) { console.error('Profile setup failed:', e.message); }
  server.listen(PORT, () => {
    console.log(`PBA data server on :${PORT}  data=${DB_FILE}  auth=${REQUIRE_AUTH ? 'discord' : 'OFF'}`);
    if (!process.env.DATA_DIR && !process.env.RAILWAY_VOLUME_MOUNT_PATH && process.env.RAILWAY_ENVIRONMENT) {
      console.warn('WARNING: no Railway Volume attached — data will be lost on every redeploy!');
    }
  });
});
