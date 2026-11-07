// Alt detection for the PBA data server.
//  • Every sign-up, sign-in and (at most once an hour) page visit records the player's network
//    (IP address) and device (a random ID the website keeps in their browser).
//  • Nothing is stored in plain text: both are scrambled with a secret key (HMAC) first, so the
//    file can only say "these accounts used the same network/device", never what the IP was.
//    Records older than 60 days are deleted.
//  • Two accounts on the same network or device → an alert for staff (the bots post it in the
//    Alt Logs channel). A network shared by more than 5 accounts (school, phone carrier) is ignored.
//  • VPN check (proxycheck.io) for new sign-ups: known VPNs/proxies are refused. Apple's iCloud
//    Private Relay is let through.
// Everything lives in its own file (alts.json), NOT in db.json, which anyone can read.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEEP_DAYS = 60;
const SHARED_LIMIT = 5;               // more accounts than this on one network = school/carrier, ignored
const VISIT_EVERY_MS = 60 * 60 * 1000;

module.exports = function makeAlts(DATA_DIR) {
  const FILE = path.join(DATA_DIR, 'alts.json');
  const SECRET_FILE = path.join(DATA_DIR, 'alt-secret');

  // The scrambling key: ALT_SECRET in Railway Variables, or one made once and kept on the volume.
  let secret = process.env.ALT_SECRET || '';
  if (!secret) {
    try { secret = fs.readFileSync(SECRET_FILE, 'utf8').trim(); } catch {}
    if (!secret) { secret = crypto.randomBytes(32).toString('hex'); try { fs.writeFileSync(SECRET_FILE, secret); } catch {} }
  }
  const hash = (kind, v) => crypto.createHmac('sha256', secret).update(kind + ':' + v).digest('hex').slice(0, 32);

  let db = { ip: {}, dev: {}, alerts: {}, ignore: {}, seen: {} };
  try { if (fs.existsSync(FILE)) db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8')) || {}); } catch (e) { console.error('alts.json unreadable:', e.message); }
  let timer = null;
  function save() {
    clearTimeout(timer);
    timer = setTimeout(() => {
      prune();
      const tmp = FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(db));
      fs.renameSync(tmp, FILE);
    }, 300);
  }
  function prune() {
    const cut = Date.now() - KEEP_DAYS * 86400000;
    for (const kind of ['ip', 'dev']) for (const [h, accts] of Object.entries(db[kind])) {
      for (const [k, at] of Object.entries(accts)) if (at < cut) delete accts[k];
      if (!Object.keys(accts).length) delete db[kind][h];
    }
    for (const [k, at] of Object.entries(db.seen)) if (at < Date.now() - VISIT_EVERY_MS) delete db.seen[k];
  }

  // The visitor's IP. Railway puts it in X-Real-IP (or as the last X-Forwarded-For entry).
  function clientIp(req) {
    const real = String(req.headers['x-real-ip'] || '').trim();
    if (real) return real;
    const xff = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
    return xff.length ? xff[xff.length - 1] : String((req.socket && req.socket.remoteAddress) || '');
  }
  const okDevice = d => typeof d === 'string' && /^[a-zA-Z0-9-]{16,64}$/.test(d);

  // Record an account on this network/device and raise alerts for any other account seen there.
  // key: 'd:<discordId>' (or 'r:<robloxId>' for old accounts without Discord).
  // event: 'signup' | 'signin' | 'visit'.
  function record(key, ip, device, event) {
    if (!key) return [];
    const now = Date.now();
    const ih = ip ? hash('ip', ip) : null, dh = okDevice(device) ? hash('dev', device) : null;
    if (event === 'visit') {
      const s = key + '|' + ih + '|' + dh;
      if (db.seen[s] && now - db.seen[s] < VISIT_EVERY_MS) return [];
      db.seen[s] = now;
    }
    const others = {};
    if (ih) {
      db.ip[ih] = db.ip[ih] || {}; db.ip[ih][key] = now;
      const keys = Object.keys(db.ip[ih]);
      if (keys.length <= SHARED_LIMIT) keys.forEach(k => { if (k !== key) (others[k] = others[k] || {}).ip = true; });
    }
    if (dh) {
      db.dev[dh] = db.dev[dh] || {}; db.dev[dh][key] = now;
      Object.keys(db.dev[dh]).forEach(k => { if (k !== key) (others[k] = others[k] || {}).dev = true; });
    }
    const made = [];
    for (const [other, m] of Object.entries(others)) {
      const pair = [key, other].sort().join('|');
      if (db.ignore[pair]) continue;
      const a = Object.values(db.alerts).find(x => x.pair === pair);
      if (a) {
        a.lastAt = now; a.count = (a.count || 1) + 1;
        const stronger = (m.ip && !a.ip) || (m.dev && !a.dev);
        a.ip = a.ip || !!m.ip; a.dev = a.dev || !!m.dev;
        // Became a strong match (same network AND device) while still open: post it again.
        if (stronger && a.ip && a.dev && a.status === 'open') { a.posted = {}; a.strongAt = now; }
        continue;
      }
      const id = now.toString(36) + crypto.randomBytes(3).toString('hex');
      db.alerts[id] = { id, pair, flagged: key, match: other, ip: !!m.ip, dev: !!m.dev, event,
        firstAt: now, lastAt: now, count: 1, status: 'open', posted: {} };
      made.push(id);
    }
    save();
    return made;
  }
  // When a pending sign-up (d:<id>) finishes, nothing to rename: accounts are keyed by Discord.

  // ── VPN / proxy check (proxycheck.io). Fails open: if the check can't run, the player isn't blocked. ──
  const vpnCache = new Map();
  async function vpnCheck(ip) {
    if (!ip || /^(127\.|10\.|192\.168\.|::1|fc|fd)/.test(ip)) return { vpn: false };
    const hit = vpnCache.get(ip);
    if (hit && hit.exp > Date.now()) return hit.res;
    let res = { vpn: false };
    try {
      const key = process.env.PROXYCHECK_KEY ? '&key=' + encodeURIComponent(process.env.PROXYCHECK_KEY) : '';
      const r = await fetch('https://proxycheck.io/v2/' + encodeURIComponent(ip) + '?vpn=1&asn=1' + key, { signal: AbortSignal.timeout(6000) });
      const j = r.ok ? await r.json() : null;
      const d = j && j[ip];
      if (d) {
        const who = [d.provider, d.organisation, d.operator && d.operator.name].filter(Boolean).join(' ');
        const isProxy = d.proxy === 'yes' || (d.detections && (d.detections.vpn || d.detections.proxy || d.detections.tor));
        const apple = /apple|icloud/i.test(who);   // iCloud Private Relay: allowed
        res = { vpn: !!isProxy && !apple, type: d.type || null };
      } else if (j && j.status && j.status !== 'ok' && j.status !== 'warning') console.warn('[vpn] proxycheck:', j.status, j.message || '');
    } catch (e) { console.warn('[vpn] check failed:', e.message); }
    vpnCache.set(ip, { res, exp: Date.now() + 60 * 60 * 1000 });
    if (vpnCache.size > 2000) vpnCache.delete(vpnCache.keys().next().value);
    return res;
  }

  // ── For the bots (X-Admin-Key) ──
  // Alerts this league's bot hasn't posted yet.
  function queue(league) {
    return Object.values(db.alerts).filter(a => a.status === 'open' && !(a.posted || {})[league]);
  }
  function ack(id, league, info) {
    const a = db.alerts[id]; if (!a) return false;
    a.posted = Object.assign({}, a.posted, { [league]: info || { at: Date.now() } });
    save(); return true;
  }
  // decision: 'alt' (confirmed) or 'not' (never flag this pair again).
  function decide(id, decision, by) {
    const a = db.alerts[id]; if (!a) return null;
    if (a.status !== 'open') return a;
    a.status = decision === 'alt' ? 'alt' : 'not';
    a.decidedBy = by || null; a.decidedAt = Date.now();
    if (a.status === 'not') db.ignore[a.pair] = Date.now();
    save(); return a;
  }
  const get = id => db.alerts[id] || null;

  return { record, vpnCheck, clientIp, okDevice, queue, ack, decide, get };
};
