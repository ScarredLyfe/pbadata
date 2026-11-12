// Alt detection for the PBA data server.
//  • Every sign-up, sign-in and (at most once an hour) page visit records the player's network
//    (IP address) and device (a random ID the website keeps in their browser).
//  • Nothing is stored in plain text: both are scrambled with a secret key (HMAC) first, so the
//    file can only say "these accounts used the same network/device", never what the IP was.
//    Records older than 60 days are deleted.
//  • Two accounts on the same network or device → an alert for staff (the bots post it in the
//    Alt Logs channel). A network shared by more than 5 accounts (school, phone carrier) is ignored.
//  • VPN check (proxycheck.io) for new sign-ups: known VPNs/proxies are refused. Apple's iCloud
//    Private Relay is let through. Staff can let one person past it with /vpn_allow in Discord
//    (vpnAllow, by Discord ID), e.g. when their home network is wrongly flagged.
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

  let db = { ip: {}, dev: {}, alerts: {}, ignore: {}, seen: {}, vpnAllow: {} };
  try { if (fs.existsSync(FILE)) db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8')) || {}); } catch (e) { console.error('alts.json unreadable:', e.message); }
  // Older alerts (one account pair each) → the new shape.
  for (const a of Object.values(db.alerts)) {
    if (!a.matches) a.matches = a.match ? { [a.match]: { ip: !!a.ip, dev: !!a.dev } } : {};
    if (!a.pairs) a.pairs = a.pair ? [a.pair] : [];
    delete a.pair;
    if (a.rev == null) a.rev = 0;
    for (const [lg, info] of Object.entries(a.posted || {})) if (info && info.rev == null) info.rev = 0;
  }
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
    // One alert per person: a new match for someone who already has an open alert is added to it,
    // and the bots EDIT their message instead of posting a new one.
    const made = [], touched = new Set();
    for (const [other, m] of Object.entries(others)) {
      const pair = [key, other].sort().join('|');
      if (db.ignore[pair]) continue;
      // Already in an alert (open or decided): just update it.
      let a = Object.values(db.alerts).find(x => (x.pairs || []).includes(pair));
      if (a) {
        for (const k of [key, other]) if (k !== a.flagged) {
          const mm = a.matches[k] || (a.matches[k] = {});
          mm.ip = mm.ip || !!m.ip; mm.dev = mm.dev || !!m.dev;
        }
        touched.add(a);
        continue;
      }
      // One of these accounts is already in an open alert: put the other one in the same alert.
      const inIt = (x, k) => x.flagged === k || !!(x.matches || {})[k];
      a = Object.values(db.alerts).find(x => x.status === 'open' && (inIt(x, key) || inIt(x, other)));
      if (a) {
        for (const k of [key, other]) if (k !== a.flagged) {
          const mm = a.matches[k] || (a.matches[k] = {});
          mm.ip = mm.ip || !!m.ip; mm.dev = mm.dev || !!m.dev;
        }
        a.pairs.push(pair);
        touched.add(a);
        continue;
      }
      const id = now.toString(36) + crypto.randomBytes(3).toString('hex');
      a = db.alerts[id] = { id, pairs: [pair], flagged: key, matches: { [other]: { ip: !!m.ip, dev: !!m.dev } }, event,
        firstAt: now, lastAt: now, count: 1, status: 'open', rev: 1, posted: {} };
      sumUp(a);
      made.push(id);
    }
    // Seen again: count it once per visit, and let the bots update their message.
    for (const a of touched) {
      if (made.includes(a.id)) continue;
      a.lastAt = now; a.count = (a.count || 1) + 1;
      if (a.status === 'open') a.rev = (a.rev || 0) + 1;
      sumUp(a);
    }
    save();
    return made;
  }
  // a.ip / a.dev / a.match: a summary of all matches (for the bot's embed).
  function sumUp(a) {
    const ms = Object.values(a.matches || {});
    a.ip = ms.some(x => x.ip); a.dev = ms.some(x => x.dev);
    a.match = Object.keys(a.matches || {})[0] || null;
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
  // Alerts this league's bot hasn't posted yet, or that changed since (the bot edits its message).
  function queue(league) {
    return Object.values(db.alerts).filter(a => {
      const p = (a.posted || {})[league];
      return a.status === 'open' ? (!p || (p.rev || 0) < (a.rev || 0)) : false;
    });
  }
  function ack(id, league, info) {
    const a = db.alerts[id]; if (!a) return false;
    a.posted = Object.assign({}, a.posted, { [league]: Object.assign({}, info, { rev: info && info.rev != null ? info.rev : (a.rev || 0) }) });
    save(); return true;
  }
  // decision: 'alt' (confirmed) or 'not' (never flag these accounts together again).
  function decide(id, decision, by) {
    const a = db.alerts[id]; if (!a) return null;
    if (a.status !== 'open') return a;
    a.status = decision === 'alt' ? 'alt' : 'not';
    a.decidedBy = by || null; a.decidedAt = Date.now();
    if (a.status === 'not') for (const pr of a.pairs || []) db.ignore[pr] = Date.now();
    save(); return a;
  }
  // Undo a "Confirm Alt" pressed by mistake (/falsealt in Discord): the alert becomes "Not an Alt"
  // (the accounts won't be flagged together again).
  function reverse(id, by) {
    const a = db.alerts[id]; if (!a) return null;
    if (a.status !== 'alt') return a;
    a.status = 'not';
    a.reversedBy = by || null; a.reversedAt = Date.now();
    a.decidedBy = by || a.decidedBy; a.decidedAt = Date.now();
    for (const pr of a.pairs || []) db.ignore[pr] = Date.now();
    save(); return a;
  }
  // Undo a "Not an Alt" pressed by mistake (/truealt in Discord): the alert becomes a confirmed alt,
  // and the accounts can be flagged together again.
  function confirm(id, by) {
    const a = db.alerts[id]; if (!a) return null;
    if (a.status !== 'not') return a;
    a.status = 'alt';
    a.confirmedLateBy = by || null; a.confirmedLateAt = Date.now();
    a.decidedBy = by || a.decidedBy; a.decidedAt = Date.now();
    for (const pr of a.pairs || []) delete db.ignore[pr];
    save(); return a;
  }
  const get = id => db.alerts[id] || null;
  // /vpn_allow: this Discord account can sign up even if the VPN check flags their network.
  function allowVpn(discordId, on, by) {
    const id = String(discordId || '').trim(); if (!/^\d{5,25}$/.test(id)) return null;
    if (!db.vpnAllow) db.vpnAllow = {};
    if (on) db.vpnAllow[id] = { by: by || null, at: Date.now() }; else delete db.vpnAllow[id];
    save(); return { discordId: id, allowed: !!on };
  }
  // Privacy deletion: remove an account's network/device records, its seen marker and VPN allowance.
  // (Alerts already posted for staff stay, as a record of the decision.)
  function forget(keys, discordId) {
    const ks = new Set(keys || []);
    for (const kind of ['ip', 'dev']) for (const [h, accts] of Object.entries(db[kind])) {
      for (const k of Object.keys(accts)) if (ks.has(k)) delete accts[k];
      if (!Object.keys(accts).length) delete db[kind][h];
    }
    for (const k of Object.keys(db.seen)) if ([...ks].some(x => k.startsWith(x))) delete db.seen[k];
    if (discordId && db.vpnAllow) delete db.vpnAllow[String(discordId)];
    save();
  }
  const vpnAllowed = discordId => !!(discordId && db.vpnAllow && db.vpnAllow[String(discordId)]);
  // Is this player in any alert? keys: ['d:<discordId>', 'r:<robloxId>'].
  // Alerts marked "Not an Alt" don't count. Returns the matching alerts, confirmed ones first.
  // all = true: include alerts marked "Not an Alt" too (for /truealt).
  function check(keys, all) {
    const ks = new Set((keys || []).filter(Boolean));
    const list = Object.values(db.alerts).filter(a => (all || a.status !== 'not') &&
      (ks.has(a.flagged) || Object.keys(a.matches || {}).some(k => ks.has(k))));
    list.sort((x, y) => (y.status === 'alt') - (x.status === 'alt') || y.lastAt - x.lastAt);
    return list.map(a => ({ id: a.id, status: a.status, ip: !!a.ip, dev: !!a.dev, lastAt: a.lastAt, posted: a.posted || {},
      others: [a.flagged, ...Object.keys(a.matches || {})].filter(k => !ks.has(k)) }));
  }

  return { forget, allowVpn, vpnAllowed, record, vpnCheck, clientIp, okDevice, queue, ack, decide, reverse, confirm, get, check };
};
