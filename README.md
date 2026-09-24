# PBA data server (Railway)

A tiny Node server (no dependencies) that speaks the same REST API as Firebase Realtime
Database — `GET/PUT/PATCH/POST/DELETE /some/path.json` — so the site only needs its URL
changed. This is the same setup the reference site uses (`laurb5data-production.up.railway.app`).

## Deploy

1. Push this folder to a new GitHub repo (or use `railway up` from the Railway CLI).
2. Railway → **New Project → Deploy from GitHub repo** → pick the repo. It detects Node and runs `node server.js`.
3. **Add a Volume** (right-click the service → *Attach Volume*), mount path `/data`.
   Without a volume, every redeploy wipes your data. Railway sets `RAILWAY_VOLUME_MOUNT_PATH`
   automatically and the server uses it.
4. Service → **Settings → Networking → Generate Domain**. You'll get something like
   `https://pba-data-production.up.railway.app`.
5. Service → **Variables**, add:

| Variable | Value | Why |
|---|---|---|
| `FIREBASE_IMPORT_URL` | `https://pba-practical-default-rtdb.firebaseio.com/` | Copies your existing data on first boot (only when the DB is empty). Remove it afterward. |
| `ADMIN_KEY` | a long random string | Lets *you* back up / restore with curl. Never put it in the website. |
| `SUPER_ADMIN_DISCORD_IDS` | `613513131741937684` | Comma-separated Discord IDs that are always super admins. |
| `ALLOWED_ORIGINS` | `*` (or `https://yoursite.com`) | Optional: restrict which sites can call the API. |

If your Firebase rules block public reads, the import can't read it; instead export JSON from
the Firebase console and restore it with the curl command below.

6. Open `https://<your-domain>/.json` — you should see your league data.

## Point the site at it

In `admin.html`, set:

```js
const DB_URL = 'https://<your-domain>.up.railway.app/';
```

Admins must sign in with Discord once more after this change (the login token is now saved
so the server can verify it).

## Who can write

- Anyone can **read** (same as before — the public pages need it).
- **Writes** need a valid Discord login belonging to a super admin (env var or
  `data/adminAccess` role `super`) or a regular admin (`role: regular`).
- Only super admins can change `data/adminAccess`, so a regular admin can't promote themselves.
- Set `REQUIRE_AUTH=false` only for local testing.

## Backups / restore

```bash
# backup everything
curl https://<your-domain>/.json -o pba-backup.json

# restore (overwrites everything!)
curl -X PUT -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
     --data-binary @pba-backup.json https://<your-domain>/.json
```

On the volume the server also keeps `db.json.bak` (the previous save).

## Supported API

| Request | Effect |
|---|---|
| `GET /a/b.json` | value at `a/b` or `null` (`?shallow=true` lists keys only) |
| `PUT /a/b.json` | replace (sending `null` deletes) |
| `PATCH /a.json` | merge keys; keys may be paths like `"teams/MET"` |
| `POST /a.json` | add with a generated id → `{"name": "<id>"}` |
| `DELETE /a/b.json` | delete |
| `X-Firebase-ETag: true` / `if-match` | conditional writes (412 if someone changed it first) |

Run locally: `REQUIRE_AUTH=false node server.js` → http://localhost:8080/.json
