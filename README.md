# AIMLOCK Backend

## Deploy
- Node.js 20+
- Build command: `npm install`
- Start command: `npm start`
- Environment variable: `ADMIN_KEY` (a long random secret)
- Optional: `FRONTEND_ORIGIN` set to your exact GitHub Pages origin, e.g. `https://YOUR-USER.github.io`
- Persistent storage is required for SQLite. Set `DB_PATH` to a file on a persistent mounted disk, e.g. `/var/data/aimlock.sqlite`.

Admin page: `/admin.html`

API:
- `POST /api/validate` body `{"key":"..."}`
- `POST /api/admin/keys` bearer ADMIN_KEY, body `{"tier":"VIP","days":30}`; use `null` days for no expiry
- `GET /api/admin/keys` bearer ADMIN_KEY
- `POST /api/admin/keys/:id/revoke` bearer ADMIN_KEY

Important: Do not commit secrets. Configure persistent disk/database before issuing real customer keys. The current GitHub Pages frontend still needs its validation JavaScript updated to call this API.
