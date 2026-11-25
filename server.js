const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";
if (!ADMIN_KEY) {
  console.error("Missing ADMIN_KEY environment variable");
  process.exit(1);
}

app.use(cors({ origin: FRONTEND_ORIGIN === "*" ? "*" : FRONTEND_ORIGIN.split(",").map(x => x.trim()) }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));

const db = new Database(process.env.DB_PATH || "aimlock.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hash TEXT UNIQUE NOT NULL,
  hint TEXT NOT NULL,
  tier TEXT NOT NULL CHECK(tier IN ('VIP','NORMAL')),
  expires_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
)`);

const sha = value => crypto.createHash("sha256").update(value).digest("hex");
const makeKey = () => "AIM-" + crypto.randomBytes(18).toString("hex").toUpperCase();
const adminOnly = (req, res, next) => {
  const token = (req.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token || !crypto.timingSafeEqual(Buffer.from(sha(token)), Buffer.from(sha(ADMIN_KEY)))) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
};

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "AIMLOCK API" }));

app.post("/api/validate", (req, res) => {
  const key = String(req.body?.key || "").trim().toUpperCase();
  if (!key || key.length > 120) return res.status(400).json({ ok: false, error: "Key không hợp lệ" });
  const row = db.prepare("SELECT tier, expires_at, revoked FROM keys WHERE hash = ?").get(sha(key));
  if (!row || row.revoked) return res.status(403).json({ ok: false, error: "Key không tồn tại hoặc đã bị thu hồi" });
  if (row.expires_at && Date.parse(row.expires_at) <= Date.now()) {
    return res.status(403).json({ ok: false, error: "Key đã hết hạn" });
  }
  res.json({ ok: true, tier: row.tier, expiresAt: row.expires_at });
});

app.post("/api/admin/keys", adminOnly, (req, res) => {
  const tier = String(req.body?.tier || "").toUpperCase();
  const days = req.body?.days === null || req.body?.days === "" ? null : Number(req.body?.days);
  if (!["VIP", "NORMAL"].includes(tier)) return res.status(400).json({ error: "Tier phải là VIP hoặc NORMAL" });
  if (days !== null && (!Number.isInteger(days) || days < 1 || days > 3650)) {
    return res.status(400).json({ error: "Thời hạn phải từ 1 đến 3650 ngày hoặc để trống" });
  }
  const key = makeKey();
  const expiresAt = days === null ? null : new Date(Date.now() + days * 86400000).toISOString();
  db.prepare("INSERT INTO keys(hash,hint,tier,expires_at,created_at) VALUES(?,?,?,?,?)")
    .run(sha(key), key.slice(-4), tier, expiresAt, new Date().toISOString());
  res.json({ ok: true, key, tier, expiresAt, message: "Hãy sao chép key ngay; máy chủ chỉ hiển thị key đầy đủ một lần." });
});

app.get("/api/admin/keys", adminOnly, (_req, res) => {
  const rows = db.prepare("SELECT id,hint,tier,expires_at,revoked,created_at FROM keys ORDER BY id DESC").all();
  res.json({ ok: true, keys: rows });
});

app.post("/api/admin/keys/:id/revoke", adminOnly, (req, res) => {
  const result = db.prepare("UPDATE keys SET revoked=1 WHERE id=?").run(Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: "Không tìm thấy key" });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`AIMLOCK API listening on ${PORT}`));
