
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  skip: req => req.path === "/health"
}));

/* DATABASE */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const db = (sql, values = []) => pool.query(sql, values);

pool.on("error", err => console.error("PostgreSQL:", err));

/* SETTINGS */

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const APP_URL = (process.env.APP_URL || "").replace(/\/$/, "");

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

const PROVIDER_URL = String(
  process.env.SOCIALADD_API_URL || "https://socialadd.in/api/v2"
).trim();

const PROVIDER_KEY = String(process.env.SOCIALADD_API_KEY || "").trim();
const UPI_ID = process.env.UPI_ID || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";

const WHATSAPP_NUMBER = "918140989426";
const WHATSAPP_LINK =
  `https://wa.me/${WHATSAPP_NUMBER}?text=Hello%20Royal%20Panel%20Support`;

const TELEGRAM_USERNAME = "Digital_marketing_aagency_India";
const TELEGRAM_LINK = `https://t.me/${TELEGRAM_USERNAME}`;

const INSTAGRAM_GROUPS = [
  "Followers", "Likes", "Reel Views", "Story Views",
  "Comments", "Saves", "Shares"
];

if (process.env.NODE_ENV === "production" && !SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required");
}

const googleClient = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  APP_URL ? APP_URL + "/auth/google/callback" : undefined
);

/* HELPERS */

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  })[c]);
}

function money(v) {
  return Number(v || 0).toFixed(2);
}

function message(v) {
  return `<div class="notice">${esc(v)}</div>`;
}

function cleanCategory(v) {
  return String(v || "Other").replace(/[<>]/g, "").trim().slice(0, 120);
}

function isInstagramService(name, category) {
  return /\binstagram\b|\binsta\b/i.test(`${name || ""} ${category || ""}`);
}

function getInstagramGroup(name, category) {
  const s = `${name || ""} ${category || ""}`.toLowerCase();

  if (/follower|subscriber/.test(s)) return "Followers";
  if (/like|favorite/.test(s)) return "Likes";
  if (/story/.test(s) && /view|watch|impression/.test(s)) return "Story Views";
  if (/reel/.test(s) && /view|watch|impression/.test(s)) return "Reel Views";
  if (/comment|reply/.test(s)) return "Comments";
  if (/share/.test(s)) return "Shares";
  if (/save|bookmark/.test(s)) return "Saves";

  return null;
}

function socialSupportLinks() {
  return `
    <div class="social-float">
      <a class="social-float-btn wa" href="${esc(WHATSAPP_LINK)}"
        target="_blank" rel="noopener">WA</a>
      <a class="social-float-btn tg" href="${esc(TELEGRAM_LINK)}"
        target="_blank" rel="noopener">TG</a>
    </div>`;
}

/* POSTGRES SESSION */

class PostgresSessionStore extends session.Store {
  get(sid, cb) {
    db("SELECT sess FROM user_sessions WHERE sid=$1 AND expire>NOW()", [sid])
      .then(r => cb(null, r.rows[0]?.sess || null))
      .catch(cb);
  }

  set(sid, sess, cb = () => {}) {
    const exp = sess.cookie?.expires
      ? new Date(sess.cookie.expires)
      : new Date(Date.now() + 7 * 86400000);

    db(`INSERT INTO user_sessions(sid,sess,expire)
        VALUES($1,$2,$3)
        ON CONFLICT(sid) DO UPDATE
        SET sess=EXCLUDED.sess,expire=EXCLUDED.expire`,
      [sid, JSON.stringify(sess), exp])
      .then(() => cb(null)).catch(cb);
  }

  destroy(sid, cb = () => {}) {
    db("DELETE FROM user_sessions WHERE sid=$1", [sid])
      .then(() => cb(null)).catch(cb);
  }

  touch(sid, sess, cb = () => {}) {
    const exp = sess.cookie?.expires
      ? new Date(sess.cookie.expires)
      : new Date(Date.now() + 7 * 86400000);

    db("UPDATE user_sessions SET expire=$1 WHERE sid=$2", [exp, sid])
      .then(() => cb(null)).catch(cb);
  }
}

app.use(session({
  name: "royal.sid",
  store: new PostgresSessionStore(),
  secret: SESSION_SECRET || crypto.randomBytes(48).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 86400000
  }
}));

/* DATABASE SETUP */

async function setupDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      email VARCHAR(200) UNIQUE,
      password_hash TEXT,
      password TEXT,
      google_id TEXT,
      balance NUMERIC(14,2) DEFAULT 0,
      is_admin BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(200);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS balance NUMERIC(14,2) DEFAULT 0
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS services(
      id SERIAL PRIMARY KEY,
      provider_id TEXT,
      provider_source TEXT DEFAULT 'socialadd',
      provider_type TEXT DEFAULT 'Default',
      name TEXT NOT NULL,
      category TEXT DEFAULT 'Other',
      service_group TEXT DEFAULT 'Other',
      description TEXT DEFAULT '',
      average_time TEXT DEFAULT '',
      rate NUMERIC(14,4) DEFAULT 0,
      provider_rate NUMERIC(14,6) DEFAULT 0,
      min INTEGER DEFAULT 100,
      max INTEGER DEFAULT 1000000,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    ALTER TABLE services ADD COLUMN IF NOT EXISTS provider_source TEXT DEFAULT 'socialadd';
    ALTER TABLE services ADD COLUMN IF NOT EXISTS provider_type TEXT DEFAULT 'Default';
    ALTER TABLE services ADD COLUMN IF NOT EXISTS provider_rate NUMERIC(14,6) DEFAULT 0;
    ALTER TABLE services ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '';
    ALTER TABLE services ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE;
    ALTER TABLE services ADD COLUMN IF NOT EXISTS service_group TEXT DEFAULT 'Other';
    ALTER TABLE services ADD COLUMN IF NOT EXISTS average_time TEXT DEFAULT ''
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS orders(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      service_id INTEGER,
      service_name TEXT,
      provider_order_id TEXT,
      link TEXT,
      quantity INTEGER,
      charge NUMERIC(14,2),
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS service_name TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS provider_order_id TEXT
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS payments(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(14,2),
      utr TEXT,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS tickets(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      message TEXT,
      status TEXT DEFAULT 'Open',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS refunds(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(14,2),
      reason TEXT,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    ALTER TABLE refunds ADD COLUMN IF NOT EXISTS funds_reserved BOOLEAN DEFAULT FALSE
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS panel_settings(
      setting_key TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS user_sessions(
      sid VARCHAR(255) PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMPTZ NOT NULL
    )
  `);

  await db(`
    CREATE INDEX IF NOT EXISTS user_sessions_expire_idx
    ON user_sessions(expire)
  `);

  await db(`
    INSERT INTO panel_settings(setting_key,setting_value)
    VALUES('provider_enabled','true'),('services_enabled','true')
    ON CONFLICT(setting_key) DO NOTHING
  `);

  await db(`
    DELETE FROM services a USING services b
    WHERE a.id>b.id AND a.provider_id IS NOT NULL
    AND a.provider_source=b.provider_source
    AND a.provider_id=b.provider_id
  `);

  await db(`
    CREATE UNIQUE INDEX IF NOT EXISTS services_provider_unique
    ON services(provider_source,provider_id)
    WHERE provider_id IS NOT NULL
  `);

  const existing = await db("SELECT id,name,category FROM services");

  for (const s of existing.rows) {
    const group = isInstagramService(s.name, s.category)
      ? getInstagramGroup(s.name, s.category) : null;

    if (group && INSTAGRAM_GROUPS.includes(group)) {
      await db(
        "UPDATE services SET category='Instagram',service_group=$1 WHERE id=$2",
        [group, s.id]
      );
    } else {
      await db("UPDATE services SET active=FALSE WHERE id=$1", [s.id]);
    }
  }

  if (ADMIN_EMAIL) {
    await db("UPDATE users SET is_admin=TRUE WHERE LOWER(email)=LOWER($1)", [ADMIN_EMAIL]);
  }

  if (ADMIN_USERNAME && ADMIN_PASSWORD) {
    const old = await db("SELECT id FROM users WHERE username=$1", [ADMIN_USERNAME]);

    if (!old.rows.length) {
      const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await db(
        `INSERT INTO users(username,email,password_hash,password,is_admin)
         VALUES($1,$2,$3,$3,TRUE) ON CONFLICT(username) DO NOTHING`,
        [ADMIN_USERNAME, ADMIN_EMAIL || null, hash]
      );
    }
  }

  console.log("Database ready");
}

/* SETTINGS */

async function setting(k) {
  const r = await db(
    "SELECT setting_value FROM panel_settings WHERE setting_key=$1", [k]
  );
  return r.rows[0]?.setting_value || "false";
}

async function setSetting(k, v) {
  await db(
    `INSERT INTO panel_settings(setting_key,setting_value)
     VALUES($1,$2) ON CONFLICT(setting_key)
     DO UPDATE SET setting_value=EXCLUDED.setting_value`,
    [k, String(v)]
  );
}

/* AUTH */

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

async function requireAdmin(req, res, next) {
  try {
    if (!req.session.user?.id) return res.status(403).send("Admin access required");

    const r = await db("SELECT is_admin FROM users WHERE id=$1", [req.session.user.id]);

    if (!r.rows[0]?.is_admin) {
      req.session.user.is_admin = false;
      return res.status(403).send("Admin access required");
    }

    req.session.user.is_admin = true;
    next();
  } catch (e) {
    next(e);
  }
}

function createUserSession(req, user, res) {
  req.session.regenerate(err => {
    if (err) return res.status(500).send("Session error");

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin: Boolean(user.is_admin)
    };

    req.session.save(err => {
      if (err) return res.status(500).send("Session save error");
      res.redirect(user.is_admin ? "/admin" : "/services");
    });
  });
}

/* DESIGN AND PAGE TEMPLATE */

function page(title, body, user = null) {
  const isAdmin = Boolean(user?.is_admin);
  const adminPage = isAdmin && (
    title === "Admin Dashboard" || title.startsWith("Admin ")
  );

  const adminMenu = isAdmin ? `
    <div class="menu-title">ADMIN PANEL</div>
    <a class="menu-link" href="/admin">▦ Dashboard</a>
    <a class="menu-link" href="/admin/users">♟ Users Management</a>
    <a class="menu-link" href="/admin/services">▦ Services Management</a>
    <a class="menu-link" href="/admin/orders">🛒 Orders Management</a>
    <a class="menu-link" href="/admin/payments">▣ Add Funds / Payments</a>
    <a class="menu-link" href="/admin/refunds">↩ Refund Management</a>
    <a class="menu-link" href="/admin/transactions">⇄ Transactions History</a>
    <a class="menu-link" href="/admin/provider">☁ API Provider</a>
    <a class="menu-link" href="/admin/reports">▥ Reports & Analytics</a>
    <a class="menu-link" href="/admin/settings">⚙ Website Settings</a>
    <a class="menu-link" href="/admin/support">☏ Support Messages</a>
    <a class="menu-link" href="/services">↗ Customer Panel</a>
    <a class="menu-link" href="/logout">⇥ Logout</a>
  ` : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#101b38">
<title>${esc(title)} | Royal SMM Seller</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f2f4ff;color:#101b38;font-family:Arial,sans-serif}
a{text-decoration:none;color:#155eef}
button{cursor:pointer;border:0;border-radius:8px;padding:11px 16px;background:#155eef;color:white;font-weight:bold}
button:hover{opacity:.88}
input,select,textarea{width:100%;padding:12px;border:1px solid #d5dced;border-radius:8px;margin:5px 0 12px;font-size:14px;background:#fff;color:#17213c}
label{font-weight:bold;font-size:13px;display:block;margin-top:8px}
.topbar{height:70px;background:#fff;border-bottom:1px solid #e6e9f3;display:flex;align-items:center;justify-content:space-between;padding:0 20px;position:sticky;top:0;z-index:20}
.brand{font-size:22px;font-weight:900;color:#fff;line-height:1.15}
.brand span{color:#ff3737}
.admin-shell{display:flex;min-height:calc(100vh - 70px)}
.sidebar{width:258px;background:#101b38;color:white;padding:18px 13px;flex-shrink:0}
.sidebar-logo{padding:10px 10px 25px;border-bottom:1px solid #ffffff20;margin-bottom:12px}
.menu-title{font-size:10px;letter-spacing:1.5px;color:#a7b4d1;font-weight:bold;padding:16px 10px 7px}
.menu-link{display:block;padding:12px 11px;border-radius:9px;color:#e7edff;margin:3px 0;font-size:13px;font-weight:600}
.menu-link:hover,.menu-link.active{background:#155eef;color:white}
.admin-content{flex:1;min-width:0;padding:25px}
.admin-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:22px}
.admin-heading h1{margin:0;font-size:27px}
.admin-heading p{margin:7px 0;color:#66738f;font-size:13px}
.card{background:white;border:1px solid #e5e9f4;border-radius:13px;padding:18px;margin:12px 0;box-shadow:0 3px 12px #17213c0a}
.stat-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px}
.stat-card{color:white;border-radius:13px;padding:20px;min-height:145px;box-shadow:0 5px 14px #17213c18}
.stat-card .symbol{font-size:27px}
.stat-card .number{font-size:29px;font-weight:900;margin:12px 0 4px}
.stat-card .caption{font-size:13px}
.blue{background:linear-gradient(135deg,#2386ff,#0649ed)}
.purple{background:linear-gradient(135deg,#ca36f5,#8211df)}
.green{background:linear-gradient(135deg,#09c87b,#008b5a)}
.orange{background:linear-gradient(135deg,#ff9b08,#f34d0b)}
.teal{background:linear-gradient(135deg,#08b9ba,#087e91)}
.content-grid{display:grid;grid-template-columns:1fr 1.6fr;gap:14px}
.bottom-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.panel-title{font-size:17px;font-weight:800;margin:0 0 16px}
.table-wrap{width:100%;overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:560px;font-size:13px}
th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #edf0f6}
th{color:#62708d;background:#f8f9fd;white-space:nowrap}
td{color:#25334f}
.badge{display:inline-block;padding:5px 9px;border-radius:20px;background:#e9f9f0;color:#07975b;font-size:11px;font-weight:bold}
.badge.pending{background:#fff3d9;color:#d17a00}
.badge.failed{background:#ffebeb;color:#d43d3d}
.notice{padding:14px;background:#edf8ff;color:#155eef;border-radius:9px;margin:12px 0}
.muted{color:#74809b;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.form-card{max-width:650px;margin:20px auto}
.customer-main{max-width:900px;margin:22px auto;padding:0 12px 100px}
.customer-header{background:#20ad62;color:white;padding:16px;font-weight:bold}
.customer-menu{display:flex;flex-wrap:wrap;gap:10px;padding:12px;background:white}
.customer-menu a{padding:10px;color:#16894b}
.social-float{position:fixed;right:14px;bottom:14px;display:flex;gap:9px;z-index:30}
.social-float-btn{width:45px;height:45px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-weight:bold}
.wa{background:#25d366}.tg{background:#229ed9}
.chart-box{height:190px;position:relative;padding:10px}
.chart-box svg{width:100%;height:100%}
.progress{height:9px;border-radius:20px;background:#e8edf5;overflow:hidden;margin:10px 0}
.progress span{display:block;height:100%;background:#0ab879}
.mobile-menu{display:none}
@media(max-width:1000px){
.stat-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
.bottom-grid{grid-template-columns:1fr 1fr}
}
@media(max-width:700px){
.admin-shell{display:block}
.sidebar{width:100%;display:none}
.sidebar.show{display:block}
.admin-content{padding:14px}
.admin-heading h1{font-size:22px}
.stat-grid{gap:8px}
.stat-card{padding:13px;min-height:120px}
.stat-card .number{font-size:23px}
.content-grid,.bottom-grid{grid-template-columns:1fr}
.mobile-menu{display:inline-block}
.topbar{height:60px;padding:0 12px}
}
</style>
</head>
<body>
<header class="topbar">
  <a href="${isAdmin ? "/admin" : user ? "/services" : "/login"}"
     style="font-weight:900;color:#101b38;font-size:20px">
    👑 Royal <span style="color:#ef3030">SMM Seller</span>
  </a>
  ${user ? `<span style="font-size:13px;color:#34415f">
    ${esc(user.username)} ${isAdmin ? " · Admin" : ""}
  </span>` : ""}
  ${isAdmin ? `<button class="mobile-menu" onclick="document.getElementById('sidebar').classList.toggle('show')">☰</button>` : ""}
</header>

${isAdmin ? `
<div class="admin-shell">
<aside class="sidebar" id="sidebar">
  <div class="sidebar-logo">
    <div class="brand">👑 Royal<br><span>SMM Seller</span></div>
  </div>
  ${adminMenu}
  <div class="card" style="background:#172d61;color:white;border:0;margin-top:22px">
    <b>Need Help?</b><p class="muted" style="color:#cbd6f2">Contact Support</p>
    <a href="${esc(WHATSAPP_LINK)}" target="_blank"
      style="display:block;background:#155eef;color:white;padding:10px;border-radius:8px;text-align:center">WhatsApp Support</a>
  </div>
</aside>
<section class="admin-content">${body}</section>
</div>
` : `
${user ? `<nav class="customer-menu">
<a href="/services">New Order</a><a href="/orders">My Orders</a>
<a href="/funds">Add Funds</a><a href="/refund">Refund</a>
<a href="/support">Support</a>
${user.is_admin ? '<a href="/admin">Admin Panel</a>' : ""}
<a href="/logout">Logout</a>
</nav>` : ""}
<main class="customer-main">${body}</main>
`}
${user ? socialSupportLinks() : ""}
</body>
</html>`;
}

/* API PROVIDER */

async function providerRequest(params) {
  if (!PROVIDER_KEY) throw new Error("SocialAdd API key missing");

  const body = new URLSearchParams({ key: PROVIDER_KEY, ...params });

  const response = await fetch(PROVIDER_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(30000)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.error) {
    throw new Error(data.error || `Provider HTTP ${response.status}`);
  }

  return data;
}

/* HOME */

app.get("/", (req, res) => {
  res.redirect(req.session.user
    ? req.session.user.is_admin ? "/admin" : "/services"
    : "/login");
});

/* LOGIN */

app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card form-card">
      <h2>Welcome Back</h2>
      <p class="muted">Sign in to your Royal SMM Seller account</p>
      <form method="POST" action="/login">
        <label>Email or Username</label>
        <input name="email" required>
        <label>Password</label>
        <input name="password" type="password" required>
        <button style="width:100%">Sign In</button>
      </form>
      <p style="text-align:center">OR</p>
      <a href="/auth/google">🌐 Sign in with Google</a>
      <p>Don't have an account? <a href="/register">Register</a></p>
    </div>
  `));
});

app.post("/login", async (req, res, next) => {
  try {
    const identity = String(req.body.email || "").trim();

    const r = await db(
      `SELECT * FROM users
       WHERE LOWER(email)=LOWER($1) OR LOWER(username)=LOWER($1) LIMIT 1`,
      [identity]
    );

    const u = r.rows[0];
    const hash = u?.password_hash || u?.password;

    if (!u || !hash ||
        !await bcrypt.compare(String(req.body.password || ""), hash)) {
      return res.status(401).send(page("Login", message("Invalid login details")));
    }

    createUserSession(req, u, res);
  } catch (e) { next(e); }
});

/* REGISTER */

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card form-card">
      <h2>Create Account</h2>
      <form method="POST" action="/register">
        <label>Username</label>
        <input name="username" required maxlength="100">
        <label>Email</label>
        <input name="email" type="email" required maxlength="200">
        <label>Password</label>
        <input name="password" type="password" minlength="6" required>
        <button style="width:100%">Create Account</button>
      </form>
      <p><a href="/auth/google">Sign up with Google</a></p>
      <p>Already registered? <a href="/login">Login</a></p>
    </div>
  `));
});

app.post("/register", async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!username || !email || password.length < 6 ||
        username.length > 100 || email.length > 200) {
      return res.status(400).send(page("Register", message("Enter valid details")));
    }

    const hash = await bcrypt.hash(password, 12);

    const r = await db(
      `INSERT INTO users(username,email,password_hash,password)
       VALUES($1,$2,$3,$3) RETURNING *`,
      [username, email, hash]
    );

    createUserSession(req, r.rows[0], res);
  } catch (e) {
    if (e.code === "23505") {
      return res.status(400).send(page("Register", message("Username or email already exists")));
    }
    next(e);
  }
});

/* GOOGLE LOGIN */

app.get("/auth/google", (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !APP_URL) {
    return res.status(503).send("Google Login environment settings are missing");
  }

  const state = crypto.randomBytes(24).toString("hex");
  req.session.googleState = state;

  req.session.save(err => {
    if (err) return res.status(500).send("Could not start Google Login");

    res.redirect(googleClient.generateAuthUrl({
      access_type: "online",
      scope: ["openid", "email", "profile"],
      state
    }));
  });
});

app.get("/auth/google/callback", async (req, res, next) => {
  try {
    if (!req.query.code || req.query.state !== req.session.googleState) {
      return res.status(400).send("Google login state error");
    }

    delete req.session.googleState;

    const { tokens } = await googleClient.getToken(req.query.code);
    if (!tokens.id_token) return res.status(400).send("Google ID token missing");

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID
    });

    const profile = ticket.getPayload();

    if (!profile?.email || !profile.email_verified) {
      return res.status(400).send("Google email not verified");
    }

    const email = profile.email.toLowerCase();
    let r = await db("SELECT * FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1", [email]);
    let user = r.rows[0];

    if (!user) {
      const base = (profile.name || email.split("@")[0])
        .replace(/[^a-zA-Z0-9_]/g, "").slice(0, 20) || "customer";

      const username = base + "_" + crypto.randomBytes(3).toString("hex");

      r = await db(
        `INSERT INTO users(username,email,google_id)
         VALUES($1,$2,$3) RETURNING *`,
        [username, email, profile.sub]
      );
      user = r.rows[0];
    } else if (!user.google_id) {
      await db("UPDATE users SET google_id=$1 WHERE id=$2", [profile.sub, user.id]);
      user.google_id = profile.sub;
    }

    if (ADMIN_EMAIL && email === ADMIN_EMAIL) {
      await db("UPDATE users SET is_admin=TRUE WHERE id=$1", [user.id]);
      user.is_admin = true;
    }

    createUserSession(req, user, res);
  } catch (e) { next(e); }
});

app.get("/dashboard", requireLogin, (req, res) => {
  res.redirect(req.session.user.is_admin ? "/admin" : "/services");
});

/* CUSTOMER SERVICES */

app.get("/services", requireLogin, async (req, res, next) => {
  try {
    const enabled = await setting("services_enabled");

    const wallet = await db("SELECT balance FROM users WHERE id=$1", [req.session.user.id]);

    const result = await db(
      `SELECT * FROM services WHERE active=TRUE AND category='Instagram'
       AND service_group=ANY($1::text[]) ORDER BY service_group,id`,
      [INSTAGRAM_GROUPS]
    );

    const services = result.rows;
    const categories = INSTAGRAM_GROUPS.filter(g =>
      services.some(s => s.service_group === g)
    );

    const payload = services.map(s => ({
      id: s.id, providerId: String(s.provider_id || ""),
      name: s.name, category: "Instagram", group: s.service_group,
      description: s.description || "", averageTime: s.average_time || "",
      rate: Number(s.rate), min: Number(s.min), max: Number(s.max)
    }));

    const safePayload = JSON.stringify(payload).replace(/</g, "\\u003c");

    res.send(page("Services", `
      <div class="card">
        <div style="background:#138e50;color:white;padding:16px;border-radius:10px">
          WALLET BALANCE
          <h2 style="color:white">₹${money(wallet.rows[0]?.balance)}</h2>
        </div>
        <h2>Instagram New Order</h2>
        ${enabled === "true" ? `
        <form method="POST" action="/order" id="orderForm">
          <label>Search Instagram Services</label>
          <input type="search" id="serviceSearch" placeholder="Search service...">
          <label>Instagram Category</label>
          <select id="categorySelect" required>
            <option value="">Select Category</option>
            ${categories.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("")}
          </select>
          <label>Service</label>
          <select name="service_id" id="serviceSelect" required disabled>
            <option value="">Select Category First</option>
          </select>
          <label>Description</label>
          <div class="notice" id="serviceDescription">Select a service.</div>
          <label>Average Time</label>
          <div class="notice" id="averageTime">—</div>
          <label>Instagram Link</label>
          <input name="link" required maxlength="2000">
          <label>Quantity</label>
          <input name="quantity" id="quantity" type="number" min="1" required>
          <div class="muted" id="quantityLimit"></div>
          <label>Charge</label>
          <h2 id="charge">₹0.00</h2>
          <button style="width:100%">Submit Order</button>
        </form>
        <script>
          const SERVICES=${safePayload};
          const cat=document.getElementById('categorySelect');
          const sel=document.getElementById('serviceSelect');
          const search=document.getElementById('serviceSearch');
          const qty=document.getElementById('quantity');
          const desc=document.getElementById('serviceDescription');
          const avg=document.getElementById('averageTime');
          const lim=document.getElementById('quantityLimit');
          const charge=document.getElementById('charge');
          let current=null;

          function fill(){
            const list=SERVICES.filter(s=>
              (!cat.value||s.group===cat.value) &&
              (!search.value||(s.name+' '+s.providerId).toLowerCase().includes(search.value.toLowerCase()))
            );
            sel.innerHTML='<option value="">Select Service</option>'+
              list.map(s=>'<option value="'+s.id+'">'+
              s.providerId+' - '+s.name+' — ₹'+s.rate.toFixed(2)+'/1K</option>').join('');
            sel.disabled=!list.length;
            current=null;info();
          }

          function info(){
            current=SERVICES.find(s=>String(s.id)===sel.value)||null;
            if(!current){
              desc.textContent='Select a service.';
              avg.textContent='—';lim.textContent='';
              qty.removeAttribute('min');qty.removeAttribute('max');
              charge.textContent='₹0.00';return;
            }
            desc.textContent=current.description||'No description';
            avg.textContent=current.averageTime||'Not provided';
            qty.min=current.min;qty.max=current.max;
            lim.textContent='Minimum: '+current.min+' | Maximum: '+current.max;
            calc();
          }

          function calc(){
            const n=Number(qty.value||0);
            charge.textContent='₹'+(current&&n>0?current.rate*n/1000:0).toFixed(2);
          }

          cat.addEventListener('change',fill);
          search.addEventListener('input',fill);
          sel.addEventListener('change',info);
          qty.addEventListener('input',calc);
          fill();
        </script>
        ` : "<p>Services are temporarily disabled.</p>"}
      </div>
    `, req.session.user));
  } catch (e) { next(e); }
});

/* PLACE ORDER */

app.post("/order", requireLogin, async (req, res, next) => {
  const client = await pool.connect();
  let orderId;

  try {
    await client.query("BEGIN");

    if (await setting("services_enabled") !== "true") {
      throw new Error("Services are disabled");
    }

    const sr = await client.query(
      `SELECT * FROM services WHERE id=$1 AND active=TRUE
       AND category='Instagram' AND service_group=ANY($2::text[]) FOR UPDATE`,
      [req.body.service_id, INSTAGRAM_GROUPS]
    );

    const service = sr.rows[0];
    if (!service) throw new Error("Instagram service not found");

    if (service.provider_source === "socialadd" &&
        (await setting("provider_enabled") !== "true" || !PROVIDER_KEY || !service.provider_id)) {
      throw new Error("Provider API is disabled or service configuration missing");
    }

    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(quantity) || quantity < Number(service.min) ||
        quantity > Number(service.max) || !link || link.length > 2000) {
      throw new Error(`Quantity must be ${service.min} to ${service.max}`);
    }

    const charge = Math.round(Number(service.rate) * quantity / 1000 * 100) / 100;
    if (!Number.isFinite(charge) || charge <= 0) throw new Error("Invalid price");

    const ur = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE", [req.session.user.id]
    );

    if (!ur.rows[0] || Number(ur.rows[0].balance) < charge) {
      throw new Error("Insufficient wallet balance");
    }

    await client.query("UPDATE users SET balance=balance-$1 WHERE id=$2",
      [charge, req.session.user.id]);

    const or = await client.query(
      `INSERT INTO orders(user_id,service_id,service_name,link,quantity,charge,status)
       VALUES($1,$2,$3,$4,$5,$6,'Pending') RETURNING id`,
      [req.session.user.id, service.id, service.name, link, quantity, charge]
    );

    orderId = or.rows[0].id;
    await client.query("COMMIT");

    if (service.provider_source === "socialadd") {
      try {
        const data = await providerRequest({
          action: "add", service: String(service.provider_id),
          link, quantity: String(quantity)
        });

        if (!data.order) throw new Error(data.error || "Provider order ID missing");

        await db(
          "UPDATE orders SET provider_order_id=$1,status='Processing' WHERE id=$2",
          [String(data.order), orderId]
        );
      } catch (pe) {
        const rc = await pool.connect();
        try {
          await rc.query("BEGIN");
          const lock = await rc.query("SELECT * FROM orders WHERE id=$1 FOR UPDATE", [orderId]);

          if (lock.rows[0]?.status === "Pending") {
            await rc.query("UPDATE users SET balance=balance+$1 WHERE id=$2",
              [lock.rows[0].charge, lock.rows[0].user_id]);
            await rc.query(
              "UPDATE orders SET status='Provider Error - Refunded' WHERE id=$1",
              [orderId]
            );
          }

          await rc.query("COMMIT");
        } catch (e) {
          await rc.query("ROLLBACK").catch(() => {});
          console.error("Automatic refund error:", e);
        } finally { rc.release(); }

        console.error("Provider order failed:", pe.message);
      }
    }

    res.redirect("/orders");
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    res.status(400).send(page("Order", message(e.message), req.session.user));
  } finally { client.release(); }
});

/* CUSTOMER ORDERS */

app.get("/orders", requireLogin, async (req, res, next) => {
  try {
    const r = await db(
      "SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC LIMIT 100",
      [req.session.user.id]
    );

    const rows = r.rows.map(o => `
      <tr><td>${esc(o.id)}</td><td>${esc(o.service_name || o.service_id)}</td>
      <td>${esc(o.quantity)}</td><td>₹${money(o.charge)}</td><td>${esc(o.status)}</td></tr>
    `).join("");

    res.send(page("My Orders", `
      <div class="card"><h2>My Orders</h2><div class="table-wrap">
      <table><tr><th>ID</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th></tr>
      ${rows}</table></div></div>
    `, req.session.user));
  } catch (e) { next(e); }
});

/* ADD FUNDS */

app.get("/funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
    <div class="card form-card">
      <h2>Add Funds</h2>
      <div style="text-align:center">
        <img src="/payment-qr.png" alt="UPI QR" style="max-width:220px;width:100%"
          onerror="this.style.display='none'">
        <p>Scan QR Code to Pay</p>
      </div>
      <p>UPI ID: <b>${esc(UPI_ID)}</b></p>
      <form method="POST" action="/funds">
        <label>Amount (₹10–₹2000)</label>
        <input name="amount" type="number" min="10" max="2000" step=".01" required>
        <label>UTR / Transaction ID</label>
        <input name="utr" required maxlength="150">
        <button style="width:100%">Submit Payment</button>
      </form>
      <p class="muted">Wallet में पैसे Admin Approval के बाद जुड़ेंगे।</p>
    </div>
  `, req.session.user));
});

app.post("/funds", requireLogin, async (req, res, next) => {
  try {
    const amount = Number(req.body.amount);
    const utr = String(req.body.utr || "").trim();

    if (!Number.isFinite(amount) || amount < 10 || amount > 2000 ||
        !utr || utr.length > 150) {
      return res.status(400).send("Minimum ₹10 and maximum ₹2000. Valid UTR required.");
    }

    await db(
      "INSERT INTO payments(user_id,amount,utr,status) VALUES($1,$2,$3,'Pending')",
      [req.session.user.id, amount, utr]
    );

    res.send(page("Payment", message("Payment submitted. Waiting for Admin Approval."), req.session.user));
  } catch (e) { next(e); }
});

/* REFUND */

app.get("/refund", requireLogin, (req, res) => {
  res.send(page("Refund", `
    <div class="card form-card"><h2>Refund Request</h2>
      <form method="POST" action="/refund">
        <label>Amount (₹10–₹2000)</label>
        <input name="amount" type="number" min="10" max="2000" step=".01" required>
        <label>Reason</label>
        <textarea name="reason" required maxlength="2000"></textarea>
        <button style="width:100%">Submit Refund Request</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/refund", requireLogin, async (req, res, next) => {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");

    const amount = Number(req.body.amount);
    const reason = String(req.body.reason || "").trim();

    if (!Number.isFinite(amount) || amount < 10 || amount > 2000 ||
        !reason || reason.length > 2000) throw new Error("Refund must be ₹10–₹2000");

    const u = await c.query("SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.session.user.id]);

    if (!u.rows[0] || Number(u.rows[0].balance) < amount) {
      throw new Error("Insufficient wallet balance");
    }

    await c.query("UPDATE users SET balance=balance-$1 WHERE id=$2",
      [amount, req.session.user.id]);

    await c.query(
      `INSERT INTO refunds(user_id,amount,reason,status,funds_reserved)
       VALUES($1,$2,$3,'Pending',TRUE)`,
      [req.session.user.id, amount, reason]
    );

    await c.query("COMMIT");
    res.send(page("Refund", message("Refund request sent to Admin."), req.session.user));
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    res.status(400).send(page("Refund", message(e.message), req.session.user));
  } finally { c.release(); }
});

/* SUPPORT */

app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
    <div class="card form-card"><h2>Support</h2>
      <form method="POST" action="/support">
        <textarea name="message" required maxlength="3000"
          placeholder="Write your message"></textarea>
        <button>Send Message</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/support", requireLogin, async (req, res, next) => {
  try {
    const t = String(req.body.message || "").trim();
    if (!t || t.length > 3000) return res.status(400).send("Enter valid message");

    await db("INSERT INTO tickets(user_id,message,status) VALUES($1,$2,'Open')",
      [req.session.user.id, t]);
    res.redirect("/services");
  } catch (e) { next(e); }
});

/* ADMIN DASHBOARD */

app.get("/admin", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const [stats, recentUsers, recentOrders, recentPayments, revenue, settings] =
      await Promise.all([
        db(`
          SELECT
          (SELECT COUNT(*) FROM users WHERE is_admin=FALSE) AS users,
          (SELECT COUNT(*) FROM orders) AS orders,
          (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Approved') AS revenue,
          (SELECT COUNT(*) FROM payments WHERE status='Pending') AS pending_payments,
          (SELECT COUNT(*) FROM orders WHERE LOWER(status) IN ('pending','processing')) AS pending_orders,
          (SELECT COUNT(*) FROM refunds WHERE status='Pending') AS pending_refunds,
          (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Approved'
             AND created_at >= date_trunc('month',NOW())) AS monthly_revenue
        `),
        db("SELECT id,username,email,created_at FROM users ORDER BY id DESC LIMIT 5"),
        db("SELECT id,service_name,quantity,status,created_at FROM orders ORDER BY id DESC LIMIT 5"),
        db("SELECT id,amount,status,created_at FROM payments ORDER BY id DESC LIMIT 5"),
        db(`
          SELECT TO_CHAR(date_trunc('day',created_at),'DD Mon') AS day,
          COALESCE(SUM(amount),0) AS amount
          FROM payments WHERE status='Approved'
          AND created_at >= NOW()-INTERVAL '30 days'
          GROUP BY date_trunc('day',created_at)
          ORDER BY date_trunc('day',created_at)
        `),
        Promise.all([setting("provider_enabled"), setting("services_enabled")])
      ]);

    const x = stats.rows[0];
    const users = recentUsers.rows;
    const orders = recentOrders.rows;
    const payments = recentPayments.rows;

    const userRows = users.map(u => `
      <tr><td>${esc(u.username)}</td><td>${esc(u.email || "—")}</td>
      <td>${new Date(u.created_at).toLocaleDateString("en-IN")}</td></tr>
    `).join("");

    const orderRows = orders.map(o => `
      <tr><td>#${esc(o.id)}</td><td>${esc(o.service_name || "Service")}</td>
      <td>${esc(o.quantity)}</td><td>${esc(o.status)}</td></tr>
    `).join("");

    const paymentRows = payments.map(p => `
      <tr><td>₹${money(p.amount)}</td><td>${esc(p.status)}</td>
      <td>${new Date(p.created_at).toLocaleDateString("en-IN")}</td></tr>
    `).join("");

    const chartData = JSON.stringify(revenue.rows.map(r => ({
      day: r.day, amount: Number(r.amount)
    }))).replace(/</g, "\\u003c");

    res.send(page("Admin Dashboard", `
      <div class="admin-heading">
        <div><h1>▣ Admin Dashboard</h1>
        <p>Welcome back, Admin! Here's what's happening today.</p></div>
        <span class="badge">Live Dashboard</span>
      </div>

      <div class="stat-grid">
        <div class="stat-card blue"><div class="symbol">♟</div>
          <div class="number">${esc(x.users)}</div><div class="caption">Total Users</div></div>
        <div class="stat-card purple"><div class="symbol">🛒</div>
          <div class="number">${esc(x.orders)}</div><div class="caption">Total Orders</div></div>
        <div class="stat-card green"><div class="symbol">▣</div>
          <div class="number">₹${money(x.revenue)}</div><div class="caption">Total Revenue</div></div>
        <div class="stat-card orange"><div class="symbol">◷</div>
          <div class="number">${esc(x.pending_payments)}</div><div class="caption">Pending Payments</div></div>
      </div>

      <div class="content-grid" style="margin-top:16px">
        <div class="card">
          <h3 class="panel-title">Payment Statistics</h3>
          <div style="font-size:35px;font-weight:900;color:#08a96e">
            ₹${money(x.monthly_revenue)}
          </div>
          <p class="muted">Approved Payments This Month</p>
          <div class="progress"><span style="width:${Number(x.pending_payments) ? 75 : 100}%"></span></div>
          <p>Pending payments: <b>${esc(x.pending_payments)}</b></p>
          <p>Pending refunds: <b>${esc(x.pending_refunds)}</b></p>
          <p>Pending orders: <b>${esc(x.pending_orders)}</b></p>
          <a href="/admin/payments">View Payments →</a>
        </div>

        <div class="card">
          <h3 class="panel-title">Revenue Overview · Last 30 Days</h3>
          <div class="chart-box"><svg id="revenueChart" viewBox="0 0 600 190"
            preserveAspectRatio="none"></svg></div>
          <p class="muted">Daily approved payment totals</p>
        </div>
      </div>

      <div class="bottom-grid">
        <div class="card">
          <h3 class="panel-title">♟ Recent Users</h3>
          <div class="table-wrap"><table>
            <tr><th>User</th><th>Email</th><th>Date</th></tr>
            ${userRows || "<tr><td colspan='3'>No users yet</td></tr>"}
          </table></div>
          <p><a href="/admin/users">View All →</a></p>
        </div>
        <div class="card">
          <h3 class="panel-title">🛒 Recent Orders</h3>
          <div class="table-wrap"><table>
            <tr><th>Order</th><th>Service</th><th>Qty</th><th>Status</th></tr>
            ${orderRows || "<tr><td colspan='4'>No orders yet</td></tr>"}
          </table></div>
          <p><a href="/admin/orders">View All →</a></p>
        </div>
        <div class="card">
          <h3 class="panel-title">▣ Recent Payments</h3>
          <div class="table-wrap"><table>
            <tr><th>Amount</th><th>Status</th><th>Date</th></tr>
            ${paymentRows || "<tr><td colspan='3'>No payments yet</td></tr>"}
          </table></div>
          <p><a href="/admin/payments">View All →</a></p>
        </div>
      </div>

      <div class="card">
        <h3 class="panel-title">Quick Management</h3>
        <div class="grid">
          <a href="/admin/users">👥 Manage Users</a>
          <a href="/admin/services">🛠 Manage Services & Prices</a>
          <a href="/admin/orders">📦 Manage Orders</a>
          <a href="/admin/payments">💳 Approve Payments</a>
          <a href="/admin/refunds">↩ Manage Refunds</a>
          <a href="/admin/provider">☁ API Settings</a>
          <a href="/admin/reports">📊 Reports</a>
          <a href="/admin/settings">⚙ Website Settings</a>
        </div>
      </div>

      <script>
      const data=${chartData};
      const svg=document.getElementById('revenueChart');
      if(data.length){
        const max=Math.max(...data.map(x=>x.amount),1);
        const points=data.map((x,i)=>{
          const px=data.length===1?300:20+i*560/(data.length-1);
          const py=165-(x.amount/max)*140;
          return px+','+py;
        }).join(' ');
        svg.innerHTML=
          '<line x1="20" y1="165" x2="580" y2="165" stroke="#dce3f1"/>'+
          '<polyline points="'+points+'" fill="none" stroke="#384cff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>'+
          points.split(' ').map(p=>{
            const a=p.split(',');
            return '<circle cx="'+a[0]+'" cy="'+a[1]+'" r="4" fill="#384cff"/>';
          }).join('');
      }else{
        svg.innerHTML='<text x="180" y="95" fill="#78849c">No revenue data yet</text>';
      }
      </script>
    `, req.session.user));
  } catch (e) { next(e); }
});

/* PROVIDER TOGGLES */

app.post("/admin/provider-toggle", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    await setSetting("provider_enabled", req.body.value === "true");
    res.redirect("/admin/provider");
  } catch (e) { next(e); }
});

app.post("/admin/services-toggle", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    await setSetting("services_enabled", req.body.value === "true");
    res.redirect("/admin");
  } catch (e) { next(e); }
});

/* PROVIDER PAGE */

app.get("/admin/provider", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const enabled = await setting("provider_enabled");
    res.send(page("Admin Provider", `
      <div class="admin-heading"><div><h1>API Provider Management</h1>
      <p>Manage your SocialAdd API connection</p></div></div>
      <div class="card">
        <h3>SocialAdd Provider</h3>
        <p>Connection status: <b>${enabled === "true" ? "Enabled" : "Disabled"}</b></p>
        <p>API URL: ${esc(PROVIDER_URL)}</p>
        <p>API key: ${PROVIDER_KEY ? "Configured" : "Missing"}</p>
        <form method="POST" action="/admin/provider-toggle">
          <button name="value" value="true">Enable Provider</button>
          <button name="value" value="false">Disable Provider</button>
        </form>
        <form method="POST" action="/admin/provider-test">
          <button>Test Provider API</button>
        </form>
        <form method="POST" action="/admin/import">
          <button>Import / Update Instagram Services</button>
        </form>
      </div>
    `, req.session.user));
  } catch (e) { next(e); }
});

app.post("/admin/provider-test", requireLogin, requireAdmin, async (req, res) => {
  try {
    const d = await providerRequest({ action: "balance" });
    res.send(page("Admin Provider", message("API response: " + JSON.stringify(d)), req.session.user));
  } catch (e) {
    res.status(500).send(page("Admin Provider", message("Provider Error: " + e.message), req.session.user));
  }
});

/* IMPORT INSTAGRAM SERVICES */

app.post("/admin/import", requireLogin, requireAdmin, async (req, res) => {
  try {
    if (await setting("provider_enabled") !== "true") {
      throw new Error("Provider API is disabled");
    }

    const list = await providerRequest({ action: "services" });
    if (!Array.isArray(list)) throw new Error("Invalid provider response");

    await db("UPDATE services SET active=FALSE WHERE provider_source='socialadd'");

    let imported = 0;
    let skipped = 0;

    for (const item of list) {
      const providerId = String(item.service || "").trim();
      const name = String(item.name || "").trim();
      const rawCategory = String(item.category || "").trim();

      if (!providerId || !name || !isInstagramService(name, rawCategory)) {
        skipped++; continue;
      }

      const group = getInstagramGroup(name, rawCategory);
      if (!group || !INSTAGRAM_GROUPS.includes(group)) { skipped++; continue; }

      const providerRate = Number(item.rate || 0);
      const min = Number(item.min || 1);
      const max = Number(item.max || 1000000);

      if (!Number.isFinite(providerRate) || providerRate < 0 ||
          !Number.isInteger(min) || !Number.isInteger(max) ||
          min < 1 || max < min) {
        skipped++; continue;
      }

      const sellingRate = providerRate * 2;
      const average = String(item.average_time || item.avg_time ||
        item.averageTime || item.time || "").slice(0, 200);
      const description = String(item.description || "").slice(0, 5000);
      const providerType = String(item.type || "Default").slice(0, 100);

      await db(
        `INSERT INTO services(
          provider_id,provider_source,provider_type,name,category,service_group,
          description,average_time,rate,provider_rate,min,max,active
        )
        VALUES($1,'socialadd',$2,$3,'Instagram',$4,$5,$6,$7,$8,$9,$10,TRUE)
        ON CONFLICT(provider_source,provider_id) WHERE provider_id IS NOT NULL
        DO UPDATE SET provider_type=EXCLUDED.provider_type,name=EXCLUDED.name,
        category='Instagram',service_group=EXCLUDED.service_group,
        description=EXCLUDED.description,average_time=EXCLUDED.average_time,
        rate=EXCLUDED.rate,provider_rate=EXCLUDED.provider_rate,
        min=EXCLUDED.min,max=EXCLUDED.max,active=TRUE`,
        [providerId, providerType, name, group, description, average,
          sellingRate, providerRate, min, max]
      );
      imported++;
    }

    res.send(page("Admin Services", message(
      `Imported or updated: ${imported}. Skipped: ${skipped}.`
    ), req.session.user));
  } catch (e) {
    res.status(500).send(page("Admin Services", message(e.message), req.session.user));
  }
});

/* ADMIN SERVICES AND PRICE MANAGEMENT */

app.get("/admin/services", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(
      `SELECT * FROM services WHERE category='Instagram'
       AND service_group=ANY($1::text[]) ORDER BY id DESC LIMIT 1000`,
      [INSTAGRAM_GROUPS]
    );

    const rows = r.rows.map(s => `
      <tr>
        <td>${esc(s.id)}</td><td>${esc(s.service_group)}</td>
        <td>${esc(s.name)}</td><td>${esc(s.min)}–${esc(s.max)}</td>
        <td>₹${money(s.provider_rate)}</td><td>₹${money(s.rate)}</td>
        <td>${s.active ? '<span class="badge">Active</span>' : '<span class="badge failed">Disabled</span>'}</td>
        <td>
          <form method="POST" action="/admin/service/${esc(s.id)}">
            <input name="rate" type="number" step=".0001" min="0"
              value="${esc(s.rate)}" required>
            <button name="action" value="save">Save Price</button>
            <button name="action" value="${s.active ? "disable" : "enable"}">
              ${s.active ? "Disable" : "Enable"}
            </button>
          </form>
        </td>
      </tr>
    `).join("");

    res.send(page("Admin Services", `
      <div class="admin-heading"><div><h1>Services Management</h1>
      <p>Manage Instagram services and selling prices</p></div></div>
      <div class="card">
        <form method="POST" action="/admin/import">
          <button>Import / Update Services</button>
        </form>
        <input id="adminSearch" placeholder="Search service ID, name or category">
        <div class="table-wrap"><table>
          <thead><tr><th>ID</th><th>Category</th><th>Service</th>
          <th>Limits</th><th>Provider Rate</th><th>Selling Rate / 1K</th>
          <th>Status</th><th>Manage Price</th></tr></thead>
          <tbody id="serviceRows">${rows}</tbody>
        </table></div>
      </div>
      <script>
      document.getElementById('adminSearch').addEventListener('input',e=>{
        document.querySelectorAll('#serviceRows tr').forEach(r=>{
          r.style.display=r.textContent.toLowerCase().includes(e.target.value.toLowerCase())?'':'none';
        });
      });
      </script>
    `, req.session.user));
  } catch (e) { next(e); }
});

app.post("/admin/service/:id", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) return res.status(400).send("Invalid service ID");

    if (req.body.action === "save") {
      const rate = Number(req.body.rate);
      if (!Number.isFinite(rate) || rate < 0) return res.status(400).send("Invalid price");

      await db(
        `UPDATE services SET rate=$1 WHERE id=$2 AND category='Instagram'
         AND service_group=ANY($3::text[])`,
        [rate, id, INSTAGRAM_GROUPS]
      );
    } else {
      const active = req.body.action === "enable";
      await db(
        `UPDATE services SET active=$1 WHERE id=$2 AND category='Instagram'
         AND service_group=ANY($3::text[])`,
        [active, id, INSTAGRAM_GROUPS]
      );
    }
    res.redirect("/admin/services");
  } catch (e) { next(e); }
});

/* ADMIN PAYMENTS */

app.get("/admin/payments", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT p.*,u.username,u.email FROM payments p
      JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 500
    `);

    const rows = r.rows.map(p => `
      <tr><td>${esc(p.id)}</td><td>${esc(p.username)}</td>
      <td>${esc(p.email || "")}</td><td>₹${money(p.amount)}</td>
      <td>${esc(p.utr)}</td><td>${esc(p.status)}</td><td>
      ${p.status === "Pending" ? `
        <form method="POST" action="/admin/payment/${esc(p.id)}">
          <button name="action" value="approve">Approve</button>
          <button name="action" value="reject">Reject</button>
        </form>` : "Processed"}
      </td></tr>
    `).join("");

    res.send(page("Admin Payments", `
      <div class="admin-heading"><div><h1>Add Funds / Payments</h1>
      <p>Review and approve customer payments</p></div></div>
      <div class="card"><div class="table-wrap"><table>
      <tr><th>ID</th><th>User</th><th>Email</th><th>Amount</th>
      <th>UTR</th><th>Status</th><th>Action</th></tr>
      ${rows || "<tr><td colspan='7'>No payments</td></tr>"}
      </table></div></div>
    `, req.session.user));
  } catch (e) { next(e); }
});

app.post("/admin/payment/:id", requireLogin, requireAdmin, async (req, res, next) => {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");

    const r = await c.query("SELECT * FROM payments WHERE id=$1 FOR UPDATE", [req.params.id]);
    const p = r.rows[0];

    if (!p || p.status !== "Pending") throw new Error("Payment already processed");

    if (req.body.action === "approve") {
      await c.query("UPDATE users SET balance=balance+$1 WHERE id=$2", [p.amount, p.user_id]);
      await c.query("UPDATE payments SET status='Approved' WHERE id=$1", [p.id]);
    } else if (req.body.action === "reject") {
      await c.query("UPDATE payments SET status='Rejected' WHERE id=$1", [p.id]);
    } else throw new Error("Invalid action");

    await c.query("COMMIT");
    res.redirect("/admin/payments");
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    res.status(400).send(page("Admin Payments", message(e.message), req.session.user));
  } finally { c.release(); }
});

/* ADMIN REFUNDS */

app.get("/admin/refunds", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT f.*,u.username FROM refunds f
      JOIN users u ON u.id=f.user_id ORDER BY f.id DESC LIMIT 500
    `);

    const rows = r.rows.map(f => `
      <tr><td>${esc(f.id)}</td><td>${esc(f.username)}</td>
      <td>₹${money(f.amount)}</td><td>${esc(f.reason)}</td>
      <td>${esc(f.status)}</td><td>
      ${f.status === "Pending" ? `
        <form method="POST" action="/admin/refund/${esc(f.id)}">
          <button name="action" value="approve">Approve</button>
          <button name="action" value="reject">Reject</button>
        </form>` : "Processed"}
      </td></tr>
    `).join("");

    res.send(page("Admin Refunds", `
      <div class="admin-heading"><div><h1>Refund Management</h1>
      <p>Approve or reject refund requests</p></div></div>
      <div class="card"><div class="table-wrap"><table>
      <tr><th>ID</th><th>User</th><th>Amount</th><th>Reason</th><th>Status</th><th>Action</th></tr>
      ${rows || "<tr><td colspan='6'>No refunds</td></tr>"}
      </table></div></div>
    `, req.session.user));
  } catch (e) { next(e); }
});

app.post("/admin/refund/:id", requireLogin, requireAdmin, async (req, res, next) => {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");

    const r = await c.query("SELECT * FROM refunds WHERE id=$1 FOR UPDATE", [req.params.id]);
    const f = r.rows[0];

    if (!f || f.status !== "Pending") throw new Error("Refund already processed");

    if (req.body.action === "approve") {
      if (!f.funds_reserved) {
        const u = await c.query("SELECT balance FROM users WHERE id=$1 FOR UPDATE", [f.user_id]);
        if (Number(u.rows[0]?.balance || 0) < Number(f.amount)) {
          throw new Error("Insufficient wallet balance");
        }
        await c.query("UPDATE users SET balance=balance-$1 WHERE id=$2", [f.amount, f.user_id]);
      }
      await c.query("UPDATE refunds SET status='Approved' WHERE id=$1", [f.id]);
    } else if (req.body.action === "reject") {
      if (f.funds_reserved) {
        await c.query("UPDATE users SET balance=balance+$1 WHERE id=$2", [f.amount, f.user_id]);
      }
      await c.query("UPDATE refunds SET status='Rejected' WHERE id=$1", [f.id]);
    } else throw new Error("Invalid action");

    await c.query("COMMIT");
    res.redirect("/admin/refunds");
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    res.status(400).send(page("Admin Refunds", message(e.message), req.session.user));
  } finally { c.release(); }
});

/* ADMIN USERS */

app.get("/admin/users", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT id,username,email,balance,is_admin,created_at
      FROM users ORDER BY id DESC LIMIT 500
    `);

    const rows = r.rows.map(u => `
      <tr><td>${esc(u.id)}</td><td>${esc(u.username)}</td>
      <td>${esc(u.email || "")}</td><td>₹${money(u.balance)}</td>
      <td>${u.is_admin ? "Admin" : "Customer"}</td><td>
      ${!u.is_admin ? `
        <form method="POST" action="/admin/user/${esc(u.id)}">
          <input name="amount" type="number" step=".01" min="0"
            placeholder="Wallet amount" required>
          <button name="action" value="add">Add</button>
          <button name="action" value="remove">Deduct</button>
        </form>` : "Protected"}
      </td></tr>
    `).join("");

    res.send(page("Admin Users", `
      <div class="admin-heading"><div><h1>Users Management</h1>
      <p>Customer accounts and wallet management</p></div></div>
      <div class="card"><input id="userSearch" placeholder="Search users">
      <div class="table-wrap"><table><tr><th>ID</th><th>Username</th>
      <th>Email</th><th>Balance</th><th>Role</th><th>Wallet Control</th></tr>
      <tbody id="userRows">${rows}</tbody></table></div></div>
      <script>
      document.getElementById('userSearch').addEventListener('input',e=>{
        document.querySelectorAll('#userRows tr').forEach(r=>{
          r.style.display=r.textContent.toLowerCase().includes(e.target.value.toLowerCase())?'':'none';
        });
      });
      </script>
    `, req.session.user));
  } catch (e) { next(e); }
});

app.post("/admin/user/:id", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const amount = Number(req.body.amount);

    if (!Number.isInteger(id) || id < 1 || !Number.isFinite(amount) || amount <= 0) {
      return res.status(400).send("Invalid user or amount");
    }

    if (!["add", "remove"].includes(req.body.action)) {
      return res.status(400).send("Invalid wallet action");
    }

    const change = req.body.action === "add" ? amount : -amount;

    const r = await db(
      `UPDATE users SET balance=balance+$1
       WHERE id=$2 AND is_admin=FALSE AND balance+$1>=0 RETURNING id`,
      [change, id]
    );

    if (!r.rows.length) throw new Error("User not found or insufficient balance");

    res.redirect("/admin/users");
  } catch (e) {
    res.status(400).send(page("Admin Users", message(e.message), req.session.user));
  }
});

/* ADMIN ORDERS */

app.get("/admin/orders", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT o.*,u.username FROM orders o
      JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 500
    `);

    const rows = r.rows.map(o => `
      <tr><td>${esc(o.id)}</td><td>${esc(o.username)}</td>
      <td>${esc(o.service_name || o.service_id)}</td>
      <td>${esc(o.quantity)}</td><td>₹${money(o.charge)}</td>
      <td>${esc(o.status)}</td><td>${esc(o.provider_order_id || "—")}</td>
      <td><form method="POST" action="/admin/order/${esc(o.id)}">
        <select name="status">
          ${["Pending","Processing","Completed","Partial","Canceled","Failed"].map(s =>
            `<option ${o.status===s?"selected":""}>${s}</option>`).join("")}
        </select><button>Update</button>
      </form></td></tr>
    `).join("");

    res.send(page("Admin Orders", `
      <div class="admin-heading"><div><h1>Orders Management</h1>
      <p>Review customer orders and update status</p></div></div>
      <div class="card"><div class="table-wrap"><table>
      <tr><th>ID</th><th>User</th><th>Service</th><th>Qty</th>
      <th>Charge</th><th>Status</th><th>Provider ID</th><th>Update</th></tr>
      ${rows || "<tr><td colspan='8'>No orders</td></tr>"}
      </table></div></div>
    `, req.session.user));
  } catch (e) { next(e); }
});

app.post("/admin/order/:id", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const allowed = ["Pending","Processing","Completed","Partial","Canceled","Failed"];

    if (!Number.isInteger(id) || !allowed.includes(req.body.status)) {
      return res.status(400).send("Invalid order update");
    }

    await db("UPDATE orders SET status=$1 WHERE id=$2", [req.body.status, id]);
    res.redirect("/admin/orders");
  } catch (e) { next(e); }
});

/* TRANSACTION HISTORY */

app.get("/admin/transactions", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT p.id,p.user_id,u.username,p.amount,p.utr,p.status,p.created_at
      FROM payments p JOIN users u ON u.id=p.user_id
      ORDER BY p.id DESC LIMIT 500
    `);

    const rows = r.rows.map(p => `
      <tr><td>${esc(p.id)}</td><td>${esc(p.username)}</td>
      <td>₹${money(p.amount)}</td><td>${esc(p.utr)}</td>
      <td>${esc(p.status)}</td>
      <td>${new Date(p.created_at).toLocaleString("en-IN")}</td></tr>
    `).join("");

    res.send(page("Admin Transactions", `
      <div class="admin-heading"><div><h1>Transactions History</h1>
      <p>Payment transaction records</p></div></div>
      <div class="card"><div class="table-wrap"><table>
      <tr><th>ID</th><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Date</th></tr>
      ${rows}</table></div></div>
    `, req.session.user));
  } catch (e) { next(e); }
});

/* REPORTS */

app.get("/admin/reports", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT
        (SELECT COUNT(*) FROM users) AS users,
        (SELECT COUNT(*) FROM orders) AS orders,
        (SELECT COALESCE(SUM(charge),0) FROM orders) AS order_sales,
        (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Approved') AS payments,
        (SELECT COUNT(*) FROM payments WHERE status='Approved') AS successful_payments,
        (SELECT COUNT(*) FROM payments WHERE status='Rejected') AS rejected_payments
    `);
    const x = r.rows[0];

    res.send(page("Admin Reports", `
      <div class="admin-heading"><div><h1>Reports & Analytics</h1>
      <p>Website performance overview</p></div></div>
      <div class="stat-grid">
        <div class="stat-card blue"><div class="number">${esc(x.users)}</div><div>Users</div></div>
        <div class="stat-card purple"><div class="number">${esc(x.orders)}</div><div>Orders</div></div>
        <div class="stat-card green"><div class="number">₹${money(x.payments)}</div><div>Approved Payments</div></div>
        <div class="stat-card orange"><div class="number">₹${money(x.order_sales)}</div><div>Order Charges</div></div>
      </div>
      <div class="card">
        <h3>Payment Report</h3>
        <p>Successful payments: <b>${esc(x.successful_payments)}</b></p>
        <p>Rejected payments: <b>${esc(x.rejected_payments)}</b></p>
        <p>Total payment amount approved: <b>₹${money(x.payments)}</b></p>
      </div>
    `, req.session.user));
  } catch (e) { next(e); }
});

/* WEBSITE SETTINGS */

app.get("/admin/settings", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const servicesEnabled = await setting("services_enabled");
    const providerEnabled = await setting("provider_enabled");

    res.send(page("Admin Settings", `
      <div class="admin-heading"><div><h1>Website Settings</h1>
      <p>Control website availability and service access</p></div></div>
      <div class="card">
        <h3>Website Service Settings</h3>
        <p>Customer services: <b>${servicesEnabled === "true" ? "Enabled" : "Disabled"}</b></p>
        <form method="POST" action="/admin/services-toggle">
          <button name="value" value="true">Enable Services</button>
          <button name="value" value="false">Disable Services</button>
        </form>
        <hr>
        <p>API Provider: <b>${providerEnabled === "true" ? "Enabled" : "Disabled"}</b></p>
        <a href="/admin/provider">Manage API Provider →</a>
      </div>
      <div class="card">
        <h3>Website Information</h3>
        <p>Brand: Royal SMM Seller</p>
        <p>Currency: Indian Rupees (₹)</p>
        <p>Support: WhatsApp and Telegram</p>
        <p class="muted">Google OAuth, payment QR and API credentials are controlled through Render Environment Variables and the public folder.</p>
      </div>
    `, req.session.user));
  } catch (e) { next(e); }
});

/* SUPPORT MESSAGES */

app.get("/admin/support", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT t.*,u.username,u.email FROM tickets t
      JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 300
    `);

    const rows = r.rows.map(t => `
      <tr><td>${esc(t.id)}</td><td>${esc(t.username)}</td>
      <td>${esc(t.email || "")}</td><td>${esc(t.message)}</td>
      <td>${esc(t.status)}</td>
      <td><form method="POST" action="/admin/ticket/${esc(t.id)}">
        <select name="status"><option>Open</option><option>Closed</option></select>
        <button>Update</button>
      </form></td></tr>
    `).join("");

    res.send(page("Admin Support", `
      <div class="admin-heading"><div><h1>Support Messages</h1>
      <p>Customer support requests</p></div></div>
      <div class="card"><div class="table-wrap"><table>
      <tr><th>ID</th><th>User</th><th>Email</th><th>Message</th><th>Status</th><th>Action</th></tr>
      ${rows}</table></div></div>
    `, req.session.user));
  } catch (e) { next(e); }
});

app.post("/admin/ticket/:id", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    if (!["Open","Closed"].includes(req.body.status)) {
      return res.status(400).send("Invalid ticket status");
    }
    await db("UPDATE tickets SET status=$1 WHERE id=$2", [req.body.status, req.params.id]);
    res.redirect("/admin/support");
  } catch (e) { next(e); }
});

/* LOGOUT */

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("royal.sid");
    res.redirect("/login");
  });
});

/* HEALTH */

app.get("/health", async (req, res) => {
  try {
    await db("SELECT 1");
    res.status(200).json({
      status: "ok",
      app: "ROYAL SMM SELLER",
      database: "connected",
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    console.error("Health error:", e.message);
    res.status(503).json({
      status: "error",
      app: "ROYAL SMM SELLER",
      database: "disconnected",
      timestamp: new Date().toISOString()
    });
  }
});

/* ERROR HANDLER */

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  if (res.headersSent) return next(err);
  res.status(500).send("Server error. Please try again later.");
});

/* SERVER START */

const PORT = Number(process.env.PORT) || 3000;
let server;
let shuttingDown = false;

async function startServer() {
  try {
    console.log("Starting Royal SMM Seller...");
    await setupDatabase();
    console.log("Database setup completed");

    server = app.listen(PORT, "0.0.0.0", () => {
      console.log("ROYAL SMM SELLER running on port " + PORT);
      console.log("Health check: /health");
    });

    server.on("error", err => {
      console.error("HTTP server error:", err);
      process.exit(1);
    });
  } catch (err) {
    console.error("Startup failed:", err);
    await pool.end().catch(() => {});
    process.exit(1);
  }
}

/* GRACEFUL SHUTDOWN */

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(signal + " received. Shutting down...");

  const forceExit = setTimeout(() => {
    console.error("Forced shutdown");
    process.exit(1);
  }, 10000);

  forceExit.unref();

  try {
    if (server) {
      await new Promise(resolve => server.close(resolve));
    }
    await pool.end();
    clearTimeout(forceExit);
    process.exit(0);
  } catch (e) {
    console.error("Shutdown error:", e);
    clearTimeout(forceExit);
    process.exit(1);
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

process.on("unhandledRejection", reason => {
  console.error("Unhandled Promise Rejection:", reason);
});

process.on("uncaughtException", err => {
  console.error("Uncaught Exception:", err);
  shutdown("UNCAUGHT_EXCEPTION");
});

startServer();
