
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
  legacyHeaders: false
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const db = (sql, values = []) => pool.query(sql, values);

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const APP_URL = (process.env.APP_URL || "").replace(/\/$/, "");

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

const PROVIDER_URL =
  process.env.SOCIALADD_API_URL || "https://socialadd.in/api/v2";

const PROVIDER_KEY = process.env.SOCIALADD_API_KEY || "";
const UPI_ID = process.env.UPI_ID || "";

const WHATSAPP_NUMBER = "918140989426";
const WHATSAPP_LINK =
  `https://wa.me/${WHATSAPP_NUMBER}?text=Hello%20Royal%20Panel%20Support`;

const TELEGRAM_USERNAME = "Digital_marketing_aagency_India";
const TELEGRAM_LINK = `https://t.me/${TELEGRAM_USERNAME}`;

const SESSION_SECRET = process.env.SESSION_SECRET || "";

const INSTAGRAM_GROUPS = [
  "Followers",
  "Likes",
  "Reel Views",
  "Story Views",
  "Comments",
  "Saves",
  "Shares"
];

if (process.env.NODE_ENV === "production" && !SESSION_SECRET) {
  throw new Error("SESSION_SECRET environment variable is required");
}

const googleClient = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  APP_URL ? APP_URL + "/auth/google/callback" : undefined
);

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function money(v) {
  return Number(v || 0).toFixed(2);
}

function message(v) {
  return `<div class="card notice">${esc(v)}</div>`;
}

function cleanCategory(v) {
  return String(v || "Other")
    .replace(/[<>]/g, "")
    .trim()
    .slice(0, 120) || "Other";
}

/* INSTAGRAM SERVICE FILTER */

function isInstagramService(name, category) {
  const s = `${name || ""} ${category || ""}`.toLowerCase();
  return /\binstagram\b|\binsta\b/.test(s);
}

function getInstagramGroup(name, category) {
  const s = `${name || ""} ${category || ""}`.toLowerCase();

  if (/follower|subscriber/.test(s)) return "Followers";
  if (/like|favorite/.test(s)) return "Likes";

  if (/story/.test(s) && /view|watch|impression/.test(s)) {
    return "Story Views";
  }

  if (/reel/.test(s) && /view|watch|impression/.test(s)) {
    return "Reel Views";
  }

  if (/comment|reply/.test(s)) return "Comments";
  if (/share/.test(s)) return "Shares";
  if (/save|bookmark/.test(s)) return "Saves";

  return null;
}

function socialSupportLinks() {
  return `
    <div class="social-float">
      <a class="social-float-btn whatsapp-float"
         href="${esc(WHATSAPP_LINK)}"
         target="_blank"
         rel="noopener">WA</a>

      <a class="social-float-btn telegram-float"
         href="${esc(TELEGRAM_LINK)}"
         target="_blank"
         rel="noopener">TG</a>
    </div>
  `;
}

/* DATABASE SESSION STORE */

class PostgresSessionStore extends session.Store {
  get(sid, cb) {
    db(
      "SELECT sess FROM user_sessions WHERE sid=$1 AND expire>NOW()",
      [sid]
    )
      .then(r => cb(null, r.rows[0]?.sess || null))
      .catch(cb);
  }

  set(sid, sess, cb = () => {}) {
    const exp = sess.cookie?.expires
      ? new Date(sess.cookie.expires)
      : new Date(Date.now() + 7 * 86400000);

    db(
      `INSERT INTO user_sessions(sid,sess,expire)
       VALUES($1,$2,$3)
       ON CONFLICT(sid)
       DO UPDATE SET sess=EXCLUDED.sess,expire=EXCLUDED.expire`,
      [sid, JSON.stringify(sess), exp]
    )
      .then(() => cb(null))
      .catch(cb);
  }

  destroy(sid, cb = () => {}) {
    db("DELETE FROM user_sessions WHERE sid=$1", [sid])
      .then(() => cb(null))
      .catch(cb);
  }

  touch(sid, sess, cb = () => {}) {
    const exp = sess.cookie?.expires
      ? new Date(sess.cookie.expires)
      : new Date(Date.now() + 7 * 86400000);

    db("UPDATE user_sessions SET expire=$1 WHERE sid=$2", [exp, sid])
      .then(() => cb(null))
      .catch(cb);
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
    ALTER TABLE refunds
    ADD COLUMN IF NOT EXISTS funds_reserved BOOLEAN DEFAULT FALSE
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
    DELETE FROM services a
    USING services b
    WHERE a.id>b.id
      AND a.provider_id IS NOT NULL
      AND a.provider_source=b.provider_source
      AND a.provider_id=b.provider_id
  `);

  await db(`
    CREATE UNIQUE INDEX IF NOT EXISTS services_provider_unique
    ON services(provider_source,provider_id)
    WHERE provider_id IS NOT NULL
  `);

  /*
    Existing services are not deleted.
    Only recognized Instagram services are enabled.
  */

  const existing = await db("SELECT id,name,category FROM services");

  for (const s of existing.rows) {
    const group = isInstagramService(s.name, s.category)
      ? getInstagramGroup(s.name, s.category)
      : null;

    if (group && INSTAGRAM_GROUPS.includes(group)) {
      await db(
        `UPDATE services
         SET category='Instagram',service_group=$1
         WHERE id=$2`,
        [group, s.id]
      );
    } else {
      await db(
        "UPDATE services SET active=FALSE WHERE id=$1",
        [s.id]
      );
    }
  }

  if (ADMIN_EMAIL) {
    await db(
      "UPDATE users SET is_admin=TRUE WHERE LOWER(email)=LOWER($1)",
      [ADMIN_EMAIL]
    );
  }

  if (ADMIN_USERNAME && ADMIN_PASSWORD) {
    const old = await db(
      "SELECT id FROM users WHERE username=$1",
      [ADMIN_USERNAME]
    );

    if (!old.rows.length) {
      const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);

      await db(
        `INSERT INTO users(username,email,password_hash,password,is_admin)
         VALUES($1,$2,$3,$3,TRUE)
         ON CONFLICT(username) DO NOTHING`,
        [ADMIN_USERNAME, ADMIN_EMAIL || null, hash]
      );
    }
  }
}

async function setting(k) {
  const r = await db(
    "SELECT setting_value FROM panel_settings WHERE setting_key=$1",
    [k]
  );
  return r.rows[0]?.setting_value || "false";
}

async function setSetting(k, v) {
  await db(
    `INSERT INTO panel_settings(setting_key,setting_value)
     VALUES($1,$2)
     ON CONFLICT(setting_key)
     DO UPDATE SET setting_value=EXCLUDED.setting_value`,
    [k, String(v)]
  );
}

/* AUTHENTICATION */

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

async function requireAdmin(req, res, next) {
  try {
    if (!req.session.user?.id) {
      return res.status(403).send("Admin access required");
    }

    const r = await db(
      "SELECT is_admin FROM users WHERE id=$1",
      [req.session.user.id]
    );

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
      res.redirect("/services");
    });
  });
}

/* PAGE TEMPLATE */

function page(title, body, user = null) {
  const admin = user?.is_admin
    ? `
      <div class="menu-section-title">ADMINISTRATION</div>
      <a class="menu-link" href="/admin">⚙️ Admin Dashboard</a>
      <a class="menu-link" href="/admin/services">🛠️ Manage Services</a>
      <a class="menu-link" href="/admin/payments">💳 Fund Approvals</a>
      <a class="menu-link" href="/admin/refunds">↩️ Refund Approvals</a>
      <a class="menu-link" href="/admin/orders">📦 Manage Orders</a>
      <a class="menu-link" href="/admin/users">👥 Customers</a>
    `
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#20ad62">
<title>${esc(title)} | ROYAL PANEL</title>

<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;font-family:Arial,sans-serif;color:#183328;background:#f1fff6}
a{color:#13894b;text-decoration:none}
.top-header{height:68px;background:#20ad62;color:white;display:flex;align-items:center;justify-content:space-between;padding:10px 16px;position:sticky;top:0;z-index:20;box-shadow:0 2px 10px #0002}
.brand{font-size:25px;font-weight:900;color:white;letter-spacing:1px}
.menu-button{background:#16894b;border:1px solid #d6ffe6;color:white;border-radius:10px;padding:9px 14px;font-size:24px}
.menu-overlay{position:fixed;inset:0;background:#0008;z-index:30;display:none}
.menu-overlay.open{display:block}
.side-drawer{position:fixed;z-index:31;left:0;top:0;height:100dvh;width:300px;max-width:86vw;overflow:auto;background:#20ad62;padding:15px;transform:translateX(-105%);transition:.25s;color:white}
.side-drawer.open{transform:translateX(0)}
.drawer-header{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #ffffff66}
.drawer-brand{font-size:22px;font-weight:bold}
.close-menu{font-size:25px;background:#147d45}
.menu-section-title{font-size:11px;font-weight:bold;letter-spacing:1px;color:#d6ffe6;margin:20px 8px 8px}
.menu-link{display:block;padding:12px;margin:4px 0;border-radius:7px;color:white;font-weight:bold}
.menu-link:hover{background:#147d45}
.logout-link{border-top:1px solid #ffffff66;margin-top:18px}
main{max-width:900px;margin:22px auto;padding:0 12px 100px}
.card{background:white;border:1px solid #d2efdd;border-radius:15px;padding:18px;margin:14px 0;box-shadow:0 5px 18px #17683b14}
.notice{background:#f0fff5;color:#176b3d}
h1,h2,h3{color:#147b43;margin-top:5px}
label{display:block;font-size:14px;font-weight:bold;margin:12px 0 4px;color:#345b46}
input,select,textarea{width:100%;padding:13px;margin:5px 0;border:1px solid #b5e6c7;border-radius:9px;background:#eaf8ff;color:#183328;font-size:15px}
input:focus,select:focus,textarea:focus{outline:2px solid #7bd99e}
button{background:#20ad62;color:white;padding:12px 18px;border:0;border-radius:9px;margin:5px 0;cursor:pointer;font-size:14px;font-weight:bold}
button:hover{background:#16894b}
.primary{width:100%;font-size:16px}
.google-btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;background:white;color:#333;border:1px solid #bbb;padding:12px;border-radius:8px;font-weight:bold}
.google-g{font-size:22px;font-weight:900;color:#4285f4}
.muted{color:#668071;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}
.table-wrap{width:100%;overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:600px}
td,th{padding:10px;border-bottom:1px solid #d8e9df;text-align:left}
th{color:#16894b;white-space:nowrap}
.service-info{background:#f7fff9;border:1px solid #b8e5c7;padding:12px;border-radius:9px;white-space:pre-wrap;min-height:55px}
.social-float{position:fixed;right:14px;bottom:14px;z-index:25;display:flex;gap:9px}
.social-float-btn{width:48px;height:48px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:13px;font-weight:bold;box-shadow:0 4px 12px #0003}
.whatsapp-float{background:#25d366}
.telegram-float{background:#229ed9}
.qr-box{text-align:center;background:white;border-radius:12px;padding:12px;max-width:300px;margin:15px auto}
.qr-box img{max-width:100%;height:auto}
.qr-caption{color:#222;font-weight:bold}
.price-box{font-size:22px;font-weight:bold;color:#16894b}
.category-help{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.category-chip{border:1px solid #a9dfbb;background:#effff4;border-radius:20px;padding:6px 10px;font-size:12px;color:#147b43}
@media(max-width:600px){
main{margin:12px auto;padding:0 9px 90px}
.card{padding:14px}
.brand{font-size:21px}
.top-header{height:62px}
.table-wrap table{font-size:13px}
}
</style>
</head>

<body>
<header class="top-header">
<a class="brand" href="${user ? "/services" : "/login"}">ROYAL PANEL</a>
${user ? '<button class="menu-button" id="menuBtn" onclick="openMenu()">☰</button>' : ""}
</header>

${user ? `
<div class="menu-overlay" id="menuOverlay" onclick="closeMenu()"></div>
<aside class="side-drawer" id="sideDrawer">
  <div class="drawer-header">
    <b class="drawer-brand">ROYAL PANEL</b>
    <button class="close-menu" onclick="closeMenu()">×</button>
  </div>
  <div class="menu-section-title">MAIN MENU</div>
  <a class="menu-link" href="/services">➕ New Order / Services</a>
  <a class="menu-link" href="/orders">📦 My Orders</a>
  <a class="menu-link" href="/funds">💰 Add Funds</a>
  <a class="menu-link" href="/refund">↩️ Refund Request</a>
  <a class="menu-link" href="/support">🎧 Support</a>
  ${admin}
  <a class="menu-link logout-link" href="/logout">🚪 Logout</a>
</aside>

<script>
function openMenu(){
  document.getElementById('sideDrawer').classList.add('open');
  document.getElementById('menuOverlay').classList.add('open');
}
function closeMenu(){
  document.getElementById('sideDrawer').classList.remove('open');
  document.getElementById('menuOverlay').classList.remove('open');
}
document.addEventListener('keydown',e=>{
  if(e.key==='Escape')closeMenu();
});
</script>
` : ""}

<main>${body}</main>
${socialSupportLinks()}
</body>
</html>`;
}

/* SOCIALADD API */

async function providerRequest(params) {
  if (!PROVIDER_KEY) {
    throw new Error("SocialAdd API key missing");
  }

  const body = new URLSearchParams({
    key: PROVIDER_KEY,
    ...params
  });

  const response = await fetch(PROVIDER_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
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
  res.redirect(req.session.user ? "/services" : "/login");
});

/* LOGIN */

app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card">
      <h2>Welcome Back</h2>
      <p class="muted">Sign in to your Royal Panel account</p>

      <form method="POST" action="/login">
        <label>Email or Username</label>
        <input name="email" placeholder="Enter email or username" required>

        <label>Password</label>
        <input name="password" type="password" placeholder="Password" required>

        <button class="primary">Sign In</button>
      </form>

      <div style="text-align:center;margin:14px 0;color:#789">OR</div>

      <a class="google-btn" href="/auth/google">
        <span class="google-g">G</span> Sign in with Google
      </a>

      <p style="text-align:center">
        Don't have an account? <a href="/register">Sign up</a>
      </p>
    </div>
  `));
});

app.post("/login", async (req, res, next) => {
  try {
    const identity = String(req.body.email || "").trim();

    const r = await db(
      `SELECT * FROM users
       WHERE LOWER(email)=LOWER($1)
          OR LOWER(username)=LOWER($1)
       LIMIT 1`,
      [identity]
    );

    const u = r.rows[0];
    const hash = u?.password_hash || u?.password;

    if (
      !u ||
      !hash ||
      !await bcrypt.compare(String(req.body.password || ""), hash)
    ) {
      return res.status(401).send(
        page("Login", message("Invalid login details"))
      );
    }

    createUserSession(req, u, res);
  } catch (e) {
    next(e);
  }
});

/* REGISTER */

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h2>Create Account</h2>

      <form method="POST" action="/register">
        <label>Username</label>
        <input name="username" required maxlength="100">

        <label>Email</label>
        <input name="email" type="email" required maxlength="200">

        <label>Password</label>
        <input name="password" type="password" minlength="6" required>

        <button class="primary">Create Account</button>
      </form>

      <a class="google-btn" href="/auth/google">
        <span class="google-g">G</span> Sign up with Google
      </a>

      <p>Already registered? <a href="/login">Login</a></p>
    </div>
  `));
});

app.post("/register", async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (
      !username ||
      !email ||
      password.length < 6 ||
      username.length > 100 ||
      email.length > 200
    ) {
      return res.status(400).send(
        page("Register", message("Enter valid details"))
      );
    }

    const hash = await bcrypt.hash(password, 12);

    const r = await db(
      `INSERT INTO users(username,email,password_hash,password)
       VALUES($1,$2,$3,$3)
       RETURNING *`,
      [username, email, hash]
    );

    createUserSession(req, r.rows[0], res);
  } catch (e) {
    if (e.code === "23505") {
      return res.status(400).send(
        page("Register", message("Username or email already exists"))
      );
    }
    next(e);
  }
});

/* GOOGLE LOGIN */

app.get("/auth/google", (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !APP_URL) {
    return res.status(503).send(
      "Google Login environment settings are missing"
    );
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
    if (
      !req.query.code ||
      req.query.state !== req.session.googleState
    ) {
      return res.status(400).send("Google login state error");
    }

    delete req.session.googleState;

    const { tokens } = await googleClient.getToken(req.query.code);

    if (!tokens.id_token) {
      return res.status(400).send("Google ID token missing");
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID
    });

    const profile = ticket.getPayload();

    if (!profile?.email || !profile.email_verified) {
      return res.status(400).send("Google email not verified");
    }

    const email = profile.email.toLowerCase();

    let r = await db(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
      [email]
    );

    let user = r.rows[0];

    if (!user) {
      const base = (profile.name || email.split("@")[0])
        .replace(/[^a-zA-Z0-9_]/g, "")
        .slice(0, 20) || "customer";

      const username =
        base + "_" + crypto.randomBytes(3).toString("hex");

      r = await db(
        `INSERT INTO users(username,email,google_id)
         VALUES($1,$2,$3)
         RETURNING *`,
        [username, email, profile.sub]
      );

      user = r.rows[0];
    } else if (!user.google_id) {
      await db(
        "UPDATE users SET google_id=$1 WHERE id=$2",
        [profile.sub, user.id]
      );
      user.google_id = profile.sub;
    }

    if (ADMIN_EMAIL && email === ADMIN_EMAIL) {
      await db(
        "UPDATE users SET is_admin=TRUE WHERE id=$1",
        [user.id]
      );
      user.is_admin = true;
    }

    createUserSession(req, user, res);
  } catch (e) {
    next(e);
  }
});

app.get("/dashboard", requireLogin, (req, res) => {
  res.redirect("/services");
});

/* CUSTOMER SERVICES - INSTAGRAM ONLY */

app.get("/services", requireLogin, async (req, res, next) => {
  try {
    const enabled = await setting("services_enabled");

    const wallet = await db(
      "SELECT balance FROM users WHERE id=$1",
      [req.session.user.id]
    );

    const result = await db(
      `SELECT * FROM services
       WHERE active=TRUE
         AND category='Instagram'
         AND service_group=ANY($1::text[])
       ORDER BY service_group,id`,
      [INSTAGRAM_GROUPS]
    );

    const services = result.rows;

    const categories = INSTAGRAM_GROUPS.filter(group =>
      services.some(s => s.service_group === group)
    );

    const payload = services.map(s => ({
      id: s.id,
      name: s.name,
      category: "Instagram",
      group: s.service_group,
      description: s.description || "",
      averageTime: s.average_time || "",
      rate: Number(s.rate),
      min: Number(s.min),
      max: Number(s.max)
    }));

    const safePayload = JSON.stringify(payload).replace(/</g, "\\u003c");

    const body = `
      <div class="card">
        <div style="background:#20ad62;color:white;border-radius:10px;padding:14px">
          <div style="font-size:13px">WALLET BALANCE</div>
          <div style="font-size:25px;font-weight:bold">
            ₹${money(wallet.rows[0]?.balance)}
          </div>
        </div>

        <h2>Instagram New Order</h2>

        <div class="category-help">
          ${INSTAGRAM_GROUPS.map(g =>
            `<span class="category-chip">${esc(g)}</span>`
          ).join("")}
        </div>

        ${enabled === "true" ? `
          <form method="POST" action="/order" id="orderForm">

            <label>Search Instagram Services</label>
            <input type="search" id="serviceSearch"
              placeholder="Search service name or ID..."
              autocomplete="off">

            <label>Instagram Category</label>
            <select id="categorySelect" required>
              <option value="">Select Category</option>
              ${categories.map(c =>
                `<option value="${esc(c)}">${esc(c)}</option>`
              ).join("")}
            </select>

            <label>Service</label>
            <select name="service_id" id="serviceSelect" required disabled>
              <option value="">Select Category First</option>
            </select>

            <label>Description</label>
            <div class="service-info" id="serviceDescription">
              Select a service to see details.
            </div>

            <label>Average Time</label>
            <div class="service-info" id="averageTime">—</div>

            <label>Link</label>
            <input name="link" id="orderLink"
              placeholder="Enter Instagram post / profile link"
              required maxlength="2000">

            <label>Quantity</label>
            <input name="quantity" id="quantity"
              type="number" min="1" step="1"
              placeholder="Enter quantity" required>

            <div class="muted" id="quantityLimit">
              Select a service to see minimum and maximum quantity.
            </div>

            <label>Charge</label>
            <div class="service-info price-box" id="charge">₹0.00</div>

            <div class="muted">
              Price is calculated automatically from the selected service rate.
            </div>

            <button class="primary" type="submit">Submit Order</button>
          </form>

          <script>
            const SERVICES = ${safePayload};

            const cat = document.getElementById('categorySelect');
            const sel = document.getElementById('serviceSelect');
            const search = document.getElementById('serviceSearch');
            const qty = document.getElementById('quantity');
            const desc = document.getElementById('serviceDescription');
            const avg = document.getElementById('averageTime');
            const lim = document.getElementById('quantityLimit');
            const charge = document.getElementById('charge');

            let current = null;

            function escapeText(v) {
              return String(v).replace(/[&<>"']/g, c => ({
                '&':'&amp;',
                '<':'&lt;',
                '>':'&gt;',
                '"':'&quot;',
                "'":'&#39;'
              }[c]));
            }

            function fillServices() {
              const group = cat.value;
              const term = search.value.trim().toLowerCase();

              const list = SERVICES.filter(s =>
                (!group || s.group === group) &&
                (!term || (s.name + ' ' + s.id + ' ' + s.category)
                  .toLowerCase().includes(term))
              );

              sel.innerHTML =
                '<option value="">Select a service</option>' +
                list.map(s =>
                  '<option value="' + s.id + '">' +
                  s.id + ' - ' + escapeText(s.name) +
                  ' — ₹' + s.rate.toFixed(2) + '/1K</option>'
                ).join('');

              sel.disabled = !list.length;
              current = null;
              showInfo();
            }

            function showInfo() {
              const s = SERVICES.find(x => String(x.id) === sel.value);
              current = s || null;

              if (!s) {
                desc.textContent = 'Select a service to see details.';
                avg.textContent = '—';
                lim.textContent = 'Select a service to see minimum and maximum quantity.';
                qty.removeAttribute('min');
                qty.removeAttribute('max');
                charge.textContent = '₹0.00';
                return;
              }

              desc.textContent = s.description || 'No description provided.';
              avg.textContent = s.averageTime || 'Not provided by provider';

              qty.min = s.min;
              qty.max = s.max;

              lim.textContent =
                'Min: ' + s.min.toLocaleString() +
                ' | Max: ' + s.max.toLocaleString();

              calc();
            }

            function calc() {
              if (!current) {
                charge.textContent = '₹0.00';
                return;
              }

              const n = Number(qty.value || 0);

              charge.textContent =
                '₹' + (n > 0 ? current.rate * n / 1000 : 0).toFixed(2);
            }

            cat.addEventListener('change', fillServices);
            search.addEventListener('input', fillServices);
            sel.addEventListener('change', showInfo);
            qty.addEventListener('input', calc);

            fillServices();
          </script>
        ` : `
          <p>Services are temporarily disabled.</p>
        `}
      </div>
    `;

    res.send(page("Instagram Services", body, req.session.user));
  } catch (e) {
    next(e);
  }
});

/* PLACE ORDER - INSTAGRAM ONLY */

app.post("/order", requireLogin, async (req, res, next) => {
  const client = await pool.connect();
  let orderId = null;

  try {
    await client.query("BEGIN");

    if (await setting("services_enabled") !== "true") {
      throw new Error("Services are disabled");
    }

    const sr = await client.query(
      `SELECT * FROM services
       WHERE id=$1
         AND active=TRUE
         AND category='Instagram'
         AND service_group=ANY($2::text[])
       FOR UPDATE`,
      [req.body.service_id, INSTAGRAM_GROUPS]
    );

    const service = sr.rows[0];

    if (!service) {
      throw new Error("Selected Instagram service not found or disabled");
    }

    if (
      service.provider_source === "socialadd" &&
      (
        await setting("provider_enabled") !== "true" ||
        !PROVIDER_KEY ||
        !service.provider_id
      )
    ) {
      throw new Error("Provider API is disabled or service configuration is missing");
    }

    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (
      !Number.isInteger(quantity) ||
      quantity < Number(service.min) ||
      quantity > Number(service.max) ||
      !link ||
      link.length > 2000
    ) {
      throw new Error(
        `Invalid link or quantity. Allowed quantity: ${service.min} to ${service.max}`
      );
    }

    const charge = Math.round(
      Number(service.rate) * quantity / 1000 * 100
    ) / 100;

    if (!Number.isFinite(charge) || charge <= 0) {
      throw new Error("Invalid service price");
    }

    const ur = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.session.user.id]
    );

    if (!ur.rows[0] || Number(ur.rows[0].balance) < charge) {
      throw new Error("Insufficient wallet balance");
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [charge, req.session.user.id]
    );

    const or = await client.query(
      `INSERT INTO orders(
        user_id,service_id,service_name,link,quantity,charge,status
      )
      VALUES($1,$2,$3,$4,$5,$6,'Pending')
      RETURNING id`,
      [
        req.session.user.id,
        service.id,
        service.name,
        link,
        quantity,
        charge
      ]
    );

    orderId = or.rows[0].id;

    await client.query("COMMIT");

    if (service.provider_source === "socialadd") {
      try {
        const data = await providerRequest({
          action: "add",
          service: String(service.provider_id),
          link,
          quantity: String(quantity)
        });

        if (!data.order) {
          throw new Error(data.error || "Provider did not return order ID");
        }

        await db(
          `UPDATE orders
           SET provider_order_id=$1,status='Processing'
           WHERE id=$2`,
          [String(data.order), orderId]
        );
      } catch (pe) {
        const rc = await pool.connect();

        try {
          await rc.query("BEGIN");

          const lock = await rc.query(
            "SELECT status,charge,user_id FROM orders WHERE id=$1 FOR UPDATE",
            [orderId]
          );

          if (lock.rows[0]?.status === "Pending") {
            await rc.query(
              "UPDATE users SET balance=balance+$1 WHERE id=$2",
              [lock.rows[0].charge, lock.rows[0].user_id]
            );

            await rc.query(
              "UPDATE orders SET status='Provider Error - Refunded' WHERE id=$1",
              [orderId]
            );
          }

          await rc.query("COMMIT");
        } catch (re) {
          await rc.query("ROLLBACK").catch(() => {});
          console.error("Automatic refund failed", re);
        } finally {
          rc.release();
        }

        console.error("Provider order failed", pe.message);
      }
    }

    res.redirect("/orders");
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    res.status(400).send(
      page("Order", message(e.message), req.session.user)
    );
  } finally {
    client.release();
  }
});

/* CUSTOMER ORDERS */

app.get("/orders", requireLogin, async (req, res, next) => {
  try {
    const r = await db(
      "SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC LIMIT 100",
      [req.session.user.id]
    );

    const rows = r.rows.map(o => `
      <tr>
        <td>${esc(o.id)}</td>
        <td>${esc(o.service_name || o.service_id)}</td>
        <td>${esc(o.quantity)}</td>
        <td>₹${money(o.charge)}</td>
        <td>${esc(o.status)}</td>
      </tr>
    `).join("");

    res.send(page("My Orders", `
      <div class="card">
        <h2>My Orders</h2>
        <div class="table-wrap">
          <table>
            <tr>
              <th>Order ID</th>
              <th>Service</th>
              <th>Quantity</th>
              <th>Charge</th>
              <th>Status</th>
            </tr>
            ${rows}
          </table>
        </div>
      </div>
    `, req.session.user));
  } catch (e) {
    next(e);
  }
});

/* ADD FUNDS */

app.get("/funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
    <div class="card">
      <h2>Add Funds</h2>

      <div class="qr-box">
        <img src="/payment-qr.png"
          alt="UPI Payment QR"
          onerror="this.style.display='none';document.getElementById('qrError').style.display='block'">
        <div class="qr-caption">Scan QR Code to Pay</div>
      </div>

      <p id="qrError" style="display:none;color:#b22">
        QR not found. Check public/payment-qr.png
      </p>

      <p>UPI ID: <b>${esc(UPI_ID)}</b></p>

      <form method="POST" action="/funds">
        <label>Amount (₹10–₹2000)</label>
        <input name="amount" type="number" min="10" max="2000" step="0.01" required>

        <label>UTR / Transaction ID</label>
        <input name="utr" required maxlength="150">

        <button class="primary">Submit Payment</button>
      </form>

      <p class="muted">
        Wallet में पैसे Admin Approval के बाद जुड़ेंगे।
      </p>
    </div>
  `, req.session.user));
});

app.post("/funds", requireLogin, async (req, res, next) => {
  try {
    const amount = Number(req.body.amount);
    const utr = String(req.body.utr || "").trim();

    if (
      !Number.isFinite(amount) ||
      amount < 10 ||
      amount > 2000 ||
      !utr ||
      utr.length > 150
    ) {
      return res.status(400).send(
        "Minimum ₹10 and maximum ₹2000. Valid UTR required."
      );
    }

    await db(
      `INSERT INTO payments(user_id,amount,utr,status)
       VALUES($1,$2,$3,'Pending')`,
      [req.session.user.id, amount, utr]
    );

    res.send(page(
      "Payment",
      message("Payment submitted. Waiting for Admin Approval."),
      req.session.user
    ));
  } catch (e) {
    next(e);
  }
});

/* REFUND REQUEST */

app.get("/refund", requireLogin, (req, res) => {
  res.send(page("Refund", `
    <div class="card">
      <h2>Refund Request</h2>
      <p class="muted">Minimum ₹10 - Maximum ₹2000</p>

      <form method="POST" action="/refund">
        <label>Amount</label>
        <input name="amount" type="number" min="10" max="2000" step="0.01" required>

        <label>Reason</label>
        <textarea name="reason" required maxlength="2000"></textarea>

        <button class="primary">Submit Refund Request</button>
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

    if (
      !Number.isFinite(amount) ||
      amount < 10 ||
      amount > 2000 ||
      !reason ||
      reason.length > 2000
    ) {
      throw new Error("Refund must be between ₹10 and ₹2000.");
    }

    const u = await c.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.session.user.id]
    );

    if (!u.rows[0] || Number(u.rows[0].balance) < amount) {
      throw new Error("Insufficient wallet balance.");
    }

    await c.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [amount, req.session.user.id]
    );

    await c.query(
      `INSERT INTO refunds(user_id,amount,reason,status,funds_reserved)
       VALUES($1,$2,$3,'Pending',TRUE)`,
      [req.session.user.id, amount, reason]
    );

    await c.query("COMMIT");

    res.send(page(
      "Refund",
      message("Refund request sent to Admin for approval."),
      req.session.user
    ));
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    res.status(400).send(
      page("Refund", message(e.message), req.session.user)
    );
  } finally {
    c.release();
  }
});

/* SUPPORT */

app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
    <div class="card">
      <h2>Support</h2>

      <form method="POST" action="/support">
        <textarea name="message" required maxlength="3000"
          placeholder="Write your message"></textarea>
        <button>Send Message</button>
      </form>

      <p class="muted">
        WhatsApp और Telegram support buttons नीचे हैं।
      </p>
    </div>
  `, req.session.user));
});

app.post("/support", requireLogin, async (req, res, next) => {
  try {
    const t = String(req.body.message || "").trim();

    if (!t || t.length > 3000) {
      return res.status(400).send("Enter a valid support message.");
    }

    await db(
      "INSERT INTO tickets(user_id,message,status) VALUES($1,$2,'Open')",
      [req.session.user.id, t]
    );

    res.redirect("/services");
  } catch (e) {
    next(e);
  }
});

/* ADMIN DASHBOARD */

app.get("/admin", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const [p, s, c] = await Promise.all([
      setting("provider_enabled"),
      setting("services_enabled"),
      db(`
        SELECT
          (SELECT COUNT(*) FROM users) AS users,
          (SELECT COUNT(*) FROM orders) AS orders,
          (SELECT COUNT(*) FROM payments WHERE status='Pending') AS pending_payments,
          (SELECT COUNT(*) FROM refunds WHERE status='Pending') AS pending_refunds
      `)
    ]);

    const x = c.rows[0];

    res.send(page("Admin", `
      <div class="card">
        <h2>Admin Dashboard</h2>

        <div class="grid">
          <div>Customers: <b>${esc(x.users)}</b></div>
          <div>Orders: <b>${esc(x.orders)}</b></div>
          <div>Pending Funds: <b>${esc(x.pending_payments)}</b></div>
          <div>Pending Refunds: <b>${esc(x.pending_refunds)}</b></div>
        </div>
      </div>

      <div class="card">
        <h3>SocialAdd Provider</h3>
        <p>API: ${p === "true" ? "Enabled" : "Disabled"}</p>

        <form method="POST" action="/admin/provider-toggle">
          <button name="value" value="true">Enable Provider API</button>
          <button name="value" value="false">Disable Provider API</button>
        </form>

        <form method="POST" action="/admin/import">
          <button>Import / Update Instagram Services</button>
        </form>

        <form method="POST" action="/admin/provider-test">
          <button>Test Provider API</button>
        </form>
      </div>

      <div class="card">
        <h3>Instagram Services</h3>
        <p>${s === "true" ? "Enabled" : "Disabled"}</p>

        <form method="POST" action="/admin/services-toggle">
          <button name="value" value="true">Enable All Services</button>
          <button name="value" value="false">Disable All Services</button>
        </form>

        <a href="/admin/services">Manage Services</a> |
        <a href="/admin/payments">Payments</a> |
        <a href="/admin/refunds">Refunds</a> |
        <a href="/admin/orders">Orders</a> |
        <a href="/admin/users">Users</a>
      </div>
    `, req.session.user));
  } catch (e) {
    next(e);
  }
});

app.post("/admin/provider-toggle", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    await setSetting("provider_enabled", req.body.value === "true");
    res.redirect("/admin");
  } catch (e) {
    next(e);
  }
});

app.post("/admin/services-toggle", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    await setSetting("services_enabled", req.body.value === "true");
    res.redirect("/admin");
  } catch (e) {
    next(e);
  }
});

app.post("/admin/provider-test", requireLogin, requireAdmin, async (req, res) => {
  try {
    const d = await providerRequest({ action: "balance" });

    res.send(page(
      "Provider Test",
      message("SocialAdd API connected: " + JSON.stringify(d)),
      req.session.user
    ));
  } catch (e) {
    res.status(500).send(page(
      "Provider Test",
      message("Provider Error: " + e.message),
      req.session.user
    ));
  }
});

/* IMPORT INSTAGRAM SERVICES ONLY */

app.post("/admin/import", requireLogin, requireAdmin, async (req, res) => {
  try {
    if (await setting("provider_enabled") !== "true") {
      throw new Error("Provider API is disabled");
    }

    const list = await providerRequest({ action: "services" });

    if (!Array.isArray(list)) {
      throw new Error("Invalid provider services response");
    }

    /*
      Disable old SocialAdd entries first.
      Historical orders and service records are preserved.
    */

    await db(
      "UPDATE services SET active=FALSE WHERE provider_source='socialadd'"
    );

    let imported = 0;
    let skipped = 0;

    for (const item of list) {
      const providerId = String(item.service || "").trim();
      const name = String(item.name || "").trim();
      const rawCategory = String(item.category || "").trim();

      if (!providerId || !name) {
        skipped++;
        continue;
      }

      if (!isInstagramService(name, rawCategory)) {
        skipped++;
        continue;
      }

      const group = getInstagramGroup(name, rawCategory);

      if (!group || !INSTAGRAM_GROUPS.includes(group)) {
        skipped++;
        continue;
      }

      const providerRate = Number(item.rate || 0);
      const min = Number(item.min || 1);
      const max = Number(item.max || 1000000);

      if (
        !Number.isFinite(providerRate) ||
        providerRate < 0 ||
        !Number.isInteger(min) ||
        !Number.isInteger(max) ||
        min < 1 ||
        max < min
      ) {
        skipped++;
        continue;
      }

      const sellingRate = providerRate * 1.75;

      const average = String(
        item.average_time ||
        item.avg_time ||
        item.averageTime ||
        item.time ||
        ""
      ).slice(0, 200);

      const description = String(item.description || "").slice(0, 5000);
      const providerType = String(item.type || "Default").slice(0, 100);

      await db(
        `INSERT INTO services(
          provider_id,
          provider_source,
          provider_type,
          name,
          category,
          service_group,
          description,
          average_time,
          rate,
          provider_rate,
          min,
          max,
          active
        )
        VALUES(
          $1,'socialadd',$2,$3,'Instagram',$4,$5,$6,$7,$8,$9,$10,TRUE
        )
        ON CONFLICT(provider_source,provider_id)
        WHERE provider_id IS NOT NULL
        DO UPDATE SET
          provider_type=EXCLUDED.provider_type,
          name=EXCLUDED.name,
          category='Instagram',
          service_group=EXCLUDED.service_group,
          description=EXCLUDED.description,
          average_time=EXCLUDED.average_time,
          rate=EXCLUDED.rate,
          provider_rate=EXCLUDED.provider_rate,
          min=EXCLUDED.min,
          max=EXCLUDED.max,
          active=TRUE`,
        [
          providerId,
          providerType,
          name,
          group,
          description,
          average,
          sellingRate,
          providerRate,
          min,
          max
        ]
      );

      imported++;
    }

    res.send(page(
      "Import",
      message(`Instagram services imported or updated: ${imported}. Skipped: ${skipped}.`),
      req.session.user
    ));
  } catch (e) {
    res.status(500).send(page(
      "Import Error",
      message(e.message),
      req.session.user
    ));
  }
});

/* ADMIN MANAGE INSTAGRAM SERVICES */

app.get("/admin/services", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(
      `SELECT * FROM services
       WHERE category='Instagram'
         AND service_group=ANY($1::text[])
       ORDER BY id DESC
       LIMIT 1000`,
      [INSTAGRAM_GROUPS]
    );

    const rows = r.rows.map(s => `
      <tr>
        <td>${esc(s.id)}</td>
        <td>${esc(s.service_group)}</td>
        <td>${esc(s.name)}</td>
        <td>${esc(s.min)}–${esc(s.max)}</td>
        <td>${esc(s.average_time || "—")}</td>
        <td>₹${money(s.rate)}</td>
        <td>${s.active ? "Active" : "Disabled"}</td>
        <td>
          <form method="POST" action="/admin/service/${esc(s.id)}">
            <input name="rate" type="number" step="0.0001"
              min="0" value="${esc(s.rate)}" required>

            <button name="save" value="1">Save Price</button>

            <button name="active" value="${!s.active}">
              ${s.active ? "Disable" : "Enable"}
            </button>
          </form>
        </td>
      </tr>
    `).join("");

    res.send(page("Manage Instagram Services", `
      <div class="card">
        <h2>Manage Instagram Services</h2>

        <input id="adminSearch"
          placeholder="Search by ID, category or service">

        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Group</th>
                <th>Name</th>
                <th>Limits</th>
                <th>Average Time</th>
                <th>Rate / 1K</th>
                <th>Status</th>
                <th>Update</th>
              </tr>
            </thead>
            <tbody id="serviceRows">${rows}</tbody>
          </table>
        </div>
      </div>

      <script>
        const q = document.getElementById('adminSearch');

        q.addEventListener('input', () => {
          document.querySelectorAll('#serviceRows tr').forEach(r => {
            r.style.display =
              r.textContent.toLowerCase().includes(q.value.toLowerCase())
                ? ''
                : 'none';
          });
        });
      </script>
    `, req.session.user));
  } catch (e) {
    next(e);
  }
});

app.post("/admin/service/:id", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).send("Invalid service ID");
    }

    if (req.body.save === "1") {
      const rate = Number(req.body.rate);

      if (!Number.isFinite(rate) || rate < 0) {
        return res.status(400).send("Invalid price");
      }

      await db(
        `UPDATE services SET rate=$1
         WHERE id=$2
           AND category='Instagram'
           AND service_group=ANY($3::text[])`,
        [rate, id, INSTAGRAM_GROUPS]
      );
    } else {
      await db(
        `UPDATE services SET active=$1
         WHERE id=$2
           AND category='Instagram'
           AND service_group=ANY($3::text[])`,
        [req.body.active === "true", id, INSTAGRAM_GROUPS]
      );
    }

    res.redirect("/admin/services");
  } catch (e) {
    next(e);
  }
});

/* ADMIN PAYMENTS */

app.get("/admin/payments", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT p.*,u.username,u.email
      FROM payments p
      JOIN users u ON u.id=p.user_id
      ORDER BY p.id DESC
      LIMIT 200
    `);

    const rows = r.rows.map(p => `
      <tr>
        <td>${esc(p.id)}</td>
        <td>${esc(p.username)}</td>
        <td>₹${money(p.amount)}</td>
        <td>${esc(p.utr)}</td>
        <td>${esc(p.status)}</td>
        <td>
          ${p.status === "Pending" ? `
            <form method="POST" action="/admin/payment/${esc(p.id)}">
              <button name="action" value="approve">Approve</button>
              <button name="action" value="reject">Reject</button>
            </form>
          ` : ""}
        </td>
      </tr>
    `).join("");

    res.send(page("Payments", `
      <div class="card">
        <h2>Fund Approvals</h2>
        <div class="table-wrap">
          <table>
            <tr>
              <th>ID</th>
              <th>User</th>
              <th>Amount</th>
              <th>UTR</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
            ${rows}
          </table>
        </div>
      </div>
    `, req.session.user));
  } catch (e) {
    next(e);
  }
});

app.post("/admin/payment/:id", requireLogin, requireAdmin, async (req, res, next) => {
  const c = await pool.connect();

  try {
    await c.query("BEGIN");

    const r = await c.query(
      "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    const p = r.rows[0];

    if (!p || p.status !== "Pending") {
      throw new Error("Payment already processed");
    }

    if (req.body.action === "approve") {
      await c.query(
        "UPDATE users SET balance=balance+$1 WHERE id=$2",
        [p.amount, p.user_id]
      );

      await c.query(
        "UPDATE payments SET status='Approved' WHERE id=$1",
        [p.id]
      );
    } else if (req.body.action === "reject") {
      await c.query(
        "UPDATE payments SET status='Rejected' WHERE id=$1",
        [p.id]
      );
    } else {
      throw new Error("Invalid payment action");
    }

    await c.query("COMMIT");
    res.redirect("/admin/payments");
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    res.status(400).send(esc(e.message));
  } finally {
    c.release();
  }
});

/* ADMIN REFUNDS */

app.get("/admin/refunds", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT f.*,u.username
      FROM refunds f
      JOIN users u ON u.id=f.user_id
      ORDER BY f.id DESC
    `);

    const rows = r.rows.map(f => `
      <tr>
        <td>${esc(f.id)}</td>
        <td>${esc(f.username)}</td>
        <td>₹${money(f.amount)}</td>
        <td>${esc(f.reason)}</td>
        <td>${esc(f.status)}</td>
        <td>
          ${f.status === "Pending" ? `
            <form method="POST" action="/admin/refund/${esc(f.id)}">
              <button name="action" value="approve">Approve</button>
              <button name="action" value="reject">Reject</button>
            </form>
          ` : ""}
        </td>
      </tr>
    `).join("");

    res.send(page("Refunds", `
      <div class="card">
        <h2>Refund Requests</h2>
        <div class="table-wrap">
          <table>
            <tr>
              <th>ID</th>
              <th>User</th>
              <th>Amount</th>
              <th>Reason</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
            ${rows}
          </table>
        </div>
      </div>
    `, req.session.user));
  } catch (e) {
    next(e);
  }
});

app.post("/admin/refund/:id", requireLogin, requireAdmin, async (req, res, next) => {
  const c = await pool.connect();

  try {
    await c.query("BEGIN");

    const r = await c.query(
      "SELECT * FROM refunds WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    const f = r.rows[0];

    if (!f || f.status !== "Pending") {
      throw new Error("Refund already processed");
    }

    if (req.body.action === "approve") {
      if (!f.funds_reserved) {
        const u = await c.query(
          "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
          [f.user_id]
        );

        if (Number(u.rows[0]?.balance || 0) < Number(f.amount)) {
          throw new Error("Insufficient wallet balance");
        }

        await c.query(
          "UPDATE users SET balance=balance-$1 WHERE id=$2",
          [f.amount, f.user_id]
        );
      }

      await c.query(
        "UPDATE refunds SET status='Approved' WHERE id=$1",
        [f.id]
      );
    } else if (req.body.action === "reject") {
      if (f.funds_reserved) {
        await c.query(
          "UPDATE users SET balance=balance+$1 WHERE id=$2",
          [f.amount, f.user_id]
        );
      }

      await c.query(
        "UPDATE refunds SET status='Rejected' WHERE id=$1",
        [f.id]
      );
    } else {
      throw new Error("Invalid refund action");
    }

    await c.query("COMMIT");
    res.redirect("/admin/refunds");
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    res.status(400).send(esc(e.message));
  } finally {
    c.release();
  }
});

/* ADMIN USERS */

app.get("/admin/users", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT id,username,email,balance,is_admin,created_at
      FROM users
      ORDER BY id DESC
      LIMIT 200
    `);

    const rows = r.rows.map(u => `
      <tr>
        <td>${esc(u.id)}</td>
        <td>${esc(u.username)}</td>
        <td>${esc(u.email || "")}</td>
        <td>₹${money(u.balance)}</td>
        <td>${u.is_admin ? "Admin" : "Customer"}</td>
      </tr>
    `).join("");

    res.send(page("Customers", `
      <div class="card">
        <h2>Customers</h2>
        <div class="table-wrap">
          <table>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Email</th>
              <th>Balance</th>
              <th>Role</th>
            </tr>
            ${rows}
          </table>
        </div>
      </div>
    `, req.session.user));
  } catch (e) {
    next(e);
  }
});

/* ADMIN ORDERS */

app.get("/admin/orders", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const r = await db(`
      SELECT o.*,u.username
      FROM orders o
      JOIN users u ON u.id=o.user_id
      ORDER BY o.id DESC
      LIMIT 200
    `);

    const rows = r.rows.map(o => `
      <tr>
        <td>${esc(o.id)}</td>
        <td>${esc(o.username)}</td>
        <td>${esc(o.service_name || o.service_id)}</td>
        <td>${esc(o.quantity)}</td>
        <td>${esc(o.status)}</td>
        <td>${esc(o.provider_order_id || "")}</td>
      </tr>
    `).join("");

    res.send(page("Orders", `
      <div class="card">
        <h2>All Orders</h2>
        <div class="table-wrap">
          <table>
            <tr>
              <th>ID</th>
              <th>User</th>
              <th>Service</th>
              <th>Qty</th>
              <th>Status</th>
              <th>Provider ID</th>
            </tr>
            ${rows}
          </table>
        </div>
      </div>
    `, req.session.user));
  } catch (e) {
    next(e);
  }
});

/* LOGOUT */

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("royal.sid");
    res.redirect("/login");
  });
});

/* HEALTH CHECK */

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    app: "ROYAL PANEL"
  });
});

/* ERROR HANDLER */

app.use((err, req, res, next) => {
  console.error("Server error:", err);

  if (res.headersSent) return next(err);

  res.status(500).send("Server error. Please try again later.");
});

/* START SERVER */

const PORT = process.env.PORT || 3000;

setupDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log("ROYAL PANEL running on port " + PORT);
    });
  })
  .catch(e => {
    console.error("Database setup failed:", e);
    process.exit(1);
  });
