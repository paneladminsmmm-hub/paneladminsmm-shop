
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

if (process.env.NODE_ENV === "production" && !SESSION_SECRET) {
  throw new Error("SESSION_SECRET environment variable is required in production");
}

const googleClient = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  APP_URL ? APP_URL + "/auth/google/callback" : undefined
);

async function db(sql, values = []) {
  return pool.query(sql, values);
}

/* -------------------- HTML SAFETY -------------------- */

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function message(value) {
  return `<div class="card">${esc(value)}</div>`;
}

/* -------------------- POSTGRES SESSION STORE -------------------- */

class PostgresSessionStore extends session.Store {
  get(sid, callback) {
    db(
      `SELECT sess FROM user_sessions
       WHERE sid=$1 AND expire > NOW()`,
      [sid]
    ).then(result => {
      callback(null, result.rows[0]?.sess || null);
    }).catch(callback);
  }

  set(sid, sess, callback = () => {}) {
    const expire = sess.cookie?.expires
      ? new Date(sess.cookie.expires)
      : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    db(
      `INSERT INTO user_sessions(sid,sess,expire)
       VALUES($1,$2,$3)
       ON CONFLICT(sid)
       DO UPDATE SET sess=EXCLUDED.sess,expire=EXCLUDED.expire`,
      [sid, JSON.stringify(sess), expire]
    ).then(() => callback(null)).catch(callback);
  }

  destroy(sid, callback = () => {}) {
    db(`DELETE FROM user_sessions WHERE sid=$1`, [sid])
      .then(() => callback(null)).catch(callback);
  }

  touch(sid, sess, callback = () => {}) {
    const expire = sess.cookie?.expires
      ? new Date(sess.cookie.expires)
      : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    db(`UPDATE user_sessions SET expire=$1 WHERE sid=$2`, [expire, sid])
      .then(() => callback(null)).catch(callback);
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
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

/* -------------------- DATABASE SETUP -------------------- */

async function setupDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
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

  await db(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(200)`);
  await db(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT`);
  await db(`ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id TEXT`);
  await db(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE`);
  await db(`ALTER TABLE users ADD COLUMN IF NOT EXISTS balance NUMERIC(14,2) DEFAULT 0`);

  await db(`
    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      provider_id TEXT,
      provider_source TEXT DEFAULT 'socialadd',
      provider_type TEXT DEFAULT 'Default',
      name TEXT NOT NULL,
      category TEXT DEFAULT 'Instagram',
      description TEXT DEFAULT '',
      rate NUMERIC(14,4) DEFAULT 0,
      provider_rate NUMERIC(14,6) DEFAULT 0,
      min INTEGER DEFAULT 100,
      max INTEGER DEFAULT 1000000,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`ALTER TABLE services ADD COLUMN IF NOT EXISTS provider_source TEXT DEFAULT 'socialadd'`);
  await db(`ALTER TABLE services ADD COLUMN IF NOT EXISTS provider_type TEXT DEFAULT 'Default'`);
  await db(`ALTER TABLE services ADD COLUMN IF NOT EXISTS provider_rate NUMERIC(14,6) DEFAULT 0`);
  await db(`ALTER TABLE services ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''`);
  await db(`ALTER TABLE services ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE`);

  await db(`
    CREATE TABLE IF NOT EXISTS orders (
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

  await db(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS service_name TEXT`);
  await db(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS provider_order_id TEXT`);

  await db(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(14,2),
      utr TEXT,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      message TEXT,
      status TEXT DEFAULT 'Open',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS refunds (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(14,2),
      reason TEXT,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`ALTER TABLE refunds ADD COLUMN IF NOT EXISTS funds_reserved BOOLEAN DEFAULT FALSE`);

  await db(`
    CREATE TABLE IF NOT EXISTS panel_settings (
      setting_key TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      sid VARCHAR(255) PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMPTZ NOT NULL
    )
  `);

  await db(`CREATE INDEX IF NOT EXISTS user_sessions_expire_idx ON user_sessions(expire)`);

  await db(`
    INSERT INTO panel_settings(setting_key,setting_value)
    VALUES ('provider_enabled','true'), ('services_enabled','true')
    ON CONFLICT (setting_key) DO NOTHING
  `);

  await db(`
    DELETE FROM services a
    USING services b
    WHERE a.id > b.id
      AND a.provider_id IS NOT NULL
      AND a.provider_source = b.provider_source
      AND a.provider_id = b.provider_id
  `);

  await db(`
    CREATE UNIQUE INDEX IF NOT EXISTS services_provider_unique
    ON services(provider_source,provider_id)
    WHERE provider_id IS NOT NULL
  `);

  if (ADMIN_EMAIL) {
    await db(
      `UPDATE users SET is_admin=TRUE WHERE LOWER(email)=LOWER($1)`,
      [ADMIN_EMAIL]
    );
  }

  if (ADMIN_USERNAME && ADMIN_PASSWORD) {
    const existing = await db(
      `SELECT id FROM users WHERE username=$1`,
      [ADMIN_USERNAME]
    );

    if (!existing.rows.length) {
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

/* -------------------- SETTINGS -------------------- */

async function setting(key) {
  const result = await db(
    `SELECT setting_value FROM panel_settings WHERE setting_key=$1`,
    [key]
  );

  return result.rows[0]?.setting_value || "false";
}

async function setSetting(key, value) {
  await db(
    `INSERT INTO panel_settings(setting_key,setting_value)
     VALUES($1,$2)
     ON CONFLICT (setting_key)
     DO UPDATE SET setting_value=EXCLUDED.setting_value`,
    [key, String(value)]
  );
}

/* -------------------- AUTHENTICATION -------------------- */

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

async function requireAdmin(req, res, next) {
  try {
    if (!req.session.user?.id) {
      return res.status(403).send("Admin access required");
    }

    const result = await db(
      `SELECT is_admin FROM users WHERE id=$1`,
      [req.session.user.id]
    );

    if (!result.rows[0]?.is_admin) {
      req.session.user.is_admin = false;
      return res.status(403).send("Admin access required");
    }

    req.session.user.is_admin = true;
    next();
  } catch (error) {
    next(error);
  }
}

function createUserSession(req, user, res) {
  req.session.regenerate(error => {
    if (error) return res.status(500).send("Session error");

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin: Boolean(user.is_admin)
    };

    req.session.save(error => {
      if (error) return res.status(500).send("Session save error");
      res.redirect("/services");
    });
  });
}

/* -------------------- GLOBAL WHATSAPP + TELEGRAM -------------------- */

function socialSupportLinks() {
  return `
    <div class="social-float" aria-label="Contact Support">

      <a class="social-float-btn whatsapp-float"
         href="${esc(WHATSAPP_LINK)}"
         target="_blank"
         rel="noopener noreferrer"
         aria-label="WhatsApp Support"
         title="WhatsApp Support">

        <svg viewBox="0 0 32 32" aria-hidden="true">
          <path fill="currentColor" d="M16 2.5A13.3 13.3 0 0 0 4.6 22.7L3 29l6.5-1.7A13.4 13.4 0 1 0 16 2.5zm0 24.2c-2 0-3.9-.5-5.6-1.5l-.4-.2-3.9 1 1-3.8-.3-.4a10.9 10.9 0 1 1 9.2 4.9zm6-8.1c-.3-.2-1.8-.9-2.1-1-.3-.1-.5-.2-.7.2-.2.3-.8 1-1 1.2-.2.2-.4.2-.7.1-1.8-.9-3-1.6-4.2-3.6-.3-.5.3-.5.9-1.6.1-.2 0-.4 0-.6l-.9-2.2c-.2-.5-.5-.4-.7-.4h-.6c-.2 0-.6.1-.9.4-.3.3-1.1 1.1-1.1 2.6s1.1 3 1.2 3.2c.2.2 2.2 3.4 5.3 4.7 2 .9 2.8 1 3.8.8.6-.1 1.8-.7 2.1-1.4.3-.7.3-1.3.2-1.4-.1-.2-.3-.3-.6-.5z"/>
        </svg>
      </a>

      <a class="social-float-btn telegram-float"
         href="${esc(TELEGRAM_LINK)}"
         target="_blank"
         rel="noopener noreferrer"
         aria-label="Telegram Support"
         title="Telegram Support">

        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path fill="currentColor" d="M21.9 4.2 18.6 20c-.2 1.1-.8 1.4-1.7.9l-4.7-3.5-2.3 2.2c-.3.3-.5.5-1 .5l.4-4.8 8.7-7.9c.4-.4-.1-.6-.6-.2L6.7 14.1 2.1 12.7c-1-.3-1-1 .2-1.5L20.2 4.3c.8-.3 1.5.2 1.7-.1z"/>
        </svg>
      </a>

    </div>
  `;
}

/* -------------------- PAGE DESIGN -------------------- */

function page(title, body, user = null) {
  const adminMenu = user?.is_admin ? `
    <div class="menu-section-title">ADMINISTRATION</div>
    <a class="menu-link" href="/admin">⚙️ Admin Dashboard</a>
    <a class="menu-link" href="/admin/services">🛠️ Manage Services</a>
    <a class="menu-link" href="/admin/payments">💳 Fund Approvals</a>
    <a class="menu-link" href="/admin/refunds">↩️ Refund Approvals</a>
    <a class="menu-link" href="/admin/orders">📦 Manage Orders</a>
    <a class="menu-link" href="/admin/users">👥 Customers</a>
  ` : "";

  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#09090d">
    <title>${esc(title)} | ROYAL PANEL</title>
    <style>
      *{box-sizing:border-box}
      html{scroll-behavior:smooth}
      body{
        margin:0;min-height:100vh;
        font-family:Arial,Helvetica,sans-serif;color:#fff;
        background:radial-gradient(ellipse at top left,#35101d 0%,transparent 42%),
        radial-gradient(ellipse at bottom right,#101d3b 0%,transparent 45%),#09090d
      }
      body.menu-open{overflow:hidden}
      .top-header{
        width:100%;min-height:82px;padding:12px 18px;
        display:flex;align-items:center;justify-content:space-between;
        gap:15px;background:rgba(12,12,17,.97);
        border-bottom:1px solid #30303a;position:sticky;top:0;z-index:100
      }
      .brand{
        color:#fff;font-size:29px;font-weight:900;letter-spacing:1.5px;
        text-decoration:none;margin:0
      }
      .menu-button{
        width:64px;height:58px;border:1px solid #e52b50;
        border-radius:12px;background:#e51d43;color:white;
        display:flex;align-items:center;justify-content:center;
        flex-direction:column;gap:7px;cursor:pointer;padding:10px;margin:0
      }
      .menu-button span{display:block;width:32px;height:4px;border-radius:5px;background:white}
      .menu-overlay{
        position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:200;
        opacity:0;visibility:hidden;transition:.25s
      }
      .menu-overlay.open{opacity:1;visibility:visible}
      .side-drawer{
        position:fixed;top:0;left:0;width:310px;max-width:86vw;
        height:100vh;height:100dvh;overflow-y:auto;background:#101015;
        border-right:1px solid #34343e;z-index:300;
        transform:translateX(-105%);transition:transform .28s ease;
        padding:0 15px 25px;box-shadow:10px 0 35px rgba(0,0,0,.4)
      }
      .side-drawer.open{transform:translateX(0)}
      .drawer-header{
        min-height:82px;display:flex;align-items:center;
        justify-content:space-between;border-bottom:1px solid #33333c;
        margin-bottom:15px;gap:8px
      }
      .drawer-brand{font-size:23px;font-weight:900;letter-spacing:1px;color:white}
      .close-menu{
        width:42px;height:42px;padding:0;margin:0;border-radius:10px;
        background:#292932;color:white;font-size:27px;line-height:1
      }
      .menu-section-title{
        color:#888894;font-size:11px;font-weight:bold;
        letter-spacing:1.5px;padding:17px 10px 8px
      }
      .menu-link{
        display:flex;align-items:center;gap:13px;width:100%;
        padding:14px 12px;margin:4px 0;color:#ededf2;
        text-decoration:none;font-size:15px;font-weight:600;
        border:1px solid transparent;border-radius:10px
      }
      .menu-link:hover{color:white;background:#29202a;border-color:#713044}
      .logout-link{
        color:#ff647c;margin-top:18px;border-top:1px solid #34343e;
        border-radius:0;padding-top:20px
      }
      main{width:100%;max-width:1100px;margin:25px auto;padding:15px 15px 95px}
      .card{
        background:rgba(23,23,29,.96);border:1px solid #393943;
        border-radius:15px;padding:20px;margin:13px 0;
        box-shadow:0 8px 25px rgba(0,0,0,.15)
      }
      h1,h2,h3{color:white}
      a{color:#ff526b;text-decoration:none}
      input,select,textarea{
        width:100%;padding:13px;margin:7px 0;border-radius:9px;
        border:1px solid #555560;background:#09090e;color:white;font-size:15px
      }
      input:focus,select:focus,textarea:focus{
        outline:none;border-color:#e51d43;box-shadow:0 0 0 2px rgba(229,29,67,.15)
      }
      button{
        background:#e51d43;color:white;padding:12px 18px;border:0;
        border-radius:9px;margin:5px;cursor:pointer;font-size:14px;font-weight:bold
      }
      button:hover{background:#c91638}
      table{width:100%;border-collapse:collapse}
      td,th{padding:11px;border-bottom:1px solid #44444e;text-align:left}
      th{color:#ff758a;white-space:nowrap}
      .muted{color:#bbb}
      .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}

      /* WhatsApp and Telegram fixed side-by-side buttons */
      .social-float{
        position:fixed;
        right:18px;
        bottom:18px;
        z-index:9999;
        display:flex;
        flex-direction:row;
        align-items:center;
        gap:10px;
      }
      .social-float-btn{
        width:54px;
        height:54px;
        border-radius:50%;
        display:flex;
        align-items:center;
        justify-content:center;
        color:#fff;
        text-decoration:none;
        box-shadow:0 5px 18px rgba(0,0,0,.45);
        border:2px solid rgba(255,255,255,.85);
        transition:transform .2s;
      }
      .social-float-btn:hover{transform:scale(1.08)}
      .social-float-btn svg{
        width:29px;
        height:29px;
        display:block;
      }
      .whatsapp-float{background:#25D366}
      .telegram-float{background:#229ED9}

      .search-box{margin:10px 0 15px}
      .qr-box{text-align:center;margin:18px auto;padding:15px;background:#fff;border-radius:14px;max-width:320px}
      .qr-box img{display:block;width:100%;max-width:260px;height:auto;margin:auto}
      .qr-caption{color:#222;font-weight:bold;margin-top:10px}
      .table-wrap{width:100%;overflow-x:auto}
      .table-wrap table{min-width:650px}

      @media(max-width:600px){
        .top-header{min-height:75px;padding:10px 13px}
        .brand{font-size:23px}
        .menu-button{width:58px;height:53px}
        main{margin:15px auto;padding:10px 10px 90px}
        .card{padding:15px}
        .social-float{right:12px;bottom:12px;gap:8px}
        .social-float-btn{width:49px;height:49px}
        .social-float-btn svg{width:26px;height:26px}
      }
    </style>
  </head>
  <body>
    <header class="top-header">
      <a class="brand" href="${user ? "/services" : "/login"}">ROYAL PANEL</a>
      ${user ? `
        <button type="button" class="menu-button"
          onclick="openRoyalMenu()" aria-label="Open Menu"
          aria-expanded="false" id="royalMenuButton">
          <span></span><span></span><span></span>
        </button>` : ""}
    </header>

    ${user ? `
      <div class="menu-overlay" id="royalMenuOverlay"
        onclick="closeRoyalMenu()"></div>
      <aside class="side-drawer" id="royalSideDrawer">
        <div class="drawer-header">
          <div class="drawer-brand">ROYAL PANEL</div>
          <button type="button" class="close-menu"
            onclick="closeRoyalMenu()" aria-label="Close Menu">×</button>
        </div>
        <div class="menu-section-title">MAIN MENU</div>
        <a class="menu-link" href="/services">➕ New Order / Services</a>
        <a class="menu-link" href="/orders">📦 My Orders</a>
        <a class="menu-link" href="/funds">💰 Add Funds</a>
        <a class="menu-link" href="/refund">↩️ Refund Request</a>
        <a class="menu-link" href="/support">🎧 Support</a>
        ${adminMenu}
        <a class="menu-link logout-link" href="/logout">🚪 Logout</a>
      </aside>
      <script>
        function openRoyalMenu(){
          const drawer=document.getElementById("royalSideDrawer");
          const overlay=document.getElementById("royalMenuOverlay");
          const button=document.getElementById("royalMenuButton");
          if(!drawer||!overlay)return;
          drawer.classList.add("open");
          overlay.classList.add("open");
          document.body.classList.add("menu-open");
          if(button)button.setAttribute("aria-expanded","true");
        }
        function closeRoyalMenu(){
          const drawer=document.getElementById("royalSideDrawer");
          const overlay=document.getElementById("royalMenuOverlay");
          const button=document.getElementById("royalMenuButton");
          if(!drawer||!overlay)return;
          drawer.classList.remove("open");
          overlay.classList.remove("open");
          document.body.classList.remove("menu-open");
          if(button)button.setAttribute("aria-expanded","false");
        }
        document.addEventListener("keydown",function(event){
          if(event.key==="Escape")closeRoyalMenu();
        });
      </script>
    ` : ""}

    <main>${body}</main>

    ${socialSupportLinks()}

  </body>
  </html>`;
}

/* -------------------- PROVIDER API -------------------- */

async function providerRequest(params) {
  if (!PROVIDER_KEY) throw new Error("SocialAdd API key missing");

  const body = new URLSearchParams({
    key: PROVIDER_KEY,
    ...params
  });

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

function isInstagram(item) {
  const value = `${item.name || ""} ${item.category || ""}`.toLowerCase();
  return value.includes("instagram") || value.includes("ig ");
}

/* -------------------- HOME -------------------- */

app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/services" : "/login");
});

/* -------------------- LOGIN -------------------- */

app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card">
      <h2>Royal Panel Login</h2>
      <form method="POST" action="/login">
        <input name="email" placeholder="Email or Username" required>
        <input name="password" type="password" placeholder="Password" required>
        <button>Login</button>
      </form>
      <a href="/auth/google">Continue with Google</a>
      <p><a href="/register">Create Account</a></p>
    </div>
  `));
});

app.post("/login", async (req, res, next) => {
  try {
    const identity = String(req.body.email || "").trim();

    const result = await db(
      `SELECT * FROM users
       WHERE LOWER(email)=LOWER($1) OR LOWER(username)=LOWER($1)
       LIMIT 1`,
      [identity]
    );

    const user = result.rows[0];
    const hash = user?.password_hash || user?.password;

    if (!user || !hash || !await bcrypt.compare(String(req.body.password || ""), hash)) {
      return res.status(401).send(page("Login", message("Invalid login details")));
    }

    createUserSession(req, user, res);
  } catch (error) {
    next(error);
  }
});

/* -------------------- REGISTER -------------------- */

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h2>Create Account</h2>
      <form method="POST" action="/register">
        <input name="username" placeholder="Username" required maxlength="100">
        <input name="email" type="email" placeholder="Email" required maxlength="200">
        <input name="password" type="password" minlength="6" placeholder="Password" required>
        <button>Continue</button>
      </form>
      <a href="/auth/google">Continue with Google</a>
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

    const result = await db(
      `INSERT INTO users(username,email,password_hash,password)
       VALUES($1,$2,$3,$3) RETURNING *`,
      [username, email, hash]
    );

    createUserSession(req, result.rows[0], res);
  } catch (error) {
    if (error.code === "23505") {
      return res.status(400).send(page("Register", message("Username or email already exists")));
    }
    next(error);
  }
});

/* -------------------- GOOGLE LOGIN -------------------- */

app.get("/auth/google", (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !APP_URL) {
    return res.status(503).send("Google Login environment settings are missing");
  }

  const state = crypto.randomBytes(24).toString("hex");
  req.session.googleState = state;

  req.session.save(error => {
    if (error) return res.status(500).send("Could not start Google Login");

    const url = googleClient.generateAuthUrl({
      access_type: "online",
      scope: ["openid", "email", "profile"],
      state
    });

    res.redirect(url);
  });
});

app.get("/auth/google/callback", async (req, res, next) => {
  try {
    if (!req.query.code || req.query.state !== req.session.googleState) {
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

    let result = await db(
      `SELECT * FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1`,
      [email]
    );

    let user = result.rows[0];

    if (!user) {
      const base = (profile.name || email.split("@")[0])
        .replace(/[^a-zA-Z0-9_]/g, "").slice(0, 20) || "customer";

      const username = base + "_" + crypto.randomBytes(3).toString("hex");

      result = await db(
        `INSERT INTO users(username,email,google_id)
         VALUES($1,$2,$3) RETURNING *`,
        [username, email, profile.sub]
      );

      user = result.rows[0];
    } else if (!user.google_id) {
      await db(
        `UPDATE users SET google_id=$1 WHERE id=$2`,
        [profile.sub, user.id]
      );
      user.google_id = profile.sub;
    }

    if (ADMIN_EMAIL && email === ADMIN_EMAIL) {
      await db(`UPDATE users SET is_admin=TRUE WHERE id=$1`, [user.id]);
      user.is_admin = true;
    }

    createUserSession(req, user, res);
  } catch (error) {
    next(error);
  }
});

/* -------------------- OLD DASHBOARD REDIRECT -------------------- */

app.get("/dashboard", requireLogin, (req, res) => {
  res.redirect("/services");
});

/* -------------------- CUSTOMER SERVICES -------------------- */

app.get("/services", requireLogin, async (req, res, next) => {
  try {
    const enabled = await setting("services_enabled");

    const walletResult = await db(
      `SELECT balance FROM users WHERE id=$1`,
      [req.session.user.id]
    );

    const balance = Number(walletResult.rows[0]?.balance || 0);

    const result = await db(
      `SELECT * FROM services
       WHERE active=TRUE
       AND LOWER(category) LIKE '%instagram%'
       ORDER BY id DESC`
    );

    const rows = result.rows.map(service => `
      <option value="${esc(service.id)}">
        ${esc(service.name)} - ₹${Number(service.rate).toFixed(2)}
        (Min ${esc(service.min)} / Max ${esc(service.max)})
      </option>
    `).join("");

    res.send(page("New Order", `
      <div class="card">
        <div style="
          background:#101d3b;
          border:1px solid #e51d43;
          border-radius:12px;
          padding:16px;
          margin-bottom:18px;
        ">
          <div style="color:#bbb;font-size:14px;">WALLET BALANCE</div>
          <h2 style="color:#fff;margin:8px 0 0;">
            ₹${balance.toFixed(2)}
          </h2>
        </div>

        <h2>New Order / Instagram Services</h2>

        ${enabled === "true" ? `
          <form method="POST" action="/order">
            <input type="search" id="serviceSearch"
              class="search-box"
              placeholder="Search Instagram services..."
              autocomplete="off">
            <select name="service_id" id="serviceSelect" required>
              <option value="">Select a service</option>
              ${rows}
            </select>
            <input name="link" placeholder="Instagram Link" required maxlength="2000">
            <input name="quantity" type="number" min="1" placeholder="Quantity" required>
            <button>Place Order</button>
          </form>
          <script>
            (function(){
              const search=document.getElementById("serviceSearch");
              const select=document.getElementById("serviceSelect");
              const options=Array.from(select.options);
              search.addEventListener("input",function(){
                const term=this.value.toLowerCase().trim();
                options.forEach(function(option,index){
                  if(index===0)return;
                  option.hidden=!option.text.toLowerCase().includes(term);
                });
                if(select.selectedOptions[0]?.hidden)select.value="";
              });
            })();
          </script>
        ` : "Services are temporarily disabled"}
      </div>
    `, req.session.user));
  } catch (error) {
    next(error);
  }
});

/* -------------------- PLACE ORDER -------------------- */

app.post("/order", requireLogin, async (req, res, next) => {
  const client = await pool.connect();
  let orderId = null;
  let charge = 0;

  try {
    await client.query("BEGIN");

    const globalEnabled = await setting("services_enabled");

    if (globalEnabled !== "true") {
      throw new Error("Services are disabled");
    }

    const serviceResult = await client.query(
      `SELECT * FROM services
       WHERE id=$1 AND active=TRUE
       AND LOWER(category) LIKE '%instagram%'
       FOR UPDATE`,
      [req.body.service_id]
    );

    const service = serviceResult.rows[0];

    if (!service) {
      throw new Error("Instagram service not found");
    }

    if (service.provider_source === "socialadd") {
      if (await setting("provider_enabled") !== "true") {
        throw new Error("Provider API is disabled. Orders are temporarily unavailable.");
      }

      if (!PROVIDER_KEY || !service.provider_id) {
        throw new Error("Provider API configuration or service ID is missing");
      }
    }

    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(quantity) ||
        quantity < Number(service.min) ||
        quantity > Number(service.max) ||
        !link || link.length > 2000) {
      throw new Error("Invalid link or quantity");
    }

    charge = Math.round(Number(service.rate) * quantity / 1000 * 100) / 100;

    if (!Number.isFinite(charge) || charge <= 0) {
      throw new Error("Invalid service price");
    }

    const userResult = await client.query(
      `SELECT balance FROM users WHERE id=$1 FOR UPDATE`,
      [req.session.user.id]
    );

    if (!userResult.rows[0] ||
        Number(userResult.rows[0].balance) < charge) {
      throw new Error("Insufficient wallet balance");
    }

    await client.query(
      `UPDATE users SET balance=balance-$1 WHERE id=$2`,
      [charge, req.session.user.id]
    );

    const orderResult = await client.query(
      `INSERT INTO orders(
        user_id,service_id,service_name,link,quantity,charge,status
      )
      VALUES($1,$2,$3,$4,$5,$6,'Pending')
      RETURNING id`,
      [req.session.user.id, service.id, service.name, link, quantity, charge]
    );

    orderId = orderResult.rows[0].id;

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
      } catch (providerError) {
        const refundClient = await pool.connect();

        try {
          await refundClient.query("BEGIN");

          const lockedOrder = await refundClient.query(
            `SELECT status,charge,user_id FROM orders WHERE id=$1 FOR UPDATE`,
            [orderId]
          );

          if (lockedOrder.rows[0]?.status === "Pending") {
            await refundClient.query(
              `UPDATE users SET balance=balance+$1 WHERE id=$2`,
              [lockedOrder.rows[0].charge, lockedOrder.rows[0].user_id]
            );

            await refundClient.query(
              `UPDATE orders SET status='Provider Error - Refunded' WHERE id=$1`,
              [orderId]
            );
          }

          await refundClient.query("COMMIT");
        } catch (refundError) {
          await refundClient.query("ROLLBACK");
          console.error("Automatic provider refund failed:", refundError);
        } finally {
          refundClient.release();
        }

        console.error("Provider order failed:", providerError.message);
      }
    }

    res.redirect("/orders");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    res.status(400).send(page("Order", message(error.message), req.session.user));
  } finally {
    client.release();
  }
});

/* -------------------- CUSTOMER ORDERS -------------------- */

app.get("/orders", requireLogin, async (req, res, next) => {
  try {
    const result = await db(
      `SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC LIMIT 100`,
      [req.session.user.id]
    );

    const rows = result.rows.map(order => `
      <tr>
        <td>${esc(order.id)}</td>
        <td>${esc(order.service_name || order.service_id)}</td>
        <td>${esc(order.quantity)}</td>
        <td>₹${esc(order.charge)}</td>
        <td>${esc(order.status)}</td>
      </tr>
    `).join("");

    res.send(page("Orders", `
      <div class="card"><h2>My Orders</h2>
      <div class="table-wrap">
        <table>
          <tr><th>ID</th><th>Service</th><th>Qty</th><th>Charge</th><th>Status</th></tr>
          ${rows}
        </table>
      </div></div>
    `, req.session.user));
  } catch (error) {
    next(error);
  }
});

/* -------------------- ADD FUNDS / QR -------------------- */

app.get("/funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
    <div class="card">
      <h2>Add Funds - Admin Approval</h2>
      <div class="qr-box">
        <img src="/payment-qr.png" alt="UPI Payment QR Code"
          onerror="this.style.display='none';document.getElementById('qrError').style.display='block';">
        <div class="qr-caption">Scan QR Code to Pay</div>
      </div>
      <p id="qrError" style="display:none;color:#ff526b;text-align:center;">
        QR image could not be loaded. Check public/payment-qr.png
      </p>
      <p>UPI ID: <b>${esc(UPI_ID)}</b></p>
      <form method="POST" action="/funds">
        <input name="amount" type="number" min="10" max="2000"
          step="0.01" placeholder="Amount ₹10 - ₹2000" required>
        <input name="utr" placeholder="UTR / Transaction ID" required maxlength="150">
        <button>Submit Payment</button>
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
      `INSERT INTO payments(user_id,amount,utr,status)
       VALUES($1,$2,$3,'Pending')`,
      [req.session.user.id, amount, utr]
    );

    res.send(page(
      "Payment",
      message("Payment submitted. Waiting for Admin Approval."),
      req.session.user
    ));
  } catch (error) {
    next(error);
  }
});

/* -------------------- REFUND REQUEST -------------------- */

app.get("/refund", requireLogin, (req, res) => {
  res.send(page("Refund", `
    <div class="card">
      <h2>Refund Request</h2>
      <p class="muted">Minimum ₹10 - Maximum ₹2000</p>
      <form method="POST" action="/refund">
        <input name="amount" type="number" min="10" max="2000"
          step="0.01" placeholder="₹10 - ₹2000" required>
        <textarea name="reason" placeholder="Refund reason" required maxlength="2000"></textarea>
        <button>Submit Refund Request</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/refund", requireLogin, async (req, res, next) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const amount = Number(req.body.amount);
    const reason = String(req.body.reason || "").trim();

    if (!Number.isFinite(amount) || amount < 10 || amount > 2000 ||
        !reason || reason.length > 2000) {
      throw new Error("Refund must be between ₹10 and ₹2000.");
    }

    const user = await client.query(
      `SELECT balance FROM users WHERE id=$1 FOR UPDATE`,
      [req.session.user.id]
    );

    if (!user.rows[0] || Number(user.rows[0].balance) < amount) {
      throw new Error("Insufficient wallet balance.");
    }

    await client.query(
      `UPDATE users SET balance=balance-$1 WHERE id=$2`,
      [amount, req.session.user.id]
    );

    await client.query(
      `INSERT INTO refunds(user_id,amount,reason,status,funds_reserved)
       VALUES($1,$2,$3,'Pending',TRUE)`,
      [req.session.user.id, amount, reason]
    );

    await client.query("COMMIT");

    res.send(page(
      "Refund",
      message("Refund request sent to Admin for approval. Requested amount is reserved."),
      req.session.user
    ));
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    res.status(400).send(page("Refund", message(error.message), req.session.user));
  } finally {
    client.release();
  }
});

/* -------------------- SUPPORT -------------------- */

app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
    <div class="card">
      <h2>Support</h2>
      <form method="POST" action="/support">
        <textarea name="message" required maxlength="3000"
          placeholder="Write your message"></textarea>
        <button>Send Message</button>
      </form>
      <h3>Contact Us</h3>
      <p class="muted">WhatsApp और Telegram के बटन स्क्रीन के नीचे दिखाई दे रहे हैं।</p>
    </div>
  `, req.session.user));
});

app.post("/support", requireLogin, async (req, res, next) => {
  try {
    const text = String(req.body.message || "").trim();

    if (!text || text.length > 3000) {
      return res.status(400).send("Enter a valid support message.");
    }

    await db(
      `INSERT INTO tickets(user_id,message,status)
       VALUES($1,$2,'Open')`,
      [req.session.user.id, text]
    );

    res.redirect("/services");
  } catch (error) {
    next(error);
  }
});

/* -------------------- ADMIN DASHBOARD -------------------- */

app.get("/admin", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const provider = await setting("provider_enabled");
    const servicesEnabled = await setting("services_enabled");

    const counts = await db(`
      SELECT
        (SELECT COUNT(*) FROM users) AS users,
        (SELECT COUNT(*) FROM orders) AS orders,
        (SELECT COUNT(*) FROM payments WHERE status='Pending') AS pending_payments,
        (SELECT COUNT(*) FROM refunds WHERE status='Pending') AS pending_refunds
    `);

    res.send(page("Admin", `
      <div class="card">
        <h2>Admin Panel</h2>
        <p>Customers: ${esc(counts.rows[0].users)}</p>
        <p>Orders: ${esc(counts.rows[0].orders)}</p>
        <p>Pending Funds: ${esc(counts.rows[0].pending_payments)}</p>
        <p>Pending Refunds: ${esc(counts.rows[0].pending_refunds)}</p>
      </div>

      <div class="card">
        <h3>SocialAdd Provider</h3>
        <p>API: ${provider === "true" ? "Enabled" : "Disabled"}</p>
        <form method="POST" action="/admin/provider-toggle">
          <button name="value" value="true">Enable Provider API</button>
          <button name="value" value="false">Disable Provider API</button>
        </form>
        <form method="POST" action="/admin/import">
          <button>Import Instagram Services</button>
        </form>
        <form method="POST" action="/admin/provider-test">
          <button>Test Provider API</button>
        </form>
      </div>

      <div class="card">
        <h3>All Instagram Services</h3>
        <p>Services: ${servicesEnabled === "true" ? "Enabled" : "Disabled"}</p>
        <form method="POST" action="/admin/services-toggle">
          <button name="value" value="true">Enable All Services</button>
          <button name="value" value="false">Disable All Services</button>
        </form>
      </div>

      <div class="card">
        <a href="/admin/services">Manage Services</a> |
        <a href="/admin/payments">Fund Approvals</a> |
        <a href="/admin/refunds">Refund Approvals</a> |
        <a href="/admin/orders">Manage Orders</a> |
        <a href="/admin/users">Customers</a>
      </div>
    `, req.session.user));
  } catch (error) {
    next(error);
  }
});

/* -------------------- PROVIDER TOGGLE -------------------- */

app.post("/admin/provider-toggle", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    await setSetting("provider_enabled", req.body.value === "true");
    res.redirect("/admin");
  } catch (error) {
    next(error);
  }
});

/* -------------------- GLOBAL SERVICES TOGGLE -------------------- */

app.post("/admin/services-toggle", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const enabled = req.body.value === "true";

    await setSetting("services_enabled", enabled);

    res.redirect("/admin");
  } catch (error) {
    next(error);
  }
});

/* -------------------- PROVIDER TEST -------------------- */

app.post("/admin/provider-test", requireLogin, requireAdmin, async (req, res) => {
  try {
    const data = await providerRequest({ action: "balance" });

    res.send(page(
      "Provider Test",
      message("SocialAdd API connected: " + JSON.stringify(data)),
      req.session.user
    ));
  } catch (error) {
    res.status(500).send(page(
      "Provider Test",
      message("Provider Error: " + error.message),
      req.session.user
    ));
  }
});

/* -------------------- IMPORT INSTAGRAM SERVICES -------------------- */

app.post("/admin/import", requireLogin, requireAdmin, async (req, res) => {
  try {
    if (await setting("provider_enabled") !== "true") {
      throw new Error("Provider API is disabled");
    }

    const list = await providerRequest({ action: "services" });

    if (!Array.isArray(list)) {
      throw new Error("Invalid provider services response");
    }

    let imported = 0;

    for (const item of list) {
      if (!isInstagram(item)) continue;

      const providerId = String(item.service || "").trim();
      const providerRate = Number(item.rate || 0);
      const min = Number(item.min || 100);
      const max = Number(item.max || 1000000);

      if (!providerId ||
          !Number.isFinite(providerRate) ||
          providerRate < 0 ||
          !Number.isInteger(min) ||
          !Number.isInteger(max) ||
          min < 1 || max < min) {
        continue;
      }

      const sellingRate = providerRate * 1.75;

      await db(`
        INSERT INTO services(
          provider_id,provider_source,provider_type,name,category,
          description,rate,provider_rate,min,max,active
        )
        VALUES($1,'socialadd','Default',$2,'Instagram',$3,$4,$5,$6,$7,TRUE)
        ON CONFLICT(provider_source,provider_id)
        WHERE provider_id IS NOT NULL
        DO UPDATE SET
          name=EXCLUDED.name,
          category='Instagram',
          description=EXCLUDED.description,
          provider_rate=EXCLUDED.provider_rate,
          rate=EXCLUDED.rate,
          min=EXCLUDED.min,
          max=EXCLUDED.max
      `, [
        providerId,
        String(item.name || "Instagram Service"),
        String(item.description || ""),
        sellingRate,
        providerRate,
        min,
        max
      ]);

      imported++;
    }

    res.send(page(
      "Import",
      message(`Instagram services imported or updated: ${imported}`),
      req.session.user
    ));
  } catch (error) {
    res.status(500).send(page(
      "Import Error",
      message(error.message),
      req.session.user
    ));
  }
});

/* -------------------- MANAGE SERVICES -------------------- */

app.get("/admin/services", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const result = await db(
      `SELECT * FROM services
       WHERE LOWER(category) LIKE '%instagram%'
       ORDER BY id DESC`
    );

    const rows = result.rows.map(service => `
      <tr class="admin-service-row">
        <td>${esc(service.id)}</td>
        <td>${esc(service.name)}</td>
        <td>₹${esc(service.provider_rate)}</td>
        <td>₹${esc(service.rate)}</td>
        <td>${service.active ? "Active" : "Disabled"}</td>
        <td>
          <form method="POST" action="/admin/service/${esc(service.id)}">
            <input name="rate" type="number" step="0.0001"
              value="${esc(service.rate)}" required>
            <button name="active" value="${!service.active}">
              ${service.active ? "Disable" : "Enable"}
            </button>
            <button name="save" value="1">Save Price</button>
          </form>
        </td>
      </tr>
    `).join("");

    res.send(page("Manage Services", `
      <div class="card">
        <h2>Instagram Services</h2>
        <input type="search" id="adminServiceSearch"
          class="search-box"
          placeholder="Search services by name, ID or status..."
          autocomplete="off">
        <div class="table-wrap">
          <table id="adminServicesTable">
            <thead><tr>
              <th>ID</th><th>Name</th><th>Provider Rate</th>
              <th>Selling Rate</th><th>Status</th><th>Manage</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>
      <script>
        (function(){
          const search=document.getElementById("adminServiceSearch");
          const tableRows=document.querySelectorAll(".admin-service-row");
          search.addEventListener("input",function(){
            const term=this.value.toLowerCase().trim();
            tableRows.forEach(function(row){
              row.style.display=row.textContent.toLowerCase().includes(term)?"":"none";
            });
          });
        })();
      </script>
    `, req.session.user));
  } catch (error) {
    next(error);
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
         WHERE id=$2 AND LOWER(category) LIKE '%instagram%'`,
        [rate, id]
      );
    } else {
      await db(
        `UPDATE services SET active=$1
         WHERE id=$2 AND LOWER(category) LIKE '%instagram%'`,
        [req.body.active === "true", id]
      );
    }

    res.redirect("/admin/services");
  } catch (error) {
    next(error);
  }
});

/* -------------------- ADMIN PAYMENTS -------------------- */

app.get("/admin/payments", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const result = await db(`
      SELECT p.*,u.username,u.email FROM payments p
      JOIN users u ON u.id=p.user_id
      ORDER BY p.id DESC LIMIT 200
    `);

    const rows = result.rows.map(payment => `
      <tr>
        <td>${esc(payment.id)}</td>
        <td>${esc(payment.username)}</td>
        <td>₹${esc(payment.amount)}</td>
        <td>${esc(payment.utr)}</td>
        <td>${esc(payment.status)}</td>
        <td>${payment.status === "Pending" ? `
          <form method="POST" action="/admin/payment/${esc(payment.id)}">
            <button name="action" value="approve">Approve</button>
            <button name="action" value="reject">Reject</button>
          </form>` : ""}
        </td>
      </tr>
    `).join("");

    res.send(page("Payments", `
      <div class="card"><h2>Fund Approval</h2>
      <div class="table-wrap">
        <table>
          <tr><th>ID</th><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>
          ${rows}
        </table>
      </div></div>
    `, req.session.user));
  } catch (error) {
    next(error);
  }
});

app.post("/admin/payment/:id", requireLogin, requireAdmin, async (req, res, next) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT * FROM payments WHERE id=$1 FOR UPDATE`,
      [req.params.id]
    );

    const payment = result.rows[0];

    if (!payment || payment.status !== "Pending") {
      throw new Error("Payment already processed");
    }

    if (req.body.action === "approve") {
      await client.query(
        `UPDATE users SET balance=balance+$1 WHERE id=$2`,
        [payment.amount, payment.user_id]
      );

      await client.query(
        `UPDATE payments SET status='Approved' WHERE id=$1`,
        [payment.id]
      );
    } else if (req.body.action === "reject") {
      await client.query(
        `UPDATE payments SET status='Rejected' WHERE id=$1`,
        [payment.id]
      );
    } else {
      throw new Error("Invalid payment action");
    }

    await client.query("COMMIT");
    res.redirect("/admin/payments");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    res.status(400).send(esc(error.message));
  } finally {
    client.release();
  }
});

/* -------------------- ADMIN REFUNDS -------------------- */

app.get("/admin/refunds", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const result = await db(`
      SELECT f.*,u.username FROM refunds f
      JOIN users u ON u.id=f.user_id
      ORDER BY f.id DESC
    `);

    const rows = result.rows.map(refund => `
      <tr>
        <td>${esc(refund.id)}</td>
        <td>${esc(refund.username)}</td>
        <td>₹${esc(refund.amount)}</td>
        <td>${esc(refund.reason)}</td>
        <td>${esc(refund.status)}</td>
        <td>${refund.status === "Pending" ? `
          <form method="POST" action="/admin/refund/${esc(refund.id)}">
            <button name="action" value="approve">Approve</button>
            <button name="action" value="reject">Reject</button>
          </form>` : ""}
        </td>
      </tr>
    `).join("");

    res.send(page("Refunds", `
      <div class="card"><h2>Refund Requests</h2>
      <div class="table-wrap">
        <table>
          <tr><th>ID</th><th>User</th><th>Amount</th><th>Reason</th><th>Status</th><th>Action</th></tr>
          ${rows}
        </table>
      </div></div>
    `, req.session.user));
  } catch (error) {
    next(error);
  }
});

app.post("/admin/refund/:id", requireLogin, requireAdmin, async (req, res, next) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT * FROM refunds WHERE id=$1 FOR UPDATE`,
      [req.params.id]
    );

    const refund = result.rows[0];

    if (!refund || refund.status !== "Pending") {
      throw new Error("Refund already processed");
    }

    if (req.body.action === "approve") {
      if (!refund.funds_reserved) {
        const user = await client.query(
          `SELECT balance FROM users WHERE id=$1 FOR UPDATE`,
          [refund.user_id]
        );

        if (Number(user.rows[0]?.balance || 0) < Number(refund.amount)) {
          throw new Error("Customer wallet balance is insufficient");
        }

        await client.query(
          `UPDATE users SET balance=balance-$1 WHERE id=$2`,
          [refund.amount, refund.user_id]
        );
      }

      await client.query(
        `UPDATE refunds SET status='Approved' WHERE id=$1`,
        [refund.id]
      );
    } else if (req.body.action === "reject") {
      if (refund.funds_reserved) {
        await client.query(
          `UPDATE users SET balance=balance+$1 WHERE id=$2`,
          [refund.amount, refund.user_id]
        );
      }

      await client.query(
        `UPDATE refunds SET status='Rejected' WHERE id=$1`,
        [refund.id]
      );
    } else {
      throw new Error("Invalid refund action");
    }

    await client.query("COMMIT");
    res.redirect("/admin/refunds");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    res.status(400).send(esc(error.message));
  } finally {
    client.release();
  }
});

/* -------------------- ADMIN USERS -------------------- */

app.get("/admin/users", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const result = await db(
      `SELECT id,username,email,balance,is_admin,created_at
       FROM users ORDER BY id DESC LIMIT 200`
    );

    const rows = result.rows.map(user => `
      <tr>
        <td>${esc(user.id)}</td>
        <td>${esc(user.username)}</td>
        <td>${esc(user.email || "")}</td>
        <td>₹${esc(user.balance)}</td>
        <td>${user.is_admin ? "Admin" : "Customer"}</td>
      </tr>
    `).join("");

    res.send(page("Customers", `
      <div class="card"><h2>Customers</h2>
      <div class="table-wrap">
        <table>
          <tr><th>ID</th><th>Username</th><th>Email</th><th>Balance</th><th>Role</th></tr>
          ${rows}
        </table>
      </div></div>
    `, req.session.user));
  } catch (error) {
    next(error);
  }
});

/* -------------------- ADMIN ORDERS -------------------- */

app.get("/admin/orders", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const result = await db(`
      SELECT o.*,u.username FROM orders o
      JOIN users u ON u.id=o.user_id
      ORDER BY o.id DESC LIMIT 200
    `);

    const rows = result.rows.map(order => `
      <tr>
        <td>${esc(order.id)}</td>
        <td>${esc(order.username)}</td>
        <td>${esc(order.service_name || order.service_id)}</td>
        <td>${esc(order.quantity)}</td>
        <td>${esc(order.status)}</td>
        <td>${esc(order.provider_order_id || "")}</td>
      </tr>
    `).join("");

    res.send(page("Orders", `
      <div class="card"><h2>All Orders</h2>
      <div class="table-wrap">
        <table>
          <tr><th>ID</th><th>User</th><th>Service</th><th>Qty</th><th>Status</th><th>Provider ID</th></tr>
          ${rows}
        </table>
      </div></div>
    `, req.session.user));
  } catch (error) {
    next(error);
  }
});

/* -------------------- LOGOUT -------------------- */

app.get("/logout", (req, res) => {
  req.session.destroy(error => {
    res.clearCookie("royal.sid");
    res.redirect("/login");
  });
});

/* -------------------- HEALTH CHECK -------------------- */

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    app: "ROYAL PANEL"
  });
});

/* -------------------- ERROR HANDLER -------------------- */

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  if (res.headersSent) return next(err);
  res.status(500).send("Server error. Please try again later.");
});

/* -------------------- START SERVER -------------------- */

const PORT = process.env.PORT || 3000;

setupDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log("ROYAL PANEL running on port " + PORT);
    });
  })
  .catch(error => {
    console.error("Database setup failed:", error);
    process.exit(1);
  });
