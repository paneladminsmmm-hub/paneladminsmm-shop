
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
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const APP_URL = (process.env.APP_URL || "").replace(/\/$/, "");

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").toLowerCase();
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

const PROVIDER_URL =
  process.env.SOCIALADD_API_URL || "https://socialadd.in/api/v2";
const PROVIDER_KEY = process.env.SOCIALADD_API_KEY || "";

const UPI_ID = process.env.UPI_ID || "";
const WHATSAPP = process.env.SUPPORT_WHATSAPP || "";
const WHATSAPP_NUMBER = WHATSAPP.replace(/\D/g, "");
const TELEGRAM_URL = process.env.TELEGRAM_URL || "";

const googleClient = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  APP_URL ? APP_URL + "/auth/google/callback" : undefined
);

app.use(session({
  name: "royal.sid",
  secret: process.env.SESSION_SECRET || crypto.randomBytes(48).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

async function db(sql, values = []) {
  return pool.query(sql, values);
}

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

  await db(`
    CREATE TABLE IF NOT EXISTS panel_settings (
      setting_key TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL
    )
  `);

  await db(`
    INSERT INTO panel_settings(setting_key, setting_value)
    VALUES ('provider_enabled','true'), ('services_enabled','true')
    ON CONFLICT (setting_key) DO NOTHING
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

async function setting(key) {
  const r = await db(
    `SELECT setting_value FROM panel_settings WHERE setting_key=$1`,
    [key]
  );
  return r.rows[0]?.setting_value || "false";
}

async function setSetting(key, value) {
  await db(
    `INSERT INTO panel_settings(setting_key,setting_value)
     VALUES($1,$2)
     ON CONFLICT(setting_key)
     DO UPDATE SET setting_value=EXCLUDED.setting_value`,
    [key, String(value)]
  );
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user?.is_admin) {
    return res.status(403).send("Admin access required");
  }
  next();
}

function socialSupportLinks() {
  return `
    <div class="social-links">
      ${WHATSAPP_NUMBER ? `
        <a class="social-link whatsapp-link"
           href="https://wa.me/${WHATSAPP_NUMBER}"
           target="_blank" rel="noopener noreferrer">
          <svg class="social-icon" viewBox="0 0 24 24"
               xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <path fill="currentColor"
              d="M20.52 3.48A11.8 11.8 0 0 0 12.13 0C5.55 0 .2 5.35.2 11.93c0 2.1.55 4.15 1.6 5.96L.1 24l6.27-1.64a11.9 11.9 0 0 0 5.76 1.47h.01c6.58 0 11.93-5.35 11.93-11.93a11.85 11.85 0 0 0-3.55-8.42ZM12.14 21.8a9.9 9.9 0 0 1-5.04-1.38l-.36-.21-3.72.98.99-3.63-.24-.37a9.86 9.86 0 0 1-1.52-5.26c0-5.46 4.45-9.91 9.91-9.91a9.84 9.84 0 0 1 7.01 2.91 9.84 9.84 0 0 1 2.9 7.01c0 5.46-4.45 9.91-9.92 9.91Zm5.44-7.42c-.3-.15-1.77-.87-2.04-.97-.28-.1-.48-.15-.68.15-.2.3-.78.97-.95 1.17-.18.2-.35.23-.65.08-.3-.15-1.26-.46-2.4-1.47-.88-.78-1.47-1.74-1.64-2.04-.17-.3-.02-.46.13-.61.14-.13.3-.35.45-.53.15-.18.2-.3.3-.5.1-.2.05-.38-.03-.53-.08-.15-.68-1.64-.93-2.25-.24-.59-.49-.51-.68-.52h-.58c-.2 0-.53.08-.8.38-.28.3-1.05 1.02-1.05 2.5s1.08 2.9 1.23 3.1c.15.2 2.12 3.24 5.14 4.55.72.31 1.28.5 1.72.64.72.23 1.38.2 1.9.12.58-.09 1.77-.72 2.02-1.42.25-.69.25-1.29.18-1.42-.08-.13-.28-.2-.58-.35Z"/>
          </svg>
          WhatsApp Support
        </a>` : ""}
      ${TELEGRAM_URL ? `
        <a class="social-link telegram-link"
           href="${TELEGRAM_URL}"
           target="_blank" rel="noopener noreferrer">
          <svg class="social-icon" viewBox="0 0 24 24"
               xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <path fill="currentColor"
              d="M21.9 4.2 18.6 20c-.25 1.12-.9 1.4-1.82.88l-5.04-3.72-2.43 2.34c-.27.27-.5.5-1.02.5l.36-5.13 9.34-8.44c.4-.36-.09-.56-.62-.2L5.82 13.5.85 11.95c-1.08-.34-1.1-1.08.22-1.6L20.5 2.8c.9-.33 1.7.22 1.4 1.4Z"/>
          </svg>
          Telegram Support
        </a>` : ""}
    </div>
  `;
}

/* =====================================================
   NEW ROYAL PANEL PAGE DESIGN + SIDE NAVIGATION
===================================================== */

function page(title, body, user = null) {
  const adminMenu = user?.is_admin ? `
    <div class="menu-section-title">ADMINISTRATION</div>
    <a class="menu-link" href="/admin">
      <span class="menu-icon">⚙️</span><span>Admin Dashboard</span>
    </a>
    <a class="menu-link" href="/admin/services">
      <span class="menu-icon">🛠️</span><span>Manage Services</span>
    </a>
    <a class="menu-link" href="/admin/payments">
      <span class="menu-icon">💳</span><span>Fund Approvals</span>
    </a>
    <a class="menu-link" href="/admin/refunds">
      <span class="menu-icon">↩️</span><span>Refund Approvals</span>
    </a>
    <a class="menu-link" href="/admin/orders">
      <span class="menu-icon">📦</span><span>Manage Orders</span>
    </a>
    <a class="menu-link" href="/admin/users">
      <span class="menu-icon">👥</span><span>Customers</span>
    </a>
  ` : "";

  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#09090d">
    <title>${title} | ROYAL PANEL</title>

    <style>
      * {
        box-sizing: border-box;
      }

      html {
        scroll-behavior: smooth;
      }

      body {
        margin: 0;
        min-height: 100vh;
        font-family: Arial, Helvetica, sans-serif;
        color: #fff;
        background:
          radial-gradient(ellipse at top left, #35101d 0%, transparent 42%),
          radial-gradient(ellipse at bottom right, #101d3b 0%, transparent 45%),
          #09090d;
      }

      body.menu-open {
        overflow: hidden;
      }

      /* TOP HEADER */

      .top-header {
        width: 100%;
        min-height: 82px;
        padding: 12px 18px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 15px;
        background: rgba(12, 12, 17, 0.97);
        border-bottom: 1px solid #30303a;
        position: sticky;
        top: 0;
        z-index: 100;
      }

      .brand {
        color: #fff;
        font-size: 29px;
        font-weight: 900;
        letter-spacing: 1.5px;
        text-decoration: none;
        margin: 0;
        text-shadow: 0 0 15px rgba(255,255,255,.15);
      }

      .menu-button {
        width: 64px;
        height: 58px;
        border: 1px solid #e52b50;
        border-radius: 12px;
        background: #e51d43;
        color: white;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
        gap: 7px;
        cursor: pointer;
        padding: 10px;
        margin: 0;
        box-shadow: 0 4px 18px rgba(229,29,67,.25);
      }

      .menu-button span {
        display: block;
        width: 32px;
        height: 4px;
        border-radius: 5px;
        background: white;
      }

      .menu-button:hover {
        background: #c91638;
      }

      /* SIDE MENU OVERLAY */

      .menu-overlay {
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,.72);
        z-index: 200;
        opacity: 0;
        visibility: hidden;
        transition: opacity .25s ease, visibility .25s ease;
      }

      .menu-overlay.open {
        opacity: 1;
        visibility: visible;
      }

      /* SIDE DRAWER */

      .side-drawer {
        position: fixed;
        top: 0;
        left: 0;
        width: 310px;
        max-width: 86vw;
        height: 100vh;
        height: 100dvh;
        overflow-y: auto;
        background: #101015;
        border-right: 1px solid #34343e;
        z-index: 300;
        transform: translateX(-105%);
        transition: transform .28s ease;
        padding: 0 15px 25px;
        box-shadow: 10px 0 35px rgba(0,0,0,.4);
      }

      .side-drawer.open {
        transform: translateX(0);
      }

      .drawer-header {
        min-height: 82px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid #33333c;
        margin-bottom: 15px;
        gap: 8px;
      }

      .drawer-brand {
        font-size: 23px;
        font-weight: 900;
        letter-spacing: 1px;
        color: white;
      }

      .close-menu {
        width: 42px;
        height: 42px;
        padding: 0;
        margin: 0;
        border-radius: 10px;
        background: #292932;
        color: white;
        font-size: 27px;
        line-height: 1;
      }

      .close-menu:hover {
        background: #e51d43;
      }

      .menu-section-title {
        color: #888894;
        font-size: 11px;
        font-weight: bold;
        letter-spacing: 1.5px;
        padding: 17px 10px 8px;
      }

      .menu-link {
        display: flex;
        align-items: center;
        gap: 13px;
        width: 100%;
        padding: 14px 12px;
        margin: 4px 0;
        color: #ededf2;
        text-decoration: none;
        font-size: 15px;
        font-weight: 600;
        border: 1px solid transparent;
        border-radius: 10px;
        transition: background .2s, border .2s;
      }

      .menu-link:hover {
        color: white;
        background: #29202a;
        border-color: #713044;
      }

      .menu-icon {
        width: 27px;
        text-align: center;
        font-size: 19px;
        flex-shrink: 0;
      }

      .logout-link {
        color: #ff647c;
        margin-top: 18px;
        border-top: 1px solid #34343e;
        border-radius: 0;
        padding-top: 20px;
      }

      .logout-link:hover {
        background: #32151e;
      }

      /* MAIN CONTENT */

      main {
        width: 100%;
        max-width: 1100px;
        margin: 25px auto;
        padding: 15px;
      }

      .card {
        background: rgba(23,23,29,.96);
        border: 1px solid #393943;
        border-radius: 15px;
        padding: 20px;
        margin: 13px 0;
        box-shadow: 0 8px 25px rgba(0,0,0,.15);
      }

      h1, h2, h3 {
        color: white;
      }

      a {
        color: #ff526b;
        text-decoration: none;
      }

      input, select, textarea {
        width: 100%;
        padding: 13px;
        margin: 7px 0;
        border-radius: 9px;
        border: 1px solid #555560;
        background: #09090e;
        color: white;
        font-size: 15px;
      }

      input:focus, select:focus, textarea:focus {
        outline: none;
        border-color: #e51d43;
        box-shadow: 0 0 0 2px rgba(229,29,67,.15);
      }

      button {
        background: #e51d43;
        color: white;
        padding: 12px 18px;
        border: 0;
        border-radius: 9px;
        margin: 5px;
        cursor: pointer;
        font-size: 14px;
        font-weight: bold;
      }

      button:hover {
        background: #c91638;
      }

      table {
        width: 100%;
        border-collapse: collapse;
      }

      td, th {
        padding: 11px;
        border-bottom: 1px solid #44444e;
        text-align: left;
      }

      th {
        color: #ff758a;
        white-space: nowrap;
      }

      .muted {
        color: #bbb;
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit,minmax(220px,1fr));
        gap: 10px;
      }

      .social-links {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 12px;
      }

      .social-link {
        display: inline-flex;
        align-items: center;
        gap: 9px;
        padding: 11px 15px;
        border-radius: 10px;
        color: white;
        font-weight: bold;
        margin: 0;
      }

      .whatsapp-link {
        background: #128c4a;
      }

      .telegram-link {
        background: #168acb;
      }

      .social-icon {
        width: 23px;
        height: 23px;
        display: inline-block;
        flex-shrink: 0;
      }

      .search-box {
        margin: 10px 0 15px;
      }

      .qr-box {
        text-align: center;
        margin: 18px auto;
        padding: 15px;
        background: #fff;
        border-radius: 14px;
        max-width: 320px;
      }

      .qr-box img {
        display: block;
        width: 100%;
        max-width: 260px;
        height: auto;
        margin: auto;
      }

      .qr-caption {
        color: #222;
        font-weight: bold;
        margin-top: 10px;
      }

      .table-wrap {
        width: 100%;
        overflow-x: auto;
      }

      .table-wrap table {
        min-width: 650px;
      }

      @media(max-width:600px) {
        .top-header {
          min-height: 75px;
          padding: 10px 13px;
        }

        .brand {
          font-size: 23px;
        }

        .menu-button {
          width: 58px;
          height: 53px;
        }

        main {
          margin: 15px auto;
          padding: 10px;
        }

        .card {
          padding: 15px;
        }
      }
    </style>
  </head>

  <body>

    <header class="top-header">
      <a class="brand" href="${user ? "/dashboard" : "/login"}">
        ROYAL PANEL
      </a>

      ${user ? `
        <button
          type="button"
          class="menu-button"
          onclick="openRoyalMenu()"
          aria-label="Open Menu"
          aria-expanded="false"
          id="royalMenuButton"
        >
          <span></span>
          <span></span>
          <span></span>
        </button>
      ` : ""}
    </header>

    ${user ? `
      <div
        class="menu-overlay"
        id="royalMenuOverlay"
        onclick="closeRoyalMenu()"
      ></div>

      <aside class="side-drawer" id="royalSideDrawer">

        <div class="drawer-header">
          <div class="drawer-brand">ROYAL PANEL</div>
          <button
            type="button"
            class="close-menu"
            onclick="closeRoyalMenu()"
            aria-label="Close Menu"
          >×</button>
        </div>

        <div class="menu-section-title">MAIN MENU</div>

        <a class="menu-link" href="/dashboard">
          <span class="menu-icon">🏠</span>
          <span>Dashboard</span>
        </a>

        <a class="menu-link" href="/services">
          <span class="menu-icon">➕</span>
          <span>New Order / Services</span>
        </a>

        <a class="menu-link" href="/orders">
          <span class="menu-icon">📦</span>
          <span>My Orders</span>
        </a>

        <a class="menu-link" href="/funds">
          <span class="menu-icon">💰</span>
          <span>Add Funds</span>
        </a>

        <a class="menu-link" href="/refund">
          <span class="menu-icon">↩️</span>
          <span>Refund Request</span>
        </a>

        <a class="menu-link" href="/support">
          <span class="menu-icon">🎧</span>
          <span>Support</span>
        </a>

        ${adminMenu}

        <a class="menu-link logout-link" href="/logout">
          <span class="menu-icon">🚪</span>
          <span>Logout</span>
        </a>

      </aside>

      <script>
        function openRoyalMenu() {
          const drawer = document.getElementById("royalSideDrawer");
          const overlay = document.getElementById("royalMenuOverlay");
          const button = document.getElementById("royalMenuButton");

          if (!drawer || !overlay) return;

          drawer.classList.add("open");
          overlay.classList.add("open");
          document.body.classList.add("menu-open");

          if (button) {
            button.setAttribute("aria-expanded", "true");
          }
        }

        function closeRoyalMenu() {
          const drawer = document.getElementById("royalSideDrawer");
          const overlay = document.getElementById("royalMenuOverlay");
          const button = document.getElementById("royalMenuButton");

          if (!drawer || !overlay) return;

          drawer.classList.remove("open");
          overlay.classList.remove("open");
          document.body.classList.remove("menu-open");

          if (button) {
            button.setAttribute("aria-expanded", "false");
          }
        }

        document.addEventListener("keydown", function(event) {
          if (event.key === "Escape") {
            closeRoyalMenu();
          }
        });
      </script>
    ` : ""}

    <main>
      ${body}
    </main>

  </body>
  </html>`;
}

function message(text) {
  return `<div class="card">${text}</div>`;
}

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

app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/dashboard" : "/login");
});

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

app.post("/login", async (req, res) => {
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

    if (!user || !hash || !await bcrypt.compare(req.body.password || "", hash)) {
      return res.send(page("Login", message("Invalid login details")));
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin: user.is_admin
    };

    res.redirect("/dashboard");
  } catch (e) {
    res.status(500).send(e.message);
  }
});

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h2>Create Account</h2>
      <form method="POST" action="/register">
        <input name="username" placeholder="Username" required>
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password" minlength="6"
        placeholder="Password" required>
        <button>Continue</button>
      </form>
      <a href="/auth/google">Continue with Google</a>
    </div>
  `));
});

app.post("/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!username || !email || password.length < 6) {
      return res.send(page("Register", message("Enter valid details")));
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await db(
      `INSERT INTO users(username,email,password_hash,password)
       VALUES($1,$2,$3,$3) RETURNING *`,
      [username, email, hash]
    );

    const user = result.rows[0];
    req.session.user = {
      id: user.id, username, email, is_admin: false
    };

    res.redirect("/dashboard");
  } catch (e) {
    res.status(400).send(page("Register", message("Username or email already exists")));
  }
});

app.get("/auth/google", (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !APP_URL) {
    return res.status(503).send("Google Login environment settings are missing");
  }

  const state = crypto.randomBytes(24).toString("hex");
  req.session.googleState = state;

  const url = googleClient.generateAuthUrl({
    access_type: "online",
    scope: ["email", "profile"],
    state
  });

  res.redirect(url);
});

app.get("/auth/google/callback", async (req, res) => {
  try {
    if (!req.query.code || req.query.state !== req.session.googleState) {
      return res.status(400).send("Google login state error");
    }

    delete req.session.googleState;

    const { tokens } = await googleClient.getToken(req.query.code);
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
      await db(`UPDATE users SET google_id=$1 WHERE id=$2`,
        [profile.sub, user.id]);
    }

    if (ADMIN_EMAIL && email === ADMIN_EMAIL) {
      await db(`UPDATE users SET is_admin=TRUE WHERE id=$1`, [user.id]);
      user.is_admin = true;
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin: user.is_admin
    };

    res.redirect("/dashboard");
  } catch (e) {
    res.status(500).send("Google Login failed: " + e.message);
  }
});

app.get("/dashboard", requireLogin, async (req, res) => {
  const r = await db(`SELECT balance FROM users WHERE id=$1`, [req.session.user.id]);
  const balance = r.rows[0]?.balance || 0;

  res.send(page("Dashboard", `
    <div class="card">
      <h2>Welcome ${req.session.user.username}</h2>
      <h3>Wallet Balance: ₹${Number(balance).toFixed(2)}</h3>
    </div>
    <div class="grid">
      <div class="card"><a href="/services">New Order / Services</a></div>
      <div class="card"><a href="/orders">My Orders</a></div>
      <div class="card"><a href="/funds">Add Funds</a></div>
      <div class="card"><a href="/refund">Refund Request</a></div>
      <div class="card"><a href="/support">Support</a></div>
    </div>
    <div class="card">
      <h3>Contact Support</h3>
      ${socialSupportLinks()}
    </div>
  `, req.session.user));
});

// Customer Instagram services with live search
app.get("/services", requireLogin, async (req, res) => {
  const enabled = await setting("services_enabled");
  const r = await db(
    `SELECT * FROM services WHERE active=TRUE
     AND LOWER(category) LIKE '%instagram%' ORDER BY id DESC`
  );

  const rows = r.rows.map(s => `
    <option value="${s.id}">
      ${s.name} - ₹${Number(s.rate).toFixed(2)}
      (Min ${s.min} / Max ${s.max})
    </option>
  `).join("");

  res.send(page("Instagram Services", `
    <div class="card">
      <h2>Instagram Services</h2>
      ${enabled === "true" ? `
        <form method="POST" action="/order">
          <input
            type="search"
            id="serviceSearch"
            class="search-box"
            placeholder="Search Instagram services..."
            autocomplete="off"
          >
          <select name="service_id" id="serviceSelect" required>
            <option value="">Select a service</option>
            ${rows}
          </select>
          <input name="link" placeholder="Instagram Link" required>
          <input name="quantity" type="number" min="1" placeholder="Quantity" required>
          <button>Place Order</button>
        </form>
        <script>
          (function(){
            const search = document.getElementById("serviceSearch");
            const select = document.getElementById("serviceSelect");
            const options = Array.from(select.options);

            search.addEventListener("input", function(){
              const term = this.value.toLowerCase().trim();

              options.forEach(function(option, index){
                if(index === 0) return;
                option.hidden = !option.text.toLowerCase().includes(term);
              });

              if(select.selectedOptions[0]?.hidden){
                select.value = "";
              }
            });
          })();
        </script>
      ` : "Services are temporarily disabled"}
    </div>
  `, req.session.user));
});

app.post("/order", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    if (await setting("services_enabled") !== "true") {
      throw new Error("Services are disabled");
    }

    const serviceResult = await client.query(
      `SELECT * FROM services WHERE id=$1 AND active=TRUE
       AND LOWER(category) LIKE '%instagram%' FOR UPDATE`,
      [req.body.service_id]
    );

    const service = serviceResult.rows[0];
    if (!service) throw new Error("Instagram service not found");

    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(quantity) ||
        quantity < Number(service.min) ||
        quantity > Number(service.max) ||
        !link) {
      throw new Error("Invalid link or quantity");
    }

    const charge = Number(service.rate) * quantity / 1000;

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
      `INSERT INTO orders(user_id,service_id,service_name,link,quantity,charge,status)
       VALUES($1,$2,$3,$4,$5,$6,'Pending') RETURNING id`,
      [req.session.user.id, service.id, service.name, link, quantity, charge]
    );

    await client.query("COMMIT");

    let providerOrderId = null;
    let status = "Pending";

    if (service.provider_source === "socialadd" &&
        await setting("provider_enabled") === "true") {
      try {
        const data = await providerRequest({
          action: "add",
          service: String(service.provider_id),
          link,
          quantity: String(quantity)
        });

        if (data.order) {
          providerOrderId = String(data.order);
          status = "Processing";

          await db(
            `UPDATE orders SET provider_order_id=$1,status=$2 WHERE id=$3`,
            [providerOrderId, status, orderResult.rows[0].id]
          );
        } else {
          throw new Error(data.error || "Provider did not return order ID");
        }
      } catch (providerError) {
        await db(
          `UPDATE orders SET status='Provider Error' WHERE id=$1`,
          [orderResult.rows[0].id]
        );
      }
    }

    res.redirect("/orders");
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).send(page("Order", message(e.message), req.session.user));
  } finally {
    client.release();
  }
});

app.get("/orders", requireLogin, async (req, res) => {
  const r = await db(
    `SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC LIMIT 100`,
    [req.session.user.id]
  );

  const rows = r.rows.map(o => `
    <tr><td>${o.id}</td><td>${o.service_name || o.service_id}</td>
    <td>${o.quantity}</td><td>₹${o.charge}</td><td>${o.status}</td></tr>
  `).join("");

  res.send(page("Orders", `
    <div class="card"><h2>My Orders</h2>
    <div class="table-wrap">
      <table><tr><th>ID</th><th>Service</th><th>Qty</th><th>Charge</th><th>Status</th></tr>
      ${rows}</table>
    </div></div>
  `, req.session.user));
});

// Add Funds with uploaded public/payment-qr.png
app.get("/funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
    <div class="card">
      <h2>Add Funds - Admin Approval</h2>

      <div class="qr-box">
        <img
          src="/payment-qr.png"
          alt="UPI Payment QR Code"
          onerror="this.style.display='none';document.getElementById('qrError').style.display='block';"
        >
        <div class="qr-caption">Scan QR Code to Pay</div>
      </div>

      <p id="qrError" style="display:none;color:#ff526b;text-align:center;">
        QR image could not be loaded. Check public/payment-qr.png
      </p>

      <p>UPI ID: <b>${UPI_ID}</b></p>

      <form method="POST" action="/funds">
        <input name="amount" type="number" min="10" max="2000"
        step="0.01" placeholder="Amount ₹10 - ₹2000" required>
        <input name="utr" placeholder="UTR / Transaction ID" required>
        <button>Submit Payment</button>
      </form>
      <p class="muted">Wallet में पैसे Admin Approval के बाद जुड़ेंगे।</p>
    </div>
  `, req.session.user));
});

app.post("/funds", requireLogin, async (req, res) => {
  const amount = Number(req.body.amount);
  const utr = String(req.body.utr || "").trim();

  if (!Number.isFinite(amount) || amount < 10 || amount > 2000 || !utr) {
    return res.status(400).send("Minimum ₹10 and maximum ₹2000. UTR required.");
  }

  await db(
    `INSERT INTO payments(user_id,amount,utr,status)
     VALUES($1,$2,$3,'Pending')`,
    [req.session.user.id, amount, utr]
  );

  res.send(page("Payment", message("Payment submitted. Waiting for Admin Approval."), req.session.user));
});

app.get("/refund", requireLogin, (req, res) => {
  res.send(page("Refund", `
    <div class="card">
      <h2>Refund Request</h2>
      <form method="POST" action="/refund">
        <input name="amount" type="number" min="10" max="2000"
        step="0.01" placeholder="₹10 - ₹2000" required>
        <textarea name="reason" placeholder="Refund reason" required></textarea>
        <button>Submit Refund Request</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/refund", requireLogin, async (req, res) => {
  const amount = Number(req.body.amount);
  const reason = String(req.body.reason || "").trim();

  if (!Number.isFinite(amount) || amount < 10 || amount > 2000 || !reason) {
    return res.status(400).send("Refund must be between ₹10 and ₹2000.");
  }

  const user = await db(`SELECT balance FROM users WHERE id=$1`, [req.session.user.id]);

  if (!user.rows[0] || Number(user.rows[0].balance) < amount) {
    return res.status(400).send("Insufficient wallet balance.");
  }

  await db(
    `INSERT INTO refunds(user_id,amount,reason,status)
     VALUES($1,$2,$3,'Pending')`,
    [req.session.user.id, amount, reason]
  );

  res.send(page("Refund", message("Refund request sent to Admin for approval."), req.session.user));
});

app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
    <div class="card">
      <h2>Support</h2>
      <form method="POST" action="/support">
        <textarea name="message" required placeholder="Write your message"></textarea>
        <button>Send Message</button>
      </form>
      <h3>Contact Us</h3>
      ${socialSupportLinks()}
    </div>
  `, req.session.user));
});

app.post("/support", requireLogin, async (req, res) => {
  await db(
    `INSERT INTO tickets(user_id,message,status)
     VALUES($1,$2,'Open')`,
    [req.session.user.id, String(req.body.message || "").slice(0, 3000)]
  );

  res.redirect("/dashboard");
});

app.get("/admin", requireLogin, requireAdmin, async (req, res) => {
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
      <p>Customers: ${counts.rows[0].users}</p>
      <p>Orders: ${counts.rows[0].orders}</p>
      <p>Pending Funds: ${counts.rows[0].pending_payments}</p>
      <p>Pending Refunds: ${counts.rows[0].pending_refunds}</p>
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
});

app.post("/admin/provider-toggle", requireLogin, requireAdmin, async (req, res) => {
  await setSetting("provider_enabled", req.body.value === "true");
  res.redirect("/admin");
});

app.post("/admin/services-toggle", requireLogin, requireAdmin, async (req, res) => {
  const enabled = req.body.value === "true";
  await setSetting("services_enabled", enabled);

  await db(
    `UPDATE services SET active=$1
     WHERE LOWER(category) LIKE '%instagram%'`,
    [enabled]
  );

  res.redirect("/admin");
});

app.post("/admin/provider-test", requireLogin, requireAdmin, async (req, res) => {
  try {
    const data = await providerRequest({ action: "balance" });
    res.send(page("Provider Test", message("SocialAdd API connected: " + JSON.stringify(data)), req.session.user));
  } catch (e) {
    res.status(500).send(page("Provider Test", message("Provider Error: " + e.message), req.session.user));
  }
});

app.post("/admin/import", requireLogin, requireAdmin, async (req, res) => {
  try {
    if (await setting("provider_enabled") !== "true") {
      throw new Error("Provider API is disabled");
    }

    const list = await providerRequest({ action: "services" });
    if (!Array.isArray(list)) throw new Error("Invalid provider services response");

    let imported = 0;

    for (const item of list) {
      if (!isInstagram(item)) continue;

      const providerId = String(item.service);
      const providerRate = Number(item.rate || 0);

      if (!providerId || !Number.isFinite(providerRate)) continue;

      const sellingRate = providerRate * 1.75;

      await db(`
        INSERT INTO services(
          provider_id,provider_source,provider_type,name,category,
          description,rate,provider_rate,min,max,active
        )
        VALUES($1,'socialadd','Default',$2,'Instagram',$3,$4,$5,$6,$7,TRUE)
        ON CONFLICT DO NOTHING
      `, [
        providerId,
        item.name || "Instagram Service",
        item.description || "",
        sellingRate,
        providerRate,
        Number(item.min || 100),
        Number(item.max || 1000000)
      ]);

      const existing = await db(
        `SELECT id FROM services
         WHERE provider_id=$1 AND provider_source='socialadd'`,
        [providerId]
      );

      if (existing.rows.length) {
        await db(
          `UPDATE services SET
           name=$1,category='Instagram',description=$2,
           provider_rate=$3,rate=$4,min=$5,max=$6,active=TRUE
           WHERE provider_id=$7 AND provider_source='socialadd'`,
          [
            item.name || "Instagram Service",
            item.description || "",
            providerRate,
            sellingRate,
            Number(item.min || 100),
            Number(item.max || 1000000),
            providerId
          ]
        );
      }

      imported++;
    }

    res.send(page("Import", message(`Instagram services imported: ${imported}`), req.session.user));
  } catch (e) {
    res.status(500).send(page("Import Error", message(e.message), req.session.user));
  }
});

// Admin services page with search
app.get("/admin/services", requireLogin, requireAdmin, async (req, res) => {
  const r = await db(
    `SELECT * FROM services
     WHERE LOWER(category) LIKE '%instagram%' ORDER BY id DESC`
  );

  const rows = r.rows.map(s => `
    <tr class="admin-service-row">
      <td>${s.id}</td>
      <td>${s.name}</td>
      <td>₹${s.provider_rate}</td>
      <td>₹${s.rate}</td>
      <td>${s.active ? "Active" : "Disabled"}</td>
      <td>
        <form method="POST" action="/admin/service/${s.id}">
          <input name="rate" type="number" step="0.0001"
          value="${s.rate}" required>
          <button name="active" value="${!s.active}">${s.active ? "Disable" : "Enable"}</button>
          <button name="save" value="1">Save Price</button>
        </form>
      </td>
    </tr>
  `).join("");

  res.send(page("Manage Services", `
    <div class="card">
      <h2>Instagram Services</h2>
      <input
        type="search"
        id="adminServiceSearch"
        class="search-box"
        placeholder="Search services by name, ID or status..."
        autocomplete="off"
      >
      <div class="table-wrap">
        <table id="adminServicesTable">
          <thead>
            <tr>
              <th>ID</th><th>Name</th><th>Provider Rate</th>
              <th>Selling Rate</th><th>Status</th><th>Manage</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>

    <script>
      (function(){
        const search = document.getElementById("adminServiceSearch");
        const tableRows = document.querySelectorAll(".admin-service-row");

        search.addEventListener("input", function(){
          const term = this.value.toLowerCase().trim();

          tableRows.forEach(function(row){
            row.style.display = row.textContent.toLowerCase().includes(term)
              ? ""
              : "none";
          });
        });
      })();
    </script>
  `, req.session.user));
});

app.post("/admin/service/:id", requireLogin, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (req.body.save === "1") {
    const rate = Number(req.body.rate);
    if (!Number.isFinite(rate) || rate < 0) return res.status(400).send("Invalid price");

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
});

app.get("/admin/payments", requireLogin, requireAdmin, async (req, res) => {
  const r = await db(`
    SELECT p.*,u.username,u.email FROM payments p
    JOIN users u ON u.id=p.user_id
    ORDER BY p.id DESC LIMIT 200
  `);

  const rows = r.rows.map(p => `
    <tr><td>${p.id}</td><td>${p.username}</td><td>₹${p.amount}</td>
    <td>${p.utr}</td><td>${p.status}</td>
    <td>${p.status === "Pending" ? `
      <form method="POST" action="/admin/payment/${p.id}">
        <button name="action" value="approve">Approve</button>
        <button name="action" value="reject">Reject</button>
      </form>` : ""}</td></tr>
  `).join("");

  res.send(page("Payments", `
    <div class="card"><h2>Fund Approval</h2>
    <div class="table-wrap">
      <table><tr><th>ID</th><th>User</th><th>Amount</th>
      <th>UTR</th><th>Status</th><th>Action</th></tr>${rows}</table>
    </div></div>
  `, req.session.user));
});

app.post("/admin/payment/:id", requireLogin, requireAdmin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const r = await client.query(
      `SELECT * FROM payments WHERE id=$1 FOR UPDATE`,
      [req.params.id]
    );

    const payment = r.rows[0];
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
    } else {
      await client.query(
        `UPDATE payments SET status='Rejected' WHERE id=$1`,
        [payment.id]
      );
    }

    await client.query("COMMIT");
    res.redirect("/admin/payments");
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).send(e.message);
  } finally {
    client.release();
  }
});

app.get("/admin/refunds", requireLogin, requireAdmin, async (req, res) => {
  const r = await db(`
    SELECT f.*,u.username FROM refunds f
    JOIN users u ON u.id=f.user_id ORDER BY f.id DESC
  `);

  const rows = r.rows.map(f => `
    <tr><td>${f.id}</td><td>${f.username}</td><td>₹${f.amount}</td>
    <td>${f.reason}</td><td>${f.status}</td>
    <td>${f.status === "Pending" ? `
      <form method="POST" action="/admin/refund/${f.id}">
        <button name="action" value="approve">Approve</button>
        <button name="action" value="reject">Reject</button>
      </form>` : ""}</td></tr>
  `).join("");

  res.send(page("Refunds", `
    <div class="card"><h2>Refund Requests</h2>
    <div class="table-wrap">
      <table><tr><th>ID</th><th>User</th><th>Amount</th>
      <th>Reason</th><th>Status</th><th>Action</th></tr>${rows}</table>
    </div></div>
  `, req.session.user));
});

app.post("/admin/refund/:id", requireLogin, requireAdmin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const r = await client.query(
      `SELECT * FROM refunds WHERE id=$1 FOR UPDATE`,
      [req.params.id]
    );

    const refund = r.rows[0];
    if (!refund || refund.status !== "Pending") {
      throw new Error("Refund already processed");
    }

    if (req.body.action === "approve") {
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

      await client.query(
        `UPDATE refunds SET status='Approved' WHERE id=$1`,
        [refund.id]
      );
    } else {
      await client.query(
        `UPDATE refunds SET status='Rejected' WHERE id=$1`,
        [refund.id]
      );
    }

    await client.query("COMMIT");
    res.redirect("/admin/refunds");
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).send(e.message);
  } finally {
    client.release();
  }
});

app.get("/admin/users", requireLogin, requireAdmin, async (req, res) => {
  const r = await db(
    `SELECT id,username,email,balance,is_admin,created_at
     FROM users ORDER BY id DESC LIMIT 200`
  );

  const rows = r.rows.map(u => `
    <tr><td>${u.id}</td><td>${u.username}</td>
    <td>${u.email || ""}</td><td>₹${u.balance}</td>
    <td>${u.is_admin ? "Admin" : "Customer"}</td></tr>
  `).join("");

  res.send(page("Customers", `
    <div class="card"><h2>Customers</h2>
    <div class="table-wrap">
      <table><tr><th>ID</th><th>Username</th><th>Email</th>
      <th>Balance</th><th>Role</th></tr>${rows}</table>
    </div></div>
  `, req.session.user));
});

app.get("/admin/orders", requireLogin, requireAdmin, async (req, res) => {
  const r = await db(`
    SELECT o.*,u.username FROM orders o
    JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200
  `);

  const rows = r.rows.map(o => `
    <tr><td>${o.id}</td><td>${o.username}</td>
    <td>${o.service_name || o.service_id}</td><td>${o.quantity}</td>
    <td>${o.status}</td><td>${o.provider_order_id || ""}</td></tr>
  `).join("");

  res.send(page("Orders", `
    <div class="card"><h2>All Orders</h2>
    <div class="table-wrap">
      <table><tr><th>ID</th><th>User</th><th>Service</th>
      <th>Qty</th><th>Status</th><th>Provider ID</th></tr>${rows}</table>
    </div></div>
  `, req.session.user));
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", app: "ROYAL PANEL" });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send("Server error");
});

const PORT = process.env.PORT || 3000;

setupDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log("ROYAL PANEL running on port " + PORT);
    });
  })
  .catch(err => {
    console.error("Database setup failed:", err);
    process.exit(1);
  });
