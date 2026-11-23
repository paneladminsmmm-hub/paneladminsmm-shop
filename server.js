
/*
=========================================================
 ROYAL PANEL - COMPLETE SMM PANEL SERVER
 Node.js 18+
 Required packages:
 npm install express express-session connect-pg-simple bcryptjs
 helmet express-rate-limit pg google-auth-library dotenv
=========================================================

ENV VARIABLES:
DATABASE_URL=
SESSION_SECRET=
APP_URL=https://your-domain.com

ADMIN_USERNAME=admin
ADMIN_PASSWORD=YourStrongPassword
ADMIN_EMAIL=your@email.com

SOCIALADD_API_URL=https://socialadd.in/api/v2
SOCIALADD_API_KEY=

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CALLBACK_URL=https://your-domain.com/auth/google/callback

UPI_ID=yourupi@bank
WHATSAPP_NUMBER=918140989426
TELEGRAM_USERNAME=Digital_marketing_aagency_India

QR IMAGE:
public/payment-qr.png
*/

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");
const path = require("path");

const app = express();

app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const APP_URL = (process.env.APP_URL || "").replace(/\/$/, "");
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL &&
       !process.env.DATABASE_URL.includes("localhost")
       ? { rejectUnauthorized: false }
       : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_CALLBACK_URL ||
  `${APP_URL}/auth/google/callback`
);

const WHATSAPP_LINK =
  `https://wa.me/${process.env.WHATSAPP_NUMBER || "918140989426"}`;

const TELEGRAM_LINK =
  `https://t.me/${process.env.TELEGRAM_USERNAME || "Digital_marketing_aagency_India"}`;

const PROVIDER_URL = String(
  process.env.SOCIALADD_API_URL || "https://socialadd.in/api/v2"
).trim();

const PROVIDER_KEY = String(
  process.env.SOCIALADD_API_KEY || ""
).trim();

const UPI_ID = process.env.UPI_ID || "";

app.use(session({
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: "royalpanel.sid",
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

function q(sql, params = []) {
  return pool.query(sql, params);
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[ch]);
}

function money(value) {
  return "₹" + Number(value || 0).toFixed(2);
}

function page(title, content, user = null) {
  const nav = user ? `
    <a href="/dashboard">Dashboard</a>
    <a href="/services">Services</a>
    <a href="/order">New Order</a>
    <a href="/orders">My Orders</a>
    <a href="/funds">Add Funds</a>
    <a href="/refund">Refund</a>
    <a href="/support">Support</a>
    ${user.is_admin ? '<a href="/admin">Admin Panel</a>' : ""}
    <a href="/logout">Logout</a>
  ` : `
    <a href="/login">Login</a>
    <a href="/register">Register</a>
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} - ROYAL PANEL</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f4f7f5;color:#17251c;font-family:Arial,sans-serif}
header{background:#102c1d;color:white;padding:16px;position:sticky;top:0;z-index:5}
.brand{font-size:23px;font-weight:900;color:#75ed9b}
nav{display:flex;gap:12px;flex-wrap:wrap;margin-top:12px}
nav a{color:white;text-decoration:none;font-size:13px}
main{max-width:1050px;margin:22px auto;padding:0 14px}
.card{background:white;border-radius:13px;padding:18px;margin-bottom:15px;box-shadow:0 3px 15px #0000000c}
h1,h2,h3{margin-top:0}
input,select,textarea{width:100%;padding:12px;margin:7px 0 13px;border:1px solid #d4ded7;border-radius:8px;font-size:15px}
button,.btn{display:inline-block;background:#138344;color:white;border:0;padding:12px 17px;border-radius:8px;text-decoration:none;cursor:pointer;font-weight:bold}
button.danger{background:#c0392b}
button.gray{background:#59665e}
small,.muted{color:#718078}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:10px;border-bottom:1px solid #e7eee9;text-align:left;vertical-align:top}
.table-wrap{overflow-x:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.stat{background:#e9f7ed;padding:16px;border-radius:10px}
.stat strong{font-size:22px;display:block;margin-top:6px}
.notice{background:#fff4d9;padding:12px;border-radius:8px;margin:12px 0}
.success{background:#e5f8e9;padding:12px;border-radius:8px}
.error{background:#ffe9e7;padding:12px;border-radius:8px}
footer{text-align:center;padding:25px;color:#7a887f}
img.qr{max-width:260px;width:100%;height:auto;display:block;margin:12px 0}
.actions{display:flex;gap:7px;flex-wrap:wrap}
.actions form{display:inline}
@media(max-width:600px){nav{gap:9px}.brand{font-size:20px}td,th{padding:7px}}
</style>
</head>
<body>
<header>
<div class="brand">ROYAL PANEL</div>
<nav>${nav}</nav>
</header>
<main>${content}</main>
<footer>ROYAL PANEL · Social Media Services</footer>
<a href="${WHATSAPP_LINK}" style="position:fixed;right:15px;bottom:65px;background:#159b55;color:white;padding:12px;border-radius:30px;text-decoration:none">WhatsApp</a>
<a href="${TELEGRAM_LINK}" style="position:fixed;right:15px;bottom:15px;background:#168ac2;color:white;padding:12px;border-radius:30px;text-decoration:none">Telegram</a>
</body>
</html>`;
}

function message(text, type = "notice") {
  return `<div class="${type}">${esc(text)}</div>`;
}

function wrap(fn) {
  return (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login");
  }
  next();
}

const requireAdmin = wrap(async (req, res, next) => {
  if (!req.session.userId) return res.redirect("/login");

  const result = await q(
    "SELECT id,is_admin FROM users WHERE id=$1",
    [req.session.userId]
  );

  if (!result.rows[0] || !result.rows[0].is_admin) {
    return res.status(403).send("Admin access denied");
  }

  req.isAdmin = true;
  next();
});

async function currentUser(req) {
  if (!req.session.userId) return null;

  const result = await q(
    "SELECT id,username,email,wallet,is_admin FROM users WHERE id=$1",
    [req.session.userId]
  );

  return result.rows[0] || null;
}

async function providerRequest(params = {}) {
  if (!PROVIDER_KEY) {
    throw new Error("SOCIALADD_API_KEY is missing in Environment");
  }

  if (!PROVIDER_URL.startsWith("https://")) {
    throw new Error("Invalid SocialAdd API URL");
  }

  const body = new URLSearchParams();
  body.set("key", PROVIDER_KEY);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      body.set(key, String(value));
    }
  }

  let response;

  try {
    response = await fetch(PROVIDER_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: body.toString(),
      signal: AbortSignal.timeout(30000)
    });
  } catch (error) {
    console.error("SocialAdd connection error:", error.message);
    throw new Error("Provider connection failed: " + error.message);
  }

  const raw = await response.text();
  let data;

  try {
    data = JSON.parse(raw);
  } catch {
    console.error("SocialAdd invalid response:", raw.slice(0, 300));
    throw new Error("Provider returned invalid JSON");
  }

  if (!response.ok || data?.error) {
    console.error("SocialAdd API error:", response.status, data);
    throw new Error(
      data?.error || `Provider HTTP ${response.status}`
    );
  }

  return data;
}

function isInstagramService(service) {
  const text = (
    String(service.name || "") + " " +
    String(service.category || "") + " " +
    String(service.type || "")
  ).toLowerCase();

  return (
    text.includes("instagram") ||
    /insta\s*(followers|likes|views|comments|story|reel)/i.test(text)
  );
}

function instagramGroup(service) {
  const text = (
    String(service.name || "") + " " +
    String(service.category || "")
  ).toLowerCase();

  if (text.includes("follower")) return "Instagram Followers";
  if (text.includes("like")) return "Instagram Likes";
  if (text.includes("reel") || text.includes("view")) return "Instagram Views";
  if (text.includes("story")) return "Instagram Story Views";
  if (text.includes("comment")) return "Instagram Comments";
  if (text.includes("save")) return "Instagram Saves";
  if (text.includes("share")) return "Instagram Shares";

  return "Instagram Other";
}

async function setupDatabase() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT,
      wallet NUMERIC(14,2) NOT NULL DEFAULT 0,
      is_admin BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      provider_source VARCHAR(50) DEFAULT 'socialadd',
      provider_id VARCHAR(100),
      name TEXT NOT NULL,
      category VARCHAR(150) DEFAULT 'Instagram Other',
      rate NUMERIC(14,4) NOT NULL DEFAULT 0,
      provider_rate NUMERIC(14,4) NOT NULL DEFAULT 0,
      min INTEGER DEFAULT 1,
      max INTEGER DEFAULT 100000,
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(provider_source,provider_id)
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      service_id INTEGER REFERENCES services(id),
      link TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      charge NUMERIC(14,2) NOT NULL,
      provider_order_id VARCHAR(150),
      status VARCHAR(100) DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(14,2) NOT NULL,
      utr VARCHAR(150) NOT NULL,
      status VARCHAR(30) DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS refunds (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(14,2) NOT NULL,
      reason TEXT,
      status VARCHAR(30) DEFAULT 'Pending',
      funds_reserved BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      status VARCHAR(30) DEFAULT 'Open',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(14,2) NOT NULL,
      type VARCHAR(40) NOT NULL,
      description TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS panel_settings (
      setting_key VARCHAR(100) PRIMARY KEY,
      setting_value TEXT NOT NULL
    )
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS orders_user_idx ON orders(user_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS payments_user_idx ON payments(user_id)
  `);

  const defaults = {
    provider_enabled: "true",
    services_enabled: "true"
  };

  for (const [key, value] of Object.entries(defaults)) {
    await q(`
      INSERT INTO panel_settings(setting_key,setting_value)
      VALUES($1,$2)
      ON CONFLICT(setting_key) DO NOTHING
    `, [key, value]);
  }

  if (process.env.ADMIN_USERNAME &&
      process.env.ADMIN_PASSWORD &&
      process.env.ADMIN_EMAIL) {

    const username = process.env.ADMIN_USERNAME.trim();
    const email = process.env.ADMIN_EMAIL.trim().toLowerCase();

    const existing = await q(
      "SELECT id FROM users WHERE email=$1 OR username=$2",
      [email, username]
    );

    if (!existing.rows.length) {
      const hash = await bcrypt.hash(
        process.env.ADMIN_PASSWORD,
        12
      );

      await q(`
        INSERT INTO users(username,email,password_hash,is_admin)
        VALUES($1,$2,$3,true)
      `, [username, email, hash]);
    } else {
      await q(`
        UPDATE users
        SET is_admin=true
        WHERE email=$1 OR username=$2
      `, [email, username]);
    }
  }

  if (process.env.ADMIN_EMAIL) {
    await q(
      "UPDATE users SET is_admin=true WHERE email=$1",
      [process.env.ADMIN_EMAIL.trim().toLowerCase()]
    );
  }

  console.log("Database setup completed");
}

async function setting(key, fallback = "false") {
  const result = await q(
    "SELECT setting_value FROM panel_settings WHERE setting_key=$1",
    [key]
  );
  return result.rows[0]?.setting_value ?? fallback;
}

async function setSetting(key, value) {
  await q(`
    INSERT INTO panel_settings(setting_key,setting_value)
    VALUES($1,$2)
    ON CONFLICT(setting_key)
    DO UPDATE SET setting_value=EXCLUDED.setting_value
  `, [key, String(value)]);
}

async function addWallet(client, userId, amount, type, description) {
  await client.query(
    "UPDATE users SET wallet=wallet+$1 WHERE id=$2",
    [amount, userId]
  );

  await client.query(`
    INSERT INTO wallet_transactions(user_id,amount,type,description)
    VALUES($1,$2,$3,$4)
  `, [userId, amount, type, description]);
}

/* HOME */

app.get("/", wrap(async (req, res) => {
  const user = await currentUser(req);

  res.send(page("Home", `
    <div class="card">
      <h1>Welcome to ROYAL PANEL</h1>
      <p>Instagram Followers, Likes, Views and other social media services.</p>
      <a class="btn" href="${user ? "/dashboard" : "/register"}">
        ${user ? "Open Dashboard" : "Get Started"}
      </a>
    </div>
  `, user));
}));

/* REGISTER */

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h2>Create Account</h2>
      <form method="POST" action="/register">
        <label>Username</label>
        <input name="username" required minlength="3" maxlength="50">
        <label>Email</label>
        <input name="email" type="email" required>
        <label>Password</label>
        <input name="password" type="password" required minlength="8">
        <button>Create Account</button>
      </form>
      <p><a href="/login">Already have an account? Login</a></p>
    </div>
  `));
});

app.post("/register", registerLimiter, wrap(async (req, res) => {
  const username = String(req.body.username || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!/^[a-zA-Z0-9_]{3,50}$/.test(username)) {
    return res.send(page("Register", message("Invalid username format.", "error")));
  }

  if (password.length < 8 || !email.includes("@")) {
    return res.send(page("Register", message("Enter valid email and password.", "error")));
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const result = await q(`
      INSERT INTO users(username,email,password_hash)
      VALUES($1,$2,$3)
      RETURNING id
    `, [username, email, hash]);

    req.session.userId = result.rows[0].id;
    res.redirect("/dashboard");
  } catch (error) {
    if (error.code === "23505") {
      return res.send(page("Register", message("Username or email already exists.", "error")));
    }
    throw error;
  }
}));

/* LOGIN */

app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card">
      <h2>Login</h2>
      <form method="POST" action="/login">
        <label>Email or Username</label>
        <input name="identity" required>
        <label>Password</label>
        <input name="password" type="password" required>
        <button>Login</button>
      </form>
      <hr>
      <a class="btn" href="/auth/google">Continue with Google</a>
      <p><a href="/register">Create new account</a></p>
    </div>
  `));
});

app.post("/login", loginLimiter, wrap(async (req, res) => {
  const identity = String(req.body.identity || "").trim();
  const password = String(req.body.password || "");

  const result = await q(`
    SELECT * FROM users
    WHERE LOWER(email)=LOWER($1) OR LOWER(username)=LOWER($1)
    LIMIT 1
  `, [identity]);

  const user = result.rows[0];

  if (!user || !user.password_hash ||
      !(await bcrypt.compare(password, user.password_hash))) {
    return res.send(page("Login", message("Incorrect login details.", "error")));
  }

  req.session.userId = user.id;
  res.redirect("/dashboard");
}));

/* GOOGLE LOGIN */

app.get("/auth/google", (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID ||
      !process.env.GOOGLE_CLIENT_SECRET) {
    return res.send(page("Google Login", message("Google login is not configured.", "error")));
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

app.get("/auth/google/callback", wrap(async (req, res) => {
  if (!req.query.code ||
      !req.query.state ||
      req.query.state !== req.session.googleState) {
    return res.status(400).send("Invalid Google login state");
  }

  delete req.session.googleState;

  const { tokens } = await googleClient.getToken(req.query.code);
  const ticket = await googleClient.verifyIdToken({
    idToken: tokens.id_token,
    audience: process.env.GOOGLE_CLIENT_ID
  });

  const profile = ticket.getPayload();

  if (!profile || !profile.email || !profile.email_verified) {
    return res.status(400).send("Google email is not verified");
  }

  const email = profile.email.toLowerCase();
  let result = await q(
    "SELECT id FROM users WHERE email=$1",
    [email]
  );

  let userId;

  if (!result.rows.length) {
    let username = String(profile.name || email.split("@")[0])
      .replace(/[^a-zA-Z0-9_]/g, "")
      .slice(0, 30) || "user";

    if (username.length < 3) username = "user" + Date.now();

    const exists = await q(
      "SELECT id FROM users WHERE username=$1",
      [username]
    );

    if (exists.rows.length) {
      username += "_" + crypto.randomBytes(3).toString("hex");
    }

    result = await q(`
      INSERT INTO users(username,email)
      VALUES($1,$2)
      RETURNING id
    `, [username, email]);

    userId = result.rows[0].id;
  } else {
    userId = result.rows[0].id;
  }

  req.session.userId = userId;
  res.redirect("/dashboard");
}));

/* LOGOUT */

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

/* DASHBOARD */

app.get("/dashboard", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);

  const orders = await q(
    "SELECT COUNT(*) FROM orders WHERE user_id=$1",
    [user.id]
  );

  const payments = await q(
    "SELECT COUNT(*) FROM payments WHERE user_id=$1 AND status='Pending'",
    [user.id]
  );

  res.send(page("Dashboard", `
    <h2>Hello, ${esc(user.username)}</h2>
    <div class="grid">
      <div class="stat">Wallet Balance<strong>${money(user.wallet)}</strong></div>
      <div class="stat">Total Orders<strong>${orders.rows[0].count}</strong></div>
      <div class="stat">Pending Payments<strong>${payments.rows[0].count}</strong></div>
    </div>
    <div class="card">
      <h3>Quick Actions</h3>
      <div class="actions">
        <a class="btn" href="/order">New Order</a>
        <a class="btn" href="/funds">Add Funds</a>
        <a class="btn" href="/orders">Order History</a>
      </div>
    </div>
  `, user));
}));

/* SERVICES */

app.get("/services", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);

  const result = await q(`
    SELECT id,name,category,rate,min,max
    FROM services
    WHERE active=true
    ORDER BY category,name
  `);

  const rows = result.rows.map(s => `
    <tr>
      <td>${esc(s.name)}</td>
      <td>${esc(s.category)}</td>
      <td>${money(s.rate)} / 1000</td>
      <td>${s.min} - ${s.max}</td>
    </tr>
  `).join("");

  res.send(page("Services", `
    <div class="card">
      <h2>Available Instagram Services</h2>
      <div class="table-wrap">
      <table>
        <tr><th>Service</th><th>Category</th><th>Rate / 1000</th><th>Min-Max</th></tr>
        ${rows || "<tr><td colspan='4'>No active services available.</td></tr>"}
      </table>
      </div>
    </div>
  `, user));
}));

/* NEW ORDER */

app.get("/order", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);

  if (await setting("services_enabled") !== "true") {
    return res.send(page("New Order", message("All services are temporarily disabled.", "error"), user));
  }

  const result = await q(`
    SELECT id,name,category,rate,min,max
    FROM services
    WHERE active=true
    ORDER BY category,name
  `);

  const options = result.rows.map(s => `
    <option value="${s.id}"
      data-rate="${s.rate}"
      data-min="${s.min}"
      data-max="${s.max}">
      ${esc(s.category)} - ${esc(s.name)}
      (${money(s.rate)}/1000)
    </option>
  `).join("");

  res.send(page("New Order", `
    <div class="card">
      <h2>Place New Order</h2>
      <p>Wallet Balance: <b>${money(user.wallet)}</b></p>
      <form method="POST" action="/order">
        <label>Select Service</label>
        <select name="service_id" required>
          <option value="">Select Service</option>
          ${options}
        </select>
        <label>Instagram Link</label>
        <input name="link" type="url" required placeholder="https://www.instagram.com/...">
        <label>Quantity</label>
        <input name="quantity" type="number" required min="1">
        <button>Place Order</button>
      </form>
    </div>
  `, user));
}));

app.post("/order", requireLogin, wrap(async (req, res) => {
  if (await setting("services_enabled") !== "true") {
    return res.send(page("Order", message("Services are disabled.", "error"), await currentUser(req)));
  }

  const user = await currentUser(req);
  const serviceId = Number(req.body.service_id);
  const quantity = Number(req.body.quantity);
  const link = String(req.body.link || "").trim();

  if (!Number.isInteger(serviceId) ||
      !Number.isInteger(quantity) ||
      quantity <= 0 ||
      !/^https:\/\/(www\.)?instagram\.com\//i.test(link)) {
    return res.send(page("Order", message("Invalid service, quantity or Instagram link.", "error"), user));
  }

  const serviceResult = await q(
    "SELECT * FROM services WHERE id=$1 AND active=true",
    [serviceId]
  );

  const service = serviceResult.rows[0];

  if (!service) {
    return res.send(page("Order", message("Service not found or disabled.", "error"), user));
  }

  if (quantity < service.min || quantity > service.max) {
    return res.send(page("Order", message(`Quantity must be between ${service.min} and ${service.max}.`, "error"), user));
  }

  const charge = Number(
    (Number(service.rate) * quantity / 1000).toFixed(2)
  );

  if (!Number.isFinite(charge) || charge <= 0) {
    return res.send(page("Order", message("Invalid order price.", "error"), user));
  }

  const client = await pool.connect();
  let orderId;

  try {
    await client.query("BEGIN");

    const lockedUser = await client.query(
      "SELECT wallet FROM users WHERE id=$1 FOR UPDATE",
      [user.id]
    );

    if (!lockedUser.rows[0] ||
        Number(lockedUser.rows[0].wallet) < charge) {
      await client.query("ROLLBACK");
      return res.send(page("Order", message("Insufficient wallet balance. Please add funds.", "error"), user));
    }

    await client.query(
      "UPDATE users SET wallet=wallet-$1 WHERE id=$2",
      [charge, user.id]
    );

    const inserted = await client.query(`
      INSERT INTO orders(user_id,service_id,link,quantity,charge,status)
      VALUES($1,$2,$3,$4,$5,'Submitting')
      RETURNING id
    `, [user.id, service.id, link, quantity, charge]);

    orderId = inserted.rows[0].id;

    await client.query(`
      INSERT INTO wallet_transactions(user_id,amount,type,description)
      VALUES($1,$2,'order_debit',$3)
    `, [user.id, -charge, `Order #${orderId}`]);

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  try {
    if (await setting("provider_enabled") !== "true") {
      throw new Error("Provider API is disabled by admin");
    }

    const providerResult = await providerRequest({
      action: "add",
      service: service.provider_id,
      link,
      quantity
    });

    if (!providerResult.order) {
      throw new Error("Provider did not return an order ID");
    }

    await q(`
      UPDATE orders
      SET provider_order_id=$1,status='Processing'
      WHERE id=$2
    `, [String(providerResult.order), orderId]);

    res.redirect("/orders");
  } catch (error) {
    console.error("Order provider failure:", error.message);

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const order = await client.query(
        "SELECT * FROM orders WHERE id=$1 FOR UPDATE",
        [orderId]
      );

      if (order.rows[0] &&
          order.rows[0].status === "Submitting") {

        await addWallet(
          client,
          user.id,
          charge,
          "order_refund",
          `Automatic refund for failed order #${orderId}`
        );

        await client.query(`
          UPDATE orders
          SET status='Provider Error - Refunded'
          WHERE id=$1
        `, [orderId]);
      }

      await client.query("COMMIT");
    } catch (refundError) {
      await client.query("ROLLBACK");
      console.error("Automatic refund failed:", refundError);
    } finally {
      client.release();
    }

    res.send(page("Order Error", message(
      "Provider order failed. If the order was not submitted, your wallet refund has been processed. Please check Order History.",
      "error"
    ), await currentUser(req)));
  }
}));

/* ORDER HISTORY */

app.get("/orders", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);

  const result = await q(`
    SELECT o.*,s.name AS service_name
    FROM orders o
    LEFT JOIN services s ON s.id=o.service_id
    WHERE o.user_id=$1
    ORDER BY o.id DESC
    LIMIT 200
  `, [user.id]);

  const rows = result.rows.map(o => `
    <tr>
      <td>#${o.id}</td>
      <td>${esc(o.service_name)}</td>
      <td>${o.quantity}</td>
      <td>${money(o.charge)}</td>
      <td>${esc(o.status)}</td>
      <td>${new Date(o.created_at).toLocaleString("en-IN")}</td>
    </tr>
  `).join("");

  res.send(page("Orders", `
    <div class="card">
      <h2>Order History</h2>
      <div class="table-wrap">
      <table>
      <tr><th>ID</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th><th>Date</th></tr>
      ${rows || "<tr><td colspan='6'>No orders yet.</td></tr>"}
      </table>
      </div>
    </div>
  `, user));
}));

/* ADD FUNDS */

app.get("/funds", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);

  res.send(page("Add Funds", `
    <div class="card">
      <h2>Add Funds</h2>
      <p>Wallet Balance: <b>${money(user.wallet)}</b></p>
      <p>Minimum: ₹10 | Maximum: ₹2000</p>
      <img class="qr" src="/payment-qr.png" alt="Payment QR">
      <p>UPI ID: <b>${esc(UPI_ID || "Please contact support")}</b></p>
      <form method="POST" action="/funds">
        <label>Payment Amount (₹10 - ₹2000)</label>
        <input type="number" name="amount" min="10" max="2000" step="0.01" required>
        <label>UTR / Transaction ID</label>
        <input name="utr" required maxlength="150">
        <button>Submit Payment Request</button>
      </form>
      <p class="muted">Your wallet will be credited after admin approval.</p>
    </div>
  `, user));
}));

app.post("/funds", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);
  const amount = Number(req.body.amount);
  const utr = String(req.body.utr || "").trim();

  if (!Number.isFinite(amount) || amount < 10 || amount > 2000 || !utr) {
    return res.send(page("Add Funds", message("Amount must be between ₹10 and ₹2000 and UTR is required.", "error"), user));
  }

  await q(`
    INSERT INTO payments(user_id,amount,utr)
    VALUES($1,$2,$3)
  `, [user.id, amount, utr]);

  res.send(page("Add Funds", message("Payment request submitted. Wait for admin approval.", "success"), user));
}));

/* REFUND REQUEST */

app.get("/refund", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);

  res.send(page("Refund", `
    <div class="card">
      <h2>Wallet Refund Request</h2>
      <p>Minimum ₹10 - Maximum ₹2000</p>
      <p>Wallet Balance: <b>${money(user.wallet)}</b></p>
      <form method="POST" action="/refund">
        <label>Refund Amount</label>
        <input type="number" name="amount" min="10" max="2000" step="0.01" required>
        <label>Reason / UPI details</label>
        <textarea name="reason" required></textarea>
        <button>Submit Refund Request</button>
      </form>
      <p class="muted">The requested amount is reserved from your wallet until admin approval or rejection.</p>
    </div>
  `, user));
}));

app.post("/refund", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);
  const amount = Number(req.body.amount);
  const reason = String(req.body.reason || "").trim();

  if (!Number.isFinite(amount) || amount < 10 || amount > 2000 || !reason) {
    return res.send(page("Refund", message("Refund amount must be ₹10 to ₹2000. Reason is required.", "error"), user));
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const locked = await client.query(
      "SELECT wallet FROM users WHERE id=$1 FOR UPDATE",
      [user.id]
    );

    if (!locked.rows[0] || Number(locked.rows[0].wallet) < amount) {
      await client.query("ROLLBACK");
      return res.send(page("Refund", message("Insufficient wallet balance.", "error"), user));
    }

    await client.query(
      "UPDATE users SET wallet=wallet-$1 WHERE id=$2",
      [amount, user.id]
    );

    await client.query(`
      INSERT INTO wallet_transactions(user_id,amount,type,description)
      VALUES($1,$2,'refund_reserved','Refund request reserved')
    `, [user.id, -amount]);

    await client.query(`
      INSERT INTO refunds(user_id,amount,reason)
      VALUES($1,$2,$3)
    `, [user.id, amount, reason]);

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  res.send(page("Refund", message("Refund request submitted successfully.", "success"), await currentUser(req)));
}));

/* SUPPORT */

app.get("/support", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);

  const result = await q(`
    SELECT * FROM tickets
    WHERE user_id=$1 ORDER BY id DESC LIMIT 50
  `, [user.id]);

  const rows = result.rows.map(t => `
    <tr><td>#${t.id}</td><td>${esc(t.subject)}</td>
    <td>${esc(t.status)}</td><td>${new Date(t.created_at).toLocaleString("en-IN")}</td></tr>
  `).join("");

  res.send(page("Support", `
    <div class="card">
      <h2>Create Support Ticket</h2>
      <form method="POST" action="/support">
        <label>Subject</label>
        <input name="subject" required>
        <label>Message</label>
        <textarea name="message" required></textarea>
        <button>Submit Ticket</button>
      </form>
    </div>
    <div class="card">
      <h3>Your Tickets</h3>
      <div class="table-wrap"><table>
      <tr><th>ID</th><th>Subject</th><th>Status</th><th>Date</th></tr>
      ${rows || "<tr><td colspan='4'>No tickets.</td></tr>"}
      </table></div>
    </div>
  `, user));
}));

app.post("/support", requireLogin, wrap(async (req, res) => {
  const user = await currentUser(req);
  const subject = String(req.body.subject || "").trim();
  const text = String(req.body.message || "").trim();

  if (!subject || !text) {
    return res.send(page("Support", message("Subject and message are required.", "error"), user));
  }

  await q(`
    INSERT INTO tickets(user_id,subject,message)
    VALUES($1,$2,$3)
  `, [user.id, subject, text]);

  res.redirect("/support");
}));

/* ADMIN DASHBOARD */

app.get("/admin", requireAdmin, wrap(async (req, res) => {
  const [users, orders, payments, refunds, balance] = await Promise.all([
    q("SELECT COUNT(*) FROM users"),
    q("SELECT COUNT(*) FROM orders"),
    q("SELECT COUNT(*) FROM payments WHERE status='Pending'"),
    q("SELECT COUNT(*) FROM refunds WHERE status='Pending'"),
    q("SELECT COALESCE(SUM(wallet),0) AS total FROM users")
  ]);

  const providerEnabled = await setting("provider_enabled");
  const servicesEnabled = await setting("services_enabled");

  res.send(page("Admin Panel", `
    <h2>Admin Dashboard</h2>
    <div class="grid">
      <div class="stat">Users<strong>${users.rows[0].count}</strong></div>
      <div class="stat">Orders<strong>${orders.rows[0].count}</strong></div>
      <div class="stat">Pending Payments<strong>${payments.rows[0].count}</strong></div>
      <div class="stat">Pending Refunds<strong>${refunds.rows[0].count}</strong></div>
      <div class="stat">Total Wallet<strong>${money(balance.rows[0].total)}</strong></div>
    </div>
    <div class="card">
      <h3>Panel Controls</h3>
      <p>Provider API: <b>${esc(providerEnabled)}</b></p>
      <p>All Services: <b>${esc(servicesEnabled)}</b></p>
      <div class="actions">
        <a class="btn" href="/admin/provider-toggle">Toggle Provider API</a>
        <a class="btn" href="/admin/services-toggle">Toggle All Services</a>
        <a class="btn" href="/admin/provider-test">Test Provider API</a>
        <a class="btn" href="/admin/import">Import Instagram Services</a>
      </div>
    </div>
    <div class="card">
      <h3>Management</h3>
      <div class="actions">
        <a class="btn" href="/admin/services">Services</a>
        <a class="btn" href="/admin/payments">Payments</a>
        <a class="btn" href="/admin/refunds">Refunds</a>
        <a class="btn" href="/admin/orders">Orders</a>
        <a class="btn" href="/admin/users">Users</a>
        <a class="btn" href="/admin/tickets">Tickets</a>
      </div>
    </div>
  `));
}));

/* PROVIDER TOGGLE */

app.get("/admin/provider-toggle", requireAdmin, wrap(async (req, res) => {
  const current = await setting("provider_enabled");
  await setSetting("provider_enabled", current === "true" ? "false" : "true");
  res.redirect("/admin");
}));

/* SERVICES TOGGLE */

app.get("/admin/services-toggle", requireAdmin, wrap(async (req, res) => {
  const current = await setting("services_enabled");
  await setSetting("services_enabled", current === "true" ? "false" : "true");
  res.redirect("/admin");
}));

/* PROVIDER TEST */

app.get("/admin/provider-test", requireAdmin, wrap(async (req, res) => {
  try {
    const data = await providerRequest({ action: "balance" });

    res.send(page("Provider Test", `
      <div class="card">
        <h2>Provider API Connected</h2>
        <pre>${esc(JSON.stringify(data, null, 2))}</pre>
        <a class="btn" href="/admin">Back to Admin</a>
      </div>
    `));
  } catch (error) {
    console.error("Provider test failed:", error.message);

    res.send(page("Provider Test", `
      <div class="card">
        ${message("Provider API Error: " + error.message, "error")}
        <p>Check SOCIALADD_API_URL and SOCIALADD_API_KEY in Render Environment.</p>
        <a class="btn" href="/admin">Back to Admin</a>
      </div>
    `));
  }
}));

/* IMPORT INSTAGRAM SERVICES */

app.get("/admin/import", requireAdmin, wrap(async (req, res) => {
  if (await setting("provider_enabled") !== "true") {
    return res.send(page("Import", message("Provider API is disabled. Enable it first.", "error")));
  }

  try {
    const services = await providerRequest({ action: "services" });

    if (!Array.isArray(services)) {
      throw new Error("Provider services response is not an array");
    }

    let imported = 0;
    let skipped = 0;

    await q(`
      UPDATE services
      SET active=false
      WHERE provider_source='socialadd'
    `);

    for (const s of services) {
      if (!isInstagramService(s)) {
        skipped++;
        continue;
      }

      const providerId = String(s.service || s.id || "");
      const name = String(s.name || "").trim();
      const providerRate = Number(s.rate);
      const min = Number(s.min || 1);
      const max = Number(s.max || 100000);

      if (!providerId || !name ||
          !Number.isFinite(providerRate) ||
          providerRate <= 0 ||
          !Number.isInteger(min) ||
          !Number.isInteger(max) ||
          min <= 0 || max < min) {
        skipped++;
        continue;
      }

      const category = instagramGroup(s);
      const initialRate = Number((providerRate * 1.75).toFixed(4));

      await q(`
        INSERT INTO services(
          provider_source,provider_id,name,category,
          rate,provider_rate,min,max,active
        )
        VALUES('socialadd',$1,$2,$3,$4,$5,$6,$7,true)
        ON CONFLICT(provider_source,provider_id)
        DO UPDATE SET
          name=EXCLUDED.name,
          category=EXCLUDED.category,
          provider_rate=EXCLUDED.provider_rate,
          min=EXCLUDED.min,
          max=EXCLUDED.max,
          active=true
      `, [
        providerId,
        name,
        category,
        initialRate,
        providerRate,
        min,
        max
      ]);

      imported++;
    }

    res.send(page("Import Services", `
      <div class="card">
        <h2>Instagram Service Import Complete</h2>
        ${message(`Imported/updated: ${imported} | Skipped: ${skipped}`, "success")}
        <p>Existing manually configured selling rates are preserved.</p>
        <a class="btn" href="/admin/services">Manage Services</a>
      </div>
    `));
  } catch (error) {
    console.error("Service import error:", error.message);

    res.send(page("Import Error", `
      ${message("Import failed: " + error.message, "error")}
      <a class="btn" href="/admin">Back</a>
    `));
  }
}));

/* ADMIN SERVICES */

app.get("/admin/services", requireAdmin, wrap(async (req, res) => {
  const result = await q(
    "SELECT * FROM services ORDER BY id DESC LIMIT 500"
  );

  const rows = result.rows.map(s => `
    <tr>
      <td>${s.id}</td>
      <td>${esc(s.name)}</td>
      <td>${esc(s.category)}</td>
      <td>${money(s.provider_rate)}</td>
      <td>${money(s.rate)}</td>
      <td>${s.min}-${s.max}</td>
      <td>${s.active ? "Active" : "Disabled"}</td>
      <td>
        <form method="POST" action="/admin/service/${s.id}">
          <input type="number" name="rate" step="0.0001" min="0.0001" value="${s.rate}" required>
          <label><input type="checkbox" name="active" ${s.active ? "checked" : ""} style="width:auto"> Active</label>
          <button>Save</button>
        </form>
      </td>
    </tr>
  `).join("");

  res.send(page("Manage Services", `
    <div class="card">
      <h2>Service Management</h2>
      <p>Provider rate and selling rate are separate. Importing services will not overwrite your manually set selling rates.</p>
      <div class="table-wrap">
      <table>
      <tr><th>ID</th><th>Name</th><th>Category</th><th>Provider Rate</th><th>Selling Rate</th><th>Min-Max</th><th>Status</th><th>Update</th></tr>
      ${rows || "<tr><td colspan='8'>No services imported.</td></tr>"}
      </table>
      </div>
      <p><a class="btn" href="/admin/import">Import Services</a></p>
    </div>
  `));
}));

app.post("/admin/service/:id", requireAdmin, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const rate = Number(req.body.rate);
  const active = req.body.active === "on";

  if (!Number.isInteger(id) || !Number.isFinite(rate) || rate <= 0) {
    return res.status(400).send("Invalid service update");
  }

  await q(`
    UPDATE services SET rate=$1,active=$2 WHERE id=$3
  `, [rate, active, id]);

  res.redirect("/admin/services");
}));

/* ADMIN PAYMENTS */

app.get("/admin/payments", requireAdmin, wrap(async (req, res) => {
  const result = await q(`
    SELECT p.*,u.username,u.email
    FROM payments p JOIN users u ON u.id=p.user_id
    ORDER BY p.id DESC LIMIT 300
  `);

  const rows = result.rows.map(p => `
    <tr>
      <td>#${p.id}</td>
      <td>${esc(p.username)}<br>${esc(p.email)}</td>
      <td>${money(p.amount)}</td>
      <td>${esc(p.utr)}</td>
      <td>${esc(p.status)}</td>
      <td>
        ${p.status === "Pending" ? `
        <div class="actions">
        <form method="POST" action="/admin/payment/${p.id}">
          <input type="hidden" name="action" value="approve">
          <button>Approve</button>
        </form>
        <form method="POST" action="/admin/payment/${p.id}">
          <input type="hidden" name="action" value="reject">
          <button class="danger">Reject</button>
        </form>
        </div>` : "-"}
      </td>
    </tr>
  `).join("");

  res.send(page("Payments", `
    <div class="card">
      <h2>Payment Requests</h2>
      <div class="table-wrap"><table>
      <tr><th>ID</th><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>
      ${rows || "<tr><td colspan='6'>No payments.</td></tr>"}
      </table></div>
    </div>
  `));
}));

app.post("/admin/payment/:id", requireAdmin, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const action = req.body.action;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
      [id]
    );

    const payment = result.rows[0];

    if (!payment || payment.status !== "Pending") {
      await client.query("ROLLBACK");
      return res.redirect("/admin/payments");
    }

    if (action === "approve") {
      await addWallet(
        client,
        payment.user_id,
        Number(payment.amount),
        "payment_credit",
        `Payment #${payment.id} approved`
      );

      await client.query(
        "UPDATE payments SET status='Approved' WHERE id=$1",
        [id]
      );
    } else if (action === "reject") {
      await client.query(
        "UPDATE payments SET status='Rejected' WHERE id=$1",
        [id]
      );
    } else {
      await client.query("ROLLBACK");
      return res.redirect("/admin/payments");
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  res.redirect("/admin/payments");
}));

/* ADMIN REFUNDS */

app.get("/admin/refunds", requireAdmin, wrap(async (req, res) => {
  const result = await q(`
    SELECT r.*,u.username,u.email
    FROM refunds r JOIN users u ON u.id=r.user_id
    ORDER BY r.id DESC LIMIT 300
  `);

  const rows = result.rows.map(r => `
    <tr>
      <td>#${r.id}</td>
      <td>${esc(r.username)}<br>${esc(r.email)}</td>
      <td>${money(r.amount)}</td>
      <td>${esc(r.reason)}</td>
      <td>${esc(r.status)}</td>
      <td>
      ${r.status === "Pending" ? `
        <form method="POST" action="/admin/refund/${r.id}">
          <button name="action" value="approve">Approve</button>
          <button class="danger" name="action" value="reject">Reject</button>
        </form>
      ` : "-"}
      </td>
    </tr>
  `).join("");

  res.send(page("Refund Requests", `
    <div class="card">
      <h2>Refund Requests</h2>
      <div class="table-wrap"><table>
      <tr><th>ID</th><th>User</th><th>Amount</th><th>Reason</th><th>Status</th><th>Action</th></tr>
      ${rows || "<tr><td colspan='6'>No refunds.</td></tr>"}
      </table></div>
    </div>
  `));
}));

app.post("/admin/refund/:id", requireAdmin, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const action = req.body.action;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM refunds WHERE id=$1 FOR UPDATE",
      [id]
    );

    const refund = result.rows[0];

    if (!refund || refund.status !== "Pending") {
      await client.query("ROLLBACK");
      return res.redirect("/admin/refunds");
    }

    if (action === "approve") {
      await client.query(
        "UPDATE refunds SET status='Approved',funds_reserved=false WHERE id=$1",
        [id]
      );
    } else if (action === "reject") {
      if (refund.funds_reserved) {
        await addWallet(
          client,
          refund.user_id,
          Number(refund.amount),
          "refund_rejected_credit",
          `Refund #${refund.id} rejected; reserved funds returned`
        );
      }

      await client.query(
        "UPDATE refunds SET status='Rejected',funds_reserved=false WHERE id=$1",
        [id]
      );
    } else {
      await client.query("ROLLBACK");
      return res.redirect("/admin/refunds");
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  res.redirect("/admin/refunds");
}));

/* ADMIN ORDERS */

app.get("/admin/orders", requireAdmin, wrap(async (req, res) => {
  const result = await q(`
    SELECT o.*,u.username,s.name AS service_name
    FROM orders o
    JOIN users u ON u.id=o.user_id
    LEFT JOIN services s ON s.id=o.service_id
    ORDER BY o.id DESC LIMIT 300
  `);

  const rows = result.rows.map(o => `
    <tr>
      <td>#${o.id}</td>
      <td>${esc(o.username)}</td>
      <td>${esc(o.service_name)}</td>
      <td>${o.quantity}</td>
      <td>${money(o.charge)}</td>
      <td>${esc(o.provider_order_id || "-")}</td>
      <td>${esc(o.status)}</td>
    </tr>
  `).join("");

  res.send(page("All Orders", `
    <div class="card">
      <h2>All Orders</h2>
      <div class="table-wrap"><table>
      <tr><th>ID</th><th>User</th><th>Service</th><th>Qty</th><th>Charge</th><th>Provider ID</th><th>Status</th></tr>
      ${rows || "<tr><td colspan='7'>No orders.</td></tr>"}
      </table></div>
    </div>
  `));
}));

/* ADMIN USERS */

app.get("/admin/users", requireAdmin, wrap(async (req, res) => {
  const result = await q(`
    SELECT id,username,email,wallet,is_admin,created_at
    FROM users ORDER BY id DESC LIMIT 500
  `);

  const rows = result.rows.map(u => `
    <tr>
      <td>${u.id}</td>
      <td>${esc(u.username)}</td>
      <td>${esc(u.email)}</td>
      <td>${money(u.wallet)}</td>
      <td>${u.is_admin ? "Admin" : "Customer"}</td>
      <td>${new Date(u.created_at).toLocaleDateString("en-IN")}</td>
    </tr>
  `).join("");

  res.send(page("Users", `
    <div class="card">
      <h2>Users</h2>
      <div class="table-wrap"><table>
      <tr><th>ID</th><th>Username</th><th>Email</th><th>Wallet</th><th>Role</th><th>Joined</th></tr>
      ${rows || "<tr><td colspan='6'>No users.</td></tr>"}
      </table></div>
    </div>
  `));
}));

/* ADMIN SUPPORT TICKETS */

app.get("/admin/tickets", requireAdmin, wrap(async (req, res) => {
  const result = await q(`
    SELECT t.*,u.username
    FROM tickets t JOIN users u ON u.id=t.user_id
    ORDER BY t.id DESC LIMIT 300
  `);

  const rows = result.rows.map(t => `
    <tr>
      <td>#${t.id}</td>
      <td>${esc(t.username)}</td>
      <td>${esc(t.subject)}</td>
      <td>${esc(t.message)}</td>
      <td>${esc(t.status)}</td>
      <td>
        <form method="POST" action="/admin/ticket/${t.id}">
          <button name="status" value="Closed">Close</button>
          <button class="gray" name="status" value="Open">Reopen</button>
        </form>
      </td>
    </tr>
  `).join("");

  res.send(page("Support Tickets", `
    <div class="card">
      <h2>Support Tickets</h2>
      <div class="table-wrap"><table>
      <tr><th>ID</th><th>User</th><th>Subject</th><th>Message</th><th>Status</th><th>Action</th></tr>
      ${rows || "<tr><td colspan='6'>No tickets.</td></tr>"}
      </table></div>
    </div>
  `));
}));

app.post("/admin/ticket/:id", requireAdmin, wrap(async (req, res) => {
  const status = req.body.status;

  if (!["Open", "Closed"].includes(status)) {
    return res.status(400).send("Invalid ticket status");
  }

  await q(
    "UPDATE tickets SET status=$1 WHERE id=$2",
    [status, Number(req.params.id)]
  );

  res.redirect("/admin/tickets");
}));

/* HEALTH CHECK */

app.get("/health", wrap(async (req, res) => {
  await q("SELECT 1");
  res.json({
    status: "ok",
    database: "connected",
    providerConfigured: Boolean(PROVIDER_KEY),
    time: new Date().toISOString()
  });
}));

/* 404 */

app.use((req, res) => {
  res.status(404).send(page("Not Found", `
    <div class="card">
      <h2>404 - Page Not Found</h2>
      <a class="btn" href="/">Home</a>
    </div>
  `));
});

/* ERROR HANDLER */

app.use((error, req, res, next) => {
  console.error("Server error:", error);

  if (res.headersSent) return next(error);

  res.status(500).send(page("Server Error", `
    <div class="card">
      <h2>Something went wrong</h2>
      <p>Please try again later or contact support.</p>
      <a class="btn" href="/">Home</a>
    </div>
  `));
});

/* START SERVER */

async function startServer() {
  try {
    await pool.query("SELECT 1");
    await setupDatabase();

    app.listen(PORT, () => {
      console.log(`ROYAL PANEL running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup failed:", error);
    process.exit(1);
  }
}

startServer();
