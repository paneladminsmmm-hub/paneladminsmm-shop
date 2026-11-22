require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/public", express.static("public"));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

const db = (sql, values = []) => pool.query(sql, values);

const PORT = process.env.PORT || 3000;
const APP_URL = (process.env.APP_URL || "").replace(/\/+$/, "");
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";

const PROVIDER_URL =
  process.env.SOCIALADD_API_URL || "https://socialadd.in/api/v2";
const PROVIDER_KEY = process.env.SOCIALADD_API_KEY || "";

const TELEGRAM_USERNAME = "Digital_marketing_aagency_India";
const TELEGRAM_LINK = `https://t.me/${TELEGRAM_USERNAME}`;

app.use(
  session({
    name: "royalpanel.sid",
    secret: process.env.SESSION_SECRET || "CHANGE_THIS_SESSION_SECRET",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false
});

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function money(value) {
  return "₹" + Number(value || 0).toFixed(2);
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  if (!req.session.user.is_admin) return res.status(403).send("Admin access required");
  next();
}

function setSession(req, res, user, redirectTo) {
  req.session.regenerate(err => {
    if (err) return res.status(500).send("Session error");

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin: user.is_admin
    };

    req.session.save(err2 => {
      if (err2) return res.status(500).send("Session save error");
      res.redirect(redirectTo || (user.is_admin ? "/admin" : "/dashboard"));
    });
  });
}

function layout(title, content, user = null) {
  const nav = user
    ? `
      <nav>
        <a href="/dashboard">Dashboard</a>
        <a href="/services">Services</a>
        <a href="/new-order">New Order</a>
        <a href="/orders">My Orders</a>
        <a href="/add-funds">Add Funds</a>
        <a href="/support">Support</a>
        <a href="/api-keys">My API</a>
        ${user.is_admin ? '<a href="/admin">Admin Panel</a>' : ""}
        <a href="/logout">Logout</a>
      </nav>`
    : `
      <nav>
        <a href="/login">Login</a>
        <a href="/register">Register</a>
      </nav>`;

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} - ROYAL PANEL</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#10131c;color:#f5f5f5;font-family:Arial,sans-serif}
header{background:#191e2b;padding:18px;text-align:center;border-bottom:2px solid #e63946}
header h2{margin:0;color:#ff454f}
nav{display:flex;gap:8px;flex-wrap:wrap;padding:12px;background:#191e2b;justify-content:center}
nav a{padding:9px 11px;background:#252c3c;border-radius:7px;color:white;text-decoration:none;font-size:13px}
main{max-width:1100px;margin:22px auto;padding:0 14px}
.card{background:#1b2130;border:1px solid #30394c;border-radius:12px;padding:17px;margin-bottom:15px}
input,select,textarea{width:100%;padding:12px;margin:7px 0 13px;border:1px solid #414b60;border-radius:7px;background:#101723;color:white}
button,.btn{display:inline-block;border:0;background:#e63946;color:white;padding:12px 16px;border-radius:7px;cursor:pointer;text-decoration:none}
.google{display:block;text-align:center;background:white;color:#222;padding:13px;border-radius:7px;text-decoration:none;font-weight:bold;margin-top:12px}
table{width:100%;border-collapse:collapse;min-width:700px}
th,td{padding:10px;border-bottom:1px solid #384154;text-align:left;font-size:13px}
.wrap{overflow-x:auto}
small{color:#aeb8c9}
a{color:#ff5964}
.success{color:#35d07f}
.danger{color:#ff5964}
.telegram{position:fixed;right:18px;bottom:18px;background:#229ED9;color:white;padding:15px 18px;border-radius:50px;text-decoration:none;font-weight:bold;box-shadow:0 3px 12px #0008}
</style>
</head>
<body>
<header><h2>ROYAL PANEL</h2><small>Panel Admin SMM.shop</small></header>
${nav}
<main><h2>${esc(title)}</h2>${content}</main>
<a class="telegram" href="${TELEGRAM_LINK}" target="_blank" rel="noopener">Telegram Support</a>
</body>
</html>`;
}

function googleButton() {
  return `<a class="google" href="/auth/google">🌐 Continue with Google</a>`;
}

async function providerRequest(params) {
  if (!PROVIDER_KEY) throw new Error("SOCIALADD_API_KEY is not configured");

  const body = new URLSearchParams({
    key: PROVIDER_KEY,
    ...Object.fromEntries(
      Object.entries(params).map(([key, value]) => [key, String(value)])
    )
  });

  const response = await fetch(PROVIDER_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(30000)
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) throw new Error("Provider HTTP error: " + response.status);
  if (!data || data.error) throw new Error(data?.error || "Provider error");

  return data;
}

function providerStatus(status) {
  const s = String(status || "").toLowerCase();

  if (s === "completed") return "Completed";
  if (s === "partial") return "Partial";
  if (s === "canceled" || s === "cancelled") return "Canceled";
  if (s === "failed" || s === "error") return "Failed";
  if (s === "pending") return "Pending";
  if (s === "in progress" || s === "processing") return "Processing";

  return status || "Processing";
}

function makeUsername(email) {
  const base = email.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "").slice(0, 18) || "googleuser";
  return base + "_" + crypto.randomBytes(3).toString("hex");
}

async function setupDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      email TEXT,
      google_id TEXT,
      balance NUMERIC(12,2) DEFAULT 0,
      is_admin BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS password_hash TEXT,
    ADD COLUMN IF NOT EXISTS google_id TEXT,
    ADD COLUMN IF NOT EXISTS balance NUMERIC(12,2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE
  `);

  await db(`CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
    ON users(LOWER(email)) WHERE email IS NOT NULL`);

  await db(`CREATE UNIQUE INDEX IF NOT EXISTS users_google_id_unique
    ON users(google_id) WHERE google_id IS NOT NULL`);

  await db(`
    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      provider_id TEXT,
      provider_source TEXT DEFAULT 'manual',
      provider_type TEXT DEFAULT 'Default',
      name TEXT NOT NULL,
      category TEXT DEFAULT 'Other',
      description TEXT DEFAULT '',
      rate NUMERIC(14,4) DEFAULT 0,
      provider_rate NUMERIC(14,6) DEFAULT 0,
      min INTEGER DEFAULT 100,
      max INTEGER DEFAULT 1000000,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`ALTER TABLE services
    ADD COLUMN IF NOT EXISTS provider_id TEXT,
    ADD COLUMN IF NOT EXISTS provider_source TEXT DEFAULT 'manual',
    ADD COLUMN IF NOT EXISTS provider_type TEXT DEFAULT 'Default',
    ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'Other',
    ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '',
    ADD COLUMN IF NOT EXISTS rate NUMERIC(14,4) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS provider_rate NUMERIC(14,6) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS min INTEGER DEFAULT 100,
    ADD COLUMN IF NOT EXISTS max INTEGER DEFAULT 1000000,
    ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE
  `);

  await db(`CREATE UNIQUE INDEX IF NOT EXISTS services_provider_unique
    ON services(provider_source,provider_id)
    WHERE provider_id IS NOT NULL`);

  await db(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      service_id INTEGER,
      service_name TEXT,
      provider_order_id TEXT,
      link TEXT,
      quantity INTEGER,
      charge NUMERIC(12,2),
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS service_name TEXT,
    ADD COLUMN IF NOT EXISTS provider_order_id TEXT,
    ADD COLUMN IF NOT EXISTS link TEXT,
    ADD COLUMN IF NOT EXISTS quantity INTEGER,
    ADD COLUMN IF NOT EXISTS charge NUMERIC(12,2),
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Pending',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(12,2),
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
    CREATE TABLE IF NOT EXISTS api_keys (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      key_hash TEXT UNIQUE NOT NULL,
      key_prefix TEXT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const username = String(process.env.ADMIN_USERNAME || "").trim();
  const password = String(process.env.ADMIN_PASSWORD || "");

  if (email && username && password) {
    const hash = await bcrypt.hash(password, 12);
    const existing = await db(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1) OR username=$2 LIMIT 1",
      [email, username]
    );

    if (existing.rowCount) {
      await db(
        "UPDATE users SET email=$1,username=$2,password_hash=$3,is_admin=TRUE WHERE id=$4",
        [email, username, hash, existing.rows[0].id]
      );
    } else {
      await db(
        "INSERT INTO users(email,username,password_hash,is_admin) VALUES($1,$2,$3,TRUE)",
        [email, username, hash]
      );
    }
  }
}

// HOME
app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/dashboard" : "/login");
});

app.get("/health", (req, res) => {
  res.send("ROYAL PANEL OK");
});

// GOOGLE LOGIN
app.get("/auth/google", authLimit, (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !APP_URL) {
    return res.status(503).send("Google Login अभी configure नहीं है।");
  }

  const state = crypto.randomBytes(24).toString("hex");
  req.session.googleState = state;

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: APP_URL + "/auth/google/callback",
    response_type: "code",
    scope: "openid email profile",
    state,
    prompt: "select_account"
  });

  res.redirect("https://accounts.google.com/o/oauth2/v2/auth?" + params.toString());
});

app.get("/auth/google/callback", authLimit, async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) return res.redirect("/login?error=google");
    if (!code || !state || state !== req.session.googleState) {
      return res.status(400).send("Google login state invalid.");
    }

    delete req.session.googleState;

    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: String(code),
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: APP_URL + "/auth/google/callback",
        grant_type: "authorization_code"
      })
    });

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      throw new Error("Google token verification failed");
    }

    const profileResponse = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: "Bearer " + tokenData.access_token }
    });

    const profile = await profileResponse.json();

    if (!profile.email || !profile.verified_email) {
      throw new Error("Google email is not verified");
    }

    const email = profile.email.toLowerCase();
    let result = await db(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1) OR google_id=$2 LIMIT 1",
      [email, profile.id]
    );

    let user;

    if (result.rowCount) {
      user = result.rows[0];

      if (user.google_id && user.google_id !== String(profile.id)) {
        throw new Error("This email is linked to another Google account.");
      }

      await db(
        "UPDATE users SET google_id=$1,email=$2 WHERE id=$3",
        [String(profile.id), email, user.id]
      );

      user.google_id = String(profile.id);
    } else {
      const username = makeUsername(email);
      const randomPassword = await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 12);

      result = await db(
        `INSERT INTO users(username,email,google_id,password_hash,balance,is_admin)
         VALUES($1,$2,$3,$4,0,FALSE) RETURNING *`,
        [username, email, String(profile.id), randomPassword]
      );

      user = result.rows[0];
    }

    setSession(req, res, user);
  } catch (error) {
    console.error("Google login error:", error.message);
    res.redirect("/login?error=google");
  }
});

// REGISTER
app.get("/register", (req, res) => {
  const content = `
    <div class="card">
      <form method="POST" action="/register">
        <label>Username</label>
        <input name="username" required minlength="3">
        <label>Email</label>
        <input name="email" type="email" required>
        <label>Password</label>
        <input name="password" type="password" required minlength="6">
        <button type="submit">Create Account</button>
      </form>
      ${googleButton()}
      <p>Already have an account? <a href="/login">Login</a></p>
    </div>`;
  res.send(layout("Register", content));
});

app.post("/register", authLimit, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (username.length < 3 || password.length < 6 || !email.includes("@")) {
      return res.status(400).send(layout("Register", "Please enter valid details."));
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await db(
      `INSERT INTO users(username,email,password_hash)
       VALUES($1,$2,$3) RETURNING *`,
      [username, email, hash]
    );

    setSession(req, res, result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(400).send(layout("Register", "Username या Email पहले से इस्तेमाल हो सकता है।"));
  }
});

// LOGIN
app.get("/login", (req, res) => {
  const error = req.query.error ? "<p class='danger'>Google Login नहीं हो पाया। दोबारा कोशिश करें।</p>" : "";

  const content = `
    <div class="card">
      ${error}
      <form method="POST" action="/login">
        <label>Username या Email</label>
        <input name="identity" required>
        <label>Password</label>
        <input name="password" type="password" required>
        <button type="submit">Login</button>
      </form>
      ${googleButton()}
      <p>New user? <a href="/register">Create Account</a></p>
    </div>`;

  res.send(layout("Login", content));
});

app.post("/login", authLimit, async (req, res) => {
  try {
    const identity = String(req.body.identity || "").trim();
    const result = await db(
      "SELECT * FROM users WHERE LOWER(username)=LOWER($1) OR LOWER(email)=LOWER($1) LIMIT 1",
      [identity]
    );

    if (!result.rowCount || !result.rows[0].password_hash) {
      return res.status(401).send(layout("Login", "Invalid username/email or password."));
    }

    const valid = await bcrypt.compare(String(req.body.password || ""), result.rows[0].password_hash);

    if (!valid) return res.status(401).send(layout("Login", "Invalid username/email or password."));

    setSession(req, res, result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).send("Login error");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// DASHBOARD
app.get("/dashboard", requireLogin, async (req, res) => {
  const user = req.session.user;

  const balance = await db("SELECT balance FROM users WHERE id=$1", [user.id]);
  const orders = await db("SELECT COUNT(*) FROM orders WHERE user_id=$1", [user.id]);

  const content = `
    <div class="card">
      <h3>Welcome, ${esc(user.username)}</h3>
      <h2>Balance: ${money(balance.rows[0]?.balance)}</h2>
      <p>Total Orders: ${orders.rows[0].count}</p>
      <a class="btn" href="/new-order">Place New Order</a>
      <a class="btn" href="/add-funds">Add Funds</a>
    </div>`;

  res.send(layout("Dashboard", content, user));
});

// SERVICES
app.get("/services", requireLogin, async (req, res) => {
  const result = await db("SELECT * FROM services WHERE active=TRUE ORDER BY category,name");

  const rows = result.rows.map(s => `
    <tr>
      <td>${s.id}</td>
      <td>${esc(s.category)}</td>
      <td>${esc(s.name)}</td>
      <td>${money(s.rate)} / 1K</td>
      <td>${s.min}</td>
      <td>${s.max}</td>
    </tr>`).join("");

  res.send(layout("Services", `
    <div class="card wrap">
      <table>
        <tr><th>ID</th><th>Category</th><th>Service</th><th>Rate</th><th>Min</th><th>Max</th></tr>
        ${rows || "<tr><td colspan='6'>No services available</td></tr>"}
      </table>
    </div>`, req.session.user));
});

// NEW ORDER
app.get("/new-order", requireLogin, async (req, res) => {
  const result = await db("SELECT * FROM services WHERE active=TRUE ORDER BY category,name");

  const options = result.rows.map(s =>
    `<option value="${s.id}">${s.id} - ${esc(s.name)} (${money(s.rate)}/1K)</option>`
  ).join("");

  const content = `
    <div class="card">
      <form method="POST" action="/new-order">
        <label>Select Service</label>
        <select name="service_id" required>${options}</select>
        <label>Link</label>
        <input name="link" type="url" required placeholder="https://">
        <label>Quantity</label>
        <input name="quantity" type="number" min="1" required>
        <button type="submit">Submit Order</button>
      </form>
    </div>`;

  res.send(layout("New Order", content, req.session.user));
});

app.post("/new-order", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    const serviceId = Number(req.body.service_id);
    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(serviceId) || !Number.isInteger(quantity) || quantity < 1 || !link.startsWith("http")) {
      return res.status(400).send("Invalid order details.");
    }

    await client.query("BEGIN");

    const serviceResult = await client.query(
      "SELECT * FROM services WHERE id=$1 AND active=TRUE",
      [serviceId]
    );

    if (!serviceResult.rowCount) throw new Error("Service not available.");

    const service = serviceResult.rows[0];

    if (quantity < Number(service.min) || quantity > Number(service.max)) {
      throw new Error(`Quantity ${service.min} से ${service.max} के बीच होनी चाहिए।`);
    }

    const charge = Number(service.rate) * quantity / 1000;

    const userResult = await client.query(
      "SELECT * FROM users WHERE id=$1 FOR UPDATE",
      [req.session.user.id]
    );

    if (!userResult.rowCount || Number(userResult.rows[0].balance) < charge) {
      throw new Error("Insufficient balance. Please Add Funds.");
    }

    let providerOrderId = null;

    if (service.provider_source === "socialadd") {
      const providerResult = await providerRequest({
        action: "add",
        service: service.provider_id,
        link,
        quantity
      });

      if (!providerResult.order) throw new Error("Provider order ID missing.");
      providerOrderId = String(providerResult.order);
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [charge, req.session.user.id]
    );

    await client.query(
      `INSERT INTO orders(user_id,service_id,service_name,provider_order_id,link,quantity,charge,status)
       VALUES($1,$2,$3,$4,$5,$6,$7,'Pending')`,
      [req.session.user.id, service.id, service.name, providerOrderId, link, quantity, charge]
    );

    await client.query("COMMIT");
    res.redirect("/orders");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(400).send(layout("Order Error", `<div class="card danger">${esc(error.message)}</div>`, req.session.user));
  } finally {
    client.release();
  }
});

// MY ORDERS
app.get("/orders", requireLogin, async (req, res) => {
  const result = await db(
    "SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC LIMIT 200",
    [req.session.user.id]
  );

  const rows = result.rows.map(o => `
    <tr>
      <td>${o.id}</td>
      <td>${esc(o.service_name)}</td>
      <td>${o.quantity}</td>
      <td>${money(o.charge)}</td>
      <td>${esc(o.status)}</td>
      <td>${new Date(o.created_at).toLocaleString("en-IN")}</td>
    </tr>`).join("");

  res.send(layout("My Orders", `
    <div class="card wrap"><table>
      <tr><th>Order ID</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th><th>Date</th></tr>
      ${rows || "<tr><td colspan='6'>No orders yet</td></tr>"}
    </table></div>`, req.session.user));
});

// ADD FUNDS
app.get("/add-funds", requireLogin, async (req, res) => {
  const content = `
    <div class="card">
      <h3>Add Funds</h3>
      <p>Minimum: ₹100 | Maximum: ₹2000</p>
      <form method="POST" action="/add-funds">
        <label>Amount</label>
        <input type="number" name="amount" min="100" max="2000" required>
        <label>UTR / Transaction ID</label>
        <input name="utr" required>
        <button type="submit">Submit Payment Request</button>
      </form>
      <p><small>Payment request admin approval के बाद balance में जोड़ी जाएगी।</small></p>
    </div>`;

  res.send(layout("Add Funds", content, req.session.user));
});

app.post("/add-funds", requireLogin, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const utr = String(req.body.utr || "").trim();

    if (!Number.isFinite(amount) || amount < 100 || amount > 2000 || !utr) {
      return res.status(400).send("Amount ₹100 से ₹2000 के बीच होना चाहिए।");
    }

    await db(
      "INSERT INTO payments(user_id,amount,utr,status) VALUES($1,$2,$3,'Pending')",
      [req.session.user.id, amount, utr]
    );

    res.redirect("/dashboard");
  } catch (error) {
    console.error(error);
    res.status(500).send("Payment request failed.");
  }
});

// SUPPORT
app.get("/support", requireLogin, (req, res) => {
  const content = `
    <div class="card">
      <h3>Telegram Support</h3>
      <p>किसी भी समस्या के लिए Telegram पर संपर्क करें।</p>
      <a class="btn" href="${TELEGRAM_LINK}" target="_blank" rel="noopener">Message on Telegram</a>
      <hr>
      <form method="POST" action="/support">
        <label>Your Message</label>
        <textarea name="message" required rows="5"></textarea>
        <button type="submit">Submit Ticket</button>
      </form>
    </div>`;

  res.send(layout("Support", content, req.session.user));
});

app.post("/support", requireLogin, async (req, res) => {
  const message = String(req.body.message || "").trim();

  if (!message) return res.status(400).send("Message required.");

  await db(
    "INSERT INTO tickets(user_id,message) VALUES($1,$2)",
    [req.session.user.id, message]
  );

  res.redirect("/support");
});

// USER API KEYS
app.get("/api-keys", requireLogin, async (req, res) => {
  const result = await db(
    "SELECT id,key_prefix,active,created_at FROM api_keys WHERE user_id=$1 ORDER BY id DESC",
    [req.session.user.id]
  );

  const rows = result.rows.map(k => `
    <tr>
      <td>${k.id}</td>
      <td>${esc(k.key_prefix)}...</td>
      <td>${k.active ? "Active" : "Disabled"}</td>
      <td>
        <form method="POST" action="/api-keys/${k.id}/toggle">
          <button type="submit">Toggle</button>
        </form>
        <form method="POST" action="/api-keys/${k.id}/delete">
          <button class="danger" type="submit">Delete</button>
        </form>
      </td>
    </tr>`).join("");

  res.send(layout("My API", `
    <div class="card">
      <form method="POST" action="/api-keys/create">
        <button type="submit">Generate New API Key</button>
      </form>
      <p>New API key केवल एक बार दिखाई जाएगी। इसे सुरक्षित रखें।</p>
    </div>
    <div class="card wrap"><table>
      <tr><th>ID</th><th>Key</th><th>Status</th><th>Action</th></tr>
      ${rows || "<tr><td colspan='4'>No API keys</td></tr>"}
    </table></div>`, req.session.user));
});

app.post("/api-keys/create", requireLogin, async (req, res) => {
  const key = "royal_" + crypto.randomBytes(32).toString("hex");
  const hash = crypto.createHash("sha256").update(key).digest("hex");
  const prefix = key.slice(0, 14);

  await db(
    "INSERT INTO api_keys(user_id,key_hash,key_prefix) VALUES($1,$2,$3)",
    [req.session.user.id, hash, prefix]
  );

  res.send(layout("Your New API Key", `
    <div class="card">
      <p>Copy and save this key now. It will not be shown again.</p>
      <textarea rows="3" readonly>${esc(key)}</textarea>
      <a class="btn" href="/api-keys">Back to API Keys</a>
    </div>`, req.session.user));
});

app.post("/api-keys/:id/toggle", requireLogin, async (req, res) => {
  await db(
    "UPDATE api_keys SET active=NOT active WHERE id=$1 AND user_id=$2",
    [req.params.id, req.session.user.id]
  );
  res.redirect("/api-keys");
});

app.post("/api-keys/:id/delete", requireLogin, async (req, res) => {
  await db(
    "DELETE FROM api_keys WHERE id=$1 AND user_id=$2",
    [req.params.id, req.session.user.id]
  );
  res.redirect("/api-keys");
});

// RESELLER API
async function apiUser(req, res, next) {
  try {
    const key = String(req.body.key || req.query.key || "");
    if (!key) return res.status(401).json({ error: "API key required" });

    const hash = crypto.createHash("sha256").update(key).digest("hex");

    const result = await db(
      `SELECT u.* FROM api_keys k
       JOIN users u ON u.id=k.user_id
       WHERE k.key_hash=$1 AND k.active=TRUE`,
      [hash]
    );

    if (!result.rowCount) return res.status(401).json({ error: "Invalid API key" });

    req.apiUser = result.rows[0];
    next();
  } catch (error) {
    res.status(500).json({ error: "API error" });
  }
}

app.post("/api/v2", apiLimit, apiUser, async (req, res) => {
  try {
    const action = String(req.body.action || "");

    if (action === "balance") {
      return res.json({
        balance: Number(req.apiUser.balance),
        currency: "INR"
      });
    }

    if (action === "services") {
      const result = await db(
        "SELECT id AS service,name,rate,min,max,category FROM services WHERE active=TRUE ORDER BY id"
      );
      return res.json(result.rows);
    }

    if (action === "add") {
      const serviceId = Number(req.body.service);
      const quantity = Number(req.body.quantity);
      const link = String(req.body.link || "");

      if (!Number.isInteger(serviceId) || !Number.isInteger(quantity) || quantity < 1 || !link.startsWith("http")) {
        return res.status(400).json({ error: "Invalid order details" });
      }

      const serviceResult = await db(
        "SELECT * FROM services WHERE id=$1 AND active=TRUE",
        [serviceId]
      );

      if (!serviceResult.rowCount) return res.status(400).json({ error: "Invalid service" });

      const service = serviceResult.rows[0];

      if (quantity < service.min || quantity > service.max) {
        return res.status(400).json({ error: "Quantity out of range" });
      }

      const charge = Number(service.rate) * quantity / 1000;
      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const userResult = await client.query(
          "SELECT * FROM users WHERE id=$1 FOR UPDATE",
          [req.apiUser.id]
        );

        if (Number(userResult.rows[0].balance) < charge) {
          throw new Error("Insufficient balance");
        }

        let providerOrderId = null;

        if (service.provider_source === "socialadd") {
          const providerResult = await providerRequest({
            action: "add",
            service: service.provider_id,
            link,
            quantity
          });
          providerOrderId = String(providerResult.order);
        }

        await client.query(
          "UPDATE users SET balance=balance-$1 WHERE id=$2",
          [charge, req.apiUser.id]
        );

        const orderResult = await client.query(
          `INSERT INTO orders(user_id,service_id,service_name,provider_order_id,link,quantity,charge,status)
           VALUES($1,$2,$3,$4,$5,$6,$7,'Pending') RETURNING id`,
          [req.apiUser.id, service.id, service.name, providerOrderId, link, quantity, charge]
        );

        await client.query("COMMIT");

        return res.json({ order: orderResult.rows[0].id });
      } catch (error) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: error.message });
      } finally {
        client.release();
      }
    }

    if (action === "status") {
      const orderId = Number(req.body.order);
      const result = await db(
        "SELECT * FROM orders WHERE id=$1 AND user_id=$2",
        [orderId, req.apiUser.id]
      );

      if (!result.rowCount) return res.status(404).json({ error: "Order not found" });

      return res.json({
        charge: Number(result.rows[0].charge),
        status: result.rows[0].status,
        start_count: "0",
        remains: "0"
      });
    }

    return res.status(400).json({ error: "Invalid action" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// ADMIN DASHBOARD
app.get("/admin", requireAdmin, async (req, res) => {
  const users = await db("SELECT COUNT(*) FROM users");
  const orders = await db("SELECT COUNT(*) FROM orders");
  const payments = await db("SELECT COUNT(*) FROM payments WHERE status='Pending'");
  const services = await db("SELECT COUNT(*) FROM services");

  const content = `
    <div class="card">
      <h3>Admin Dashboard</h3>
      <p>Total Users: ${users.rows[0].count}</p>
      <p>Total Orders: ${orders.rows[0].count}</p>
      <p>Pending Payments: ${payments.rows[0].count}</p>
      <p>Total Services: ${services.rows[0].count}</p>
      <p><a href="/admin/services">Manage Services</a></p>
      <p><a href="/admin/payments">Manage Payments</a></p>
      <p><a href="/admin/orders">Manage Orders</a></p>
      <p><a href="/admin/provider">Provider Import</a></p>
      <p><a href="/admin/tickets">Support Tickets</a></p>
    </div>`;

  res.send(layout("Admin Panel", content, req.session.user));
});

// ADMIN SERVICES
app.get("/admin/services", requireAdmin, async (req, res) => {
  const result = await db("SELECT * FROM services ORDER BY id DESC LIMIT 300");

  const rows = result.rows.map(s => `
    <tr>
      <td>${s.id}</td>
      <td>${esc(s.name)}</td>
      <td>${money(s.rate)}</td>
      <td>${esc(s.provider_source)}</td>
      <td>${s.active ? "Active" : "Disabled"}</td>
      <td>
        <a href="/admin/services/${s.id}/edit">Edit</a>
        <form method="POST" action="/admin/services/${s.id}/toggle">
          <button type="submit">Toggle</button>
        </form>
      </td>
    </tr>`).join("");

  const content = `
    <div class="card">
      <h3>Add Manual Service</h3>
      <form method="POST" action="/admin/services">
        <input name="name" placeholder="Service Name" required>
        <input name="category" placeholder="Category">
        <input name="rate" type="number" step="0.0001" placeholder="Selling Rate per 1K" required>
        <input name="min" type="number" value="100" required>
        <input name="max" type="number" value="1000000" required>
        <button type="submit">Add Service</button>
      </form>
    </div>
    <div class="card wrap"><table>
      <tr><th>ID</th><th>Name</th><th>Rate</th><th>Provider</th><th>Status</th><th>Action</th></tr>
      ${rows}
    </table></div>`;

  res.send(layout("Manage Services", content, req.session.user));
});

app.post("/admin/services", requireAdmin, async (req, res) => {
  const name = String(req.body.name || "").trim();
  const category = String(req.body.category || "Other");
  const rate = Number(req.body.rate);
  const min = Number(req.body.min);
  const max = Number(req.body.max);

  if (!name || !Number.isFinite(rate) || rate < 0 || !Number.isInteger(min) || !Number.isInteger(max) || min < 1 || max < min) {
    return res.status(400).send("Invalid service details");
  }

  await db(
    `INSERT INTO services(name,category,rate,min,max,provider_source,active)
     VALUES($1,$2,$3,$4,$5,'manual',TRUE)`,
    [name, category, rate, min, max]
  );

  res.redirect("/admin/services");
});

app.get("/admin/services/:id/edit", requireAdmin, async (req, res) => {
  const result = await db("SELECT * FROM services WHERE id=$1", [req.params.id]);
  if (!result.rowCount) return res.status(404).send("Service not found");

  const s = result.rows[0];

  res.send(layout("Edit Service", `
    <div class="card">
      <form method="POST">
        <label>Service Name</label>
        <input name="name" value="${esc(s.name)}" required>
        <label>Category</label>
        <input name="category" value="${esc(s.category)}">
        <label>Selling Rate per 1K</label>
        <input name="rate" type="number" step="0.0001" value="${s.rate}" required>
        <label>Minimum</label>
        <input name="min" type="number" value="${s.min}" required>
        <label>Maximum</label>
        <input name="max" type="number" value="${s.max}" required>
        <button type="submit">Update Service</button>
      </form>
    </div>`, req.session.user));
});

app.post("/admin/services/:id/edit", requireAdmin, async (req, res) => {
  const name = String(req.body.name || "").trim();
  const category = String(req.body.category || "Other");
  const rate = Number(req.body.rate);
  const min = Number(req.body.min);
  const max = Number(req.body.max);

  if (!name || !Number.isFinite(rate) || rate < 0 || !Number.isInteger(min) || !Number.isInteger(max) || min < 1 || max < min) {
    return res.status(400).send("Invalid service details");
  }

  await db(
    "UPDATE services SET name=$1,category=$2,rate=$3,min=$4,max=$5 WHERE id=$6",
    [name, category, rate, min, max, req.params.id]
  );

  res.redirect("/admin/services");
});

app.post("/admin/services/:id/toggle", requireAdmin, async (req, res) => {
  await db("UPDATE services SET active=NOT active WHERE id=$1", [req.params.id]);
  res.redirect("/admin/services");
});

// PROVIDER IMPORT
app.get("/admin/provider", requireAdmin, (req, res) => {
  res.send(layout("Provider Import", `
    <div class="card">
      <p>SocialAdd Provider से Instagram services import करें।</p>
      <form method="POST" action="/admin/provider/import">
        <button type="submit">Import Instagram Services</button>
      </form>
      <form method="POST" action="/admin/provider/test">
        <button type="submit">Test Provider Connection</button>
      </form>
    </div>`, req.session.user));
});

app.post("/admin/provider/test", requireAdmin, async (req, res) => {
  try {
    const data = await providerRequest({ action: "balance" });
    res.send(layout("Provider Test", `<div class="card success">Provider Connected: ${esc(JSON.stringify(data))}</div>`, req.session.user));
  } catch (error) {
    res.status(400).send(layout("Provider Test", `<div class="card danger">${esc(error.message)}</div>`, req.session.user));
  }
});

app.post("/admin/provider/import", requireAdmin, async (req, res) => {
  try {
    const services = await providerRequest({ action: "services" });

    if (!Array.isArray(services)) throw new Error("Provider services response is invalid");

    let imported = 0;

    for (const s of services) {
      const name = String(s.name || "");
      if (!name.toLowerCase().includes("instagram")) continue;

      const providerId = String(s.service || s.id || "");
      if (!providerId) continue;

      const providerRate = Number(s.rate || 0);
      if (!Number.isFinite(providerRate)) continue;

      const sellingRate = Number((providerRate * 1.5).toFixed(4));

      await db(
        `INSERT INTO services
         (provider_id,provider_source,provider_type,name,category,description,rate,provider_rate,min,max,active)
         VALUES($1,'socialadd',$2,$3,'Instagram',$4,$5,$6,$7,$8,TRUE)
         ON CONFLICT(provider_source,provider_id)
         WHERE provider_id IS NOT NULL
         DO UPDATE SET
           provider_type=EXCLUDED.provider_type,
           name=EXCLUDED.name,
           category=EXCLUDED.category,
           description=EXCLUDED.description,
           provider_rate=EXCLUDED.provider_rate,
           min=EXCLUDED.min,
           max=EXCLUDED.max`,
        [
          providerId,
          String(s.type || "Default"),
          name,
          String(s.description || ""),
          sellingRate,
          providerRate,
          Number(s.min || 100),
          Number(s.max || 1000000)
        ]
      );

      imported++;
    }

    res.send(layout("Provider Import", `<div class="card success">Imported / Updated ${imported} Instagram services.</div>`, req.session.user));
  } catch (error) {
    console.error(error);
    res.status(400).send(layout("Provider Import", `<div class="card danger">${esc(error.message)}</div>`, req.session.user));
  }
});

// ADMIN PAYMENTS
app.get("/admin/payments", requireAdmin, async (req, res) => {
  const result = await db(
    `SELECT p.*,u.username,u.email
     FROM payments p JOIN users u ON u.id=p.user_id
     ORDER BY p.id DESC LIMIT 300`
  );

  const rows = result.rows.map(p => `
    <tr>
      <td>${p.id}</td>
      <td>${esc(p.username)}</td>
      <td>${money(p.amount)}</td>
      <td>${esc(p.utr)}</td>
      <td>${esc(p.status)}</td>
      <td>
        ${p.status === "Pending" ? `
          <form method="POST" action="/admin/payments/${p.id}/approve">
            <button type="submit">Approve</button>
          </form>` : ""}
      </td>
    </tr>`).join("");

  res.send(layout("Payments", `
    <div class="card wrap"><table>
      <tr><th>ID</th><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>
      ${rows}
    </table></div>`, req.session.user));
});

app.post("/admin/payments/:id/approve", requireAdmin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const payment = await client.query(
      "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    if (!payment.rowCount) throw new Error("Payment not found");

    const p = payment.rows[0];

    if (p.status !== "Pending") throw new Error("Payment already processed");

    await client.query(
      "UPDATE users SET balance=balance+$1 WHERE id=$2",
      [p.amount, p.user_id]
    );

    await client.query(
      "UPDATE payments SET status='Approved' WHERE id=$1",
      [p.id]
    );

    await client.query("COMMIT");
    res.redirect("/admin/payments");
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).send(esc(error.message));
  } finally {
    client.release();
  }
});

// ADMIN ORDERS
app.get("/admin/orders", requireAdmin, async (req, res) => {
  const result = await db(
    `SELECT o.*,u.username
     FROM orders o JOIN users u ON u.id=o.user_id
     ORDER BY o.id DESC LIMIT 300`
  );

  const rows = result.rows.map(o => `
    <tr>
      <td>${o.id}</td>
      <td>${esc(o.username)}</td>
      <td>${esc(o.service_name)}</td>
      <td>${o.quantity}</td>
      <td>${money(o.charge)}</td>
      <td>${esc(o.status)}</td>
      <td>
        <form method="POST" action="/admin/orders/${o.id}/status">
          <select name="status">
            ${["Pending","Processing","Completed","Partial","Canceled","Failed"].map(s =>
              `<option ${s === o.status ? "selected" : ""}>${s}</option>`
            ).join("")}
          </select>
          <button type="submit">Update</button>
        </form>
        ${o.provider_order_id ? `
          <form method="POST" action="/admin/orders/${o.id}/sync">
            <button type="submit">Sync Provider</button>
          </form>` : ""}
      </td>
    </tr>`).join("");

  res.send(layout("All Orders", `
    <div class="card wrap"><table>
      <tr><th>ID</th><th>User</th><th>Service</th><th>Qty</th><th>Charge</th><th>Status</th><th>Action</th></tr>
      ${rows}
    </table></div>`, req.session.user));
});

app.post("/admin/orders/:id/status", requireAdmin, async (req, res) => {
  const allowed = ["Pending","Processing","Completed","Partial","Canceled","Failed"];
  const status = String(req.body.status || "");

  if (!allowed.includes(status)) return res.status(400).send("Invalid status");

  await db("UPDATE orders SET status=$1 WHERE id=$2", [status, req.params.id]);
  res.redirect("/admin/orders");
});

app.post("/admin/orders/:id/sync", requireAdmin, async (req, res) => {
  try {
    const result = await db("SELECT * FROM orders WHERE id=$1", [req.params.id]);
    if (!result.rowCount) throw new Error("Order not found");

    const order = result.rows[0];
    if (!order.provider_order_id) throw new Error("Provider order ID missing");

    const data = await providerRequest({
      action: "status",
      order: order.provider_order_id
    });

    await db(
      "UPDATE orders SET status=$1 WHERE id=$2",
      [providerStatus(data.status), order.id]
    );

    res.redirect("/admin/orders");
  } catch (error) {
    res.status(400).send(esc(error.message));
  }
});

// ADMIN SUPPORT TICKETS
app.get("/admin/tickets", requireAdmin, async (req, res) => {
  const result = await db(
    `SELECT t.*,u.username
     FROM tickets t JOIN users u ON u.id=t.user_id
     ORDER BY t.id DESC LIMIT 300`
  );

  const rows = result.rows.map(t => `
    <tr>
      <td>${t.id}</td>
      <td>${esc(t.username)}</td>
      <td>${esc(t.message)}</td>
      <td>${esc(t.status)}</td>
      <td>
        <form method="POST" action="/admin/tickets/${t.id}/close">
          <button type="submit">Close Ticket</button>
        </form>
      </td>
    </tr>`).join("");

  res.send(layout("Support Tickets", `
    <div class="card wrap"><table>
      <tr><th>ID</th><th>User</th><th>Message</th><th>Status</th><th>Action</th></tr>
      ${rows}
    </table></div>`, req.session.user));
});

app.post("/admin/tickets/:id/close", requireAdmin, async (req, res) => {
  await db("UPDATE tickets SET status='Closed' WHERE id=$1", [req.params.id]);
  res.redirect("/admin/tickets");
});

// 404
app.use((req, res) => {
  res.status(404).send(layout("Page Not Found", `
    <div class="card">
      <p>यह पेज उपलब्ध नहीं है।</p>
      <a class="btn" href="/">Home</a>
    </div>`, req.session.user));
});

// ERROR HANDLER
app.use((error, req, res, next) => {
  console.error("Server error:", error);
  if (res.headersSent) return next(error);
  res.status(500).send("Internal Server Error");
});

// START SERVER
async function startServer() {
  try {
    await setupDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("ROYAL PANEL running on port " + PORT);
    });
  } catch (error) {
    console.error("Database startup error:", error);
    process.exit(1);
  }
}

startServer();
