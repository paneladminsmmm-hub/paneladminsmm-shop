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
  ssl: process.env.DATABASE_URL?.includes("localhost") ? false : { rejectUnauthorized: false }
});
const db = (sql, params = []) => pool.query(sql, params);

const PROVIDER_URL = process.env.SOCIALADD_API_URL || "https://socialadd.in/api/v2";
const PROVIDER_KEY = process.env.SOCIALADD_API_KEY || "";
const WHATSAPP_NUMBER = "918140989426";
const WHATSAPP_LINK = `https://wa.me/${WHATSAPP_NUMBER}?text=Hello%20Royal%20Panel%20Support`;

app.use(session({
  name: "royalpanel.sid",
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_LONG_SECRET",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const resellerApiLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false
});

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  })[c]);
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

// COMMON PAGE DESIGN - WHATSAPP FLOATING BUTTON HAR PAGE PAR
function page(title, content, user = null) {
  const nav = user ? `
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
    </nav>` : `
    <nav><a href="/login">Login</a><a href="/register">Register</a></nav>`;

  return `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} - ROYAL PANEL</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#10131c;color:#f5f5f5;font-family:Arial,sans-serif}
header{background:#191e2b;padding:18px;text-align:center;border-bottom:2px solid #e63946}
header h2{margin:0;color:#ff454f}
nav{display:flex;gap:8px;flex-wrap:wrap;padding:12px;background:#191e2b;justify-content:center}
a{color:#ff5964;text-decoration:none}
nav a{padding:9px 11px;background:#252c3c;border-radius:7px;color:white;font-size:13px}
main{max-width:1100px;margin:22px auto;padding:0 14px}
.card{background:#1b2130;border:1px solid #30394c;border-radius:12px;padding:17px;margin-bottom:15px}
input,select,textarea{width:100%;padding:12px;margin:7px 0 13px;border:1px solid #414b60;border-radius:7px;background:#101723;color:white}
button,.btn{display:inline-block;border:0;background:#e63946;color:white;padding:12px 16px;border-radius:7px;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
table{width:100%;border-collapse:collapse;min-width:750px}
th,td{padding:10px;border-bottom:1px solid #384154;text-align:left;font-size:13px}
.tablewrap{overflow-x:auto}
small{color:#aeb8c9}
.danger{background:#b42332}
.success{background:#16834a}

/* FLOATING WHATSAPP BUTTON */
.whatsapp-float{
  position:fixed;
  width:60px;
  height:60px;
  bottom:20px;
  right:20px;
  background:#25D366;
  color:#fff;
  border-radius:50%;
  display:flex;
  align-items:center;
  justify-content:center;
  font-size:29px;
  font-weight:bold;
  text-decoration:none;
  z-index:99999;
  box-shadow:0 4px 12px rgba(0,0,0,.4);
  border:2px solid white;
}
.whatsapp-float:hover{background:#1ebe5d;color:white}
</style>
</head>
<body>
<header><h2>ROYAL PANEL</h2><small>Panel Admin SMM.shop</small></header>
${nav}
<main><h2>${esc(title)}</h2>${content}</main>

<!-- WHATSAPP FLOATING BUTTON ON EVERY PAGE -->
<a class="whatsapp-float"
   href="${WHATSAPP_LINK}"
   target="_blank"
   rel="noopener noreferrer"
   aria-label="WhatsApp Support">
   WA
</a>

</body>
</html>`;
}

// SOCIALADD API HELPER
async function providerRequest(params) {
  if (!PROVIDER_KEY) throw new Error("SOCIALADD_API_KEY Render Environment में सेट नहीं है।");

  const body = new URLSearchParams({
    key: PROVIDER_KEY,
    ...Object.fromEntries(Object.entries(params).map(([k, v]) => [k, String(v)]))
  });

  const response = await fetch(PROVIDER_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(30000)
  });

  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error("SocialAdd API HTTP error: " + response.status);
  if (!data || data.error) throw new Error(data?.error || "SocialAdd API से गलत response मिला।");
  return data;
}

function providerStatus(status) {
  const s = String(status || "").toLowerCase();
  if (s === "completed") return "Completed";
  if (s === "partial") return "Partial";
  if (s === "canceled" || s === "cancelled") return "Canceled";
  if (s === "failed" || s === "error") return "Failed";
  if (s === "in progress" || s === "processing") return "Processing";
  if (s === "pending") return "Pending";
  return status || "Processing";
}

function calculateProviderRate(providerRate) {
  const rate = Number(providerRate);
  if (!Number.isFinite(rate) || rate <= 0) {
    throw new Error("SocialAdd से Provider Rate सही नहीं मिला।");
  }
  return rate;
}

function categoryFromName(name, category) {
  const text = `${name || ""} ${category || ""}`.toLowerCase();
  for (const word of ["instagram", "facebook", "youtube", "tiktok", "whatsapp", "twitter", "telegram"]) {
    if (text.includes(word)) return word[0].toUpperCase() + word.slice(1);
  }
  return category || "Other";
}

async function submitProviderOrder(service, link, quantity) {
  if (service.provider_source !== "socialadd") {
    throw new Error("यह सर्विस SocialAdd Provider से कनेक्ट नहीं है।");
  }
  if (service.provider_type && service.provider_type.toLowerCase() !== "default") {
    throw new Error("इस सर्विस का type " + service.provider_type +
      " है। इस type के लिए अलग input fields चाहिए; इसे अभी ऑर्डर नहीं किया जा सकता।");
  }
  const result = await providerRequest({
    action: "add",
    service: service.provider_id,
    link,
    quantity
  });
  if (!result.order) throw new Error("Provider ने Order ID नहीं दिया।");
  return String(result.order);
}

async function syncProviderOrder(orderId) {
  const result = await db("SELECT * FROM orders WHERE id=$1", [orderId]);
  if (!result.rowCount) throw new Error("Order not found.");
  const order = result.rows[0];
  if (!order.provider_order_id) throw new Error("इस ऑर्डर का Provider Order ID नहीं है।");
  const data = await providerRequest({ action: "status", order: order.provider_order_id });
  const status = providerStatus(data.status);
  await db("UPDATE orders SET status=$1 WHERE id=$2", [status, orderId]);
  return { ...data, status };
}

// DATABASE SETUP
async function setupDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT,
      balance NUMERIC(12,2) DEFAULT 0,
      is_admin BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS password_hash TEXT,
    ADD COLUMN IF NOT EXISTS balance NUMERIC(12,2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE
  `);

  await db(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
    ON users (LOWER(email)) WHERE email IS NOT NULL
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      provider_id TEXT,
      name TEXT NOT NULL,
      category TEXT DEFAULT 'Other',
      description TEXT DEFAULT '',
      rate NUMERIC(12,4) DEFAULT 0,
      min INTEGER DEFAULT 100,
      max INTEGER DEFAULT 1000000,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    ALTER TABLE services
    ADD COLUMN IF NOT EXISTS provider_id TEXT,
    ADD COLUMN IF NOT EXISTS name TEXT,
    ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'Other',
    ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '',
    ADD COLUMN IF NOT EXISTS rate NUMERIC(12,4) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS min INTEGER DEFAULT 100,
    ADD COLUMN IF NOT EXISTS max INTEGER DEFAULT 1000000,
    ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS provider_source TEXT DEFAULT 'manual',
    ADD COLUMN IF NOT EXISTS provider_type TEXT,
    ADD COLUMN IF NOT EXISTS provider_rate NUMERIC(14,6)
  `);

  await db(`
    CREATE UNIQUE INDEX IF NOT EXISTS services_provider_unique
    ON services(provider_source,provider_id)
    WHERE provider_id IS NOT NULL
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      service_id INTEGER,
      provider_order_id TEXT,
      link TEXT,
      quantity INTEGER,
      charge NUMERIC(12,2),
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS service_id INTEGER,
    ADD COLUMN IF NOT EXISTS provider_order_id TEXT,
    ADD COLUMN IF NOT EXISTS link TEXT,
    ADD COLUMN IF NOT EXISTS quantity INTEGER,
    ADD COLUMN IF NOT EXISTS charge NUMERIC(12,2),
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Pending',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS service_name TEXT
  `);

  await db(`
    UPDATE orders o SET service_name=s.name
    FROM services s
    WHERE o.service_id=s.id AND (o.service_name IS NULL OR o.service_name='')
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
    ALTER TABLE payments
    ADD COLUMN IF NOT EXISTS amount NUMERIC(12,2),
    ADD COLUMN IF NOT EXISTS utr TEXT,
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Pending',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
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
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const adminUsername = String(process.env.ADMIN_USERNAME || "").trim();
  const adminPassword = String(process.env.ADMIN_PASSWORD || "");

  if (adminEmail && adminUsername && adminPassword) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail)) {
      throw new Error("ADMIN_EMAIL is invalid.");
    }
    const existing = await db(
      `SELECT id FROM users WHERE LOWER(email)=LOWER($1) OR username=$2 LIMIT 1`,
      [adminEmail, adminUsername]
    );
    const hash = await bcrypt.hash(adminPassword, 12);
    if (existing.rowCount) {
      await db(`
        UPDATE users SET email=$1,username=$2,password_hash=$3,is_admin=TRUE
        WHERE id=$4
      `, [adminEmail, adminUsername, hash, existing.rows[0].id]);
    } else {
      await db(`
        INSERT INTO users(email,username,password_hash,balance,is_admin)
        VALUES($1,$2,$3,0,TRUE)
      `, [adminEmail, adminUsername, hash]);
    }
    console.log("Admin account configured.");
  }
}

// HEALTH / HOME
app.get("/health", (req, res) => res.send("ROYAL PANEL OK"));
app.get("/", (req, res) => res.redirect(req.session.user ? "/dashboard" : "/login"));

// REGISTER
app.get("/register", (req, res) => {
  res.send(page("Create Account", `
    <div class="card"><form method="POST">
      <label>Email</label><input type="email" name="email" required>
      <label>Username</label><input name="username" minlength="3" maxlength="30" required>
      <label>Password</label><input type="password" name="password" minlength="6" required>
      <button>Register</button>
    </form><p>Already registered? <a href="/login">Login</a></p></div>
  `));
});

app.post("/register", authLimit, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).send("Valid email required.");
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) return res.status(400).send("Invalid username.");
    if (password.length < 6) return res.status(400).send("Password must be at least 6 characters.");

    const exists = await db(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1) OR username=$2",
      [email, username]
    );
    if (exists.rowCount) return res.status(409).send("Email or username already exists.");

    const hash = await bcrypt.hash(password, 12);
    await db(`
      INSERT INTO users(email,username,password_hash,balance,is_admin)
      VALUES($1,$2,$3,0,FALSE)
    `, [email, username, hash]);
    res.redirect("/login");
  } catch (e) {
    console.error(e);
    res.status(500).send("Registration failed.");
  }
});

// LOGIN
app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card"><form method="POST">
      <label>Email</label><input type="email" name="email" required>
      <label>Password</label><input type="password" name="password" required>
      <button>Login</button>
    </form><p>New user? <a href="/register">Create Account</a></p></div>
  `));
});

app.post("/login", authLimit, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const result = await db("SELECT * FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1", [email]);
    if (!result.rowCount) return res.status(401).send("Email or password incorrect.");
    const user = result.rows[0];
    if (!user.password_hash || !await bcrypt.compare(String(req.body.password || ""), user.password_hash)) {
      return res.status(401).send("Email or password incorrect.");
    }
    req.session.regenerate(err => {
      if (err) return res.status(500).send("Session error.");
      req.session.user = {
        id: user.id, username: user.username,
        email: user.email, is_admin: user.is_admin
      };
      res.redirect(user.is_admin ? "/admin" : "/dashboard");
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("Login error.");
  }
});

app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/login")));

// DASHBOARD
app.get("/dashboard", requireLogin, async (req, res) => {
  try {
    const result = await db("SELECT balance FROM users WHERE id=$1", [req.session.user.id]);
    res.send(page("Dashboard", `
      <div class="card">
        <h3>Welcome, ${esc(req.session.user.username)}</h3>
        <p>${esc(req.session.user.email)}</p>
        <h2>Wallet Balance: ₹${Number(result.rows[0]?.balance || 0).toFixed(2)}</h2>
        <a class="btn" href="/new-order">Place New Order</a>
        <a class="btn" href="/api-keys">My Reseller API</a>
      </div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Dashboard error.");
  }
});

// SERVICES
app.get("/services", requireLogin, async (req, res) => {
  try {
    const result = await db(`
      SELECT category,COUNT(*) AS total FROM services
      WHERE active=TRUE GROUP BY category ORDER BY category
    `);
    const html = result.rows.map(r => `
      <div class="card"><h3>${esc(r.category)}</h3>
      <p>${esc(r.total)} services</p>
      <a class="btn" href="/new-order?search=${encodeURIComponent(r.category)}">View Services</a></div>
    `).join("");
    res.send(page("Services", html || "<p>No services available.</p>", req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Services error.");
  }
});

// NEW ORDER PAGE
app.get("/new-order", requireLogin, async (req, res) => {
  try {
    const search = String(req.query.search || "").trim().slice(0, 100);
    const result = search
      ? await db(`
          SELECT * FROM services
          WHERE active=TRUE AND (
            name ILIKE $1 OR category ILIKE $1
            OR COALESCE(description,'') ILIKE $1
            OR COALESCE(provider_id,'') ILIKE $1
          )
          ORDER BY category,name LIMIT 500
        `, [`%${search}%`])
      : await db(`
          SELECT * FROM services
          WHERE active=TRUE ORDER BY category,name LIMIT 500
        `);

    const groups = {};
    for (const s of result.rows) {
      const c = s.category || "Other";
      if (!groups[c]) groups[c] = [];
      groups[c].push(s);
    }

    const options = Object.entries(groups).map(([category, services]) => `
      <optgroup label="${esc(category)}">
        ${services.map(s => `
          <option value="${s.id}" data-rate="${Number(s.rate)}"
            data-min="${Number(s.min)}" data-max="${Number(s.max)}">
            ${esc(s.name)} | Provider ID: ${esc(s.provider_id || "-")} | ₹${Number(s.rate).toFixed(2)}/1K
          </option>
        `).join("")}
      </optgroup>
    `).join("");

    res.send(page("New Order", `
      <div class="card">
        <form method="GET">
          <label>Search Service Name or Provider Service ID</label>
          <input name="search" value="${esc(search)}" placeholder="Enter service name or Provider ID">
          <button>Search</button>
          <a class="btn" href="/new-order">Show All</a>
        </form>
      </div>
      <div class="card">
        <form method="POST">
          <label>Select Service</label>
          <select name="service_id" id="serviceSelect" required>
            <option value="">Choose service</option>${options}
          </select>
          <label>Post / Profile Link</label>
          <input name="link" type="url" placeholder="https://" required>
          <label>Quantity</label>
          <input name="quantity" id="quantityInput" type="number" min="1" max="10000000" required>
          <div style="background:#f3f4f6;color:#111;padding:15px;border-radius:10px;margin:15px 0">
            Total Price
            <div id="totalPrice" style="font-size:26px;font-weight:bold">₹0.00</div>
            <small id="priceDetails">Select service and quantity</small>
          </div>
          <button>Place Order</button>
        </form>
      </div>
      <script>
      (() => {
        const s=document.getElementById("serviceSelect");
        const q=document.getElementById("quantityInput");
        const total=document.getElementById("totalPrice");
        const detail=document.getElementById("priceDetails");
        function update(){
          const o=s.options[s.selectedIndex], rate=Number(o.dataset.rate);
          const min=Number(o.dataset.min||1), max=Number(o.dataset.max||10000000);
          const qty=Number(q.value);
          q.min=min; q.max=max;
          if(!o.value || !Number.isInteger(qty) || qty<min || qty>max){
            total.textContent="₹0.00";
            detail.textContent="Quantity must be between "+min+" and "+max;
            return;
          }
          total.textContent="₹"+(rate*qty/1000).toFixed(2);
          detail.textContent=qty.toLocaleString("en-IN")+" × ₹"+rate.toFixed(2)+" per 1,000";
        }
        s.addEventListener("change",update);
        q.addEventListener("input",update);
      })();
      </script>
      ${result.rows.length ? "" : "<p>No services found.</p>"}
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("New Order page error.");
  }
});

// PLACE CUSTOMER ORDER
app.post("/new-order", requireLogin, async (req, res) => {
  const client = await pool.connect();
  let started = false;
  try {
    const serviceId = Number(req.body.service_id);
    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();
    if (!Number.isInteger(serviceId) || !Number.isInteger(quantity) || !/^https?:\/\//i.test(link)) {
      throw new Error("Invalid order details.");
    }
    await client.query("BEGIN");
    started = true;
    const ur = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [req.session.user.id]);
    const sr = await client.query("SELECT * FROM services WHERE id=$1 AND active=TRUE", [serviceId]);
    if (!ur.rowCount || !sr.rowCount) throw new Error("User or service not found.");
    const user = ur.rows[0], service = sr.rows[0];
    if (quantity < Number(service.min) || quantity > Number(service.max)) {
      throw new Error(`Quantity must be between ${service.min} and ${service.max}.`);
    }
    const charge = Number(service.rate) * quantity / 1000;
    if (!Number.isFinite(charge) || charge <= 0) throw new Error("Invalid service price.");
    if (Number(user.balance) < charge) throw new Error("Insufficient wallet balance. Add funds first.");
    const providerOrderId = await submitProviderOrder(service, link, quantity);
    await client.query("UPDATE users SET balance=balance-$1 WHERE id=$2", [charge, user.id]);
    await client.query(`
      INSERT INTO orders
      (user_id,service_id,service_name,provider_order_id,link,quantity,charge,status)
      VALUES($1,$2,$3,$4,$5,$6,$7,'Pending')
    `, [user.id, service.id, service.name, providerOrderId, link, quantity, charge]);
    await client.query("COMMIT");
    started = false;
    res.redirect("/orders");
  } catch (e) {
    if (started) await client.query("ROLLBACK");
    console.error("Customer order error:", e);
    res.status(400).send(page("Order Error", `
      <div class="card">${esc(e.message)}<p><a href="/new-order">Go Back</a></p></div>
    `, req.session.user));
  } finally {
    client.release();
  }
});

// MY ORDERS
app.get("/orders", requireLogin, async (req, res) => {
  try {
    const result = await db(`
      SELECT o.*,COALESCE(o.service_name,s.name,'Service') AS display_name
      FROM orders o LEFT JOIN services s ON s.id=o.service_id
      WHERE o.user_id=$1 ORDER BY o.id DESC LIMIT 200
    `, [req.session.user.id]);
    const rows = result.rows.map(o => `
      <tr><td>${o.id}</td><td>${esc(o.display_name)}</td>
      <td>${esc(o.quantity)}</td><td>₹${Number(o.charge || 0).toFixed(2)}</td>
      <td>${esc(o.status)}</td><td>${esc(o.provider_order_id || "-")}</td></tr>
    `).join("");
    res.send(page("My Orders", `
      <div class="card tablewrap"><table>
      <tr><th>ID</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th><th>Provider Order ID</th></tr>
      ${rows}</table></div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Orders error.");
  }
});

// ADD FUNDS
app.get("/add-funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
    <div class="card">
      <h3>Scan QR & Pay</h3><p>Minimum ₹10 - Maximum ₹2,000</p>
      <div style="text-align:center;background:white;padding:15px;border-radius:10px;margin:15px 0">
        <img src="/public/payment-qr.png" alt="Payment QR" style="width:100%;max-width:280px">
      </div>
      <form method="POST">
        <label>Amount (₹)</label><input name="amount" type="number" min="10" max="2000" required>
        <label>UTR / Transaction ID</label><input name="utr" maxlength="30" required>
        <button>Submit Payment</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/add-funds", requireLogin, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const utr = String(req.body.utr || "").trim();
    if (!Number.isInteger(amount) || amount < 10 || amount > 2000 || !utr || utr.length > 30) {
      return res.status(400).send("Amount must be ₹10-₹2,000 and valid UTR is required.");
    }
    await db("INSERT INTO payments(user_id,amount,utr,status) VALUES($1,$2,$3,'Pending')",
      [req.session.user.id, amount, utr]);
    res.send(page("Payment Submitted", `
      <div class="card"><h3>Payment Request Submitted</h3>
      <p>Amount: ₹${amount}</p><p>Waiting for Admin approval.</p>
      <a class="btn" href="/dashboard">Dashboard</a></div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Payment submission failed.");
  }
});

// SUPPORT - WHATSAPP CHAT + SUPPORT TICKET
app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
    <div class="card">
      <h3>ROYAL PANEL Customer Support</h3>
      <p>Need help? Contact our support team on WhatsApp.</p>

      <a class="btn"
         style="background:#25D366;color:white;display:block;text-align:center;margin:15px 0"
         href="${WHATSAPP_LINK}"
         target="_blank"
         rel="noopener noreferrer">
         WhatsApp Chat - +91 8140989426
      </a>

      <hr style="border:0;border-top:1px solid #384154;margin:20px 0">

      <h3>Submit Support Ticket</h3>
      <form method="POST">
        <label>Message</label>
        <textarea name="message" maxlength="2000" required></textarea>
        <button>Send Message</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/support", requireLogin, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();
    if (!message) return res.status(400).send("Message required.");
    await db("INSERT INTO tickets(user_id,message) VALUES($1,$2)", [req.session.user.id, message]);
    res.redirect("/support");
  } catch (e) {
    console.error(e);
    res.status(500).send("Support error.");
  }
});

// USER API KEY PAGE
app.get("/api-keys", requireLogin, async (req, res) => {
  try {
    const result = await db(
      "SELECT id,key_prefix,active,created_at FROM api_keys WHERE user_id=$1 ORDER BY id DESC",
      [req.session.user.id]
    );
    const rows = result.rows.map(k => `
      <tr><td>${k.id}</td><td>${esc(k.key_prefix)}...</td>
      <td>${k.active ? "Enabled" : "Disabled"}</td><td>
      <form method="POST" action="/api-keys/${k.id}/toggle"><button>${k.active ? "Disable" : "Enable"}</button></form>
      <form method="POST" action="/api-keys/${k.id}/delete" onsubmit="return confirm('Revoke this API key?')">
      <button class="danger">Revoke</button></form></td></tr>
    `).join("");
    res.send(page("My Reseller API", `
      <div class="card"><h3>Your API URL</h3>
      <input readonly value="${esc(process.env.APP_URL || "https://paneladminsmm-shop-1.onrender.com")}/api/v2">
      <form method="POST" action="/api-keys/create"><button class="success">Generate New API Key</button></form></div>
      <div class="card tablewrap"><h3>My API Keys</h3><table>
      <tr><th>ID</th><th>Key Prefix</th><th>Status</th><th>Action</th></tr>${rows}</table></div>
      <div class="card"><h3>API Actions</h3>
      <p>services - View Services</p><p>add - Place Order</p>
      <p>status - Check Order</p><p>balance - Check Balance</p></div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("API page error.");
  }
});

app.post("/api-keys/create", requireLogin, async (req, res) => {
  try {
    const key = "ROYAL_" + crypto.randomBytes(32).toString("hex");
    const hash = crypto.createHash("sha256").update(key).digest("hex");
    await db("INSERT INTO api_keys(user_id,key_hash,key_prefix) VALUES($1,$2,$3)",
      [req.session.user.id, hash, key.slice(0, 12)]);
    res.send(page("API Key Created", `
      <div class="card"><h3>Your New API Key</h3>
      <p>इसे सुरक्षित रखो। यह Key दोबारा पूरी दिखाई नहीं जाएगी।</p>
      <input id="newApiKey" readonly value="${esc(key)}">
      <button onclick="navigator.clipboard.writeText(document.getElementById('newApiKey').value)">Copy API Key</button>
      <p><a href="/api-keys">Back to API Management</a></p></div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Could not create API key.");
  }
});

app.post("/api-keys/:id/toggle", requireLogin, async (req, res) => {
  await db("UPDATE api_keys SET active=NOT active WHERE id=$1 AND user_id=$2",
    [Number(req.params.id), req.session.user.id]);
  res.redirect("/api-keys");
});

app.post("/api-keys/:id/delete", requireLogin, async (req, res) => {
  await db("DELETE FROM api_keys WHERE id=$1 AND user_id=$2",
    [Number(req.params.id), req.session.user.id]);
  res.redirect("/api-keys");
});

// ROYAL PANEL RESELLER API
app.post("/api/v2", resellerApiLimit, async (req, res) => {
  const action = String(req.body.action || "").toLowerCase();
  const key = String(req.body.key || "");
  if (!key || !action) return res.json({ error: "Invalid API request" });
  const hash = crypto.createHash("sha256").update(key).digest("hex");

  try {
    const keyResult = await db(`
      SELECT a.user_id FROM api_keys a
      JOIN users u ON u.id=a.user_id
      WHERE a.key_hash=$1 AND a.active=TRUE LIMIT 1
    `, [hash]);
    if (!keyResult.rowCount) return res.json({ error: "Invalid or disabled API key" });
    const userId = keyResult.rows[0].user_id;

    if (action === "services") {
      const result = await db(`
        SELECT id,name,category,rate,min,max,description
        FROM services WHERE active=TRUE ORDER BY id
      `);
      return res.json(result.rows.map(s => ({
        service: s.id, name: s.name, type: "Default",
        category: s.category, rate: Number(s.rate).toFixed(4),
        min: s.min, max: s.max, description: s.description
      })));
    }

    if (action === "balance") {
      const r = await db("SELECT balance FROM users WHERE id=$1", [userId]);
      return res.json({ balance: Number(r.rows[0]?.balance || 0).toFixed(2), currency: "INR" });
    }

    if (action === "status") {
      const orderId = Number(req.body.order);
      if (!Number.isInteger(orderId) || orderId < 1) return res.json({ error: "Invalid order ID" });
      const r = await db("SELECT id,status,charge,quantity FROM orders WHERE id=$1 AND user_id=$2",
        [orderId, userId]);
      if (!r.rowCount) return res.json({ error: "Order not found" });
      const o = r.rows[0];
      return res.json({ charge: Number(o.charge).toFixed(2), status: o.status, quantity: o.quantity });
    }

    if (action === "add") {
      const serviceId = Number(req.body.service);
      const quantity = Number(req.body.quantity);
      const link = String(req.body.link || "").trim();
      if (!Number.isInteger(serviceId) || !Number.isInteger(quantity) || !/^https?:\/\//i.test(link)) {
        return res.json({ error: "Invalid order details" });
      }

      const client = await pool.connect();
      let started = false;
      try {
        await client.query("BEGIN");
        started = true;
        const ur = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [userId]);
        const sr = await client.query("SELECT * FROM services WHERE id=$1 AND active=TRUE", [serviceId]);
        if (!ur.rowCount || !sr.rowCount) throw new Error("User or service not found");
        const user = ur.rows[0], service = sr.rows[0];
        if (quantity < Number(service.min) || quantity > Number(service.max)) {
          throw new Error("Quantity outside service limits");
        }
        const charge = Number(service.rate) * quantity / 1000;
        if (!Number.isFinite(charge) || charge <= 0) throw new Error("Invalid service price");
        if (Number(user.balance) < charge) throw new Error("Insufficient balance");
        const providerOrderId = await submitProviderOrder(service, link, quantity);
        await client.query("UPDATE users SET balance=balance-$1 WHERE id=$2", [charge, userId]);
        const order = await client.query(`
          INSERT INTO orders(user_id,service_id,service_name,provider_order_id,link,quantity,charge,status)
          VALUES($1,$2,$3,$4,$5,$6,$7,'Pending') RETURNING id
        `, [userId, serviceId, service.name, providerOrderId, link, quantity, charge]);
        await client.query("COMMIT");
        started = false;
        return res.json({ order: order.rows[0].id });
      } catch (e) {
        if (started) await client.query("ROLLBACK");
        return res.json({ error: e.message || "Order failed" });
      } finally {
        client.release();
      }
    }
    return res.json({ error: "Invalid action" });
  } catch (e) {
    console.error("Reseller API error:", e);
    return res.json({ error: "API request failed" });
  }
});

// ADMIN DASHBOARD
app.get("/admin", requireAdmin, async (req, res) => {
  try {
    const [users, services, orders, payments] = await Promise.all([
      db("SELECT COUNT(*) FROM users"),
      db("SELECT COUNT(*) FROM services WHERE active=TRUE"),
      db("SELECT COUNT(*) FROM orders"),
      db("SELECT COUNT(*) FROM payments WHERE status='Pending'")
    ]);
    res.send(page("Admin Panel", `
      <div class="card"><h3>Users</h3>${users.rows[0].count}</div>
      <div class="card"><h3>Active Services</h3>${services.rows[0].count}</div>
      <div class="card"><h3>Orders</h3>${orders.rows[0].count}</div>
      <div class="card"><h3>Pending Payments</h3>${payments.rows[0].count}</div>
      <div class="card">
        <a class="btn" href="/admin/provider">SocialAdd Provider</a>
        <a class="btn" href="/admin/services">Manage Services</a>
        <a class="btn" href="/admin/payments">Payments</a>
        <a class="btn" href="/admin/orders">Orders</a>
        <a class="btn" href="/admin/api">API Management</a>
      </div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Admin error.");
  }
});

// SOCIALADD PROVIDER ADMIN PAGE
app.get("/admin/provider", requireAdmin, async (req, res) => {
  try {
    const counts = await db(`
      SELECT COUNT(*) FILTER (WHERE provider_source='socialadd') AS imported,
             COUNT(*) FILTER (WHERE provider_source='socialadd' AND active=TRUE) AS active
      FROM services
    `);
    res.send(page("SocialAdd Provider", `
      <div class="card">
        <h3>SocialAdd API Connection</h3>
        <p>API URL: ${esc(PROVIDER_URL)}</p>
        <p>API Key: ${PROVIDER_KEY ? "Configured" : "Not configured"}</p>
        <p>Provider Rate: SocialAdd API का INR rate सीधे import होगा।</p>
        <p>Imported SocialAdd services: ${counts.rows[0].imported}</p>
        <p>Active SocialAdd services: ${counts.rows[0].active}</p>
        <form method="POST" action="/admin/provider/test"><button>Test API Connection</button></form>
        <form method="POST" action="/admin/provider/import"
          onsubmit="return confirm('सिर्फ Instagram services import होंगी। बाकी services inactive रहेंगी और Instagram की कीमतें SocialAdd Rate से अपडेट होंगी।')">
          <button class="success">Import / Update Instagram Services</button>
        </form>
        <p><small>Import के बाद Manage Services में अपनी Selling Price सेट कर सकते हो। अगली Import पर कीमत फिर Provider Rate से अपडेट होगी।</small></p>
      </div>
      <div class="card">
        <a class="btn" href="/admin/services">Manage Service Prices</a>
        <a class="btn" href="/admin/orders">Manage Orders</a>
      </div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Provider page error.");
  }
});

// TEST SOCIALADD CONNECTION
app.post("/admin/provider/test", requireAdmin, async (req, res) => {
  try {
    const data = await providerRequest({ action: "balance" });
    res.send(page("Provider Connection", `
      <div class="card"><h3>SocialAdd API Connected</h3>
      <p>Provider Balance: ${esc(data.balance ?? "Not returned")}</p>
      <p>Currency: ${esc(data.currency || "API ने currency नहीं बताई")}</p>
      <a class="btn" href="/admin/provider">Back</a></div>
    `, req.session.user));
  } catch (e) {
    res.status(400).send(page("Provider Connection Error", `
      <div class="card">${esc(e.message)}<p><a href="/admin/provider">Back</a></p></div>
    `, req.session.user));
  }
});

// IMPORT ONLY INSTAGRAM SERVICES FROM SOCIALADD
app.post("/admin/provider/import", requireAdmin, async (req, res) => {
  const client = await pool.connect();
  let started = false;
  try {
    if (!PROVIDER_KEY) throw new Error("Render में SOCIALADD_API_KEY सेट करो।");
    const services = await providerRequest({ action: "services" });
    if (!Array.isArray(services)) throw new Error("Provider services list सही नहीं है।");
    await client.query("BEGIN");
    started = true;
    await client.query("UPDATE services SET active=FALSE");
    let imported = 0;
    let skipped = 0;

    for (const s of services) {
      const providerId = String(s.service || "").trim();
      const name = String(s.name || "").trim();
      const type = String(s.type || "Default").trim();
      const category = categoryFromName(name, s.category);
      if (category.toLowerCase() !== "instagram") {
        skipped++;
        continue;
      }
      const providerRate = Number(s.rate);
      const min = Number(s.min);
      const max = Number(s.max);
      if (!providerId || !name || !Number.isFinite(providerRate) ||
          providerRate <= 0 || !Number.isInteger(min) || !Number.isInteger(max) ||
          min < 1 || max < min) {
        skipped++;
        continue;
      }
      const exactProviderRate = calculateProviderRate(providerRate);
      await client.query(`
        INSERT INTO services
        (provider_id,name,category,description,rate,min,max,active,
         provider_source,provider_type,provider_rate)
        VALUES($1,$2,$3,$4,$5,$6,$7,TRUE,'socialadd',$8,$9)
        ON CONFLICT (provider_source,provider_id)
        WHERE provider_id IS NOT NULL
        DO UPDATE SET
          name=EXCLUDED.name,
          category=EXCLUDED.category,
          description=EXCLUDED.description,
          rate=EXCLUDED.rate,
          min=EXCLUDED.min,
          max=EXCLUDED.max,
          provider_type=EXCLUDED.provider_type,
          provider_rate=EXCLUDED.provider_rate,
          active=TRUE
      `, [
        providerId, name, "Instagram",
        `SocialAdd ${type} service`,
        exactProviderRate, min, max, type, exactProviderRate
      ]);
      imported++;
    }
    await client.query("COMMIT");
    started = false;
    res.send(page("Instagram Services Imported", `
      <div class="card">
        <h3>Import Complete</h3>
        <p>Instagram services imported: ${imported}</p>
        <p>Other services skipped: ${skipped}</p>
        <p>SocialAdd की INR Provider Rate सीधे Selling Rate में सेव हुई है।</p>
        <p>पुरानी Instagram services की कीमतें भी अपडेट हुई हैं।</p>
        <p>अब सिर्फ Instagram services active रहेंगी।</p>
        <a class="btn" href="/admin/services">Manage Service Prices</a>
        <a class="btn" href="/admin/provider">Provider Page</a>
      </div>
    `, req.session.user));
  } catch (e) {
    if (started) await client.query("ROLLBACK");
    console.error("SocialAdd import error:", e);
    res.status(400).send(page("Import Error", `
      <div class="card">${esc(e.message)}<p><a href="/admin/provider">Back</a></p></div>
    `, req.session.user));
  } finally {
    client.release();
  }
});

// ADMIN API MANAGEMENT
app.get("/admin/api", requireAdmin, async (req, res) => {
  try {
    const result = await db(`
      SELECT a.id,a.key_prefix,a.active,a.created_at,u.username
      FROM api_keys a JOIN users u ON u.id=a.user_id
      ORDER BY a.id DESC LIMIT 300
    `);
    const rows = result.rows.map(k => `
      <tr><td>${k.id}</td><td>${esc(k.username)}</td>
      <td>${esc(k.key_prefix)}...</td><td>${k.active ? "Enabled" : "Disabled"}</td>
      <td><form method="POST" action="/admin/api/${k.id}/toggle">
      <button>${k.active ? "Disable" : "Enable"}</button></form></td></tr>
    `).join("");
    res.send(page("API Management", `
      <div class="card"><h3>ROYAL PANEL Reseller API</h3>
      <input readonly value="${esc(process.env.APP_URL || "https://paneladminsmm-shop-1.onrender.com")}/api/v2">
      <p>Resellers अपने Dashboard से API Key बना सकते हैं।</p></div>
      <div class="card tablewrap"><table>
      <tr><th>ID</th><th>Reseller</th><th>Key Prefix</th><th>Status</th><th>Action</th></tr>
      ${rows}</table></div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Admin API page error.");
  }
});

app.post("/admin/api/:id/toggle", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).send("Invalid API key ID.");
  await db("UPDATE api_keys SET active=NOT active WHERE id=$1", [id]);
  res.redirect("/admin/api");
});

// ADMIN SERVICES - SEARCH / EDIT / ADD
app.get("/admin/services", requireAdmin, async (req, res) => {
  try {
    const search = String(req.query.search || "").trim().slice(0, 100);
    const result = search
      ? await db(`
          SELECT * FROM services
          WHERE name ILIKE $1 OR category ILIKE $1
             OR COALESCE(provider_id,'') ILIKE $1
          ORDER BY id DESC LIMIT 300
        `, [`%${search}%`])
      : await db("SELECT * FROM services ORDER BY id DESC LIMIT 300");

    const rows = result.rows.map(s => `
      <tr>
        <td>${s.id}</td><td>${esc(s.name)}</td><td>${esc(s.category)}</td>
        <td><strong>${esc(s.provider_id || "-")}</strong></td>
        <td>${esc(s.provider_source || "manual")}</td>
        <td>${s.provider_rate === null ? "-" : Number(s.provider_rate).toFixed(4)}</td>
        <td>₹${Number(s.rate).toFixed(2)}</td>
        <td>${s.min}</td><td>${s.max}</td><td>${s.active ? "Active" : "Off"}</td>
        <td>
          <a class="btn" href="/admin/services/${s.id}/edit">Edit</a>
          <form method="POST" action="/admin/services/${s.id}/toggle">
            <button>${s.active ? "Disable" : "Enable"}</button>
          </form>
        </td>
      </tr>
    `).join("");

    res.send(page("Manage Services", `
      <div class="card">
        <a class="btn" href="/admin/provider">SocialAdd Import</a>
        <form method="GET">
          <label>Search Service Name or Provider Service ID</label>
          <input name="search" value="${esc(search)}" placeholder="Search Provider ID or service name">
          <button>Search</button>
          <a class="btn" href="/admin/services">Show All</a>
        </form>
      </div>
      <div class="card">
        <h3>Bulk Service Control</h3>
        <form method="POST" action="/admin/services/disable-all"
          onsubmit="return confirm('Disable all services?')">
          <button class="danger">Disable All Services</button>
        </form>
        <form method="POST" action="/admin/services/enable-all"
          onsubmit="return confirm('Enable all services?')">
          <button class="success">Enable All Services</button>
        </form>
      </div>
      <div class="card">
        <h3>Add Manual Service</h3>
        <form method="POST" action="/admin/services">
          <label>Service Name</label><input name="name" required>
          <label>Category</label><input name="category" value="Instagram" required>
          <label>Provider Service ID</label><input name="provider_id" required>
          <label>Rate per 1000 (₹)</label><input name="rate" type="number" step="0.0001" min="0.0001" required>
          <label>Minimum</label><input name="min" type="number" value="100" min="1" required>
          <label>Maximum</label><input name="max" type="number" value="1000000" min="1" required>
          <label>Description</label><textarea name="description"></textarea>
          <button>Add / Update Service</button>
        </form>
      </div>
      <div class="card tablewrap">
        <h3>Services and Provider IDs</h3>
        <p><small>Provider Rate = SocialAdd API से आया हुआ INR rate। Selling Rate = ग्राहक को दिखाई जाने वाली कीमत (₹)।</small></p>
        <table>
          <tr>
            <th>Database ID</th><th>Service Name</th><th>Category</th>
            <th>Provider Service ID</th><th>Provider</th><th>Provider Rate (₹)</th>
            <th>Selling Rate (₹)</th><th>Min</th><th>Max</th><th>Status</th><th>Action</th>
          </tr>
          ${rows}
        </table>
      </div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Services admin error.");
  }
});

// EDIT SERVICE PAGE
app.get("/admin/services/:id/edit", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const result = await db("SELECT * FROM services WHERE id=$1", [id]);
    if (!result.rowCount) return res.status(404).send("Service not found.");
    const s = result.rows[0];
    res.send(page("Edit Service", `
      <div class="card"><h3>Update Service</h3>
      <p>Database Service ID: ${s.id}</p>
      <p>Provider: ${esc(s.provider_source || "manual")}</p>
      <p>Provider Type: ${esc(s.provider_type || "Default")}</p>
      <p>Provider Rate (INR from API): ${s.provider_rate === null ? "Not available" : "₹" + Number(s.provider_rate).toFixed(4)} / 1K</p>
      <form method="POST" action="/admin/services/${s.id}/edit">
        <label>Service Name</label><input name="name" value="${esc(s.name)}" required>
        <label>Category</label><input name="category" value="${esc(s.category)}" required>
        <label>Provider Service ID</label><input name="provider_id" value="${esc(s.provider_id)}" required>
        <label>Rate per 1000 (₹) - Your Selling Price</label>
        <input name="rate" type="number" step="0.0001" min="0.0001" value="${Number(s.rate)}" required>
        <label>Minimum</label><input name="min" type="number" min="1" value="${s.min}" required>
        <label>Maximum</label><input name="max" type="number" min="1" value="${s.max}" required>
        <label>Description</label><textarea name="description">${esc(s.description)}</textarea>
        <button>Save Changes</button>
        <a class="btn" href="/admin/services">Cancel</a>
      </form></div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Could not open edit service.");
  }
});

// UPDATE SERVICE
app.post("/admin/services/:id/edit", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const name = String(req.body.name || "").trim();
    const category = String(req.body.category || "").trim();
    const providerId = String(req.body.provider_id || "").trim();
    const rate = Number(req.body.rate);
    const min = Number(req.body.min);
    const max = Number(req.body.max);
    const description = String(req.body.description || "").trim();
    if (!Number.isInteger(id) || id < 1 || !name || !category || !providerId ||
        !Number.isFinite(rate) || rate <= 0 || !Number.isInteger(min) || min < 1 ||
        !Number.isInteger(max) || max < min || max > 10000000) {
      return res.status(400).send("Invalid service details.");
    }
    const result = await db(`
      UPDATE services SET provider_id=$1,name=$2,category=$3,rate=$4,
      min=$5,max=$6,description=$7 WHERE id=$8 RETURNING id
    `, [providerId, name, category, rate, min, max, description, id]);
    if (!result.rowCount) return res.status(404).send("Service not found.");
    res.redirect("/admin/services");
  } catch (e) {
    console.error(e);
    res.status(500).send("Could not update service.");
  }
});

// ADD / UPDATE MANUAL SERVICE
app.post("/admin/services", requireAdmin, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const category = String(req.body.category || "Instagram").trim();
    const providerId = String(req.body.provider_id || "").trim();
    const rate = Number(req.body.rate);
    const min = Number(req.body.min);
    const max = Number(req.body.max);
    const description = String(req.body.description || "").trim();
    if (!name || !category || !providerId || !Number.isFinite(rate) || rate <= 0 ||
        !Number.isInteger(min) || min < 1 || !Number.isInteger(max) || max < min) {
      return res.status(400).send("Invalid service details.");
    }
    const existing = await db(
      "SELECT id FROM services WHERE provider_source='manual' AND provider_id=$1 LIMIT 1",
      [providerId]
    );
    if (existing.rowCount) {
      await db(`
        UPDATE services SET name=$1,category=$2,rate=$3,min=$4,max=$5,
        description=$6,active=TRUE WHERE id=$7
      `, [name, category, rate, min, max, description, existing.rows[0].id]);
    } else {
      await db(`
        INSERT INTO services(provider_id,name,category,rate,min,max,description,active,provider_source)
        VALUES($1,$2,$3,$4,$5,$6,$7,TRUE,'manual')
      `, [providerId, name, category, rate, min, max, description]);
    }
    res.redirect("/admin/services");
  } catch (e) {
    console.error(e);
    res.status(500).send("Could not add or update service.");
  }
});

app.post("/admin/services/disable-all", requireAdmin, async (req, res) => {
  await db("UPDATE services SET active=FALSE WHERE active=TRUE");
  res.redirect("/admin/services");
});

app.post("/admin/services/enable-all", requireAdmin, async (req, res) => {
  await db("UPDATE services SET active=TRUE WHERE active=FALSE");
  res.redirect("/admin/services");
});

app.post("/admin/services/:id/toggle", requireAdmin, async (req, res) => {
  await db("UPDATE services SET active=NOT active WHERE id=$1", [Number(req.params.id)]);
  res.redirect("/admin/services");
});

// ADMIN PAYMENTS
app.get("/admin/payments", requireAdmin, async (req, res) => {
  try {
    const result = await db(`
      SELECT p.*,u.username FROM payments p
      LEFT JOIN users u ON u.id=p.user_id
      ORDER BY p.id DESC LIMIT 200
    `);
    const rows = result.rows.map(p => `
      <tr><td>${p.id}</td><td>${esc(p.username)}</td>
      <td>₹${Number(p.amount).toFixed(2)}</td><td>${esc(p.utr)}</td>
      <td>${esc(p.status)}</td><td>${p.status === "Pending"
        ? `<form method="POST" action="/admin/payments/${p.id}/approve"><button>Approve</button></form>` : "-"}</td></tr>
    `).join("");
    res.send(page("Payments", `<div class="card tablewrap"><table>
      <tr><th>ID</th><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>
      ${rows}</table></div>`, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Payments error.");
  }
});

app.post("/admin/payments/:id/approve", requireAdmin, async (req, res) => {
  const client = await pool.connect();
  let started = false;
  try {
    await client.query("BEGIN");
    started = true;
    const result = await client.query("SELECT * FROM payments WHERE id=$1 FOR UPDATE", [Number(req.params.id)]);
    if (!result.rowCount || result.rows[0].status !== "Pending") {
      throw new Error("Payment not found or already processed.");
    }
    const p = result.rows[0];
    await client.query("UPDATE users SET balance=balance+$1 WHERE id=$2", [p.amount, p.user_id]);
    await client.query("UPDATE payments SET status='Approved' WHERE id=$1", [p.id]);
    await client.query("COMMIT");
    started = false;
    res.redirect("/admin/payments");
  } catch (e) {
    if (started) await client.query("ROLLBACK");
    res.status(400).send(esc(e.message));
  } finally {
    client.release();
  }
});

// ADMIN ORDERS + PROVIDER STATUS SYNC
app.get("/admin/orders", requireAdmin, async (req, res) => {
  try {
    const result = await db(`
      SELECT o.*,u.username,COALESCE(o.service_name,s.name,'Service') AS display_name
      FROM orders o LEFT JOIN users u ON u.id=o.user_id
      LEFT JOIN services s ON s.id=o.service_id
      ORDER BY o.id DESC LIMIT 200
    `);
    const rows = result.rows.map(o => `
      <tr><td>${o.id}</td><td>${esc(o.username)}</td><td>${esc(o.display_name)}</td>
      <td>${esc(o.quantity)}</td><td>${esc(o.status)}</td>
      <td>${esc(o.provider_order_id || "-")}</td><td>
      ${o.provider_order_id ? `<form method="POST" action="/admin/orders/${o.id}/sync"><button>Sync Status</button></form>` : "-"}
      <form method="POST" action="/admin/orders/${o.id}/status">
        <select name="status">
          ${["Pending","Processing","In progress","Completed","Partial","Canceled","Failed"].map(x =>
            `<option ${o.status === x ? "selected" : ""}>${x}</option>`).join("")}
        </select><button>Save</button>
      </form></td></tr>
    `).join("");
    res.send(page("All Orders", `<div class="card tablewrap"><table>
      <tr><th>ID</th><th>User</th><th>Service</th><th>Qty</th><th>Status</th><th>Provider Order ID</th><th>Update</th></tr>
      ${rows}</table></div>`, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Admin orders error.");
  }
});

app.post("/admin/orders/:id/sync", requireAdmin, async (req, res) => {
  try {
    await syncProviderOrder(Number(req.params.id));
    res.redirect("/admin/orders");
  } catch (e) {
    console.error("Provider sync error:", e);
    res.status(400).send(page("Sync Error", `
      <div class="card">${esc(e.message)}<p><a href="/admin/orders">Back to Orders</a></p></div>
    `, req.session.user));
  }
});

app.post("/admin/orders/:id/status", requireAdmin, async (req, res) => {
  try {
    const allowed = ["Pending","Processing","In progress","Completed","Partial","Canceled","Failed"];
    const status = String(req.body.status || "");
    if (!allowed.includes(status)) return res.status(400).send("Invalid status");
    await db("UPDATE orders SET status=$1 WHERE id=$2", [status, Number(req.params.id)]);
    res.redirect("/admin/orders");
  } catch (e) {
    console.error(e);
    res.status(500).send("Status update error.");
  }
});

// START SERVER
async function start() {
  try {
    if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is missing.");
    await setupDatabase();
    const server = app.listen(process.env.PORT || 3000, () => {
      console.log("ROYAL PANEL running.");
    });
    process.on("SIGTERM", () => {
      server.close(async () => {
        await pool.end();
        process.exit(0);
      });
    });
  } catch (e) {
    console.error("SERVER START FAILED:", e);
    process.exit(1);
  }
}

start();
