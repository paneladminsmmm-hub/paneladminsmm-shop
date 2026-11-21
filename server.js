
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

const db = (sql, params = []) => pool.query(sql, params);

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
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  if (!req.session.user.is_admin) {
    return res.status(403).send("Admin access required");
  }
  next();
}

function page(title, content, user = null) {
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
      </nav>
    `
    : `
      <nav>
        <a href="/login">Login</a>
        <a href="/register">Register</a>
      </nav>
    `;

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
</style>
</head>
<body>
<header>
  <h2>ROYAL PANEL</h2>
  <small>Panel Admin SMM.shop</small>
</header>
${nav}
<main>
  <h2>${esc(title)}</h2>
  ${content}
</main>
</body>
</html>`;
}

// DATABASE SETUP
async function setupDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
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
    ON users (LOWER(email))
    WHERE email IS NOT NULL
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
    ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE
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

  // RESELLER API KEYS
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

  const adminEmail = String(process.env.ADMIN_EMAIL || "")
    .trim().toLowerCase();
  const adminUsername = String(process.env.ADMIN_USERNAME || "").trim();
  const adminPassword = String(process.env.ADMIN_PASSWORD || "");

  if (adminEmail && adminUsername && adminPassword) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail)) {
      throw new Error("ADMIN_EMAIL is invalid.");
    }

    const existing = await db(
      `SELECT id FROM users
       WHERE LOWER(email)=LOWER($1) OR username=$2
       LIMIT 1`,
      [adminEmail, adminUsername]
    );

    const hash = await bcrypt.hash(adminPassword, 12);

    if (existing.rowCount) {
      await db(`
        UPDATE users
        SET email=$1, username=$2, password_hash=$3, is_admin=TRUE
        WHERE id=$4
      `, [adminEmail, adminUsername, hash, existing.rows[0].id]);
    } else {
      await db(`
        INSERT INTO users
        (email,username,password_hash,balance,is_admin)
        VALUES($1,$2,$3,0,TRUE)
      `, [adminEmail, adminUsername, hash]);
    }

    console.log("Admin account configured.");
  } else {
    console.log("Admin setup skipped: set ADMIN_EMAIL, ADMIN_USERNAME and ADMIN_PASSWORD.");
  }
}

// HEALTH CHECK
app.get("/health", (req, res) => {
  res.send("ROYAL PANEL OK");
});

app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/dashboard" : "/login");
});

// REGISTER PAGE
app.get("/register", (req, res) => {
  res.send(page("Create Account", `
    <div class="card">
      <form method="POST">
        <label>Gmail / Email Address</label>
        <input type="email" name="email" placeholder="Enter your Gmail" required>
        <label>Username</label>
        <input name="username" placeholder="Choose username" required minlength="3" maxlength="30">
        <label>Password</label>
        <input type="password" name="password" placeholder="Create password" required minlength="6">
        <button type="submit">Register</button>
      </form>
      <p>Already have an account? <a href="/login">Login</a></p>
    </div>
  `));
});

// REGISTER SUBMIT
app.post("/register", authLimit, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).send("Enter a valid email address.");
    }

    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
      return res.status(400).send("Username must be 3-30 letters, numbers or underscores.");
    }

    if (password.length < 6) {
      return res.status(400).send("Password must be at least 6 characters.");
    }

    const exists = await db(
      `SELECT id FROM users
       WHERE LOWER(email)=LOWER($1) OR username=$2`,
      [email, username]
    );

    if (exists.rowCount) {
      return res.status(409).send("Email or username already exists.");
    }

    const hash = await bcrypt.hash(password, 12);

    await db(`
      INSERT INTO users
      (email,username,password_hash,balance,is_admin)
      VALUES($1,$2,$3,0,FALSE)
    `, [email, username, hash]);

    res.redirect("/login");
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).send("Registration failed.");
  }
});

// LOGIN PAGE
app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card">
      <form method="POST">
        <label>Gmail / Email Address</label>
        <input type="email" name="email" placeholder="Enter your Gmail" required>
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter password" required>
        <button type="submit">Login</button>
      </form>
      <p>New user? <a href="/register">Create Account</a></p>
      <p>Admin also logs in here using Admin Gmail and password.</p>
    </div>
  `));
});

// LOGIN SUBMIT
app.post("/login", authLimit, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await db(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
      [email]
    );

    if (!result.rowCount) {
      return res.status(401).send("Email or password is incorrect.");
    }

    const user = result.rows[0];
    const valid = user.password_hash &&
      await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).send("Email or password is incorrect.");
    }

    req.session.regenerate(error => {
      if (error) return res.status(500).send("Session error");

      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email,
        is_admin: user.is_admin
      };

      res.redirect(user.is_admin ? "/admin" : "/dashboard");
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).send("Login error");
  }
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// DASHBOARD
app.get("/dashboard", requireLogin, async (req, res) => {
  try {
    const result = await db(
      "SELECT balance FROM users WHERE id=$1",
      [req.session.user.id]
    );

    res.send(page("Dashboard", `
      <div class="card">
        <h3>Welcome, ${esc(req.session.user.username)}</h3>
        <p>${esc(req.session.user.email)}</p>
        <h2>Wallet Balance: ₹${Number(result.rows[0]?.balance || 0).toFixed(2)}</h2>
        <a class="btn" href="/new-order">Place New Order</a>
        <a class="btn" href="/api-keys">My Reseller API</a>
      </div>
    `, req.session.user));
  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(500).send("Dashboard error");
  }
});

// SERVICES PAGE
app.get("/services", requireLogin, async (req, res) => {
  try {
    const result = await db(`
      SELECT category,COUNT(*) AS total
      FROM services
      WHERE active=TRUE
      GROUP BY category
      ORDER BY category
    `);

    const html = result.rows.map(row => `
      <div class="card">
        <h3>${esc(row.category)}</h3>
        <p>${esc(row.total)} services</p>
        <a class="btn" href="/new-order?search=${encodeURIComponent(row.category)}">View Services</a>
      </div>
    `).join("");

    res.send(page("Services", html || "<p>No services available.</p>", req.session.user));
  } catch (error) {
    console.error("Services error:", error);
    res.status(500).send("Services error");
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
            name ILIKE $1 OR category ILIKE $1 OR
            COALESCE(description,'') ILIKE $1 OR
            COALESCE(provider_id,'') ILIKE $1
          )
          ORDER BY category,name LIMIT 500
        `, [`%${search}%`])
      : await db(`
          SELECT * FROM services
          WHERE active=TRUE
          ORDER BY category,name LIMIT 500
        `);

    const groups = {};

    for (const service of result.rows) {
      const category = service.category || "Other";
      if (!groups[category]) groups[category] = [];
      groups[category].push(service);
    }

    const options = Object.entries(groups).map(([category, services]) => `
      <optgroup label="${esc(category)}">
        ${services.map(s => `
          <option value="${s.id}"
            data-rate="${Number(s.rate)}"
            data-min="${Math.max(100, Number(s.min) || 100)}"
            data-max="${Math.min(10000000, Number(s.max) || 10000000)}">
            ${esc(s.name)} | ₹${Number(s.rate).toFixed(2)}/1K
          </option>
        `).join("")}
      </optgroup>
    `).join("");

    res.send(page("New Order", `
      <div class="card">
        <form method="GET">
          <label>Search Services</label>
          <input name="search" value="${esc(search)}" placeholder="Search Instagram, Facebook, YouTube...">
          <button type="submit">Search</button>
        </form>
      </div>

      <div class="card">
        <form method="POST">
          <label>Select Service</label>
          <select name="service_id" id="serviceSelect" required>
            <option value="">Choose a service</option>
            ${options}
          </select>

          <label>Post / Profile Link</label>
          <input name="link" type="url" placeholder="https://" required>

          <label>Quantity</label>
          <input name="quantity" id="quantityInput" type="number"
            min="100" max="10000000" step="1"
            placeholder="Minimum 100 - Maximum 10000000" required>

          <div style="background:#f3f4f6;color:#111;padding:15px;border-radius:10px;margin:15px 0">
            <div style="font-size:14px">Total Price</div>
            <div id="totalPrice" style="font-size:26px;font-weight:bold;margin-top:5px">₹0.00</div>
            <small id="priceDetails">Select service and quantity</small>
          </div>

          <button type="submit">Place Order</button>
        </form>
      </div>

      ${result.rows.length ? "" : "<p>No services found.</p>"}

      <script>
        (function () {
          const serviceSelect = document.getElementById("serviceSelect");
          const quantityInput = document.getElementById("quantityInput");
          const totalPrice = document.getElementById("totalPrice");
          const priceDetails = document.getElementById("priceDetails");

          function updatePrice() {
            const option = serviceSelect.options[serviceSelect.selectedIndex];
            const rate = Number(option.dataset.rate);
            const quantity = Number(quantityInput.value);
            const min = Number(option.dataset.min || 100);
            const max = Number(option.dataset.max || 10000000);

            quantityInput.min = min;
            quantityInput.max = max;

            if (!option.value || !Number.isFinite(rate) ||
                !Number.isInteger(quantity) || quantity < min || quantity > max) {
              totalPrice.textContent = "₹0.00";
              priceDetails.textContent = "Quantity must be between " + min + " and " + max;
              return;
            }

            const total = (rate * quantity) / 1000;
            totalPrice.textContent = "₹" + total.toFixed(2);
            priceDetails.textContent =
              quantity.toLocaleString("en-IN") +
              " × ₹" + rate.toFixed(2) + " per 1,000";
          }

          serviceSelect.addEventListener("change", updatePrice);
          quantityInput.addEventListener("input", updatePrice);
        })();
      </script>
    `, req.session.user));
  } catch (error) {
    console.error("New Order page error:", error);
    res.status(500).send("New Order page error");
  }
});

// PLACE NEW ORDER - MANUAL PENDING ORDER
app.post("/new-order", requireLogin, async (req, res) => {
  const client = await pool.connect();
  let transactionStarted = false;

  try {
    const serviceId = Number(req.body.service_id);
    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(serviceId) ||
        !Number.isInteger(quantity) ||
        !/^https?:\/\//i.test(link)) {
      throw new Error("Invalid order details.");
    }

    await client.query("BEGIN");
    transactionStarted = true;

    const userResult = await client.query(
      "SELECT * FROM users WHERE id=$1 FOR UPDATE",
      [req.session.user.id]
    );

    const serviceResult = await client.query(
      "SELECT * FROM services WHERE id=$1 AND active=TRUE",
      [serviceId]
    );

    if (!userResult.rowCount || !serviceResult.rowCount) {
      throw new Error("User or service not found.");
    }

    const user = userResult.rows[0];
    const service = serviceResult.rows[0];

    const minimum = Math.max(100, Number(service.min) || 100);
    const maximum = Math.min(10000000, Number(service.max) || 10000000);

    if (quantity < minimum || quantity > maximum) {
      throw new Error(`Quantity must be between ${minimum} and ${maximum}.`);
    }

    const charge = Number(service.rate) * quantity / 1000;

    if (!Number.isFinite(charge) || charge <= 0) {
      throw new Error("Invalid service price.");
    }

    if (Number(user.balance) < charge) {
      throw new Error("Insufficient wallet balance. Add funds first.");
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [charge, user.id]
    );

    await client.query(`
      INSERT INTO orders
      (user_id,service_id,link,quantity,charge,status)
      VALUES($1,$2,$3,$4,$5,'Pending')
    `, [user.id, service.id, link, quantity, charge]);

    await client.query("COMMIT");
    transactionStarted = false;

    res.redirect("/orders");
  } catch (error) {
    if (transactionStarted) await client.query("ROLLBACK");

    console.error("Order error:", error);

    res.status(400).send(page(
      "Order Error",
      `<div class="card">${esc(error.message)}<p><a href="/new-order">Go Back</a></p></div>`,
      req.session.user
    ));
  } finally {
    client.release();
  }
});

// MY ORDERS
app.get("/orders", requireLogin, async (req, res) => {
  try {
    const result = await db(`
      SELECT o.*,s.name AS service_name
      FROM orders o
      LEFT JOIN services s ON s.id=o.service_id
      WHERE o.user_id=$1
      ORDER BY o.id DESC LIMIT 200
    `, [req.session.user.id]);

    const rows = result.rows.map(o => `
      <tr>
        <td>${o.id}</td>
        <td>${esc(o.service_name || "Service")}</td>
        <td>${esc(o.quantity)}</td>
        <td>₹${Number(o.charge || 0).toFixed(2)}</td>
        <td>${esc(o.status)}</td>
        <td>${esc(o.provider_order_id || "-")}</td>
      </tr>
    `).join("");

    res.send(page("My Orders", `
      <div class="card tablewrap">
        <table>
          <tr><th>ID</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th><th>Provider ID</th></tr>
          ${rows}
        </table>
      </div>
    `, req.session.user));
  } catch (error) {
    console.error("Orders error:", error);
    res.status(500).send("Orders error");
  }
});

// ADD FUNDS PAGE
app.get("/add-funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
    <div class="card">
      <h3>Scan QR & Pay</h3>
      <p>Minimum Amount: ₹10</p>
      <p>Maximum Amount: ₹2,000</p>
      <div style="text-align:center;background:white;padding:15px;border-radius:10px;margin:15px 0">
        <img src="/public/payment-qr.png" alt="Payment QR Code"
          style="width:100%;max-width:280px;height:auto">
      </div>
      <p>Scan this QR using any UPI app.</p>
      <form method="POST">
        <label>Amount (₹)</label>
        <input name="amount" type="number" min="10" max="2000" step="1" required>
        <label>UTR / Transaction ID</label>
        <input name="utr" maxlength="10" placeholder="Enter payment UTR" required>
        <button type="submit">Submit Payment</button>
      </form>
    </div>
  `, req.session.user));
});

// ADD FUNDS SUBMIT
app.post("/add-funds", requireLogin, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const utr = String(req.body.utr || "").trim();

    if (!Number.isInteger(amount) || amount < 10 ||
        amount > 2000 || !utr || utr.length > 10) {
      return res.status(400).send("Amount must be ₹10-₹2,000 and valid UTR is required.");
    }

    await db(`
      INSERT INTO payments(user_id,amount,utr,status)
      VALUES($1,$2,$3,'Pending')
    `, [req.session.user.id, amount, utr]);

    res.send(page("Payment Submitted", `
      <div class="card">
        <h3>Payment Request Submitted</h3>
        <p>Amount: ₹${amount}</p>
        <p>Your payment is waiting for Admin approval.</p>
        <a class="btn" href="/dashboard">Go to Dashboard</a>
      </div>
    `, req.session.user));
  } catch (error) {
    console.error("Add Funds Error:", error);
    res.status(500).send("Payment submission failed.");
  }
});

// SUPPORT PAGE
app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
    <div class="card">
      <form method="POST">
        <label>Message</label>
        <textarea name="message" required maxlength="2000"></textarea>
        <button type="submit">Send Message</button>
      </form>
    </div>
  `, req.session.user));
});

// SUPPORT SUBMIT
app.post("/support", requireLogin, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message) return res.status(400).send("Message required.");

    await db(
      "INSERT INTO tickets(user_id,message) VALUES($1,$2)",
      [req.session.user.id, message]
    );

    res.redirect("/support");
  } catch (error) {
    console.error("Support error:", error);
    res.status(500).send("Support error");
  }
});

// RESELLER API KEY PAGE
app.get("/api-keys", requireLogin, async (req, res) => {
  try {
    const result = await db(
      `SELECT id,key_prefix,active,created_at
       FROM api_keys WHERE user_id=$1 ORDER BY id DESC`,
      [req.session.user.id]
    );

    const rows = result.rows.map(k => `
      <tr>
        <td>${k.id}</td>
        <td>${esc(k.key_prefix)}...</td>
        <td>${k.active ? "Enabled" : "Disabled"}</td>
        <td>
          <form method="POST" action="/api-keys/${k.id}/toggle">
            <button>${k.active ? "Disable" : "Enable"}</button>
          </form>
          <form method="POST" action="/api-keys/${k.id}/delete"
            onsubmit="return confirm('Revoke this API key?')">
            <button class="danger">Revoke</button>
          </form>
        </td>
      </tr>
    `).join("");

    res.send(page("My Reseller API", `
      <div class="card">
        <h3>Your API URL</h3>
        <input readonly value="${esc(process.env.APP_URL || "https://paneladminsmm-shop-1.onrender.com")}/api/v2">
        <form method="POST" action="/api-keys/create">
          <button class="success">Generate New API Key</button>
        </form>
      </div>
      <div class="card tablewrap">
        <h3>My API Keys</h3>
        <table>
          <tr><th>ID</th><th>Key Prefix</th><th>Status</th><th>Action</th></tr>
          ${rows}
        </table>
      </div>
      <div class="card">
        <h3>API Actions</h3>
        <p>services - View Services</p>
        <p>add - Place Order</p>
        <p>status - Check Order</p>
        <p>balance - Check Balance</p>
      </div>
    `, req.session.user));
  } catch (error) {
    console.error("API page error:", error);
    res.status(500).send("API page error");
  }
});

// CREATE API KEY
app.post("/api-keys/create", requireLogin, async (req, res) => {
  try {
    const key = "ROYAL_" + crypto.randomBytes(32).toString("hex");
    const hash = crypto.createHash("sha256").update(key).digest("hex");
    const prefix = key.slice(0, 12);

    await db(`
      INSERT INTO api_keys(user_id,key_hash,key_prefix)
      VALUES($1,$2,$3)
    `, [req.session.user.id, hash, prefix]);

    res.send(page("API Key Created", `
      <div class="card">
        <h3>Your New API Key</h3>
        <p>इसे सुरक्षित रखो। यह Key दोबारा पूरी दिखाई नहीं जाएगी।</p>
        <input id="newApiKey" readonly value="${esc(key)}">
        <button onclick="navigator.clipboard.writeText(document.getElementById('newApiKey').value)">
          Copy API Key
        </button>
        <p><a href="/api-keys">Back to API Management</a></p>
      </div>
    `, req.session.user));
  } catch (error) {
    console.error("Create API key error:", error);
    res.status(500).send("Could not create API key.");
  }
});

// ENABLE / DISABLE OWN API KEY
app.post("/api-keys/:id/toggle", requireLogin, async (req, res) => {
  try {
    await db(`
      UPDATE api_keys
      SET active=NOT active
      WHERE id=$1 AND user_id=$2
    `, [Number(req.params.id), req.session.user.id]);

    res.redirect("/api-keys");
  } catch (error) {
    console.error("API key toggle error:", error);
    res.status(500).send("Could not update API key.");
  }
});

// REVOKE OWN API KEY
app.post("/api-keys/:id/delete", requireLogin, async (req, res) => {
  try {
    await db(`
      DELETE FROM api_keys
      WHERE id=$1 AND user_id=$2
    `, [Number(req.params.id), req.session.user.id]);

    res.redirect("/api-keys");
  } catch (error) {
    console.error("API key revoke error:", error);
    res.status(500).send("Could not revoke API key.");
  }
});

// ROYAL PANEL RESELLER API
app.post("/api/v2", resellerApiLimit, async (req, res) => {
  const action = String(req.body.action || "").toLowerCase();
  const key = String(req.body.key || "");

  if (!key || !action) {
    return res.json({ error: "Invalid API request" });
  }

  const hash = crypto.createHash("sha256").update(key).digest("hex");

  try {
    const keyResult = await db(`
      SELECT a.user_id
      FROM api_keys a
      JOIN users u ON u.id=a.user_id
      WHERE a.key_hash=$1 AND a.active=TRUE
      LIMIT 1
    `, [hash]);

    if (!keyResult.rowCount) {
      return res.json({ error: "Invalid or disabled API key" });
    }

    const userId = keyResult.rows[0].user_id;

    if (action === "services") {
      const services = await db(`
        SELECT id,name,category,rate,min,max,description
        FROM services
        WHERE active=TRUE
        ORDER BY id
      `);

      return res.json(services.rows.map(s => ({
        service: s.id,
        name: s.name,
        type: "Default",
        category: s.category,
        rate: Number(s.rate).toFixed(4),
        min: s.min,
        max: s.max,
        description: s.description
      })));
    }

    if (action === "balance") {
      const result = await db(
        "SELECT balance FROM users WHERE id=$1",
        [userId]
      );

      return res.json({
        balance: Number(result.rows[0]?.balance || 0).toFixed(2),
        currency: "INR"
      });
    }

    if (action === "status") {
      const orderId = Number(req.body.order);

      if (!Number.isInteger(orderId) || orderId < 1) {
        return res.json({ error: "Invalid order ID" });
      }

      const result = await db(`
        SELECT id,status,charge,quantity
        FROM orders
        WHERE id=$1 AND user_id=$2
      `, [orderId, userId]);

      if (!result.rowCount) {
        return res.json({ error: "Order not found" });
      }

      const order = result.rows[0];

      return res.json({
        charge: Number(order.charge).toFixed(2),
        status: order.status,
        quantity: order.quantity
      });
    }

    if (action === "add") {
      const serviceId = Number(req.body.service);
      const quantity = Number(req.body.quantity);
      const link = String(req.body.link || "").trim();

      if (!Number.isInteger(serviceId) ||
          !Number.isInteger(quantity) ||
          !/^https?:\/\//i.test(link)) {
        return res.json({ error: "Invalid order details" });
      }

      const client = await pool.connect();
      let transactionStarted = false;

      try {
        await client.query("BEGIN");
        transactionStarted = true;

        const userResult = await client.query(
          "SELECT * FROM users WHERE id=$1 FOR UPDATE",
          [userId]
        );

        const serviceResult = await client.query(
          "SELECT * FROM services WHERE id=$1 AND active=TRUE",
          [serviceId]
        );

        if (!userResult.rowCount || !serviceResult.rowCount) {
          throw new Error("User or service not found");
        }

        const user = userResult.rows[0];
        const service = serviceResult.rows[0];

        if (quantity < Number(service.min) ||
            quantity > Number(service.max)) {
          throw new Error("Quantity outside service limits");
        }

        const charge = Number(service.rate) * quantity / 1000;

        if (!Number.isFinite(charge) || charge <= 0) {
          throw new Error("Invalid service price");
        }

        if (Number(user.balance) < charge) {
          throw new Error("Insufficient balance");
        }

        await client.query(
          "UPDATE users SET balance=balance-$1 WHERE id=$2",
          [charge, userId]
        );

        const order = await client.query(`
          INSERT INTO orders
          (user_id,service_id,link,quantity,charge,status)
          VALUES($1,$2,$3,$4,$5,'Pending')
          RETURNING id
        `, [userId, serviceId, link, quantity, charge]);

        await client.query("COMMIT");
        transactionStarted = false;

        return res.json({ order: order.rows[0].id });
      } catch (error) {
        if (transactionStarted) {
          await client.query("ROLLBACK");
        }
        console.error("API order error:", error.message);
        return res.json({ error: error.message || "Order failed" });
      } finally {
        client.release();
      }
    }

    return res.json({ error: "Invalid action" });

  } catch (error) {
    console.error("Reseller API error:", error.message);
    return res.json({ error: "API request failed" });
  }
});

// ADMIN DASHBOARD
app.get("/admin", requireAdmin, async (req, res) => {
  try {
    const [users, services, orders, payments] = await Promise.all([
      db("SELECT COUNT(*) FROM users"),
      db("SELECT COUNT(*) FROM services"),
      db("SELECT COUNT(*) FROM orders"),
      db("SELECT COUNT(*) FROM payments WHERE status='Pending'")
    ]);

    res.send(page("Admin Panel", `
      <div class="card"><h3>Users</h3>${users.rows[0].count}</div>
      <div class="card"><h3>Services</h3>${services.rows[0].count}</div>
      <div class="card"><h3>Orders</h3>${orders.rows[0].count}</div>
      <div class="card"><h3>Pending Payments</h3>${payments.rows[0].count}</div>
      <div class="card">
        <a class="btn" href="/admin/services">Manage Services</a>
        <a class="btn" href="/admin/payments">Payments</a>
        <a class="btn" href="/admin/orders">Orders</a>
        <a class="btn" href="/admin/api">API Management</a>
      </div>
    `, req.session.user));
  } catch (error) {
    console.error("Admin error:", error);
    res.status(500).send("Admin error");
  }
});

// ADMIN API MANAGEMENT
app.get("/admin/api", requireAdmin, async (req, res) => {
  try {
    const result = await db(`
      SELECT a.id,a.key_prefix,a.active,a.created_at,u.username
      FROM api_keys a
      JOIN users u ON u.id=a.user_id
      ORDER BY a.id DESC LIMIT 300
    `);

    const rows = result.rows.map(k => `
      <tr>
        <td>${k.id}</td>
        <td>${esc(k.username)}</td>
        <td>${esc(k.key_prefix)}...</td>
        <td>${k.active ? "Enabled" : "Disabled"}</td>
        <td>
          <form method="POST" action="/admin/api/${k.id}/toggle">
            <button>${k.active ? "Disable" : "Enable"}</button>
          </form>
        </td>
      </tr>
    `).join("");

    res.send(page("API Management", `
      <div class="card">
        <h3>ROYAL PANEL Reseller API</h3>
        <p>API URL:</p>
        <input readonly value="${esc(process.env.APP_URL || "https://paneladminsmm-shop-1.onrender.com")}/api/v2">
        <p>Reseller अपने Dashboard से API Key बना सकते हैं।</p>
      </div>
      <div class="card tablewrap">
        <table>
          <tr><th>ID</th><th>Reseller</th><th>Key Prefix</th><th>Status</th><th>Action</th></tr>
          ${rows}
        </table>
      </div>
    `, req.session.user));
  } catch (error) {
    console.error("Admin API page error:", error);
    res.status(500).send("Admin API page error");
  }
});

// ADMIN ENABLE / DISABLE API KEY
app.post("/admin/api/:id/toggle", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).send("Invalid API key ID.");
    }

    await db(
      "UPDATE api_keys SET active=NOT active WHERE id=$1",
      [id]
    );

    res.redirect("/admin/api");
  } catch (error) {
    console.error("Admin API toggle error:", error);
    res.status(500).send("Could not update API key.");
  }
});

// ADMIN SERVICES PAGE WITH SEARCH AND EDIT
app.get("/admin/services", requireAdmin, async (req, res) => {
  try {
    const search = String(req.query.search || "").trim().slice(0, 100);

    const result = search
      ? await db(`
          SELECT * FROM services
          WHERE name ILIKE $1
             OR category ILIKE $1
             OR COALESCE(provider_id,'') ILIKE $1
          ORDER BY id DESC LIMIT 300
        `, [`%${search}%`])
      : await db(`
          SELECT * FROM services
          ORDER BY id DESC LIMIT 300
        `);

    const rows = result.rows.map(s => `
      <tr>
        <td>${s.id}</td>
        <td>${esc(s.name)}</td>
        <td>${esc(s.category)}</td>
        <td>${esc(s.provider_id || "-")}</td>
        <td>₹${Number(s.rate).toFixed(2)}</td>
        <td>${s.min}</td>
        <td>${s.max}</td>
        <td>${s.active ? "Active" : "Off"}</td>
        <td>
          <a class="btn" href="/admin/services/${s.id}/edit">Edit</a>
          <form method="POST" action="/admin/services/${s.id}/toggle" style="margin-top:6px">
            <button type="submit">${s.active ? "Disable" : "Enable"}</button>
          </form>
        </td>
      </tr>
    `).join("");

    res.send(page("Manage Services", `
      <div class="card">
        <h3>Search Existing Service</h3>
        <form method="GET" action="/admin/services">
          <input name="search" value="${esc(search)}"
            placeholder="Search Provider ID, e.g. 13216">
          <button type="submit">Search</button>
        </form>
      </div>

      <div class="card">
        <h3>Bulk Service Control</h3>
        <p>एक क्लिक में सभी Services बंद या चालू करें।</p>
        <form method="POST" action="/admin/services/disable-all"
          onsubmit="return confirm('क्या आप सभी Services Disable करना चाहते हैं?')">
          <button type="submit" class="danger">Disable All Services</button>
        </form>
        <form method="POST" action="/admin/services/enable-all"
          onsubmit="return confirm('क्या आप सभी Services Enable करना चाहते हैं?')"
          style="margin-top:10px">
          <button type="submit" class="success">Enable All Services</button>
        </form>
      </div>

      <div class="card">
        <h3>Add Service</h3>
        <form method="POST" action="/admin/services">
          <label>Service Name</label>
          <input name="name" required>
          <label>Category</label>
          <select name="category">
            <option>Instagram</option>
            <option>Facebook</option>
            <option>YouTube</option>
            <option>TikTok</option>
            <option>WhatsApp</option>
            <option>Twitter</option>
            <option>Telegram</option>
            <option>Other</option>
          </select>
          <label>Provider Service ID</label>
          <input name="provider_id" required>
          <label>Rate per 1000 (₹)</label>
          <input name="rate" type="number" step="0.0001" min="0.0001" required>
          <label>Minimum</label>
          <input name="min" type="number" value="100" min="100" max="10000000" required>
          <label>Maximum</label>
          <input name="max" type="number" value="1000000" min="100" max="10000000" required>
          <label>Description</label>
          <textarea name="description"></textarea>
          <button type="submit">Add / Update Service</button>
        </form>
      </div>

      <div class="card tablewrap">
        <table>
          <tr>
            <th>ID</th><th>Name</th><th>Category</th>
            <th>Provider ID</th><th>Rate</th><th>Min</th>
            <th>Max</th><th>Status</th><th>Action</th>
          </tr>
          ${rows}
        </table>
        ${result.rows.length ? "" : "<p>No services found.</p>"}
      </div>
    `, req.session.user));

  } catch (error) {
    console.error("Services admin error:", error);
    res.status(500).send("Services admin error");
  }
});

// EDIT SERVICE PAGE
app.get("/admin/services/:id/edit", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).send("Invalid service ID.");
    }

    const result = await db(
      "SELECT * FROM services WHERE id=$1",
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).send("Service not found.");
    }

    const s = result.rows[0];

    res.send(page("Edit Service", `
      <div class="card">
        <h3>Update Existing Service</h3>
        <p>Database Service ID: ${s.id}</p>
        <form method="POST" action="/admin/services/${s.id}/edit">
          <label>Service Name</label>
          <input name="name" value="${esc(s.name)}" required>
          <label>Category</label>
          <input name="category" value="${esc(s.category)}" required>
          <label>Provider Service ID</label>
          <input name="provider_id" value="${esc(s.provider_id)}" required>
          <label>Rate per 1000 (₹)</label>
          <input name="rate" type="number" step="0.0001"
            min="0.0001" value="${Number(s.rate)}" required>
          <label>Minimum</label>
          <input name="min" type="number" min="100"
            max="10000000" value="${s.min}" required>
          <label>Maximum</label>
          <input name="max" type="number" min="100"
            max="10000000" value="${s.max}" required>
          <label>Description</label>
          <textarea name="description">${esc(s.description)}</textarea>
          <button type="submit">Save Changes</button>
          <a class="btn" href="/admin/services">Cancel</a>
        </form>
      </div>
    `, req.session.user));

  } catch (error) {
    console.error("Edit service page error:", error);
    res.status(500).send("Could not open edit service.");
  }
});

// UPDATE EXISTING SERVICE
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

    if (
      !Number.isInteger(id) || id < 1 ||
      !name || !category || !providerId ||
      !Number.isFinite(rate) || rate <= 0 ||
      !Number.isInteger(min) || min < 100 ||
      !Number.isInteger(max) || max < min ||
      max > 10000000
    ) {
      return res.status(400).send("Invalid service details.");
    }

    const result = await db(`
      UPDATE services
      SET provider_id=$1,
          name=$2,
          category=$3,
          rate=$4,
          min=$5,
          max=$6,
          description=$7
      WHERE id=$8
      RETURNING id
    `, [providerId, name, category, rate, min, max, description, id]);

    if (!result.rowCount) {
      return res.status(404).send("Service not found.");
    }

    res.redirect("/admin/services");
  } catch (error) {
    console.error("Update service error:", error);
    if (error.code === "23505") {
      return res.status(409).send("This Provider Service ID already belongs to another service.");
    }
    res.status(500).send("Could not update service.");
  }
});

// ADD SERVICE OR UPDATE EXISTING PROVIDER ID
app.post("/admin/services", requireAdmin, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const category = String(req.body.category || "Other").trim();
    const providerId = String(req.body.provider_id || "").trim();
    const rate = Number(req.body.rate);
    const min = Number(req.body.min);
    const max = Number(req.body.max);
    const description = String(req.body.description || "").trim();

    if (
      !name || !category || !providerId ||
      !Number.isFinite(rate) || rate <= 0 ||
      !Number.isInteger(min) ||
      !Number.isInteger(max) ||
      min < 100 || max < min || max > 10000000
    ) {
      return res.status(400).send("Invalid service details.");
    }

    const existing = await db(
      "SELECT id FROM services WHERE provider_id=$1 LIMIT 1",
      [providerId]
    );

    if (existing.rowCount) {
      await db(`
        UPDATE services
        SET name=$1,category=$2,rate=$3,min=$4,max=$5,
            description=$6,active=TRUE
        WHERE id=$7
      `, [name, category, rate, min, max, description, existing.rows[0].id]);
    } else {
      await db(`
        INSERT INTO services
        (provider_id,name,category,rate,min,max,description,active)
        VALUES($1,$2,$3,$4,$5,$6,$7,TRUE)
      `, [providerId, name, category, rate, min, max, description]);
    }

    res.redirect("/admin/services");
  } catch (error) {
    console.error("Add/update service error:", error);
    res.status(500).send("Could not add or update service.");
  }
});

// DISABLE ALL SERVICES
app.post("/admin/services/disable-all", requireAdmin, async (req, res) => {
  try {
    await db("UPDATE services SET active=FALSE WHERE active=TRUE");
    res.redirect("/admin/services");
  } catch (error) {
    console.error("Disable all services error:", error);
    res.status(500).send("Could not disable services.");
  }
});

// ENABLE ALL SERVICES
app.post("/admin/services/enable-all", requireAdmin, async (req, res) => {
  try {
    await db("UPDATE services SET active=TRUE WHERE active=FALSE");
    res.redirect("/admin/services");
  } catch (error) {
    console.error("Enable all services error:", error);
    res.status(500).send("Could not enable services.");
  }
});

// ENABLE / DISABLE ONE SERVICE
app.post("/admin/services/:id/toggle", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).send("Invalid service ID.");
    }

    await db(
      "UPDATE services SET active=NOT active WHERE id=$1",
      [id]
    );

    res.redirect("/admin/services");
  } catch (error) {
    console.error("Service toggle error:", error);
    res.status(500).send("Update error");
  }
});

// ADMIN PAYMENTS PAGE
app.get("/admin/payments", requireAdmin, async (req, res) => {
  try {
    const result = await db(`
      SELECT p.*,u.username
      FROM payments p
      LEFT JOIN users u ON u.id=p.user_id
      ORDER BY p.id DESC LIMIT 200
    `);

    const rows = result.rows.map(p => `
      <tr>
        <td>${p.id}</td>
        <td>${esc(p.username)}</td>
        <td>₹${Number(p.amount).toFixed(2)}</td>
        <td>${esc(p.utr)}</td>
        <td>${esc(p.status)}</td>
        <td>
          ${p.status === "Pending"
            ? `<form method="POST" action="/admin/payments/${p.id}/approve"><button>Approve</button></form>`
            : "-"}
        </td>
      </tr>
    `).join("");

    res.send(page("Payments", `
      <div class="card tablewrap">
        <table>
          <tr><th>ID</th><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>
          ${rows}
        </table>
      </div>
    `, req.session.user));
  } catch (error) {
    console.error("Payments error:", error);
    res.status(500).send("Payments error");
  }
});

// APPROVE PAYMENT
app.post("/admin/payments/:id/approve", requireAdmin, async (req, res) => {
  const client = await pool.connect();
  let transactionStarted = false;

  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const result = await client.query(
      "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
      [Number(req.params.id)]
    );

    if (!result.rowCount || result.rows[0].status !== "Pending") {
      throw new Error("Payment not found or already processed.");
    }

    const payment = result.rows[0];

    await client.query(
      "UPDATE users SET balance=balance+$1 WHERE id=$2",
      [payment.amount, payment.user_id]
    );

    await client.query(
      "UPDATE payments SET status='Approved' WHERE id=$1",
      [payment.id]
    );

    await client.query("COMMIT");
    transactionStarted = false;

    res.redirect("/admin/payments");
  } catch (error) {
    if (transactionStarted) await client.query("ROLLBACK");
    console.error("Approve payment error:", error);
    res.status(400).send(esc(error.message));
  } finally {
    client.release();
  }
});

// ADMIN ORDERS PAGE
app.get("/admin/orders", requireAdmin, async (req, res) => {
  try {
    const result = await db(`
      SELECT o.*,u.username,s.name AS service_name
      FROM orders o
      LEFT JOIN users u ON u.id=o.user_id
      LEFT JOIN services s ON s.id=o.service_id
      ORDER BY o.id DESC LIMIT 200
    `);

    const rows = result.rows.map(o => `
      <tr>
        <td>${o.id}</td>
        <td>${esc(o.username)}</td>
        <td>${esc(o.service_name || "Service")}</td>
        <td>${esc(o.quantity)}</td>
        <td>${esc(o.status)}</td>
        <td>${esc(o.provider_order_id || "-")}</td>
        <td>
          <form method="POST" action="/admin/orders/${o.id}/status">
            <select name="status">
              ${["Pending","Processing","In progress","Completed","Partial","Canceled","Failed"].map(x =>
                `<option ${o.status === x ? "selected" : ""}>${x}</option>`
              ).join("")}
            </select>
            <button>Save</button>
          </form>
        </td>
      </tr>
    `).join("");

    res.send(page("All Orders", `
      <div class="card tablewrap">
        <table>
          <tr>
            <th>ID</th><th>User</th><th>Service</th>
            <th>Qty</th><th>Status</th><th>Provider ID</th><th>Update</th>
          </tr>
          ${rows}
        </table>
      </div>
    `, req.session.user));
  } catch (error) {
    console.error("Admin orders error:", error);
    res.status(500).send("Admin orders error");
  }
});

// UPDATE ORDER STATUS
app.post("/admin/orders/:id/status", requireAdmin, async (req, res) => {
  try {
    const allowed = [
      "Pending", "Processing", "In progress",
      "Completed", "Partial", "Canceled", "Failed"
    ];

    const status = String(req.body.status || "");

    if (!allowed.includes(status)) {
      return res.status(400).send("Invalid status");
    }

    await db(
      "UPDATE orders SET status=$1 WHERE id=$2",
      [status, Number(req.params.id)]
    );

    res.redirect("/admin/orders");
  } catch (error) {
    console.error("Status update error:", error);
    res.status(500).send("Status update error");
  }
});

// START SERVER
async function start() {
  try {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is missing.");
    }

    await setupDatabase();

    const server = app.listen(
      process.env.PORT || 3000,
      () => console.log("ROYAL PANEL running.")
    );

    process.on("SIGTERM", async () => {
      server.close(async () => {
        await pool.end();
        process.exit(0);
      });
    });

  } catch (error) {
    console.error("SERVER START FAILED:", error);
    process.exit(1);
  }
}

start();
