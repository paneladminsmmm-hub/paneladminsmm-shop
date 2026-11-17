
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const {
  providerAddOrder,
  providerOrderStatus
} = require("./src/provider");

const app = express();

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

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

function page(title, content, user = null) {
  const nav = user ? `
    <nav>
      <a href="/dashboard">Dashboard</a>
      <a href="/services">Services</a>
      <a href="/new-order">New Order</a>
      <a href="/orders">My Orders</a>
      <a href="/add-funds">Add Funds</a>
      <a href="/support">Support</a>
      ${user.is_admin ? '<a href="/admin">Admin Panel</a>' : ""}
      <a href="/logout">Logout</a>
    </nav>
  ` : `
    <nav><a href="/login">Login</a><a href="/register">Register</a></nav>
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
main{max-width:950px;margin:22px auto;padding:0 14px}
.card{background:#1b2130;border:1px solid #30394c;border-radius:12px;padding:17px;margin-bottom:15px}
input,select,textarea{width:100%;padding:12px;margin:7px 0 13px;border:1px solid #414b60;border-radius:7px;background:#101723;color:white}
button,.btn{display:inline-block;border:0;background:#e63946;color:white;padding:12px 16px;border-radius:7px;cursor:pointer}
table{width:100%;border-collapse:collapse;min-width:550px}
th,td{padding:10px;border-bottom:1px solid #384154;text-align:left;font-size:13px}
.tablewrap{overflow-x:auto}
small{color:#aeb8c9}
</style>
</head>
<body>
<header><h2>ROYAL PANEL</h2><small>Panel Admin SMM.shop</small></header>
${nav}
<main><h2>${esc(title)}</h2>${content}</main>
</body>
</html>`;
}

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
      min INTEGER DEFAULT 1,
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
    ADD COLUMN IF NOT EXISTS min INTEGER DEFAULT 1,
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
    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      message TEXT,
      status TEXT DEFAULT 'Open',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Configure admin through Render Environment Variables.
  const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const adminUsername = String(process.env.ADMIN_USERNAME || "").trim();
  const adminPassword = String(process.env.ADMIN_PASSWORD || "");

  if (adminEmail && adminUsername && adminPassword) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail)) {
      throw new Error("ADMIN_EMAIL is invalid.");
    }

    const existing = await db(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1) OR username=$2 LIMIT 1",
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
        INSERT INTO users(email,username,password_hash,balance,is_admin)
        VALUES($1,$2,$3,0,TRUE)
      `, [adminEmail, adminUsername, hash]);
    }

    console.log("Admin account configured.");
  } else {
    console.log("Admin setup skipped: set ADMIN_EMAIL, ADMIN_USERNAME and ADMIN_PASSWORD.");
  }
}

app.get("/health", (req, res) => res.send("ROYAL PANEL OK"));

app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/dashboard" : "/login");
});

// REGISTER: EMAIL + USERNAME + PASSWORD
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

app.post("/register", authLimit, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).send(page("Register", "<div class='card'>Enter a valid email address. <a href='/register'>Try again</a></div>"));
    }

    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
      return res.status(400).send(page("Register", "<div class='card'>Username must be 3-30 letters, numbers or underscores. <a href='/register'>Try again</a></div>"));
    }

    if (password.length < 6) {
      return res.status(400).send(page("Register", "<div class='card'>Password must be at least 6 characters. <a href='/register'>Try again</a></div>"));
    }

    const exists = await db(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1) OR username=$2",
      [email, username]
    );

    if (exists.rowCount) {
      return res.status(409).send(page("Register", "<div class='card'>Email or username already exists. <a href='/register'>Try again</a></div>"));
    }

    const hash = await bcrypt.hash(password, 12);

    await db(`
      INSERT INTO users(email,username,password_hash,balance,is_admin)
      VALUES($1,$2,$3,0,FALSE)
    `, [email, username, hash]);

    res.redirect("/login");
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).send(page("Register Error", "<div class='card'>Registration failed. Please try again.</div>"));
  }
});

// LOGIN: EMAIL + PASSWORD
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

app.post("/login", authLimit, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await db(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
      [email]
    );

    if (!result.rowCount) {
      return res.status(401).send(page("Login Failed", "<div class='card'>Email or password is incorrect. <a href='/login'>Try again</a></div>"));
    }

    const user = result.rows[0];
    const valid = user.password_hash &&
      await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).send(page("Login Failed", "<div class='card'>Email or password is incorrect. <a href='/login'>Try again</a></div>"));
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

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

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
      </div>
    `, req.session.user));
  } catch (error) {
    res.status(500).send("Dashboard error");
  }
});

app.get("/services", requireLogin, async (req, res) => {
  try {
    const result = await db(`
      SELECT category,COUNT(*) AS total
      FROM services WHERE active=TRUE
      GROUP BY category ORDER BY category
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
    res.status(500).send("Services error");
  }
});

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
          WHERE active=TRUE ORDER BY category,name LIMIT 500
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
          <option value="${s.id}">
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
          <button>Search</button>
        </form>
      </div>
      <div class="card">
        <form method="POST">
          <label>Select Service</label>
          <select name="service_id" required>
            <option value="">Choose a service</option>
            ${options}
          </select>
          <label>Post / Profile Link</label>
          <input name="link" type="url" placeholder="https://" required>
          <label>Quantity</label>
          <input name="quantity" type="number" min="1" required>
          <button>Place Order</button>
        </form>
      </div>
      ${result.rows.length ? "" : "<p>No services found.</p>"}
    `, req.session.user));
  } catch (error) {
    console.error(error);
    res.status(500).send("New Order page error");
  }
});

app.post("/new-order", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    const serviceId = Number(req.body.service_id);
    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(serviceId) ||
        !Number.isInteger(quantity) || quantity < 1 ||
        !/^https?:\/\//i.test(link)) {
      throw new Error("Invalid order details.");
    }

    await client.query("BEGIN");

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

    if (quantity < Number(service.min) || quantity > Number(service.max)) {
      throw new Error(`Quantity must be between ${service.min} and ${service.max}.`);
    }

    if (!service.provider_id) {
      throw new Error("Provider ID missing for this service.");
    }

    const charge = Number(service.rate) * quantity / 1000;

    if (Number(user.balance) < charge) {
      throw new Error("Insufficient wallet balance. Add funds first.");
    }

    const providerResult = await providerAddOrder(
      service.provider_id,
      link,
      quantity
    );

    const providerOrderId =
      providerResult?.order ??
      providerResult?.order_id ??
      providerResult?.data?.order;

    if (!providerOrderId) {
      throw new Error("Provider did not return an order ID.");
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [charge, user.id]
    );

    await client.query(`
      INSERT INTO orders
      (user_id,service_id,provider_order_id,link,quantity,charge,status)
      VALUES($1,$2,$3,$4,$5,$6,'Processing')
    `, [user.id, service.id, String(providerOrderId), link, quantity, charge]);

    await client.query("COMMIT");
    res.redirect("/orders");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Order error:", error);
    res.status(400).send(page("Order Error", `
      <div class="card">${esc(error.message)}<p><a href="/new-order">Go Back</a></p></div>
    `, req.session.user));
  } finally {
    client.release();
  }
});

app.get("/orders", requireLogin, async (req, res) => {
  try {
    const result = await db(`
      SELECT o.*,s.name AS service_name
      FROM orders o LEFT JOIN services s ON s.id=o.service_id
      WHERE o.user_id=$1 ORDER BY o.id DESC LIMIT 200
    `, [req.session.user.id]);

    const rows = result.rows.map(o => `
      <tr>
        <td>${o.id}</td><td>${esc(o.service_name || "Service")}</td>
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
    res.status(500).send("Orders error");
  }
});

app.get("/add-funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
    <div class="card">
      <p>Submit your payment amount and UTR. Admin approval is required.</p>
      <form method="POST">
        <label>Amount (₹)</label>
        <input name="amount" type="number" min="100" max="2000" required>
        <label>UTR / Transaction ID</label>
        <input name="utr" required maxlength="100">
        <button>Submit Payment</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/add-funds", requireLogin, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const utr = String(req.body.utr || "").trim();

    if (!Number.isFinite(amount) || amount < 100 || amount > 2000 || !utr) {
      return res.status(400).send("Invalid amount or UTR.");
    }

    await db(`
      INSERT INTO payments(user_id,amount,utr,status)
      VALUES($1,$2,$3,'Pending')
    `, [req.session.user.id, amount, utr]);

    res.send(page("Payment Submitted", "<div class='card'>Payment submitted. Wait for admin approval.</div>", req.session.user));
  } catch (error) {
    res.status(500).send("Payment error");
  }
});

app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
    <div class="card">
      <form method="POST">
        <label>Message</label>
        <textarea name="message" required maxlength="2000"></textarea>
        <button>Send Message</button>
      </form>
    </div>
  `, req.session.user));
});

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
    res.status(500).send("Support error");
  }
});

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
      </div>
    `, req.session.user));
  } catch (error) {
    res.status(500).send("Admin error");
  }
});

app.get("/admin/services", requireAdmin, async (req, res) => {
  try {
    const result = await db("SELECT * FROM services ORDER BY category,name");

    const rows = result.rows.map(s => `
      <tr>
        <td>${s.id}</td><td>${esc(s.name)}</td>
        <td>${esc(s.category)}</td><td>${esc(s.provider_id || "-")}</td>
        <td>₹${Number(s.rate).toFixed(2)}</td>
        <td>${s.active ? "Active" : "Off"}</td>
        <td><form method="POST" action="/admin/services/${s.id}/toggle"><button>${s.active ? "Disable" : "Enable"}</button></form></td>
      </tr>
    `).join("");

    res.send(page("Manage Services", `
      <div class="card">
        <h3>Add Service</h3>
        <form method="POST">
          <label>Service Name</label><input name="name" required>
          <label>Category</label>
          <select name="category">
            <option>Instagram</option><option>Facebook</option>
            <option>YouTube</option><option>TikTok</option>
            <option>WhatsApp</option><option>Twitter</option>
            <option>Telegram</option><option>Other</option>
          </select>
          <label>Provider Service ID</label><input name="provider_id" required>
          <label>Rate per 1000 (₹)</label><input name="rate" type="number" step="0.0001" required>
          <label>Minimum</label><input name="min" type="number" value="100" required>
          <label>Maximum</label><input name="max" type="number" value="100000" required>
          <label>Description</label><textarea name="description"></textarea>
          <button>Add Service</button>
        </form>
      </div>
      <div class="card tablewrap">
        <table><tr><th>ID</th><th>Name</th><th>Category</th><th>Provider ID</th><th>Rate</th><th>Status</th><th>Action</th></tr>${rows}</table>
      </div>
    `, req.session.user));
  } catch (error) {
    res.status(500).send("Services admin error");
  }
});

app.post("/admin/services", requireAdmin, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const category = String(req.body.category || "Other").trim();
    const providerId = String(req.body.provider_id || "").trim();
    const rate = Number(req.body.rate);
    const min = Number(req.body.min);
    const max = Number(req.body.max);
    const description = String(req.body.description || "").trim();

    if (!name || !providerId || !Number.isFinite(rate) ||
        !Number.isInteger(min) || !Number.isInteger(max) ||
        rate < 0 || min < 1 || max < min) {
      return res.status(400).send("Invalid service details.");
    }

    await db(`
      INSERT INTO services(name,category,provider_id,rate,min,max,description,active)
      VALUES($1,$2,$3,$4,$5,$6,$7,TRUE)
    `, [name, category, providerId, rate, min, max, description]);

    res.redirect("/admin/services");
  } catch (error) {
    res.status(500).send("Could not add service.");
  }
});

app.post("/admin/services/:id/toggle", requireAdmin, async (req, res) => {
  try {
    await db("UPDATE services SET active=NOT active WHERE id=$1", [Number(req.params.id)]);
    res.redirect("/admin/services");
  } catch (error) {
    res.status(500).send("Update error");
  }
});

app.get("/admin/payments", requireAdmin, async (req, res) => {
  try {
    const result = await db(`
      SELECT p.*,u.username
      FROM payments p LEFT JOIN users u ON u.id=p.user_id
      ORDER BY p.id DESC LIMIT 200
    `);

    const rows = result.rows.map(p => `
      <tr>
        <td>${p.id}</td><td>${esc(p.username)}</td>
        <td>₹${Number(p.amount).toFixed(2)}</td>
        <td>${esc(p.utr)}</td><td>${esc(p.status)}</td>
        <td>${p.status === "Pending" ? `<form method="POST" action="/admin/payments/${p.id}/approve"><button>Approve</button></form>` : "-"}</td>
      </tr>
    `).join("");

    res.send(page("Payments", `
      <div class="card tablewrap">
        <table><tr><th>ID</th><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>${rows}</table>
      </div>
    `, req.session.user));
  } catch (error) {
    res.status(500).send("Payments error");
  }
});

app.post("/admin/payments/:id/approve", requireAdmin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

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
    res.redirect("/admin/payments");
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).send(esc(error.message));
  } finally {
    client.release();
  }
});

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
        <td>${o.id}</td><td>${esc(o.username)}</td>
        <td>${esc(o.service_name || "Service")}</td>
        <td>${esc(o.quantity)}</td><td>${esc(o.status)}</td>
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
        <table><tr><th>ID</th><th>User</th><th>Service</th><th>Qty</th><th>Status</th><th>Provider ID</th><th>Update</th></tr>${rows}</table>
      </div>
    `, req.session.user));
  } catch (error) {
    res.status(500).send("Admin orders error");
  }
});

app.post("/admin/orders/:id/status", requireAdmin, async (req, res) => {
  try {
    const allowed = ["Pending","Processing","In progress","Completed","Partial","Canceled","Failed"];
    const status = String(req.body.status || "");

    if (!allowed.includes(status)) return res.status(400).send("Invalid status");

    await db("UPDATE orders SET status=$1 WHERE id=$2", [
      status, Number(req.params.id)
    ]);

    res.redirect("/admin/orders");
  } catch (error) {
    res.status(500).send("Status update error");
  }
});

async function syncProviderStatuses() {
  try {
    const result = await db(`
      SELECT id,provider_order_id FROM orders
      WHERE provider_order_id IS NOT NULL
      AND status NOT IN ('Completed','Canceled','Failed')
      ORDER BY id DESC LIMIT 30
    `);

    for (const order of result.rows) {
      try {
        const data = await providerOrderStatus(order.provider_order_id);
        const raw = String(data?.status ?? data?.data?.status ?? "").trim().toLowerCase();

        const mapping = {
          pending: "Pending",
          processing: "Processing",
          "in progress": "In progress",
          completed: "Completed",
          partial: "Partial",
          canceled: "Canceled",
          cancelled: "Canceled",
          failed: "Failed"
        };

        if (mapping[raw]) {
          await db("UPDATE orders SET status=$1 WHERE id=$2", [mapping[raw], order.id]);
        }
      } catch (error) {
        console.error("Provider status error:", error.message);
      }
    }
  } catch (error) {
    console.error("Status sync error:", error.message);
  }
}

async function start() {
  try {
    await setupDatabase();

    const server = app.listen(process.env.PORT || 3000, () => {
      console.log("ROYAL PANEL running.");
    });

    const timer = setInterval(syncProviderStatuses, 60000);
    timer.unref();

    process.on("SIGTERM", async () => {
      clearInterval(timer);
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
