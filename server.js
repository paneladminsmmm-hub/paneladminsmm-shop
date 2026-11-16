
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(session({
  secret: process.env.SESSION_SECRET || "royal-panel-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

const PORT = process.env.PORT || 3000;
const platforms = ["Instagram", "Facebook", "YouTube", "TikTok", "Telegram", "WhatsApp", "Twitter"];

function esc(value = "") {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  }[c]));
}

function money(value) {
  return "₹" + Number(value || 0).toFixed(2);
}

function page(title, content, user = null) {
  const nav = user ? `
    <nav>
      <a href="/dashboard">Dashboard</a>
      <a href="/new-order">New Order</a>
      <a href="/orders">My Orders</a>
      <a href="/add-funds">Add Funds</a>
      <a href="/support">Support</a>
      ${user.role === "admin" ? '<a href="/admin">Admin Panel</a>' : ""}
      <a href="/logout">Logout</a>
    </nav>` : "";

  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${esc(title)} - Royal Panel</title>
    <style>
      *{box-sizing:border-box}
      body{margin:0;background:#f3f4f6;color:#171717;font-family:Arial,sans-serif}
      header{background:#111;color:white;padding:17px 20px;border-bottom:4px solid #dc2626}
      header h2{margin:0;color:#fff} header span{color:#ef4444}
      nav{display:flex;gap:8px;flex-wrap:wrap;background:#202020;padding:12px 16px}
      nav a{color:white;text-decoration:none;padding:9px 11px;border-radius:7px;font-size:14px}
      nav a:hover{background:#dc2626}
      main{max-width:1050px;margin:22px auto;padding:0 14px}
      .card{background:white;border:1px solid #e5e7eb;border-radius:12px;padding:17px;margin-bottom:15px;box-shadow:0 2px 7px #00000008}
      h1{font-size:24px;margin:5px 0 18px}h3{margin:4px 0 12px}
      input,select,textarea{width:100%;padding:12px;border:1px solid #d1d5db;border-radius:8px;margin:7px 0 13px;font-size:15px;background:white}
      button,.btn{display:inline-block;border:0;background:#dc2626;color:white;padding:11px 16px;border-radius:8px;text-decoration:none;font-size:14px;cursor:pointer}
      button:hover,.btn:hover{background:#b91c1c}
      .muted{color:#6b7280;font-size:13px}.red{color:#dc2626}
      .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:12px}
      .platform{display:block;text-align:center;text-decoration:none;color:#111;background:#fff;border:1px solid #ddd;border-radius:12px;padding:18px 8px;font-weight:bold}
      .platform:hover{border:2px solid #dc2626;padding:17px 7px}
      .emoji{display:block;font-size:30px;margin-bottom:9px}
      .service{border:1px solid #e5e7eb;border-radius:9px;padding:12px;margin:9px 0}
      .row{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center}
      .notice{background:#fff7ed;border:1px solid #fed7aa;padding:12px;border-radius:8px;margin:10px 0}
      table{width:100%;border-collapse:collapse;background:white}
      th,td{text-align:left;padding:10px;border-bottom:1px solid #eee;font-size:13px}
      .tablewrap{overflow-x:auto}.small{font-size:12px}
      @media(max-width:600px){main{margin:14px auto}h1{font-size:21px}nav a{font-size:12px;padding:8px}}
    </style>
  </head>
  <body>
    <header><h2>ROYAL <span>PANEL</span></h2></header>
    ${nav}
    <main>${content}</main>
  </body>
  </html>`;
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  if (req.session.user.role !== "admin") {
    return res.status(403).send(page("Access denied", "<div class='card'>Admin access required.</div>", req.session.user));
  }
  next();
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(150),
      email VARCHAR(200),
      password TEXT,
      balance NUMERIC DEFAULT 0,
      role VARCHAR(30) DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Safe additions for older databases; existing records are not deleted.
  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS name VARCHAR(150),
      ADD COLUMN IF NOT EXISTS email VARCHAR(200),
      ADD COLUMN IF NOT EXISTS password TEXT,
      ADD COLUMN IF NOT EXISTS balance NUMERIC DEFAULT 0,
      ADD COLUMN IF NOT EXISTS role VARCHAR(30) DEFAULT 'user',
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      provider_id TEXT,
      name TEXT,
      category TEXT,
      rate NUMERIC DEFAULT 0,
      min INTEGER DEFAULT 1,
      max INTEGER DEFAULT 100000,
      description TEXT,
      active BOOLEAN DEFAULT TRUE,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE services
      ADD COLUMN IF NOT EXISTS provider_id TEXT,
      ADD COLUMN IF NOT EXISTS name TEXT,
      ADD COLUMN IF NOT EXISTS category TEXT,
      ADD COLUMN IF NOT EXISTS rate NUMERIC DEFAULT 0,
      ADD COLUMN IF NOT EXISTS min INTEGER DEFAULT 1,
      ADD COLUMN IF NOT EXISTS max INTEGER DEFAULT 100000,
      ADD COLUMN IF NOT EXISTS description TEXT,
      ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE,
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      service_id INTEGER,
      provider_order_id TEXT,
      link TEXT,
      quantity INTEGER,
      charge NUMERIC,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS user_id INTEGER,
      ADD COLUMN IF NOT EXISTS service_id INTEGER,
      ADD COLUMN IF NOT EXISTS provider_order_id TEXT,
      ADD COLUMN IF NOT EXISTS link TEXT,
      ADD COLUMN IF NOT EXISTS quantity INTEGER,
      ADD COLUMN IF NOT EXISTS charge NUMERIC,
      ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Pending',
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      amount NUMERIC,
      utr TEXT,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS user_id INTEGER,
      ADD COLUMN IF NOT EXISTS amount NUMERIC,
      ADD COLUMN IF NOT EXISTS utr TEXT,
      ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Pending',
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      message TEXT,
      status TEXT DEFAULT 'Open',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE tickets
      ADD COLUMN IF NOT EXISTS user_id INTEGER,
      ADD COLUMN IF NOT EXISTS message TEXT,
      ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Open',
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  // Promote only the email configured by the site owner.
  if (process.env.ADMIN_EMAIL) {
    await pool.query(
      "UPDATE users SET role='admin' WHERE LOWER(email)=LOWER($1)",
      [process.env.ADMIN_EMAIL]
    );
  }
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.send("Royal Panel is running");
  } catch (err) {
    res.status(500).send("Database connection error");
  }
});

app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/dashboard" : "/login");
});

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h1>Create Account</h1>
      <form method="POST" action="/register">
        <label>Full Name</label><input name="name" required>
        <label>Email</label><input name="email" type="email" required>
        <label>Password</label><input name="password" type="password" minlength="6" required>
        <button>Create Account</button>
      </form>
      <p>Already registered? <a href="/login">Login</a></p>
    </div>`));
});

app.post("/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || password.length < 6) {
      return res.send(page("Register", "<div class='card'>Please enter valid details. Password must be at least 6 characters.</div>"));
    }

    const exists = await pool.query("SELECT id FROM users WHERE LOWER(email)=LOWER($1)", [email]);
    if (exists.rows.length) {
      return res.send(page("Register", "<div class='card'>This email is already registered. <a href='/login'>Login</a></div>"));
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users(name,email,password,balance,role) VALUES($1,$2,$3,0,'user') RETURNING id,name,email,role,balance",
      [name, email, hash]
    );

    req.session.user = result.rows[0];
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).send(page("Error", "<div class='card'>Registration failed. Please try again.</div>"));
  }
});

app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card">
      <h1>Customer Login</h1>
      <form method="POST" action="/login">
        <label>Email</label><input name="email" type="email" required>
        <label>Password</label><input name="password" type="password" required>
        <button>Login</button>
      </form>
      <p>New customer? <a href="/register">Create Account</a></p>
    </div>`));
});

app.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const result = await pool.query("SELECT * FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1", [email]);

    if (!result.rows.length) {
      return res.status(401).send(page("Login", "<div class='card'>Email or password is incorrect. <a href='/login'>Try again</a></div>"));
    }

    const user = result.rows[0];
    let valid = false;

    if (String(user.password || "").startsWith("$2")) {
      valid = await bcrypt.compare(password, user.password);
    } else {
      // Supports older accounts that stored a plain password.
      valid = password === String(user.password || "");
      if (valid) {
        const hash = await bcrypt.hash(password, 12);
        await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, user.id]);
      }
    }

    if (!valid) {
      return res.status(401).send(page("Login", "<div class='card'>Email or password is incorrect. <a href='/login'>Try again</a></div>"));
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role || "user",
      balance: user.balance || 0
    };
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).send(page("Error", "<div class='card'>Login error. Please check the server logs.</div>"));
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const balance = await pool.query("SELECT balance FROM users WHERE id=$1", [user.id]);
    const orders = await pool.query("SELECT COUNT(*) FROM orders WHERE user_id=$1", [user.id]);
    const payments = await pool.query("SELECT COUNT(*) FROM payments WHERE user_id=$1", [user.id]);

    res.send(page("Dashboard", `
      <h1>Welcome, ${esc(user.name || "Customer")}!</h1>
      <div class="grid">
        <div class="card"><div class="muted">Available Balance</div><h2>${money(balance.rows[0]?.balance)}</h2></div>
        <div class="card"><div class="muted">Total Orders</div><h2>${orders.rows[0].count}</h2></div>
        <div class="card"><div class="muted">Payment Requests</div><h2>${payments.rows[0].count}</h2></div>
      </div>
      <div class="card">
        <h3>Royal Panel Services</h3>
        <p>Choose a platform to view its services.</p>
        <a class="btn" href="/new-order">Place New Order</a>
        <a class="btn" href="/add-funds">Add Funds</a>
      </div>`, user));
  } catch (err) {
    console.error("Dashboard error:", err.message);
    res.status(500).send(page("Error", "<div class='card'>Dashboard could not load.</div>", req.session.user));
  }
});

app.get("/new-order", requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const platform = String(req.query.platform || "");
    const search = String(req.query.q || "").trim();

    if (!platforms.includes(platform)) {
      const icons = {
        Instagram: "📸", Facebook: "📘", YouTube: "▶️",
        TikTok: "🎵", Telegram: "✈️", WhatsApp: "🟢", Twitter: "𝕏"
      };

      const cards = platforms.map(p => `
        <a class="platform" href="/new-order?platform=${encodeURIComponent(p)}">
          <span class="emoji">${icons[p]}</span>${p}
        </a>`).join("");

      return res.send(page("New Order", `
        <h1>Select Platform</h1>
        <div class="grid">${cards}</div>`, user));
    }

    const result = await pool.query(
      `SELECT id,name,category,rate,min,max,description
       FROM services
       WHERE active=TRUE
       AND category ILIKE $1
       AND ($2='' OR name ILIKE $3 OR description ILIKE $3)
       ORDER BY id DESC`,
      [`%${platform}%`, search, `%${search}%`]
    );

    const services = result.rows.map(s => `
      <div class="service">
        <div class="row">
          <strong>${esc(s.name)}</strong>
          <strong>${money(s.rate)} / 1K</strong>
        </div>
        <p class="muted">${esc(s.description || "")}</p>
        <p class="small">Min: ${esc(s.min)} | Max: ${esc(s.max)}</p>
        <form method="POST" action="/orders">
          <input type="hidden" name="service_id" value="${s.id}">
          <label>Post / Profile Link</label>
          <input name="link" type="url" placeholder="https://..." required>
          <label>Quantity</label>
          <input name="quantity" type="number" min="${Number(s.min) || 1}" max="${Number(s.max) || 100000}" required>
          <button>Place Order</button>
        </form>
      </div>`).join("");

    res.send(page("New Order", `
      <div class="row">
        <h1>${esc(platform)} Services</h1>
        <a href="/new-order">← All Platforms</a>
      </div>
      <div class="card">
        <form method="GET" action="/new-order">
          <input type="hidden" name="platform" value="${esc(platform)}">
          <input name="q" value="${esc(search)}" placeholder="Search ${esc(platform)} services...">
          <button>Search</button>
        </form>
      </div>
      ${services || `<div class="card">No active ${esc(platform)} services found. Please contact Admin.</div>`}`,
      user));
  } catch (err) {
    console.error("Services error:", err.message);
    res.status(500).send(page("Error", "<div class='card'>Services could not load.</div>", req.session.user));
  }
});

app.post("/orders", requireLogin, async (req, res) => {
  const client = await pool.connect();
  try {
    const serviceId = Number(req.body.service_id);
    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(serviceId) || !Number.isInteger(quantity) || quantity < 1 || !link.startsWith("http")) {
      return res.status(400).send(page("Order Error", "<div class='card'>Please enter a valid link and quantity.</div>", req.session.user));
    }

    await client.query("BEGIN");
    const serviceResult = await client.query(
      "SELECT * FROM services WHERE id=$1 AND active=TRUE FOR UPDATE",
      [serviceId]
    );

    if (!serviceResult.rows.length) throw new Error("Service not available");

    const service = serviceResult.rows[0];
    if (quantity < Number(service.min) || quantity > Number(service.max)) {
      throw new Error(`Quantity must be between ${service.min} and ${service.max}`);
    }

    const charge = Number((Number(service.rate) * quantity / 1000).toFixed(2));
    const userResult = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.session.user.id]
    );

    if (!userResult.rows.length || Number(userResult.rows[0].balance) < charge) {
      throw new Error("Insufficient balance. Please Add Funds.");
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [charge, req.session.user.id]
    );

    await client.query(
      `INSERT INTO orders(user_id,service_id,link,quantity,charge,status)
       VALUES($1,$2,$3,$4,$5,'Pending')`,
      [req.session.user.id, serviceId, link, quantity, charge]
    );

    await client.query("COMMIT");
    res.redirect("/orders");
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(400).send(page("Order Error", `<div class="card">${esc(err.message)}<p><a href="/new-order">Back to Services</a></p></div>`, req.session.user));
  } finally {
    client.release();
  }
});

app.get("/orders", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*,s.name AS service_name,s.category
       FROM orders o LEFT JOIN services s ON s.id=o.service_id
       WHERE o.user_id=$1 ORDER BY o.id DESC`,
      [req.session.user.id]
    );

    const rows = result.rows.map(o => `
      <tr>
        <td>${o.id}</td><td>${esc(o.service_name || "Service")}</td>
        <td>${esc(o.quantity)}</td><td>${money(o.charge)}</td>
        <td>${esc(o.status)}</td><td>${esc(o.created_at)}</td>
      </tr>`).join("");

    res.send(page("My Orders", `
      <h1>My Orders</h1>
      <div class="card tablewrap"><table>
        <tr><th>ID</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th><th>Date</th></tr>
        ${rows || "<tr><td colspan='6'>No orders yet.</td></tr>"}
      </table></div>`, req.session.user));
  } catch (err) {
    console.error("Orders error:", err.message);
    res.status(500).send(page("Error", "<div class='card'>Orders could not load.</div>", req.session.user));
  }
});

app.get("/add-funds", requireLogin, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM payments WHERE user_id=$1 ORDER BY id DESC",
    [req.session.user.id]
  );

  const rows = result.rows.map(p => `
    <tr><td>${p.id}</td><td>${money(p.amount)}</td>
    <td>${esc(p.utr)}</td><td>${esc(p.status)}</td><td>${esc(p.created_at)}</td></tr>`).join("");

  res.send(page("Add Funds", `
    <h1>Add Funds</h1>
    <div class="card">
      <div class="notice">Minimum Add Funds: ₹100 | Maximum: ₹2000</div>
      <p>Payment verification will be done manually by Admin.</p>
      <form method="POST" action="/add-funds">
        <label>Amount (₹)</label><input type="number" name="amount" min="100" max="2000" step="1" required>
        <label>UTR / Transaction ID</label><input name="utr" required>
        <button>Submit Payment Request</button>
      </form>
    </div>
    <div class="card tablewrap"><h3>Payment History</h3><table>
      <tr><th>ID</th><th>Amount</th><th>UTR</th><th>Status</th><th>Date</th></tr>
      ${rows || "<tr><td colspan='5'>No payment requests yet.</td></tr>"}
    </table></div>`, req.session.user));
});

app.post("/add-funds", requireLogin, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const utr = String(req.body.utr || "").trim();

    if (!Number.isInteger(amount) || amount < 100 || amount > 2000 || !utr) {
      return res.status(400).send(page("Add Funds", "<div class='card'>Amount must be between ₹100 and ₹2000, and UTR is required.</div>", req.session.user));
    }

    await pool.query(
      "INSERT INTO payments(user_id,amount,utr,status) VALUES($1,$2,$3,'Pending')",
      [req.session.user.id, amount, utr]
    );

    res.redirect("/add-funds");
  } catch (err) {
    console.error("Payment request error:", err.message);
    res.status(500).send(page("Error", "<div class='card'>Payment request failed.</div>", req.session.user));
  }
});

app.get("/support", requireLogin, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM tickets WHERE user_id=$1 ORDER BY id DESC",
    [req.session.user.id]
  );

  const rows = result.rows.map(t => `
    <div class="service"><strong>Ticket #${t.id}</strong>
    <p>${esc(t.message)}</p><span class="muted">${esc(t.status)} · ${esc(t.created_at)}</span></div>`).join("");

  res.send(page("Support", `
    <h1>Support</h1>
    <div class="card"><form method="POST" action="/support">
      <label>Your Message</label><textarea name="message" rows="4" required></textarea>
      <button>Send Message</button>
    </form></div>
    <div class="card"><h3>Your Tickets</h3>${rows || "No support messages yet."}</div>`,
    req.session.user));
});

app.post("/support", requireLogin, async (req, res) => {
  const message = String(req.body.message || "").trim();
  if (!message) return res.redirect("/support");

  await pool.query(
    "INSERT INTO tickets(user_id,message,status) VALUES($1,$2,'Open')",
    [req.session.user.id, message]
  );
  res.redirect("/support");
});

app.get("/admin", requireAdmin, async (req, res) => {
  try {
    const services = await pool.query("SELECT * FROM services ORDER BY id DESC");
    const payments = await pool.query(
      `SELECT p.*,u.email FROM payments p
       LEFT JOIN users u ON u.id=p.user_id ORDER BY p.id DESC`
    );

    const serviceRows = services.rows.map(s => `
      <tr><td>${s.id}</td><td>${esc(s.category)}</td><td>${esc(s.name)}</td>
      <td>${money(s.rate)}</td><td>${s.min}–${s.max}</td><td>${s.active ? "Active" : "Off"}</td>
      <td><form method="POST" action="/admin/services/${s.id}/toggle">
        <button>${s.active ? "Disable" : "Enable"}</button></form></td></tr>`).join("");

    const paymentRows = payments.rows.map(p => `
      <tr><td>${p.id}</td><td>${esc(p.email || p.user_id)}</td>
      <td>${money(p.amount)}</td><td>${esc(p.utr)}</td><td>${esc(p.status)}</td>
      <td>${p.status === "Pending" ? `<form method="POST" action="/admin/payments/${p.id}/approve"><button>Approve</button></form>` : "—"}</td></tr>`).join("");

    res.send(page("Admin Panel", `
      <h1>Admin Panel</h1>
      <div class="card">
        <h3>Add New Service</h3>
        <form method="POST" action="/admin/services">
          <label>Platform</label>
          <select name="category" required>${platforms.map(p => `<option>${p}</option>`).join("")}</select>
          <label>Service Name</label><input name="name" required>
          <label>Rate per 1000 (₹)</label><input type="number" name="rate" min="0" step="0.01" required>
          <label>Minimum Quantity</label><input type="number" name="min" min="1" value="100" required>
          <label>Maximum Quantity</label><input type="number" name="max" min="1" value="100000" required>
          <label>Description</label><textarea name="description"></textarea>
          <button>Add Service</button>
        </form>
      </div>
      <div class="card tablewrap"><h3>All Services</h3><table>
        <tr><th>ID</th><th>Platform</th><th>Name</th><th>Rate/1K</th><th>Min–Max</th><th>Status</th><th>Action</th></tr>
        ${serviceRows || "<tr><td colspan='7'>No services added yet.</td></tr>"}
      </table></div>
      <div class="card tablewrap"><h3>Payment Requests</h3><table>
        <tr><th>ID</th><th>Customer</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>
        ${paymentRows || "<tr><td colspan='6'>No payment requests.</td></tr>"}
      </table></div>`, req.session.user));
  } catch (err) {
    console.error("Admin error:", err.message);
    res.status(500).send(page("Admin Error", "<div class='card'>Admin panel could not load.</div>", req.session.user));
  }
});

app.post("/admin/services", requireAdmin, async (req, res) => {
  try {
    const category = String(req.body.category || "");
    const name = String(req.body.name || "").trim();
    const rate = Number(req.body.rate);
    const min = Number(req.body.min);
    const max = Number(req.body.max);
    const description = String(req.body.description || "");

    if (!platforms.includes(category) || !name || !Number.isFinite(rate) ||
        rate < 0 || !Number.isInteger(min) || !Number.isInteger(max) ||
        min < 1 || max < min) {
      throw new Error("Please check service details.");
    }

    await pool.query(
      `INSERT INTO services(name,category,rate,min,max,description,active,updated_at)
       VALUES($1,$2,$3,$4,$5,$6,TRUE,NOW())`,
      [name, category, rate, min, max, description]
    );

    res.redirect("/admin");
  } catch (err) {
    res.status(400).send(page("Service Error", `<div class='card'>${esc(err.message)} <a href='/admin'>Back</a></div>`, req.session.user));
  }
});

app.post("/admin/services/:id/toggle", requireAdmin, async (req, res) => {
  await pool.query(
    "UPDATE services SET active=NOT active,updated_at=NOW() WHERE id=$1",
    [Number(req.params.id)]
  );
  res.redirect("/admin");
});

app.post("/admin/payments/:id/approve", requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
      [Number(req.params.id)]
    );

    if (!result.rows.length) throw new Error("Payment not found");

    const payment = result.rows[0];
    if (payment.status !== "Pending") throw new Error("Payment already processed");

    await client.query(
      "UPDATE payments SET status='Approved' WHERE id=$1",
      [payment.id]
    );
    await client.query(
      "UPDATE users SET balance=COALESCE(balance,0)+$1 WHERE id=$2",
      [payment.amount, payment.user_id]
    );

    await client.query("COMMIT");
    res.redirect("/admin");
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(400).send(page("Payment Error", `<div class='card'>${esc(err.message)} <a href='/admin'>Back</a></div>`, req.session.user));
  } finally {
    client.release();
  }
});

app.use((req, res) => {
  res.status(404).send(page("Not Found", "<div class='card'>Page not found. <a href='/dashboard'>Go to Dashboard</a></div>", req.session.user));
});

async function start() {
  try {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is missing in environment variables");
    }
    await initDB();
    app.listen(PORT, () => console.log(`Royal Panel running on port ${PORT}`));
  } catch (err) {
    console.error("Server startup failed:", err);
    process.exit(1);
  }
}

start();
