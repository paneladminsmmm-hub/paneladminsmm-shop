require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const path = require("path");

const app = express();

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret-before-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200
}));

const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const UPI_ID = process.env.UPI_ID || "gujaratiasfak806@okhdfcbank";
const WHATSAPP = process.env.SUPPORT_WHATSAPP || "918140989426";

let provider = {};

try {
  provider = require("./src/provider");
} catch (e) {
  console.log("Provider module not configured:", e.message);
}

const {
  providerServices,
  providerAddOrder,
  providerOrderStatus
} = provider;

async function db(sql, params = []) {
  return pool.query(sql, params);
}

async function setupDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance NUMERIC(14,2) DEFAULT 0,
      is_admin BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      provider_id TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      category TEXT DEFAULT 'Other',
      rate NUMERIC(14,4) DEFAULT 0,
      min INTEGER DEFAULT 1,
      max INTEGER DEFAULT 100000,
      description TEXT DEFAULT '',
      active BOOLEAN DEFAULT TRUE,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      service_id INTEGER REFERENCES services(id),
      provider_order_id TEXT,
      link TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      charge NUMERIC(14,2) NOT NULL,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(14,2) NOT NULL,
      utr TEXT NOT NULL,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      message TEXT NOT NULL,
      status TEXT DEFAULT 'Open',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);

    await db(`
      INSERT INTO users
      (username, email, password_hash, is_admin)
      VALUES ($1, $2, $3, TRUE)
      ON CONFLICT (email)
      DO UPDATE SET is_admin = TRUE
    `, ["admin", ADMIN_EMAIL, hash]);
  }

  console.log("Database ready");
}

function page(title, content, user = null) {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} - PanelAdminSMM.shop</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#101010;color:white;font-family:Arial,sans-serif}
header{background:#191919;padding:18px;border-bottom:2px solid #e00000}
header h2{margin:0;color:#ff2929}
nav{padding:15px;background:#202020;display:flex;gap:12px;flex-wrap:wrap}
a{color:#ff5555;text-decoration:none}
main{max-width:950px;margin:25px auto;padding:15px}
.card{background:#202020;padding:20px;border-radius:12px;margin-bottom:18px}
input,select,textarea{width:100%;padding:13px;margin:8px 0;background:#111;color:white;border:1px solid #555;border-radius:7px}
button{background:#e00000;color:white;padding:12px 20px;border:0;border-radius:7px;cursor:pointer;font-weight:bold}
table{width:100%;border-collapse:collapse}
td,th{padding:10px;border-bottom:1px solid #444;text-align:left}
small{color:#aaa}
h2{color:#ff4242}
</style>
</head>
<body>
<header><h2>ROYAL PANEL</h2><small>PanelAdminSMM.shop</small></header>
${user ? `<nav>
<a href="/dashboard">Dashboard</a>
<a href="/services">Services</a>
<a href="/new-order">New Order</a>
<a href="/orders">My Orders</a>
<a href="/add-funds">Add Funds</a>
<a href="/support">Support</a>
${user.is_admin ? '<a href="/admin">Admin Panel</a>' : ''}
<a href="/logout">Logout</a>
</nav>` : ""}
<main>${content}</main>
</body>
</html>`;
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) {
    return res.status(403).send("Admin access required");
  }
  next();
}

function message(res, text, user = null) {
  res.send(page("Message", `<div class="card">${text}<p><a href="/dashboard">Go Dashboard</a></p></div>`, user));
}

app.get("/", (req, res) => {
  res.send(page("Home", `
  <div class="card">
  <h1>Welcome to PanelAdminSMM.shop</h1>
  <p>Your Social Media Marketing Panel</p>
  <a href="/register"><button>Create Account</button></a>
  <a href="/login"><button>Login</button></a>
  </div>`));
});

app.get("/register", (req, res) => {
  res.send(page("Register", `
  <div class="card">
  <h2>Create Account</h2>
  <form method="POST">
  <input name="username" placeholder="Username" required minlength="3">
  <input name="email" type="email" placeholder="Email" required>
  <input name="password" type="password" placeholder="Password" required minlength="8">
  <button>Create Account</button>
  </form>
  <a href="/login">Already have an account? Login</a>
  </div>`));
});

app.post("/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username) ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        password.length < 8) {
      return message(res, "Please enter valid registration details.");
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await db(`
      INSERT INTO users(username,email,password_hash)
      VALUES($1,$2,$3) RETURNING id,username,email,balance,is_admin
    `, [username, email, hash]);

    req.session.user = result.rows[0];
    res.redirect("/dashboard");
  } catch (e) {
    message(res, "Account already exists or registration failed.");
  }
});

app.get("/login", (req, res) => {
  res.send(page("Login", `
  <div class="card">
  <h2>Login</h2>
  <form method="POST">
  <input name="email" type="email" placeholder="Email" required>
  <input name="password" type="password" placeholder="Password" required>
  <button>Login</button>
  </form>
  <a href="/register">Create New Account</a>
  </div>`));
});

app.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const result = await db("SELECT * FROM users WHERE email=$1", [email]);

    if (!result.rows.length ||
        !await bcrypt.compare(String(req.body.password || ""), result.rows[0].password_hash)) {
      return message(res, "Incorrect email or password.");
    }

    const u = result.rows[0];

    req.session.regenerate(err => {
      if (err) return res.status(500).send("Session error");
      req.session.user = {
        id: u.id,
        username: u.username,
        email: u.email,
        balance: u.balance,
        is_admin: u.is_admin
      };
      res.redirect("/dashboard");
    });
  } catch (e) {
    message(res, "Login failed.");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/dashboard", requireLogin, async (req, res) => {
  const u = await db("SELECT * FROM users WHERE id=$1", [req.session.user.id]);
  const orders = await db("SELECT COUNT(*) FROM orders WHERE user_id=$1", [req.session.user.id]);

  res.send(page("Dashboard", `
  <div class="card">
  <h2>Welcome ${req.session.user.username}</h2>
  <h1>₹${Number(u.rows[0].balance).toFixed(2)}</h1>
  <p>Available Wallet Balance</p>
  <p>Total Orders: ${orders.rows[0].count}</p>
  <a href="/services"><button>View Services</button></a>
  <a href="/add-funds"><button>Add Funds</button></a>
  </div>`, req.session.user));
});

app.get("/services", requireLogin, async (req, res) => {
  const q = String(req.query.search || "").slice(0, 100);

  const result = await db(`
    SELECT * FROM services
    WHERE active=TRUE AND
    (name ILIKE $1 OR category ILIKE $1)
    ORDER BY id DESC LIMIT 300
  `, [`%${q}%`]);

  let rows = result.rows.map(s => `
    <tr>
    <td>${s.id}</td>
    <td>${escapeHtml(s.name)}</td>
    <td>${escapeHtml(s.category)}</td>
    <td>₹${Number(s.rate).toFixed(2)}</td>
    <td>${s.min} - ${s.max}</td>
    </tr>`).join("");

  res.send(page("Services", `
  <div class="card">
  <h2>Available Services</h2>
  <form method="GET">
  <input name="search" placeholder="Search Services">
  <button>Search</button>
  </form>
  <table><tr><th>ID</th><th>Service</th><th>Category</th><th>Rate</th><th>Min/Max</th></tr>
  ${rows || "<tr><td colspan='5'>No services available. Admin needs to sync services.</td></tr>"}
  </table>
  </div>`, req.session.user));
});

app.get("/new-order", requireLogin, async (req, res) => {
  const services = await db("SELECT * FROM services WHERE active=TRUE ORDER BY name");

  res.send(page("New Order", `
  <div class="card">
  <h2>Place New Order</h2>
  <form method="POST">
  <label>Select Service</label>
  <select name="service_id" required>
  ${services.rows.map(s => `<option value="${s.id}">${escapeHtml(s.name)} - ₹${Number(s.rate).toFixed(2)}</option>`).join("")}
  </select>
  <input name="link" type="url" placeholder="Post/Profile Link" required>
  <input name="quantity" type="number" placeholder="Quantity" min="1" required>
  <button>Place Order</button>
  </form>
  </div>`, req.session.user));
});

app.post("/new-order", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const sid = Number(req.body.service_id);
    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isSafeInteger(sid) || !Number.isSafeInteger(quantity) ||
        quantity < 1 || !/^https?:\/\//i.test(link)) {
      throw new Error("Invalid order details");
    }

    const sr = await client.query(
      "SELECT * FROM services WHERE id=$1 AND active=TRUE",
      [sid]
    );

    if (!sr.rows.length) throw new Error("Service unavailable");

    const service = sr.rows[0];

    if (quantity < service.min || quantity > service.max) {
      throw new Error("Quantity outside allowed limits");
    }

    const charge = Number((quantity * Number(service.rate) / 1000).toFixed(2));

    if (!Number.isFinite(charge) || charge <= 0) {
      throw new Error("Invalid service price");
    }

    const ur = await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2 AND balance >= $1 RETURNING id",
      [charge, req.session.user.id]
    );

    if (!ur.rows.length) throw new Error("Insufficient wallet balance");

    const order = await client.query(`
      INSERT INTO orders(user_id,service_id,link,quantity,charge,status)
      VALUES($1,$2,$3,$4,$5,'Pending') RETURNING id
    `, [req.session.user.id, sid, link, quantity, charge]);

    await client.query("COMMIT");

    let providerOrder = null;

    if (typeof providerAddOrder === "function") {
      try {
        const result = await providerAddOrder(service.provider_id, link, quantity);
        providerOrder = result && result.order;

        if (!providerOrder) throw new Error("Provider did not return order ID");

        await db(`
          UPDATE orders SET provider_order_id=$1,status='Processing'
          WHERE id=$2
        `, [String(providerOrder), order.rows[0].id]);
      } catch (e) {
        await refundOrder(order.rows[0].id, req.session.user.id, charge);
        return message(res, "Provider order failed. Your wallet has been refunded.", req.session.user);
      }
    }

    res.redirect("/orders");
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    message(res, escapeHtml(e.message), req.session.user);
  } finally {
    client.release();
  }
});

async function refundOrder(orderId, userId, amount) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query(
      "SELECT status FROM orders WHERE id=$1 AND user_id=$2 FOR UPDATE",
      [orderId, userId]
    );
    if (r.rows.length && r.rows[0].status !== "Refunded") {
      await client.query("UPDATE users SET balance=balance+$1 WHERE id=$2", [amount, userId]);
      await client.query("UPDATE orders SET status='Refunded' WHERE id=$1", [orderId]);
    }
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

app.get("/orders", requireLogin, async (req, res) => {
  const result = await db(`
    SELECT o.*,s.name AS service_name
    FROM orders o LEFT JOIN services s ON s.id=o.service_id
    WHERE o.user_id=$1 ORDER BY o.id DESC LIMIT 200
  `, [req.session.user.id]);

  res.send(page("Orders", `
  <div class="card"><h2>My Orders</h2>
  <table><tr><th>ID</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th></tr>
  ${result.rows.map(o => `<tr>
  <td>${o.id}</td><td>${escapeHtml(o.service_name || "")}</td>
  <td>${o.quantity}</td><td>₹${Number(o.charge).toFixed(2)}</td>
  <td>${escapeHtml(o.status)}</td></tr>`).join("")}
  </table></div>`, req.session.user));
});

app.get("/add-funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
  <div class="card">
  <h2>Add Funds</h2>
  <p>Minimum ₹10 - Maximum ₹2000</p>
  <p>UPI ID: <b>${escapeHtml(UPI_ID)}</b></p>
  <img src="/payment-qr.png" style="width:220px;max-width:100%" alt="Payment QR">
  <form method="POST">
  <input name="amount" type="number" min="10" max="2000" placeholder="Amount ₹" required>
  <input name="utr" placeholder="12-digit UTR / Transaction ID" required minlength="12" maxlength="30">
  <button>Submit Payment Request</button>
  </form>
  <p>Payment will be added after admin verification.</p>
  </div>`, req.session.user));
});

app.post("/add-funds", requireLogin, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const utr = String(req.body.utr || "").trim();

    if (!Number.isFinite(amount) || amount < 10 || amount > 2000 ||
        !/^[A-Za-z0-9]{12,30}$/.test(utr)) {
      return message(res, "Invalid amount or UTR.", req.session.user);
    }

    await db(`
      INSERT INTO payments(user_id,amount,utr)
      VALUES($1,$2,$3)
    `, [req.session.user.id, amount, utr]);

    message(res, "Payment request submitted. Waiting for admin approval.", req.session.user);
  } catch (e) {
    message(res, "Payment request failed.", req.session.user);
  }
});

app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
  <div class="card">
  <h2>Customer Support</h2>
  <form method="POST">
  <textarea name="message" placeholder="Write your problem" required></textarea>
  <button>Submit Ticket</button>
  </form>
  <p><a href="https://wa.me/${WHATSAPP}" target="_blank">WhatsApp Support</a></p>
  </div>`, req.session.user));
});

app.post("/support", requireLogin, async (req, res) => {
  const text = String(req.body.message || "").trim().slice(0, 2000);
  if (!text) return message(res, "Please enter your message.", req.session.user);

  await db("INSERT INTO tickets(user_id,message) VALUES($1,$2)", [
    req.session.user.id, text
  ]);

  message(res, "Support ticket submitted.", req.session.user);
});

app.get("/admin", requireAdmin, async (req, res) => {
  const [users, orders, payments, services, tickets] = await Promise.all([
    db("SELECT COUNT(*) FROM users"),
    db("SELECT COUNT(*) FROM orders"),
    db("SELECT COUNT(*) FROM payments WHERE status='Pending'"),
    db("SELECT COUNT(*) FROM services WHERE active=TRUE"),
    db("SELECT COUNT(*) FROM tickets WHERE status='Open'")
  ]);

  res.send(page("Admin Panel", `
  <div class="card">
  <h2>Admin Dashboard</h2>
  <p>Users: ${users.rows[0].count}</p>
  <p>Orders: ${orders.rows[0].count}</p>
  <p>Pending Payments: ${payments.rows[0].count}</p>
  <p>Active Services: ${services.rows[0].count}</p>
  <p>Open Tickets: ${tickets.rows[0].count}</p>
  </div>
  <div class="card">
  <h2>Service Management</h2>
  <form method="POST" action="/admin/sync">
  <button>Sync Services</button>
  </form>
  </div>
  <div class="card">
  <h2>Payment Requests</h2>
  <a href="/admin/payments">Manage Payments</a>
  </div>
  <div class="card">
  <h2>Orders</h2>
  <a href="/admin/orders">Manage Orders</a>
  </div>
  <div class="card">
  <h2>Support Tickets</h2>
  <a href="/admin/tickets">View Tickets</a>
  </div>`, req.session.user));
});

app.post("/admin/sync", requireAdmin, async (req, res) => {
  try {
    if (typeof providerServices !== "function") {
      return message(res, "Provider API is not configured.", req.session.user);
    }

    const list = await providerServices();

    if (!Array.isArray(list)) throw new Error("Invalid provider service response");

    for (const s of list) {
      if (!s.service || !s.name) continue;

      await db(`
        INSERT INTO services
        (provider_id,name,category,rate,min,max,description,active,updated_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,TRUE,NOW())
        ON CONFLICT(provider_id) DO UPDATE SET
        name=EXCLUDED.name,
        category=EXCLUDED.category,
        rate=EXCLUDED.rate,
        min=EXCLUDED.min,
        max=EXCLUDED.max,
        description=EXCLUDED.description,
        active=TRUE,
        updated_at=NOW()
      `, [
        String(s.service),
        String(s.name),
        String(s.category || "Other"),
        Number(s.rate) || 0,
        Number(s.min) || 1,
        Number(s.max) || 100000,
        String(s.desc || "")
      ]);
    }

    message(res, `${list.length} provider services synchronized.`, req.session.user);
  } catch (e) {
    message(res, "Service sync failed: " + escapeHtml(e.message), req.session.user);
  }
});

app.get("/admin/payments", requireAdmin, async (req, res) => {
  const r = await db(`
    SELECT p.*,u.username,u.email
    FROM payments p JOIN users u ON u.id=p.user_id
    ORDER BY p.id DESC LIMIT 200
  `);

  res.send(page("Payments", `
  <div class="card"><h2>Payment Requests</h2>
  <table><tr><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>
  ${r.rows.map(p => `<tr>
  <td>${escapeHtml(p.username)}</td>
  <td>₹${Number(p.amount).toFixed(2)}</td>
  <td>${escapeHtml(p.utr)}</td>
  <td>${escapeHtml(p.status)}</td>
  <td>${p.status === "Pending" ? `<form method="POST" action="/admin/payments/${p.id}/approve"><button>Approve</button></form><form method="POST" action="/admin/payments/${p.id}/reject"><button>Reject</button></form>` : "-"}</td>
  </tr>`).join("")}</table></div>`, req.session.user));
});

app.post("/admin/payments/:id/approve", requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const p = await client.query(
      "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    if (!p.rows.length || p.rows[0].status !== "Pending") {
      throw new Error("Payment is not pending");
    }

    await client.query(
      "UPDATE users SET balance=balance+$1 WHERE id=$2",
      [p.rows[0].amount, p.rows[0].user_id]
    );

    await client.query(
      "UPDATE payments SET status='Approved' WHERE id=$1",
      [req.params.id]
    );

    await client.query("COMMIT");
    message(res, "Payment approved.", req.session.user);
  } catch (e) {
    await client.query("ROLLBACK");
    message(res, escapeHtml(e.message), req.session.user);
  } finally {
    client.release();
  }
});

app.post("/admin/payments/:id/reject", requireAdmin, async (req, res) => {
  await db(`
    UPDATE payments SET status='Rejected'
    WHERE id=$1 AND status='Pending'
  `, [req.params.id]);

  message(res, "Payment request rejected.", req.session.user);
});

app.get("/admin/orders", requireAdmin, async (req, res) => {
  const r = await db(`
    SELECT o.*,u.username,s.name AS service_name
    FROM orders o
    LEFT JOIN users u ON u.id=o.user_id
    LEFT JOIN services s ON s.id=o.service_id
    ORDER BY o.id DESC LIMIT 200
  `);

  res.send(page("Admin Orders", `
  <div class="card"><h2>All Orders</h2>
  <table><tr><th>ID</th><th>User</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th></tr>
  ${r.rows.map(o => `<tr>
  <td>${o.id}</td><td>${escapeHtml(o.username || "")}</td>
  <td>${escapeHtml(o.service_name || "")}</td>
  <td>${o.quantity}</td><td>₹${Number(o.charge).toFixed(2)}</td>
  <td>${escapeHtml(o.status)}</td></tr>`).join("")}
  </table></div>`, req.session.user));
});

app.get("/admin/tickets", requireAdmin, async (req, res) => {
  const r = await db(`
    SELECT t.*,u.username
    FROM tickets t JOIN users u ON u.id=t.user_id
    ORDER BY t.id DESC LIMIT 200
  `);

  res.send(page("Support Tickets", `
  <div class="card"><h2>Support Tickets</h2>
  ${r.rows.map(t => `<p>#${t.id} - ${escapeHtml(t.username)} - ${escapeHtml(t.message)} - ${escapeHtml(t.status)}</p>`).join("")}
  </div>`, req.session.user));
});

app.get("/api/health", async (req, res) => {
  try {
    await db("SELECT 1");
    res.json({ status: "OK", database: "Connected" });
  } catch (e) {
    res.status(503).json({ status: "ERROR", database: "Disconnected" });
  }
});

app.get("/terms", (req, res) => {
  res.send(page("Terms", `
  <div class="card"><h2>Terms & Conditions</h2>
  <p>All orders are subject to service availability and provider policies.</p>
  <p>Payments are credited after verification.</p>
  </div>`, req.session.user));
});

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));
}

setupDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log("PanelAdminSMM.shop running on port " + PORT);
    });
  })
  .catch(err => {
    console.error("Database startup failed:", err);
    process.exit(1);
  });

process.on("SIGTERM", async () => {
  await pool.end();
  process.exit(0);
});

