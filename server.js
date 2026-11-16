
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

const {
  providerServices,
  providerAddOrder,
  providerOrderStatus
} = require("./src/provider");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database("database.sqlite");

app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
}));

if (process.env.NODE_ENV === "production" &&
    (!process.env.SESSION_SECRET ||
     process.env.SESSION_SECRET.length < 32)) {
  throw new Error("SESSION_SECRET must be at least 32 characters.");
}

app.use(session({
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: __dirname
  }),
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  balance REAL NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id TEXT UNIQUE,
  name TEXT NOT NULL,
  category TEXT,
  rate REAL NOT NULL DEFAULT 0,
  min INTEGER NOT NULL DEFAULT 1,
  max INTEGER NOT NULL DEFAULT 1000000,
  description TEXT,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  service_id INTEGER NOT NULL,
  provider_order_id TEXT,
  link TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  charge REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(service_id) REFERENCES services(id)
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  reference TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Open',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

function addColumnIfMissing(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some(c => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

addColumnIfMissing("payments", "phone", "TEXT");
addColumnIfMissing("payments", "approved_at", "TEXT");
addColumnIfMissing("orders", "provider_order_id", "TEXT");

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").toLowerCase().trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

if (ADMIN_EMAIL && ADMIN_PASSWORD) {
  const existingAdmin = db.prepare(
    "SELECT id FROM users WHERE email = ?"
  ).get(ADMIN_EMAIL);

  if (!existingAdmin) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
    db.prepare(`
      INSERT INTO users (name,email,password,role)
      VALUES (?,?,?,'admin')
    `).run("Administrator", ADMIN_EMAIL, hash);
  }
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

function money(value) {
  return "₹" + Number(value || 0).toFixed(2);
}

function page(title, content, user = null) {
  const nav = user ? `
    <nav>
      <a href="/dashboard">Dashboard</a>
      <a href="/services">Services</a>
      <a href="/new-order">New Order</a>
      <a href="/orders">Orders</a>
      <a href="/add-funds">Add Funds</a>
      <a href="/support">Support</a>
      ${user.role === "admin" ? '<a href="/admin">Admin</a>' : ""}
      <a href="/logout">Logout</a>
    </nav>
  ` : `
    <nav>
      <a href="/login">Login</a>
      <a href="/register">Register</a>
    </nav>
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} - PanelAdminSMM.shop</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f3f4f6;color:#222;font-family:Arial,sans-serif}
header{background:#111827;color:white;padding:18px;text-align:center}
header h2{margin:0;color:#ff3030}
nav{background:#202938;padding:12px;display:flex;gap:12px;flex-wrap:wrap;justify-content:center}
nav a{color:white;text-decoration:none;font-size:14px}
main{max-width:1000px;margin:22px auto;padding:16px}
.card{background:white;padding:20px;margin-bottom:16px;border-radius:12px;box-shadow:0 2px 10px #0000000c}
h2,h3{margin-top:0}
input,select,textarea{width:100%;padding:12px;margin:7px 0 14px;border:1px solid #ddd;border-radius:7px;font-size:15px}
button,.btn{display:inline-block;background:#e32636;color:white;padding:11px 17px;border:0;border-radius:7px;text-decoration:none;cursor:pointer}
button:hover,.btn:hover{background:#b91c2c}
table{width:100%;border-collapse:collapse;min-width:600px}
th,td{padding:11px;border-bottom:1px solid #eee;text-align:left;font-size:14px}
.tablewrap{overflow-x:auto}
.muted{color:#666;font-size:14px}
.success{color:green}.error{color:#c00}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
.big{font-size:24px;font-weight:bold}
footer{text-align:center;padding:25px;color:#777}
a{color:#d21f32}
</style>
</head>
<body>
<header><h2>ROYAL PANEL</h2><div>PanelAdminSMM.shop</div></header>
${nav}
<main>${content}</main>
<footer>PanelAdminSMM.shop · Social Media Services</footer>
</body></html>`;
}

function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare("SELECT id,name,email,balance,role FROM users WHERE id=?")
    .get(req.session.userId);
}

function requireLogin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.redirect("/login");
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user || user.role !== "admin") {
    return res.status(403).send(page("Access denied",
      '<div class="card"><h2>Access denied</h2></div>', user));
  }
  req.user = user;
  next();
}

function notice(message, type = "success") {
  return `<p class="${type}">${esc(message)}</p>`;
}

app.get("/", (req, res) => {
  const user = currentUser(req);
  res.send(page("Home", `
    <div class="card">
      <h2>Welcome to PanelAdminSMM.shop</h2>
      <p>Buy social media services easily.</p>
      <a class="btn" href="/register">Create Account</a>
      <a class="btn" href="/login">Login</a>
    </div>
  `, user));
});

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h2>Create Account</h2>
      <form method="POST" action="/register">
        <label>Full Name</label>
        <input name="name" required maxlength="80">
        <label>Email</label>
        <input type="email" name="email" required>
        <label>Password</label>
        <input type="password" name="password" required minlength="8">
        <button>Create Account</button>
      </form>
      <p>Already registered? <a href="/login">Login</a></p>
    </div>
  `));
});

app.post("/register", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!name || !email || password.length < 8) {
    return res.send(page("Register", notice("Enter valid details. Password must be at least 8 characters.", "error")));
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(`
      INSERT INTO users (name,email,password) VALUES (?,?,?)
    `).run(name, email, hash);

    req.session.userId = result.lastInsertRowid;
    res.redirect("/dashboard");
  } catch (error) {
    res.send(page("Register", notice("This email may already be registered.", "error")));
  }
});

app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card">
      <h2>Login</h2>
      <form method="POST" action="/login">
        <label>Email</label>
        <input type="email" name="email" required>
        <label>Password</label>
        <input type="password" name="password" required>
        <button>Login</button>
      </form>
      <p>New user? <a href="/register">Register</a></p>
    </div>
  `));
});

app.post("/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.send(page("Login", notice("Incorrect email or password.", "error")));
  }

  req.session.userId = user.id;
  res.redirect("/dashboard");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireLogin, (req, res) => {
  const orderCount = db.prepare(
    "SELECT COUNT(*) AS total FROM orders WHERE user_id=?"
  ).get(req.user.id).total;

  const content = `
    <div class="card">
      <h2>Hello, ${esc(req.user.name)}</h2>
      <p>Your account dashboard</p>
      <div class="grid">
        <div class="card"><div class="muted">Available Balance</div><div class="big">${money(req.user.balance)}</div></div>
        <div class="card"><div class="muted">Total Orders</div><div class="big">${orderCount}</div></div>
      </div>
      <a class="btn" href="/new-order">Place New Order</a>
      <a class="btn" href="/add-funds">Add Funds</a>
    </div>
  `;
  res.send(page("Dashboard", content, req.user));
});

app.get("/services", requireLogin, (req, res) => {
  const search = String(req.query.search || "").trim();
  let services;

  if (search) {
    services = db.prepare(`
      SELECT * FROM services
      WHERE active=1 AND (name LIKE ? OR category LIKE ?)
      ORDER BY category,name LIMIT 500
    `).all("%" + search + "%", "%" + search + "%");
  } else {
    services = db.prepare(
      "SELECT * FROM services WHERE active=1 ORDER BY category,name LIMIT 500"
    ).all();
  }

  const rows = services.map(s => `
    <tr>
      <td>${s.id}</td>
      <td>${esc(s.category || "Other")}</td>
      <td>${esc(s.name)}</td>
      <td>${money(s.rate)} / 1000</td>
      <td>${s.min} - ${s.max}</td>
    </tr>
  `).join("");

  res.send(page("Services", `
    <div class="card">
      <h2>Available Services</h2>
      <form method="GET">
        <input name="search" placeholder="Search services..." value="${esc(search)}">
        <button>Search</button>
      </form>
      <div class="tablewrap"><table>
        <tr><th>ID</th><th>Category</th><th>Service</th><th>Rate</th><th>Min-Max</th></tr>
        ${rows || "<tr><td colspan='5'>No services found. Please sync services from Admin.</td></tr>"}
      </table></div>
    </div>
  `, req.user));
});

app.get("/new-order", requireLogin, (req, res) => {
  const services = db.prepare(
    "SELECT * FROM services WHERE active=1 ORDER BY category,name"
  ).all();

  const options = services.map(s =>
    `<option value="${s.id}">${esc(s.name)} — ${money(s.rate)}/1000 (ID ${s.id})</option>`
  ).join("");

  res.send(page("New Order", `
    <div class="card">
      <h2>Place New Order</h2>
      <p>Balance: <b>${money(req.user.balance)}</b></p>
      <form method="POST" action="/new-order">
        <label>Select Service</label>
        <input id="serviceSearch" placeholder="Search service..." oninput="filterServices()">
        <select name="service_id" id="serviceSelect" required size="7">
          ${options}
        </select>
        <label>Post / Profile Link</label>
        <input type="url" name="link" placeholder="https://..." required>
        <label>Quantity</label>
        <input type="number" name="quantity" min="1" required>
        <button>Submit Order</button>
      </form>
    </div>
    <script>
    function filterServices(){
      const q=document.getElementById('serviceSearch').value.toLowerCase();
      const sel=document.getElementById('serviceSelect');
      for(const o of sel.options){o.hidden=!o.text.toLowerCase().includes(q);}
    }
    </script>
  `, req.user));
});

app.post("/new-order", requireLogin, async (req, res) => {
  const serviceId = Number(req.body.service_id);
  const quantity = Number(req.body.quantity);
  const link = String(req.body.link || "").trim();

  const service = db.prepare(
    "SELECT * FROM services WHERE id=? AND active=1"
  ).get(serviceId);

  if (!service || !Number.isInteger(quantity) ||
      quantity < service.min || quantity > service.max ||
      !/^https?:\/\//i.test(link)) {
    return res.send(page("New Order", notice("Invalid service, link or quantity.", "error"), req.user));
  }

  const charge = Math.ceil((service.rate * quantity / 1000) * 100) / 100;
  if (charge <= 0 || charge > req.user.balance) {
    return res.send(page("New Order", notice("Insufficient balance. Please add funds.", "error"), req.user));
  }

  const reserve = db.transaction(() => {
    const result = db.prepare(
      "UPDATE users SET balance=balance-? WHERE id=? AND balance>=?"
    ).run(charge, req.user.id, charge);

    if (!result.changes) throw new Error("Insufficient balance");

    return db.prepare(`
      INSERT INTO orders (user_id,service_id,link,quantity,charge,status)
      VALUES (?,?,?,?,?,'Processing')
    `).run(req.user.id, service.id, link, quantity, charge).lastInsertRowid;
  });

  let orderId;
  try {
    orderId = reserve();
  } catch (error) {
    return res.send(page("New Order", notice("Unable to reserve balance.", "error"), req.user));
  }

  try {
    const result = await providerAddOrder(service.provider_id, link, quantity);
    const providerId = result && (result.order || result.id);

    if (!providerId) throw new Error("Provider did not return an order ID");

    db.prepare(`
      UPDATE orders SET provider_order_id=?,status='Processing' WHERE id=?
    `).run(String(providerId), orderId);

    res.redirect("/orders");
  } catch (error) {
    db.transaction(() => {
      db.prepare("UPDATE users SET balance=balance+? WHERE id=?")
        .run(charge, req.user.id);
      db.prepare("UPDATE orders SET status='Failed' WHERE id=?")
        .run(orderId);
    })();

    res.send(page("New Order", notice("Provider order failed. Your balance has been refunded.", "error"), req.user));
  }
});

app.get("/orders", requireLogin, (req, res) => {
  const orders = db.prepare(`
    SELECT o.*,s.name AS service_name
    FROM orders o JOIN services s ON s.id=o.service_id
    WHERE o.user_id=? ORDER BY o.id DESC LIMIT 200
  `).all(req.user.id);

  const rows = orders.map(o => `
    <tr>
      <td>${o.id}</td>
      <td>${esc(o.service_name)}</td>
      <td>${esc(o.link)}</td>
      <td>${o.quantity}</td>
      <td>${money(o.charge)}</td>
      <td>${esc(o.status)}</td>
      <td>${esc(o.created_at)}</td>
    </tr>
  `).join("");

  res.send(page("Orders", `
    <div class="card">
      <h2>Order History</h2>
      <div class="tablewrap"><table>
        <tr><th>ID</th><th>Service</th><th>Link</th><th>Quantity</th><th>Charge</th><th>Status</th><th>Date</th></tr>
        ${rows || "<tr><td colspan='7'>No orders yet.</td></tr>"}
      </table></div>
    </div>
  `, req.user));
});

app.get("/add-funds", requireLogin, (req, res) => {
  const payments = db.prepare(`
    SELECT * FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 20
  `).all(req.user.id);

  const rows = payments.map(p => `
    <tr><td>${p.id}</td><td>${money(p.amount)}</td>
    <td>${esc(p.reference)}</td><td>${esc(p.status)}</td>
    <td>${esc(p.created_at)}</td></tr>
  `).join("");

  res.send(page("Add Funds", `
    <div class="card">
      <h2>Add Funds</h2>
      <p>Choose an amount between ₹10 and ₹2,000.</p>
      <p><b>Current Balance: ${money(req.user.balance)}</b></p>
      <form method="POST" action="/add-funds">
        <label>Amount (₹)</label>
        <input type="number" name="amount" min="10" max="2000" step="1" required>
        <label>Your Mobile Number</label>
        <input type="tel" name="phone" pattern="[0-9]{10}" minlength="10" maxlength="10" placeholder="10 digit mobile number" required>
        <label>UTR / UPI Transaction Reference</label>
        <input name="reference" maxlength="100" placeholder="Enter UTR after payment" required>
        <div style="text-align:center;margin:15px 0">
          <h3>Scan QR to Pay</h3>
          <img src="/payment-qr.png" alt="Payment QR Code" style="max-width:260px;width:100%;border:1px solid #ddd;padding:8px;border-radius:10px" onerror="this.style.display='none';document.getElementById('qrMissing').style.display='block'">
          <p id="qrMissing" style="display:none;color:#c00">Payment QR has not been uploaded yet.</p>
        </div>
        <button>Submit Payment Request</button>
      </form>
      <p class="muted">Your balance will be credited after the admin verifies your payment. Submitting a UTR alone does not verify payment automatically.</p>
    </div>
    <div class="card">
      <h3>Payment Requests</h3>
      <div class="tablewrap"><table>
        <tr><th>ID</th><th>Amount</th><th>UTR</th><th>Status</th><th>Date</th></tr>
        ${rows || "<tr><td colspan='5'>No payment requests.</td></tr>"}
      </table></div>
    </div>
    <div class="card">
      <h3>Need Help?</h3>
      <a class="btn" href="https://wa.me/918140989426" target="_blank" rel="noopener">WhatsApp Support</a>
    </div>
  `, req.user));
});

app.post("/add-funds", requireLogin, (req, res) => {
  const amount = Number(req.body.amount);
  const phone = String(req.body.phone || "").replace(/\D/g, "");
  const reference = String(req.body.reference || "").trim();

  if (!Number.isInteger(amount) || amount < 10 || amount > 2000) {
    return res.send(page("Add Funds", notice("Amount must be between ₹10 and ₹2,000.", "error"), req.user));
  }

  if (!/^[0-9]{10}$/.test(phone) || reference.length < 5 || reference.length > 100) {
    return res.send(page("Add Funds", notice("Enter a valid 10-digit mobile number and UTR.", "error"), req.user));
  }

  const duplicate = db.prepare(
    "SELECT id FROM payments WHERE reference=?"
  ).get(reference);

  if (duplicate) {
    return res.send(page("Add Funds", notice("This UTR has already been submitted.", "error"), req.user));
  }

  db.prepare(`
    INSERT INTO payments (user_id,amount,reference,phone,status)
    VALUES (?,?,?,?,'Pending')
  `).run(req.user.id, amount, reference, phone);

  res.send(page("Payment Submitted",
    notice("Payment request submitted. Admin will verify it before adding balance.") +
    '<p><a class="btn" href="/add-funds">Back to Add Funds</a></p>',
    req.user));
});

app.get("/support", requireLogin, (req, res) => {
  const tickets = db.prepare(
    "SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC"
  ).all(req.user.id);

  const rows = tickets.map(t => `
    <tr><td>${t.id}</td><td>${esc(t.subject)}</td>
    <td>${esc(t.message)}</td><td>${esc(t.status)}</td>
    <td>${esc(t.created_at)}</td></tr>
  `).join("");

  res.send(page("Support", `
    <div class="card">
      <h2>Contact Support</h2>
      <a class="btn" href="https://wa.me/918140989426" target="_blank" rel="noopener">Chat on WhatsApp</a>
    </div>
    <div class="card">
      <h3>Create Support Ticket</h3>
      <form method="POST" action="/support">
        <input name="subject" placeholder="Subject" maxlength="120" required>
        <textarea name="message" placeholder="Write your message..." rows="5" maxlength="2000" required></textarea>
        <button>Submit Ticket</button>
      </form>
    </div>
    <div class="card">
      <h3>Your Tickets</h3>
      <div class="tablewrap"><table>
        <tr><th>ID</th><th>Subject</th><th>Message</th><th>Status</th><th>Date</th></tr>
        ${rows || "<tr><td colspan='5'>No tickets yet.</td></tr>"}
      </table></div>
    </div>
  `, req.user));
});

app.post("/support", requireLogin, (req, res) => {
  const subject = String(req.body.subject || "").trim();
  const message = String(req.body.message || "").trim();

  if (!subject || !message) {
    return res.send(page("Support", notice("Please fill all fields.", "error"), req.user));
  }

  db.prepare(`
    INSERT INTO tickets (user_id,subject,message) VALUES (?,?,?)
  `).run(req.user.id, subject.slice(0, 120), message.slice(0, 2000));

  res.redirect("/support");
});

app.get("/admin", requireAdmin, (req, res) => {
  const users = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
  const orders = db.prepare("SELECT COUNT(*) AS n FROM orders").get().n;
  const pending = db.prepare(
    "SELECT COUNT(*) AS n FROM payments WHERE status='Pending'"
  ).get().n;

  res.send(page("Admin", `
    <div class="card">
      <h2>Admin Panel</h2>
      <div class="grid">
        <div class="card"><div class="muted">Users</div><div class="big">${users}</div></div>
        <div class="card"><div class="muted">Orders</div><div class="big">${orders}</div></div>
        <div class="card"><div class="muted">Pending Payments</div><div class="big">${pending}</div></div>
      </div>
      <p><a class="btn" href="/admin/payments">Payment Requests</a></p>
      <p><a class="btn" href="/admin/orders">All Orders</a></p>
      <form method="POST" action="/admin/sync-services">
        <button>Sync VIP Pro Services</button>
      </form>
    </div>
  `, req.user));
});

app.post("/admin/sync-services", requireAdmin, async (req, res) => {
  try {
    const response = await providerServices();
    const list = Array.isArray(response) ? response :
      (response && Array.isArray(response.services) ? response.services : []);

    const insert = db.prepare(`
      INSERT INTO services
      (provider_id,name,category,rate,min,max,description,active)
      VALUES (@provider_id,@name,@category,@rate,@min,@max,@description,1)
      ON CONFLICT(provider_id) DO UPDATE SET
        name=excluded.name,
        category=excluded.category,
        rate=excluded.rate,
        min=excluded.min,
        max=excluded.max,
        description=excluded.description,
        active=1
    `);

    const sync = db.transaction(items => {
      for (const item of items) {
        if (!item || item.service == null || !item.name) continue;
        insert.run({
          provider_id: String(item.service),
          name: String(item.name),
          category: String(item.category || "Other"),
          rate: Number(item.rate || 0),
          min: Number(item.min || 1),
          max: Number(item.max || 1000000),
          description: String(item.description || "")
        });
      }
    });

    sync(list);
    res.send(page("Services Synced",
      notice("Service sync completed. Imported " + list.length + " provider services.") +
      '<p><a class="btn" href="/admin">Back to Admin</a></p>', req.user));
  } catch (error) {
    console.error("Service sync error:", error);
    res.send(page("Sync Error",
      notice("Service sync failed. Check VIP Pro API settings and server logs.", "error") +
      '<p><a href="/admin">Back to Admin</a></p>', req.user));
  }
});

app.get("/admin/payments", requireAdmin, (req, res) => {
  const payments = db.prepare(`
    SELECT p.*,u.name,u.email
    FROM payments p JOIN users u ON u.id=p.user_id
    ORDER BY p.id DESC LIMIT 300
  `).all();

  const rows = payments.map(p => `
    <tr>
      <td>${p.id}</td><td>${esc(p.name)}<br>${esc(p.email)}</td>
      <td>${money(p.amount)}</td><td>${esc(p.phone || "")}</td>
      <td>${esc(p.reference)}</td><td>${esc(p.status)}</td>
      <td>${p.status === "Pending" ? `
        <form method="POST" action="/admin/payments/${p.id}/approve" style="display:inline">
          <button>Approve</button>
        </form>
        <form method="POST" action="/admin/payments/${p.id}/reject" style="display:inline">
          <button style="background:#555">Reject</button>
        </form>` : "-"}
      </td>
    </tr>
  `).join("");

  res.send(page("Payment Requests", `
    <div class="card">
      <h2>Payment Requests</h2>
      <p>Verify the actual payment in your payment app/bank before approving.</p>
      <div class="tablewrap"><table>
        <tr><th>ID</th><th>User</th><th>Amount</th><th>Phone</th><th>UTR</th><th>Status</th><th>Action</th></tr>
        ${rows || "<tr><td colspan='7'>No payments.</td></tr>"}
      </table></div>
    </div>
  `, req.user));
});

app.post("/admin/payments/:id/approve", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  try {
    const approve = db.transaction(() => {
      const payment = db.prepare(
        "SELECT * FROM payments WHERE id=?"
      ).get(id);

      if (!payment || payment.status !== "Pending") {
        throw new Error("Payment is not pending.");
      }

      db.prepare(
        "UPDATE payments SET status='Approved',approved_at=CURRENT_TIMESTAMP WHERE id=? AND status='Pending'"
      ).run(id);

      db.prepare(
        "UPDATE users SET balance=balance+? WHERE id=?"
      ).run(payment.amount, payment.user_id);
    });

    approve();
    res.redirect("/admin/payments");
  } catch (error) {
    res.send(page("Payment Error", notice(error.message, "error"), req.user));
  }
});

app.post("/admin/payments/:id/reject", requireAdmin, (req, res) => {
  db.prepare(`
    UPDATE payments SET status='Rejected'
    WHERE id=? AND status='Pending'
  `).run(Number(req.params.id));

  res.redirect("/admin/payments");
});

app.get("/admin/orders", requireAdmin, (req, res) => {
  const orders = db.prepare(`
    SELECT o.*,u.email,s.name AS service_name
    FROM orders o
    JOIN users u ON u.id=o.user_id
    JOIN services s ON s.id=o.service_id
    ORDER BY o.id DESC LIMIT 300
  `).all();

  const rows = orders.map(o => `
    <tr><td>${o.id}</td><td>${esc(o.email)}</td>
    <td>${esc(o.service_name)}</td><td>${o.quantity}</td>
    <td>${money(o.charge)}</td><td>${esc(o.provider_order_id || "")}</td>
    <td>${esc(o.status)}</td></tr>
  `).join("");

  res.send(page("All Orders", `
    <div class="card">
      <h2>All Orders</h2>
      <div class="tablewrap"><table>
        <tr><th>ID</th><th>User</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Provider ID</th><th>Status</th></tr>
        ${rows || "<tr><td colspan='7'>No orders.</td></tr>"}
      </table></div>
    </div>
  `, req.user));
});

app.get("/order-status/:id", requireLogin, async (req, res) => {
  const order = db.prepare(`
    SELECT * FROM orders WHERE id=? AND user_id=?
  `).get(Number(req.params.id), req.user.id);

  if (!order) return res.status(404).send("Order not found");

  if (!order.provider_order_id) {
    return res.send("Provider order ID not available.");
  }

  try {
    const result = await providerOrderStatus(order.provider_order_id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: "Unable to fetch provider status" });
  }
});

app.use((req, res) => {
  res.status(404).send(page("Not Found",
    '<div class="card"><h2>Page not found</h2><a href="/">Home</a></div>',
    currentUser(req)));
});

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).send(page("Server Error",
    '<div class="card"><h2>Something went wrong</h2><p>Please try again later.</p></div>',
    currentUser(req)));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("PanelAdminSMM.shop running on port " + PORT);
});
