
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const {
  providerServices,
  providerAddOrder,
  providerOrderStatus
} = require("./src/provider");

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";

if (isProduction && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error("Set a SESSION_SECRET of at least 32 characters in Render Environment.");
}

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const db = new Database(process.env.DB_PATH || path.join(__dirname, "database.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  balance REAL NOT NULL DEFAULT 0,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id TEXT UNIQUE,
  name TEXT NOT NULL,
  category TEXT DEFAULT 'Other',
  rate REAL NOT NULL DEFAULT 0,
  min_qty INTEGER NOT NULL DEFAULT 1,
  max_qty INTEGER NOT NULL DEFAULT 100000,
  description TEXT DEFAULT '',
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
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(service_id) REFERENCES services(id)
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  reference TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Open',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

function addColumnIfMissing(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some(c => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

// Basic compatibility for databases created by earlier versions.
addColumnIfMissing("users", "password_hash", "TEXT");
addColumnIfMissing("users", "balance", "REAL NOT NULL DEFAULT 0");
addColumnIfMissing("users", "is_admin", "INTEGER NOT NULL DEFAULT 0");
addColumnIfMissing("services", "provider_id", "TEXT");
addColumnIfMissing("services", "category", "TEXT DEFAULT 'Other'");
addColumnIfMissing("services", "rate", "REAL NOT NULL DEFAULT 0");
addColumnIfMissing("services", "min_qty", "INTEGER NOT NULL DEFAULT 1");
addColumnIfMissing("services", "max_qty", "INTEGER NOT NULL DEFAULT 100000");
addColumnIfMissing("services", "description", "TEXT DEFAULT ''");
addColumnIfMissing("services", "active", "INTEGER NOT NULL DEFAULT 1");
addColumnIfMissing("orders", "provider_order_id", "TEXT");
addColumnIfMissing("orders", "status", "TEXT NOT NULL DEFAULT 'Pending'");
addColumnIfMissing("payments", "reference", "TEXT");
addColumnIfMissing("payments", "status", "TEXT NOT NULL DEFAULT 'Pending'");
addColumnIfMissing("tickets", "status", "TEXT NOT NULL DEFAULT 'Open'");

const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD;

if (adminEmail && adminPassword) {
  const existingAdmin = db.prepare("SELECT id FROM users WHERE email = ?").get(adminEmail);
  if (!existingAdmin) {
    const hash = bcrypt.hashSync(adminPassword, 12);
    db.prepare(
      "INSERT INTO users (email, password_hash, balance, is_admin) VALUES (?, ?, 0, 1)"
    ).run(adminEmail, hash);
  } else {
    db.prepare("UPDATE users SET is_admin = 1 WHERE email = ?").run(adminEmail);
  }
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
    secure: isProduction,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function escapeHtml(value) {
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
    <a href="/dashboard">Dashboard</a>
    <a href="/services">Services</a>
    <a href="/new-order">New Order</a>
    <a href="/orders">Orders</a>
    <a href="/add-funds">Add Funds</a>
    <a href="/support">Support</a>
    ${user.is_admin ? '<a href="/admin">Admin</a>' : ""}
    <form method="post" action="/logout" style="display:inline">
      <button class="navbutton">Logout</button>
    </form>
  ` : `
    <a href="/login">Login</a>
    <a href="/register">Register</a>
  `;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} - PanelAdminSMM.shop</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f4f6fb;color:#202638;font-family:Arial,sans-serif}
header{background:#111827;color:white;padding:16px}
.head{max-width:1100px;margin:auto;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.brand{font-size:21px;font-weight:bold;color:#fff;text-decoration:none}
nav{display:flex;gap:13px;align-items:center;flex-wrap:wrap}
nav a{color:white;text-decoration:none;font-size:14px}
.navbutton{background:#374151;padding:7px 10px}
main{max-width:1100px;margin:25px auto;padding:0 15px}
.card{background:white;padding:20px;border-radius:12px;margin-bottom:18px;box-shadow:0 2px 12px #0000000b}
h1,h2{margin-top:0}
input,select,textarea{width:100%;padding:12px;margin:7px 0 14px;border:1px solid #d5d9e2;border-radius:7px;font-size:15px;background:white}
button,.btn{display:inline-block;background:#dc2626;color:white;border:0;padding:11px 16px;border-radius:7px;text-decoration:none;cursor:pointer;font-size:14px}
button:hover,.btn:hover{background:#b91c1c}
.navbutton:hover{background:#4b5563}
table{width:100%;border-collapse:collapse;background:white}
th,td{text-align:left;padding:11px;border-bottom:1px solid #eee;font-size:14px}
th{background:#f8fafc}
.tablewrap{overflow-x:auto}
.muted{color:#667085;font-size:14px}
.success{background:#dcfce7;color:#166534;padding:12px;border-radius:7px;margin-bottom:15px}
.error{background:#fee2e2;color:#991b1b;padding:12px;border-radius:7px;margin-bottom:15px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:15px}
.stat{font-size:25px;font-weight:bold;color:#dc2626}
.service-choice{display:block;border:1px solid #e5e7eb;padding:12px;border-radius:8px;margin:8px 0;cursor:pointer;background:#fff}
.service-choice.selected{border:2px solid #dc2626;background:#fff7f7}
.service-choice small{display:block;color:#667085;margin-top:5px}
footer{text-align:center;color:#667085;padding:25px}
@media(max-width:600px){nav{gap:9px}.card{padding:15px}th,td{padding:8px}}
</style>
</head>
<body>
<header><div class="head">
<a class="brand" href="/">PanelAdminSMM.shop</a>
<nav>${nav}</nav>
</div></header>
<main>${content}</main>
<footer>© ${new Date().getFullYear()} PanelAdminSMM.shop</footer>
</body>
</html>`;
}

function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare(
    "SELECT id,email,balance,is_admin FROM users WHERE id=?"
  ).get(req.session.userId) || null;
}

function requireLogin(req, res, next) {
  if (!currentUser(req)) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user || !user.is_admin) {
    return res.status(403).send(page("Access denied", '<div class="card"><h2>Access denied</h2></div>', user));
  }
  next();
}

function messageBox(req) {
  if (req.query.error) return `<div class="error">${escapeHtml(req.query.error)}</div>`;
  if (req.query.success) return `<div class="success">${escapeHtml(req.query.success)}</div>`;
  return "";
}

app.get("/", (req, res) => {
  const user = currentUser(req);
  res.send(page("Home", `
    <div class="card">
      <h1>Welcome to PanelAdminSMM.shop</h1>
      <p>Social Media Marketing Services</p>
      <p class="muted">Instagram, YouTube, Facebook and other social media services.</p>
      <a class="btn" href="${user ? "/dashboard" : "/register"}">${user ? "Open Dashboard" : "Get Started"}</a>
    </div>
  `, user));
});

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h2>Create Account</h2>
      ${messageBox(req)}
      <form method="post" action="/register">
        <label>Email</label><input type="email" name="email" required>
        <label>Password</label><input type="password" name="password" minlength="8" required>
        <button type="submit">Register</button>
      </form>
      <p>Already registered? <a href="/login">Login</a></p>
    </div>
  `));
});

app.post("/register", authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) {
    return res.redirect("/register?error=Enter%20a%20valid%20email%20and%20password%20of%208%20characters");
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(
      "INSERT INTO users (email,password_hash,balance,is_admin) VALUES (?, ?, 0, 0)"
    ).run(email, hash);
    req.session.userId = Number(result.lastInsertRowid);
    res.redirect("/dashboard");
  } catch {
    res.redirect("/register?error=Email%20already%20registered");
  }
});

app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card">
      <h2>Login</h2>
      ${messageBox(req)}
      <form method="post" action="/login">
        <label>Email</label><input type="email" name="email" required>
        <label>Password</label><input type="password" name="password" required>
        <button type="submit">Login</button>
      </form>
      <p>New user? <a href="/register">Create account</a></p>
    </div>
  `));
});

app.post("/login", authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);

  if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash))) {
    return res.redirect("/login?error=Incorrect%20email%20or%20password");
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).send("Login session error");
    req.session.userId = user.id;
    res.redirect("/dashboard");
  });
});

app.post("/logout", requireLogin, (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireLogin, (req, res) => {
  const user = currentUser(req);
  const orders = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE user_id=?").get(user.id).n;
  const payments = db.prepare("SELECT COUNT(*) AS n FROM payments WHERE user_id=? AND status='Pending'").get(user.id).n;

  res.send(page("Dashboard", `
    <h1>Dashboard</h1>
    <div class="grid">
      <div class="card"><p class="muted">Available Balance</p><div class="stat">${money(user.balance)}</div></div>
      <div class="card"><p class="muted">Total Orders</p><div class="stat">${orders}</div></div>
      <div class="card"><p class="muted">Pending Payments</p><div class="stat">${payments}</div></div>
    </div>
    <div class="card">
      <h2>Welcome!</h2>
      <p>${escapeHtml(user.email)}</p>
      <a class="btn" href="/new-order">Place New Order</a>
      <a class="btn" href="/add-funds">Add Funds</a>
    </div>
  `, user));
});

app.get("/services", requireLogin, (req, res) => {
  const user = currentUser(req);
  const services = db.prepare(
    "SELECT * FROM services WHERE active=1 ORDER BY category,name"
  ).all();

  const rows = services.map(s => `
    <tr data-search="${escapeHtml((s.name + " " + s.category + " " + s.id).toLowerCase())}">
      <td>${s.id}</td>
      <td>${escapeHtml(s.category)}</td>
      <td>${escapeHtml(s.name)}</td>
      <td>${money(s.rate)}</td>
      <td>${s.min_qty} - ${s.max_qty}</td>
    </tr>
  `).join("");

  res.send(page("Services", `
    <div class="card">
      <h1>All Services</h1>
      <input id="serviceSearch" type="search" placeholder="Search service name, category or ID...">
      <p class="muted"><span id="serviceCount">${services.length}</span> services available</p>
      <div class="tablewrap">
      <table><thead><tr><th>ID</th><th>Category</th><th>Service</th><th>Rate</th><th>Quantity</th></tr></thead>
      <tbody id="serviceRows">${rows || '<tr><td colspan="5">No services available. Admin can sync services.</td></tr>'}</tbody>
      </table></div>
    </div>
    <script>
    const search=document.getElementById("serviceSearch");
    search.addEventListener("input",()=>{
      const q=search.value.toLowerCase();
      let count=0;
      document.querySelectorAll("#serviceRows tr").forEach(row=>{
        const show=row.dataset.search?.includes(q);
        row.hidden=!show;
        if(show)count++;
      });
      document.getElementById("serviceCount").textContent=count;
    });
    </script>
  `, user));
});

app.get("/new-order", requireLogin, (req, res) => {
  const user = currentUser(req);
  const services = db.prepare(
    "SELECT * FROM services WHERE active=1 ORDER BY category,name"
  ).all();

  const safeServices = JSON.stringify(services.map(s => ({
    id: s.id,
    name: s.name,
    category: s.category,
    rate: s.rate,
    min: s.min_qty,
    max: s.max_qty
  }))).replace(/</g, "\\u003c");

  res.send(page("New Order", `
    <div class="card">
      <h1>Place New Order</h1>
      ${messageBox(req)}
      <p>Available balance: <b>${money(user.balance)}</b></p>
      <form method="post" action="/new-order" id="orderForm">
        <label>Search service</label>
        <input type="search" id="serviceSearch" placeholder="Type service name or category...">
        <div id="serviceList"></div>
        <input type="hidden" name="service_id" id="serviceId" required>
        <div id="selectedService" class="success" hidden></div>
        <label>Link</label>
        <input type="url" name="link" placeholder="https://..." required>
        <label>Quantity</label>
        <input type="number" name="quantity" id="quantity" min="1" required>
        <p id="estimate" class="muted">Estimated charge: ₹0.00</p>
        <button type="submit">Submit Order</button>
      </form>
    </div>
    <script>
    const services=${safeServices};
    const list=document.getElementById("serviceList");
    const search=document.getElementById("serviceSearch");
    const serviceId=document.getElementById("serviceId");
    const selected=document.getElementById("selectedService");
    const quantity=document.getElementById("quantity");
    const estimate=document.getElementById("estimate");
    let chosen=null;

    function render(){
      const q=search.value.toLowerCase();
      const matches=services.filter(s=>(s.name+" "+s.category+" "+s.id).toLowerCase().includes(q)).slice(0,100);
      list.innerHTML="";
      if(!matches.length){list.textContent="No matching services found.";return;}
      matches.forEach(s=>{
        const b=document.createElement("button");
        b.type="button";
        b.className="service-choice";
        b.style.width="100%";
        b.style.color="#202638";
        b.style.textAlign="left";
        b.style.background=chosen&&chosen.id===s.id?"#fff7f7":"white";
        b.innerHTML="";
        const name=document.createElement("strong");
        name.textContent=s.name;
        const info=document.createElement("small");
        info.textContent=s.category+" | Rate: ₹"+Number(s.rate).toFixed(2)+" | Min "+s.min+" / Max "+s.max;
        b.append(name,info);
        b.addEventListener("click",()=>{
          chosen=s;
          serviceId.value=s.id;
          selected.hidden=false;
          selected.textContent="Selected: "+s.name;
          quantity.min=s.min;
          quantity.max=s.max;
          quantity.value=s.min;
          updateEstimate();
          render();
        });
        list.appendChild(b);
      });
    }
    function updateEstimate(){
      if(!chosen){estimate.textContent="Estimated charge: ₹0.00";return;}
      const qty=Number(quantity.value||0);
      const cost=(Number(chosen.rate)*qty)/1000;
      estimate.textContent="Estimated charge: ₹"+cost.toFixed(2);
    }
    search.addEventListener("input",render);
    quantity.addEventListener("input",updateEstimate);
    document.getElementById("orderForm").addEventListener("submit",e=>{
      if(!chosen||!serviceId.value){e.preventDefault();alert("Please select a service.");}
    });
    render();
    </script>
  `, user));
});

app.post("/new-order", requireLogin, async (req, res) => {
  const user = currentUser(req);
  const serviceId = Number(req.body.service_id);
  const quantity = Number(req.body.quantity);
  const link = String(req.body.link || "").trim();

  if (!Number.isInteger(serviceId) || !Number.isInteger(quantity) || quantity < 1 ||
      !/^https?:\/\/\S+$/i.test(link)) {
    return res.redirect("/new-order?error=Please%20enter%20valid%20order%20details");
  }

  const service = db.prepare(
    "SELECT * FROM services WHERE id=? AND active=1"
  ).get(serviceId);

  if (!service || !service.provider_id) {
    return res.redirect("/new-order?error=Service%20not%20available");
  }

  if (quantity < service.min_qty || quantity > service.max_qty) {
    return res.redirect("/new-order?error=Quantity%20is%20outside%20the%20allowed%20range");
  }

  const charge = Number(((service.rate * quantity) / 1000).toFixed(2));
  if (!Number.isFinite(charge) || charge <= 0) {
    return res.redirect("/new-order?error=Invalid%20service%20price");
  }

  const reserve = db.transaction(() => {
    const freshUser = db.prepare("SELECT balance FROM users WHERE id=?").get(user.id);
    if (!freshUser || freshUser.balance < charge) return false;
    db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(charge, user.id);
    return true;
  });

  if (!reserve()) {
    return res.redirect("/new-order?error=Insufficient%20balance.%20Please%20add%20funds");
  }

  try {
    const result = await providerAddOrder(service.provider_id, link, quantity);
    if (!result || !result.order) throw new Error("Provider did not return an order ID");

    db.prepare(`
      INSERT INTO orders (user_id,service_id,provider_order_id,link,quantity,charge,status)
      VALUES (?,?,?,?,?,?,?)
    `).run(user.id, service.id, String(result.order), link, quantity, charge, "Pending");

    res.redirect("/orders?success=Order%20submitted%20successfully");
  } catch (error) {
    db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(charge, user.id);
    console.error("Provider order error:", error.message);
    res.redirect("/new-order?error=Order%20failed.%20Your%20balance%20has%20been%20refunded");
  }
});

app.get("/orders", requireLogin, (req, res) => {
  const user = currentUser(req);
  const orders = db.prepare(`
    SELECT o.*,s.name AS service_name
    FROM orders o LEFT JOIN services s ON s.id=o.service_id
    WHERE o.user_id=? ORDER BY o.id DESC LIMIT 300
  `).all(user.id);

  const rows = orders.map(o => `
    <tr>
      <td>${o.id}</td>
      <td>${escapeHtml(o.service_name || "Service")}</td>
      <td>${o.quantity}</td>
      <td>${money(o.charge)}</td>
      <td>${escapeHtml(o.status)}</td>
      <td>${escapeHtml(o.created_at)}</td>
    </tr>
  `).join("");

  res.send(page("My Orders", `
    <div class="card">
      <h1>My Orders</h1>
      ${messageBox(req)}
      <div class="tablewrap"><table>
      <thead><tr><th>Order</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th><th>Date</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6">No orders yet.</td></tr>'}</tbody>
      </table></div>
    </div>
  `, user));
});

app.get("/add-funds", requireLogin, (req, res) => {
  const user = currentUser(req);
  const upiId = process.env.UPI_ID || "";

  res.send(page("Add Funds", `
    <div class="card">
      <h1>Add Funds</h1>
      ${messageBox(req)}
      <p>Minimum amount: ₹100</p>
      <p>Maximum amount: ₹20,000</p>
      ${upiId ? `<p>UPI ID: <b>${escapeHtml(upiId)}</b></p>` : '<p class="muted">Payment UPI details will be provided by the administrator.</p>'}
      <p class="muted">After payment, submit your UPI transaction reference. Funds are added only after admin verification. This is manual verification, not automatic payment confirmation.</p>
      <form method="post" action="/add-funds">
        <label>Amount (₹)</label><input type="number" name="amount" min="100" max="20000" step="1" required>
        <label>UPI Transaction Reference</label><input name="reference" maxlength="100" required>
        <button type="submit">Submit Payment Request</button>
      </form>
    </div>
  `, user));
});

app.post("/add-funds", requireLogin, (req, res) => {
  const user = currentUser(req);
  const amount = Number(req.body.amount);
  const reference = String(req.body.reference || "").trim();

  if (!Number.isInteger(amount) || amount < 100 || amount > 20000 ||
      reference.length < 4 || reference.length > 100) {
    return res.redirect("/add-funds?error=Please%20enter%20valid%20payment%20details");
  }

  db.prepare(
    "INSERT INTO payments (user_id,amount,reference,status) VALUES (?,?,?,'Pending')"
  ).run(user.id, amount, reference);

  res.redirect("/add-funds?success=Payment%20request%20submitted%20for%20verification");
});

app.get("/support", requireLogin, (req, res) => {
  const user = currentUser(req);
  const tickets = db.prepare(
    "SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC"
  ).all(user.id);

  const rows = tickets.map(t => `
    <div class="card">
      <b>${escapeHtml(t.subject)}</b>
      <p>${escapeHtml(t.message)}</p>
      <small>Status: ${escapeHtml(t.status)} | ${escapeHtml(t.created_at)}</small>
    </div>
  `).join("");

  res.send(page("Support", `
    <div class="card">
      <h1>Support</h1>
      ${messageBox(req)}
      <form method="post" action="/support">
        <label>Subject</label><input name="subject" maxlength="120" required>
        <label>Message</label><textarea name="message" rows="5" maxlength="3000" required></textarea>
        <button type="submit">Send Message</button>
      </form>
    </div>
    <h2>My Tickets</h2>${rows || '<div class="card">No support tickets yet.</div>'}
  `, user));
});

app.post("/support", requireLogin, (req, res) => {
  const user = currentUser(req);
  const subject = String(req.body.subject || "").trim();
  const message = String(req.body.message || "").trim();

  if (!subject || !message || subject.length > 120 || message.length > 3000) {
    return res.redirect("/support?error=Please%20enter%20a%20valid%20message");
  }

  db.prepare(
    "INSERT INTO tickets (user_id,subject,message) VALUES (?,?,?)"
  ).run(user.id, subject, message);

  res.redirect("/support?success=Support%20message%20sent");
});

app.get("/admin", requireLogin, requireAdmin, (req, res) => {
  const user = currentUser(req);
  const users = db.prepare("SELECT id,email,balance,is_admin,created_at FROM users ORDER BY id DESC LIMIT 100").all();
  const payments = db.prepare(`
    SELECT p.*,u.email FROM payments p JOIN users u ON u.id=p.user_id
    ORDER BY p.id DESC LIMIT 100
  `).all();
  const serviceCount = db.prepare("SELECT COUNT(*) AS n FROM services WHERE active=1").get().n;
  const orderCount = db.prepare("SELECT COUNT(*) AS n FROM orders").get().n;

  const userRows = users.map(u => `
    <tr><td>${u.id}</td><td>${escapeHtml(u.email)}</td><td>${money(u.balance)}</td><td>${u.is_admin ? "Admin" : "User"}</td></tr>
  `).join("");

  const paymentRows = payments.map(p => `
    <tr>
      <td>${p.id}</td><td>${escapeHtml(p.email)}</td><td>${money(p.amount)}</td>
      <td>${escapeHtml(p.reference || "")}</td><td>${escapeHtml(p.status)}</td>
      <td>${p.status === "Pending" ? `
        <form method="post" action="/admin/payment/${p.id}/approve"><button>Approve</button></form>
        <form method="post" action="/admin/payment/${p.id}/reject"><button style="background:#555">Reject</button></form>
      ` : "-"}</td>
    </tr>
  `).join("");

  res.send(page("Admin", `
    <h1>Admin Panel</h1>
    ${messageBox(req)}
    <div class="grid">
      <div class="card"><p class="muted">Active Services</p><div class="stat">${serviceCount}</div></div>
      <div class="card"><p class="muted">Total Orders</p><div class="stat">${orderCount}</div></div>
    </div>
    <div class="card">
      <h2>Provider Services</h2>
      <form method="post" action="/admin/sync"><button>Sync Services From Provider</button></form>
      <p class="muted">This imports or updates services from your configured SMM provider.</p>
    </div>
    <div class="card">
      <h2>Payment Requests</h2>
      <div class="tablewrap"><table>
      <thead><tr><th>ID</th><th>User</th><th>Amount</th><th>Reference</th><th>Status</th><th>Action</th></tr></thead>
      <tbody>${paymentRows || '<tr><td colspan="6">No payment requests.</td></tr>'}</tbody>
      </table></div>
    </div>
    <div class="card">
      <h2>Users</h2>
      <div class="tablewrap"><table>
      <thead><tr><th>ID</th><th>Email</th><th>Balance</th><th>Role</th></tr></thead>
      <tbody>${userRows}</tbody>
      </table></div>
    </div>
  `, user));
});

app.post("/admin/sync", requireLogin, requireAdmin, async (req, res) => {
  try {
    const services = await providerServices();
    const upsert = db.prepare(`
      INSERT INTO services (provider_id,name,category,rate,min_qty,max_qty,description,active)
      VALUES (@provider_id,@name,@category,@rate,@min_qty,@max_qty,@description,1)
      ON CONFLICT(provider_id) DO UPDATE SET
        name=excluded.name,
        category=excluded.category,
        rate=excluded.rate,
        min_qty=excluded.min_qty,
        max_qty=excluded.max_qty,
        description=excluded.description,
        active=1
    `);

    const sync = db.transaction(items => {
      for (const s of items) {
        if (!s || s.service === undefined || !s.name) continue;
        const rate = Number(s.rate);
        const min = Math.max(1, Number(s.min) || 1);
        const max = Math.max(min, Number(s.max) || 100000);

        upsert.run({
          provider_id: String(s.service),
          name: String(s.name),
          category: String(s.category || "Other"),
          rate: Number.isFinite(rate) ? rate : 0,
          min_qty: min,
          max_qty: max,
          description: String(s.desc || "")
        });
      }
    });

    sync(services);
    res.redirect("/admin?success=Provider%20services%20synced");
  } catch (error) {
    console.error("Service sync error:", error.message);
    res.redirect("/admin?error=Provider%20sync%20failed.%20Check%20API%20settings");
  }
});

app.post("/admin/payment/:id/approve", requireLogin, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const approve = db.transaction(() => {
    const payment = db.prepare("SELECT * FROM payments WHERE id=?").get(id);
    if (!payment || payment.status !== "Pending") return false;

    db.prepare("UPDATE payments SET status='Approved' WHERE id=?").run(id);
    db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(payment.amount, payment.user_id);
    return true;
  });

  const result = approve();
  res.redirect("/admin?" + (result ? "success=Payment%20approved" : "error=Payment%20already%20processed"));
});

app.post("/admin/payment/:id/reject", requireLogin, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const result = db.prepare(
    "UPDATE payments SET status='Rejected' WHERE id=? AND status='Pending'"
  ).run(id);

  res.redirect("/admin?" + (result.changes ? "success=Payment%20request%20rejected" : "error=Payment%20already%20processed"));
});

app.get("/terms", (req, res) => {
  res.send(page("Terms", `
    <div class="card">
      <h1>Terms and Conditions</h1>
      <p>Orders are processed according to the selected service details and provider availability.</p>
      <p>Payment requests require administrator verification.</p>
      <p>Users must submit correct links and quantities when placing orders.</p>
    </div>
  `, currentUser(req)));
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", app: "PanelAdminSMM.shop" });
});

app.use((req, res) => {
  res.status(404).send(page("Not Found", `
    <div class="card"><h1>404</h1><p>Page not found.</p><a href="/">Go Home</a></div>
  `, currentUser(req)));
});

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).send(page("Server Error", `
    <div class="card"><h1>Something went wrong</h1><p>Please try again later.</p></div>
  `, currentUser(req)));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`PanelAdminSMM.shop running on port ${PORT}`);
});
