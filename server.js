require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
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
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300
}));

const platforms = [
  { name: "Instagram", icon: "📸" },
  { name: "Facebook", icon: "📘" },
  { name: "YouTube", icon: "▶️" },
  { name: "TikTok", icon: "🎵" },
  { name: "Telegram", icon: "✈️" },
  { name: "WhatsApp", icon: "💬" },
  { name: "Twitter", icon: "𝕏" }
];

const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;",
  '"': "&quot;", "'": "&#39;"
}[c]));

const money = value => "₹" + Number(value || 0).toFixed(2);

async function initDB() {
  // Existing data is preserved.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(150),
      email VARCHAR(255) UNIQUE,
      password TEXT,
      balance NUMERIC DEFAULT 0,
      role VARCHAR(30) DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Fix missing columns in existing users table.
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS name VARCHAR(150),
    ADD COLUMN IF NOT EXISTS email VARCHAR(255),
    ADD COLUMN IF NOT EXISTS password TEXT,
    ADD COLUMN IF NOT EXISTS balance NUMERIC DEFAULT 0,
    ADD COLUMN IF NOT EXISTS role VARCHAR(30) DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  await pool.query(`
    UPDATE users SET role = 'user' WHERE role IS NULL
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      provider_id TEXT,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      rate NUMERIC DEFAULT 0,
      min INTEGER DEFAULT 1,
      max INTEGER DEFAULT 1000000,
      description TEXT,
      active BOOLEAN DEFAULT TRUE,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id BIGINT,
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
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id BIGINT,
      amount NUMERIC,
      utr TEXT,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
      user_id BIGINT,
      message TEXT,
      status TEXT DEFAULT 'Open',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Create admin only if configured and not already present.
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminEmail && adminPassword) {
    const found = await pool.query(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
      [adminEmail]
    );

    if (found.rows.length) {
      await pool.query(
        "UPDATE users SET role='admin' WHERE id=$1",
        [found.rows[0].id]
      );
    } else {
      const hash = await bcrypt.hash(adminPassword, 12);
      await pool.query(
        `INSERT INTO users (name,email,password,balance,role)
         VALUES ($1,$2,$3,0,'admin')`,
        ["Administrator", adminEmail, hash]
      );
    }
  }

  console.log("Database initialized successfully");
}

function page(title, body, user = null) {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} - Royal Panel</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f3f4f8;color:#202033;font-family:Arial,sans-serif}
header{background:#171727;color:white;padding:17px 20px;font-size:21px;font-weight:bold}
header span{color:#ff4545}
nav{background:#24243b;padding:12px;display:flex;gap:10px;flex-wrap:wrap}
nav a{color:white;text-decoration:none;padding:9px 12px;border-radius:7px;font-size:14px}
nav a:hover{background:#41415e}
main{max-width:1050px;margin:22px auto;padding:0 14px}
.card{background:white;padding:19px;border-radius:13px;margin-bottom:15px;box-shadow:0 2px 12px #0000000c}
h2{margin-top:0}
input,select,textarea{width:100%;padding:12px;margin:7px 0 14px;border:1px solid #ddd;border-radius:8px;font-size:15px}
button,.btn{background:#e52e39;color:white;border:0;padding:12px 17px;border-radius:8px;cursor:pointer;text-decoration:none;display:inline-block}
button:hover,.btn:hover{background:#c51e2b}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.platform{background:white;border:1px solid #e3e3e9;padding:20px 10px;border-radius:12px;text-align:center;text-decoration:none;color:#222;font-weight:bold}
.platform b{display:block;font-size:30px;margin-bottom:9px}
.platform:hover{border-color:#e52e39}
.muted{color:#777;font-size:13px}
table{width:100%;border-collapse:collapse;background:white}
td,th{padding:11px;border-bottom:1px solid #eee;text-align:left;font-size:14px}
.badge{background:#fff0d5;padding:5px 8px;border-radius:6px}
.danger{background:#333}
@media(max-width:600px){td,th{padding:7px;font-size:12px}}
</style>
</head>
<body>
<header>ROYAL <span>PANEL</span></header>
${user ? `<nav>
<a href="/dashboard">Dashboard</a>
<a href="/new-order">New Order</a>
<a href="/orders">My Orders</a>
<a href="/add-funds">Add Funds</a>
<a href="/support">Support</a>
${user.role === "admin" ? '<a href="/admin">Admin Panel</a>' : ""}
<a href="/logout">Logout</a>
</nav>` : ""}
<main>${body}</main>
</body></html>`;
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Admin access required");
  }
  next();
}

app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/dashboard" : "/login");
});

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h2>Create Account</h2>
      <form method="POST">
        <input name="name" placeholder="Your Name" required>
        <input name="email" type="email" placeholder="Email Address" required>
        <input name="password" type="password" placeholder="Password" required minlength="6">
        <button>Create Account</button>
      </form>
      <a href="/login">Already have an account? Login</a>
    </div>
  `));
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 6) {
      return res.send("Please enter valid details. Password must be at least 6 characters.");
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1)",
      [email]
    );

    if (existing.rows.length) return res.send("Email already registered.");

    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      `INSERT INTO users(name,email,password,balance,role)
       VALUES($1,$2,$3,0,'user')`,
      [name, email, hash]
    );

    res.redirect("/login");
  } catch (e) {
    console.error(e);
    res.status(500).send("Registration failed.");
  }
});

app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card">
      <h2>Login to Royal Panel</h2>
      <form method="POST">
        <input name="email" type="email" placeholder="Email Address" required>
        <input name="password" type="password" placeholder="Password" required>
        <button>Login</button>
      </form>
      <a href="/register">Create New Account</a>
    </div>
  `));
});

app.post("/login", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
      [req.body.email]
    );

    if (!result.rows.length) return res.send("Invalid email or password.");

    const user = result.rows[0];
    const valid = await bcrypt.compare(req.body.password, user.password);

    if (!valid) return res.send("Invalid email or password.");

    req.session.regenerate(err => {
      if (err) return res.status(500).send("Login failed.");
      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role || "user"
      };
      res.redirect("/dashboard");
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("Login error.");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireLogin, async (req, res) => {
  try {
    const u = await pool.query(
      "SELECT balance FROM users WHERE id=$1",
      [req.session.user.id]
    );

    const orders = await pool.query(
      "SELECT COUNT(*) AS total FROM orders WHERE user_id=$1",
      [req.session.user.id]
    );

    res.send(page("Dashboard", `
      <div class="card">
        <h2>Welcome, ${esc(req.session.user.name)}</h2>
        <p>Your Royal Panel account</p>
        <h2>Balance: ${money(u.rows[0]?.balance)}</h2>
        <p>Total Orders: ${orders.rows[0].total}</p>
        <a class="btn" href="/new-order">Place New Order</a>
      </div>
      <div class="grid">
        <a class="platform" href="/new-order"><b>📦</b>New Order</a>
        <a class="platform" href="/orders"><b>📋</b>My Orders</a>
        <a class="platform" href="/add-funds"><b>💰</b>Add Funds</a>
        <a class="platform" href="/support"><b>🎧</b>Support</a>
      </div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Dashboard error.");
  }
});

// Separate platform selection and search.
app.get("/new-order", requireLogin, (req, res) => {
  const cards = platforms.map(p => `
    <a class="platform" href="/new-order/${encodeURIComponent(p.name)}">
      <b>${p.icon}</b>${p.name}
    </a>
  `).join("");

  res.send(page("New Order", `
    <div class="card">
      <h2>Select Platform</h2>
      <p class="muted">Choose a platform to view its services.</p>
      <div class="grid">${cards}</div>
    </div>
  `, req.session.user));
});

app.get("/new-order/:platform", requireLogin, async (req, res) => {
  try {
    const platform = platforms.find(
      p => p.name.toLowerCase() === req.params.platform.toLowerCase()
    );
    if (!platform) return res.redirect("/new-order");

    const result = await pool.query(
      `SELECT id,name,category,rate,min,max,description
       FROM services
       WHERE active=TRUE AND LOWER(category)=LOWER($1)
       ORDER BY id DESC`,
      [platform.name]
    );

    const services = result.rows.map(s => `
      <option value="${s.id}"
        data-rate="${Number(s.rate)}"
        data-min="${Number(s.min)}"
        data-max="${Number(s.max)}">
        ${esc(s.name)} — ${money(s.rate)} per 1000
      </option>
    `).join("");

    res.send(page("New Order", `
      <div class="card">
        <a href="/new-order">← All Platforms</a>
        <h2>${platform.icon} ${platform.name} Services</h2>
        <input id="search" placeholder="Search ${platform.name} services...">
        <form method="POST" action="/place-order">
          <input type="hidden" name="platform" value="${esc(platform.name)}">
          <label>Select Service</label>
          <select name="service_id" id="service" required>
            <option value="">Choose a service</option>
            ${services}
          </select>
          <label>Post / Profile Link</label>
          <input name="link" type="url" placeholder="https://..." required>
          <label>Quantity</label>
          <input name="quantity" id="quantity" type="number" min="1" required>
          <p id="price" class="muted">Select service and quantity to calculate price.</p>
          <button type="submit">Place Order</button>
        </form>
      </div>
      <script>
      const search=document.getElementById('search');
      const select=document.getElementById('service');
      const qty=document.getElementById('quantity');
      const price=document.getElementById('price');
      const original=[...select.options];
      search.addEventListener('input',()=>{
        const term=search.value.toLowerCase();
        select.innerHTML='';
        original.forEach((o,i)=>{
          if(i===0 || o.text.toLowerCase().includes(term)) select.add(o.cloneNode(true));
        });
      });
      function calc(){
        const o=select.selectedOptions[0];
        if(!o || !o.value || !qty.value){price.textContent='Select service and quantity to calculate price.';return;}
        const rate=Number(o.dataset.rate);
        const min=Number(o.dataset.min);
        const max=Number(o.dataset.max);
        const q=Number(qty.value);
        price.textContent='Price: ₹'+(rate*q/1000).toFixed(2)+' | Min: '+min+' | Max: '+max;
        qty.min=min;qty.max=max;
      }
      select.addEventListener('change',calc);
      qty.addEventListener('input',calc);
      </script>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Could not load services.");
  }
});

app.post("/place-order", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    const userId = req.session.user.id;
    const serviceId = Number(req.body.service_id);
    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(serviceId) || !Number.isInteger(quantity) || quantity < 1 || !link) {
      return res.status(400).send("Invalid order details.");
    }

    await client.query("BEGIN");

    const serviceResult = await client.query(
      `SELECT * FROM services WHERE id=$1 AND active=TRUE FOR UPDATE`,
      [serviceId]
    );

    if (!serviceResult.rows.length) throw new Error("Service not available.");

    const service = serviceResult.rows[0];

    if (quantity < Number(service.min) || quantity > Number(service.max)) {
      throw new Error("Quantity must be between " + service.min + " and " + service.max);
    }

    const charge = Number(service.rate) * quantity / 1000;

    const userResult = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [userId]
    );

    if (!userResult.rows.length) throw new Error("Account not found.");

    if (Number(userResult.rows[0].balance) < charge) {
      throw new Error("Insufficient balance. Please add funds.");
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [charge, userId]
    );

    await client.query(
      `INSERT INTO orders(user_id,service_id,link,quantity,charge,status)
       VALUES($1,$2,$3,$4,$5,'Pending')`,
      [userId, serviceId, link, quantity, charge]
    );

    await client.query("COMMIT");
    res.redirect("/orders");
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).send(esc(e.message));
  } finally {
    client.release();
  }
});

app.get("/orders", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*,s.name AS service_name,s.category
       FROM orders o
       LEFT JOIN services s ON s.id=o.service_id
       WHERE o.user_id=$1 ORDER BY o.id DESC`,
      [req.session.user.id]
    );

    const rows = result.rows.map(o => `
      <tr>
        <td>${o.id}</td>
        <td>${esc(o.category || "")}<br>${esc(o.service_name || "Service")}</td>
        <td>${Number(o.quantity)}</td>
        <td>${money(o.charge)}</td>
        <td><span class="badge">${esc(o.status)}</span></td>
      </tr>
    `).join("");

    res.send(page("My Orders", `
      <div class="card">
        <h2>My Orders</h2>
        <table><tr><th>ID</th><th>Service</th><th>Qty</th><th>Charge</th><th>Status</th></tr>
        ${rows || '<tr><td colspan="5">No orders yet.</td></tr>'}
        </table>
      </div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Orders error.");
  }
});

app.get("/add-funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
    <div class="card">
      <h2>Add Funds</h2>
      <p>Minimum ₹100 — Maximum ₹2000</p>
      <form method="POST">
        <input name="amount" type="number" min="100" max="2000" step="1" placeholder="Amount ₹" required>
        <input name="utr" placeholder="Payment UTR / Transaction ID" required>
        <button>Submit Payment Request</button>
      </form>
      <p class="muted">Payment requests are manually verified by admin.</p>
    </div>
  `, req.session.user));
});

app.post("/add-funds", requireLogin, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const utr = String(req.body.utr || "").trim();

    if (!Number.isInteger(amount) || amount < 100 || amount > 2000 || !utr) {
      return res.status(400).send("Amount must be between ₹100 and ₹2000.");
    }

    await pool.query(
      `INSERT INTO payments(user_id,amount,utr,status)
       VALUES($1,$2,$3,'Pending')`,
      [req.session.user.id, amount, utr]
    );

    res.send(page("Payment Request", `
      <div class="card"><h2>Request Submitted</h2>
      <p>Your payment is pending admin verification.</p>
      <a class="btn" href="/dashboard">Dashboard</a></div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Payment request failed.");
  }
});

app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
    <div class="card">
      <h2>Support</h2>
      <form method="POST">
        <textarea name="message" placeholder="Write your message..." required></textarea>
        <button>Send Message</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/support", requireLogin, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();
    if (!message) return res.send("Please write a message.");

    await pool.query(
      `INSERT INTO tickets(user_id,message,status)
       VALUES($1,$2,'Open')`,
      [req.session.user.id, message]
    );

    res.redirect("/support");
  } catch (e) {
    console.error(e);
    res.status(500).send("Support message failed.");
  }
});

app.get("/admin", requireLogin, requireAdmin, async (req, res) => {
  try {
    const [users, orders, payments, services] = await Promise.all([
      pool.query("SELECT COUNT(*) AS n FROM users"),
      pool.query("SELECT COUNT(*) AS n FROM orders"),
      pool.query("SELECT * FROM payments WHERE status='Pending' ORDER BY id DESC"),
      pool.query("SELECT * FROM services ORDER BY category,id DESC")
    ]);

    const paymentRows = payments.rows.map(p => `
      <tr><td>${p.id}</td><td>${p.user_id}</td><td>${money(p.amount)}</td>
      <td>${esc(p.utr)}</td><td>${esc(p.status)}</td>
      <td><form method="POST" action="/admin/approve-payment/${p.id}">
      <button>Approve</button></form></td></tr>
    `).join("");

    const serviceRows = services.rows.map(s => `
      <tr><td>${s.id}</td><td>${esc(s.category)}</td><td>${esc(s.name)}</td>
      <td>${money(s.rate)}</td><td>${s.active ? "Active" : "Inactive"}</td>
      <td><form method="POST" action="/admin/toggle-service/${s.id}">
      <button class="danger">Toggle</button></form></td></tr>
    `).join("");

    res.send(page("Admin Panel", `
      <div class="card">
        <h2>Admin Dashboard</h2>
        <p>Users: ${users.rows[0].n} | Orders: ${orders.rows[0].n}</p>
      </div>
      <div class="card">
        <h2>Add Service</h2>
        <form method="POST" action="/admin/add-service">
          <select name="category" required>
            ${platforms.map(p => `<option>${p.name}</option>`).join("")}
          </select>
          <input name="name" placeholder="Service Name" required>
          <input name="rate" type="number" step="0.01" placeholder="Rate per 1000" required>
          <input name="min" type="number" placeholder="Minimum Quantity" required>
          <input name="max" type="number" placeholder="Maximum Quantity" required>
          <textarea name="description" placeholder="Description"></textarea>
          <button>Add Service</button>
        </form>
      </div>
      <div class="card">
        <h2>Services</h2>
        <table><tr><th>ID</th><th>Platform</th><th>Name</th><th>Rate</th><th>Status</th><th>Action</th></tr>
        ${serviceRows}</table>
      </div>
      <div class="card">
        <h2>Pending Payments</h2>
        <table><tr><th>ID</th><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>
        ${paymentRows || '<tr><td colspan="6">No pending payments.</td></tr>'}</table>
      </div>
    `, req.session.user));
  } catch (e) {
    console.error(e);
    res.status(500).send("Admin page error.");
  }
});

app.post("/admin/add-service", requireLogin, requireAdmin, async (req, res) => {
  try {
    const { category, name, description } = req.body;
    const rate = Number(req.body.rate);
    const min = Number(req.body.min);
    const max = Number(req.body.max);

    if (!platforms.some(p => p.name === category) ||
        !name || !Number.isFinite(rate) || rate < 0 ||
        !Number.isInteger(min) || !Number.isInteger(max) ||
        min < 1 || max < min) {
      return res.status(400).send("Invalid service details.");
    }

    await pool.query(
      `INSERT INTO services(name,category,rate,min,max,description,active,updated_at)
       VALUES($1,$2,$3,$4,$5,$6,TRUE,NOW())`,
      [name, category, rate, min, max, description || ""]
    );

    res.redirect("/admin");
  } catch (e) {
    console.error(e);
    res.status(500).send("Could not add service.");
  }
});

app.post("/admin/toggle-service/:id", requireLogin, requireAdmin, async (req, res) => {
  try {
    await pool.query(
      "UPDATE services SET active=NOT active,updated_at=NOW() WHERE id=$1",
      [req.params.id]
    );
    res.redirect("/admin");
  } catch (e) {
    console.error(e);
    res.status(500).send("Could not update service.");
  }
});

app.post("/admin/approve-payment/:id", requireLogin, requireAdmin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    if (!result.rows.length) throw new Error("Payment not found.");

    const payment = result.rows[0];

    if (payment.status !== "Pending") {
      throw new Error("Payment has already been processed.");
    }

    await client.query(
      "UPDATE users SET balance=balance+$1 WHERE id=$2",
      [payment.amount, payment.user_id]
    );

    await client.query(
      "UPDATE payments SET status='Approved' WHERE id=$1",
      [payment.id]
    );

    await client.query("COMMIT");
    res.redirect("/admin");
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).send(esc(e.message));
  } finally {
    client.release();
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", app: "Royal Panel" });
});

app.use((req, res) => {
  res.status(404).send(page("Not Found", `
    <div class="card"><h2>Page Not Found</h2><a href="/">Go Home</a></div>
  `, req.session.user));
});

async function start() {
  try {
    await initDB();
    const port = process.env.PORT || 3000;
    app.listen(port, "0.0.0.0", () => {
      console.log("Royal Panel running on port " + port);
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

start();

