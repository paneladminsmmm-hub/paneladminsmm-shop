
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  throw new Error("DATABASE_URL and SESSION_SECRET are required");
}

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "100kb" }));

app.use(session({
  name: "royal_smm_session",
  secret: process.env.SESSION_SECRET,
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
  limit: 200,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

const categories = [
  { name: "Instagram", icon: "📸" },
  { name: "Facebook", icon: "🔵" },
  { name: "YouTube", icon: "▶️" },
  { name: "TikTok", icon: "🎵" },
  { name: "Telegram", icon: "✈️" },
  { name: "WhatsApp", icon: "💬" },
  { name: "Twitter", icon: "𝕏" }
];

const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
}[c]));

const money = n => "₹" + Number(n || 0).toFixed(2);

function auth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function admin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Admin access required");
  }
  next();
}

// Existing database is preserved.
// These CREATE statements only create missing tables;
// they do not replace existing tables or their data.
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      balance NUMERIC(12,2) DEFAULT 0,
      role VARCHAR(50) DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      provider_id TEXT,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      rate NUMERIC(12,2) DEFAULT 0,
      min INTEGER DEFAULT 100,
      max INTEGER DEFAULT 100000,
      description TEXT DEFAULT '',
      active BOOLEAN DEFAULT TRUE,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      service_id INTEGER REFERENCES services(id),
      provider_order_id TEXT,
      link TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      charge NUMERIC(12,2) NOT NULL,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      amount NUMERIC(12,2) NOT NULL,
      utr TEXT NOT NULL,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      message TEXT NOT NULL,
      status TEXT DEFAULT 'Open',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Promote the configured admin without changing an existing password.
  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const email = process.env.ADMIN_EMAIL.toLowerCase().trim();

    const existing = await db.query(
      "SELECT id FROM users WHERE LOWER(email)=$1 LIMIT 1",
      [email]
    );

    if (existing.rows.length) {
      await db.query(
        "UPDATE users SET role='admin' WHERE id=$1",
        [existing.rows[0].id]
      );
    } else {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
      await db.query(
        "INSERT INTO users(name,email,password,role) VALUES($1,$2,$3,$4)",
        ["Administrator", email, hash, "admin"]
      );
    }
  }
}

function page(title, content, user = null) {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} | SMM.com</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f3f5fa;color:#202438;font-family:Arial,sans-serif}
header{background:#111827;color:white;padding:17px 5%;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.logo{font-size:25px;font-weight:900;color:#ff354d}
header a{color:white;text-decoration:none;margin:5px;font-size:14px}
.container{max-width:1100px;margin:25px auto;padding:0 15px}
.card{background:white;padding:20px;border-radius:14px;margin-bottom:17px;box-shadow:0 3px 15px #00000008}
h2{margin-top:0}
input,select,textarea{width:100%;padding:13px;border:1px solid #ddd;border-radius:9px;margin:8px 0 15px;font-size:15px}
button,.btn{background:#e92e48;color:white;border:0;border-radius:9px;padding:12px 18px;cursor:pointer;text-decoration:none;display:inline-block}
button:hover,.btn:hover{opacity:.85}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.category{background:white;padding:19px 8px;border-radius:13px;text-align:center;border:2px solid #eee;cursor:pointer;display:block;text-decoration:none;color:inherit;transition:.2s}
.category:hover{border-color:#e92e48;transform:translateY(-2px)}
.category .icon{font-size:34px;display:block;margin-bottom:9px}
.category strong{font-size:15px}
.service{padding:15px;border:1px solid #eee;border-radius:10px;margin:10px 0;background:white}
.service h3{margin:0 0 8px}
.small{color:#777;font-size:13px}
table{width:100%;border-collapse:collapse;background:white;display:block;overflow-x:auto}
td,th{padding:11px;border-bottom:1px solid #eee;text-align:left;font-size:13px}
.red{color:#e92e48;font-weight:bold}
.notice{background:#fff4dc;padding:13px;border-radius:9px;margin:12px 0}
.back{display:inline-block;margin-bottom:14px;color:#e92e48;text-decoration:none;font-weight:bold}
.platform-title{display:flex;align-items:center;gap:10px}
.platform-title span{font-size:32px}
.search-box input{padding:15px;border:2px solid #e5e7eb}
.search-box input:focus{outline:none;border-color:#e92e48}
@media(max-width:600px){
header{padding:14px}
.container{margin:15px auto}
.card{padding:15px}
.grid{grid-template-columns:repeat(2,1fr)}
}
</style>
</head>
<body>
<header>
<div class="logo">ROYAL PANEL</div>
<nav>
${user ? `
<a href="/dashboard">Dashboard</a>
<a href="/services">Services</a>
<a href="/new-order">New Order</a>
<a href="/orders">My Orders</a>
<a href="/add-funds">Add Funds</a>
<a href="/support">Support</a>
${user.role === "admin" ? '<a href="/admin">Admin Panel</a>' : ''}
<a href="/logout">Logout</a>
` : '<a href="/login">Login</a><a href="/register">Register</a>'}
</nav>
</header>
<div class="container">${content}</div>
</body></html>`;
}

function sendPage(res, title, content, user = null) {
  res.send(page(title, content, user));
}

// HOME
app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");

  sendPage(res, "Welcome", `
  <div class="card" style="text-align:center;padding:45px 15px">
    <h1>Welcome to <span class="red">ROYAL PANEL</span></h1>
    <p>Social Media Services Management Panel</p>
    <a class="btn" href="/register">Create Account</a>
    <a class="btn" href="/login">Login</a>
  </div>`);
});

// REGISTER
app.get("/register", (req, res) => {
  sendPage(res, "Register", `
  <div class="card">
  <h2>Create Account</h2>
  <form method="POST" action="/register">
  <input name="name" placeholder="Full Name" required maxlength="80">
  <input name="email" type="email" placeholder="Email Address" required>
  <input name="password" type="password" placeholder="Password (minimum 8 characters)" minlength="8" required>
  <button>Create Account</button>
  </form>
  <a href="/login">Already have an account? Login</a>
  </div>`);
});

app.post("/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || password.length < 8) {
      return res.status(400).send("Please enter valid details and an 8-character password.");
    }

    const hash = await bcrypt.hash(password, 12);

    await db.query(
      "INSERT INTO users(name,email,password) VALUES($1,$2,$3)",
      [name, email, hash]
    );

    res.redirect("/login");
  } catch (e) {
    console.error("Registration error:", e);
    res.status(400).send("Registration failed. Email may already exist.");
  }
});

// LOGIN
app.get("/login", (req, res) => {
  sendPage(res, "Login", `
  <div class="card">
  <h2>Account Login</h2>
  <form method="POST" action="/login">
  <input name="email" type="email" placeholder="Email" required>
  <input name="password" type="password" placeholder="Password" required>
  <button>Login</button>
  </form>
  <a href="/register">Create New Account</a>
  </div>`);
});

app.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();

    const result = await db.query(
      "SELECT * FROM users WHERE LOWER(email)=$1 LIMIT 1",
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(String(req.body.password || ""), user.password))) {
      return res.status(401).send("Incorrect email or password. <a href='/login'>Try again</a>");
    }

    req.session.regenerate(err => {
      if (err) return res.status(500).send("Session error");

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      };

      res.redirect("/dashboard");
    });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).send("Login error");
  }
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// DASHBOARD
app.get("/dashboard", auth, async (req, res) => {
  const user = req.session.user;

  try {
    const [balance, orders, services] = await Promise.all([
      db.query("SELECT balance FROM users WHERE id=$1", [user.id]),
      db.query("SELECT COUNT(*) FROM orders WHERE user_id=$1", [user.id]),
      db.query("SELECT COUNT(*) FROM services WHERE active=TRUE")
    ]);

    sendPage(res, "Dashboard", `
    <div class="card">
      <h2>Welcome, ${esc(user.name)} 👋</h2>
      <p>Account: ${esc(user.email)}</p>
    </div>
    <div class="grid">
      <div class="card"><p>Available Balance</p><h2 class="red">${money(balance.rows[0].balance)}</h2></div>
      <div class="card"><p>Total Orders</p><h2>${orders.rows[0].count}</h2></div>
      <div class="card"><p>Available Services</p><h2>${services.rows[0].count}</h2></div>
    </div>
    <div class="card">
      <h2>Quick Actions</h2>
      <a class="btn" href="/new-order">New Order</a>
      <a class="btn" href="/orders">Order History</a>
      <a class="btn" href="/add-funds">Add Funds</a>
    </div>
    `, user);
  } catch (e) {
    console.error("Dashboard error:", e);
    res.status(500).send("Dashboard error");
  }
});

// SERVICES
app.get("/services", auth, async (req, res) => {
  try {
    const selected = String(req.query.category || "").trim();
    const search = String(req.query.search || "").trim();

    const result = await db.query(`
      SELECT * FROM services
      WHERE active=TRUE
      AND ($1='' OR LOWER(TRIM(category))=LOWER($1))
      AND ($2='' OR name ILIKE $3 OR COALESCE(description,'') ILIKE $3)
      ORDER BY category,id
    `, [selected, search, `%${search}%`]);

    let html = `
    <div class="card">
      <h2>All Social Media Services</h2>
      <form method="GET" action="/services">
        <input name="search" placeholder="🔍 Search services..." value="${esc(search)}">
        <button>Search</button>
      </form>
    </div>
    <div class="grid">`;

    for (const cat of categories) {
      html += `<a class="category" href="/new-order?category=${encodeURIComponent(cat.name)}">
        <span class="icon">${cat.icon}</span><strong>${cat.name}</strong>
      </a>`;
    }

    html += `</div><div class="card"><h2>${selected ? esc(selected) + " Services" : "Available Services"}</h2>`;

    if (!result.rows.length) {
      html += `<p>No services found.</p>`;
    }

    for (const s of result.rows) {
      const cat = categories.find(c => c.name.toLowerCase() === String(s.category).toLowerCase());

      html += `
      <div class="service">
        <h3>${cat?.icon || "⭐"} ${esc(s.name)}</h3>
        <p class="small">${esc(s.category)} · ${esc(s.description)}</p>
        <p>Price: <b>${money(s.rate)} / 1000</b></p>
        <p class="small">Minimum: ${s.min} | Maximum: ${s.max}</p>
        <a class="btn" href="/new-order?category=${encodeURIComponent(s.category)}&service=${s.id}">Order Now</a>
      </div>`;
    }

    html += `</div>`;
    sendPage(res, "Services", html, req.session.user);
  } catch (e) {
    console.error("Services error:", e);
    res.status(500).send("Services loading error");
  }
});

// NEW ORDER - PLATFORM SELECTION
app.get("/new-order", auth, async (req, res) => {
  try {
    const selected = String(req.query.category || "").trim();
    const search = String(req.query.search || "").trim();
    const serviceId = String(req.query.service || "").trim();

    if (selected && !categories.some(c => c.name.toLowerCase() === selected.toLowerCase())) {
      return res.status(400).send("Invalid platform");
    }

    if (!selected) {
      let html = `
      <div class="card">
        <h2>Place New Order</h2>
        <p>Select your social media platform</p>
        <input id="platformSearch" placeholder="🔍 Search platform...">
      </div>
      <div class="grid" id="platformGrid">`;

      for (const cat of categories) {
        const count = await db.query(`
          SELECT COUNT(*) FROM services
          WHERE active=TRUE
          AND LOWER(TRIM(category))=LOWER($1)
        `, [cat.name]);

        html += `
        <a class="category" data-platform="${cat.name.toLowerCase()}"
           href="/new-order?category=${encodeURIComponent(cat.name)}">
          <span class="icon">${cat.icon}</span>
          <strong>${cat.name}</strong>
          <p class="small">${count.rows[0].count} Services</p>
        </a>`;
      }

      html += `</div>
      <script>
      document.getElementById("platformSearch").addEventListener("input", function(){
        const q=this.value.toLowerCase();
        document.querySelectorAll("#platformGrid .category").forEach(el=>{
          el.style.display=el.dataset.platform.includes(q)?"block":"none";
        });
      });
      </script>`;

      return sendPage(res, "New Order", html, req.session.user);
    }

    const cat = categories.find(c => c.name.toLowerCase() === selected.toLowerCase());

    const result = await db.query(`
      SELECT * FROM services
      WHERE active=TRUE
      AND LOWER(TRIM(category))=LOWER($1)
      AND ($2='' OR name ILIKE $3 OR COALESCE(description,'') ILIKE $3)
      ORDER BY id DESC
    `, [cat.name, search, `%${search}%`]);

    let html = `
    <div class="card">
      <a class="back" href="/new-order">← All Platforms</a>
      <div class="platform-title">
        <span>${cat.icon}</span>
        <h2>${esc(cat.name)} Services</h2>
      </div>
      <form method="GET" action="/new-order">
        <input type="hidden" name="category" value="${esc(cat.name)}">
        <div class="search-box">
          <input name="search" placeholder="🔍 Search ${esc(cat.name)} services..." value="${esc(search)}">
        </div>
        <button type="submit">Search Services</button>
        <a class="btn" href="/new-order?category=${encodeURIComponent(cat.name)}">Show All</a>
      </form>
    </div>`;

    if (!result.rows.length) {
      html += `<div class="card"><p>No active ${esc(cat.name)} services found.</p></div>`;
    }

    for (const s of result.rows) {
      html += `
      <div class="service">
        <h3>${esc(s.name)}</h3>
        <p class="small">${esc(s.description)}</p>
        <p>Price: <b>${money(s.rate)} / 1000</b></p>
        <p class="small">Minimum: ${s.min} | Maximum: ${s.max}</p>
        <a class="btn" href="/new-order?category=${encodeURIComponent(cat.name)}&service=${s.id}">Select Service</a>
      </div>`;
    }

    if (serviceId) {
      const chosen = await db.query(`
        SELECT * FROM services
        WHERE id=$1 AND active=TRUE
        AND LOWER(TRIM(category))=LOWER($2)
      `, [serviceId, cat.name]);

      if (chosen.rows.length) {
        const s = chosen.rows[0];

        html += `
        <div class="card">
          <h2>Place Order</h2>
          <h3>${esc(s.name)}</h3>
          <p>Price: ${money(s.rate)} / 1000</p>
          <form method="POST" action="/new-order/${s.id}">
            <label>Post Profile Link</label>
            <input name="link" type="url" placeholder="https://..." required>
            <label>Quantity</label>
            <input name="quantity" type="number" min="${s.min}" max="${s.max}" required>
            <button type="submit">Place Order</button>
          </form>
        </div>`;
      }
    }

    sendPage(res, "New Order", html, req.session.user);
  } catch (e) {
    console.error("New order page error:", e);
    res.status(500).send("New Order loading error");
  }
});

// OLD ORDER URL SUPPORT
app.get("/new-order/:id", auth, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM services WHERE id=$1 AND active=TRUE",
      [req.params.id]
    );

    if (!result.rows.length) return res.status(404).send("Service not found");

    const s = result.rows[0];
    res.redirect(`/new-order?category=${encodeURIComponent(s.category)}&service=${s.id}`);
  } catch (e) {
    console.error(e);
    res.status(500).send("Service error");
  }
});

// PLACE ORDER
app.post("/new-order/:id", auth, async (req, res) => {
  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const service = await client.query(
      "SELECT * FROM services WHERE id=$1 AND active=TRUE",
      [req.params.id]
    );

    if (!service.rows.length) throw new Error("Service not found");

    const s = service.rows[0];
    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(quantity) ||
        quantity < Number(s.min) ||
        quantity > Number(s.max) ||
        !/^https?:\/\//i.test(link)) {
      throw new Error("Invalid link or quantity");
    }

    const charge = Number((Number(s.rate) * quantity / 1000).toFixed(2));

    const account = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.session.user.id]
    );

    if (!account.rows.length || Number(account.rows[0].balance) < charge) {
      throw new Error("Insufficient balance. Please Add Funds.");
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [charge, req.session.user.id]
    );

    // Existing orders schema has no service_name column.
    await client.query(`
      INSERT INTO orders(user_id,service_id,link,quantity,charge,status)
      VALUES($1,$2,$3,$4,$5,'Pending')
    `, [req.session.user.id, s.id, link, quantity, charge]);

    await client.query("COMMIT");
    res.redirect("/orders");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Place order error:", e);
    res.status(400).send(`${esc(e.message)} <a href="/new-order">Go back</a>`);
  } finally {
    client.release();
  }
});

// ORDER HISTORY
app.get("/orders", auth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT o.*, COALESCE(s.name, 'Service #' || o.service_id::text) AS service_name
      FROM orders o
      LEFT JOIN services s ON s.id=o.service_id
      WHERE o.user_id=$1
      ORDER BY o.id DESC
    `, [req.session.user.id]);

    let html = `<div class="card"><h2>My Order History</h2>
    <table><tr><th>ID</th><th>Service</th><th>Link</th><th>Quantity</th><th>Charge</th><th>Status</th></tr>`;

    for (const o of result.rows) {
      html += `<tr>
        <td>#${o.id}</td>
        <td>${esc(o.service_name)}</td>
        <td>${esc(o.link)}</td>
        <td>${o.quantity}</td>
        <td>${money(o.charge)}</td>
        <td>${esc(o.status)}</td>
      </tr>`;
    }

    html += `</table></div>`;
    sendPage(res, "Orders", html, req.session.user);
  } catch (e) {
    console.error("Orders error:", e);
    res.status(500).send("Order history error");
  }
});

// ADD FUNDS
app.get("/add-funds", auth, (req, res) => {
  sendPage(res, "Add Funds", `
  <div class="card">
    <h2>Add Funds</h2>
    <div class="notice">Minimum ₹100 · Maximum ₹2000</div>
    ${process.env.UPI_ID ? `<p>UPI ID: <b>${esc(process.env.UPI_ID)}</b></p>` : ""}
    ${process.env.UPI_QR_URL ? `<img src="${esc(process.env.UPI_QR_URL)}" style="width:200px;max-width:100%">` : ""}
    <p>Pay first, then submit your UTR number. Balance is added after admin verification.</p>
    <form method="POST" action="/add-funds">
      <label>Amount (₹)</label>
      <input type="number" name="amount" min="100" max="2000" required>
      <label>UTR / Transaction ID</label>
      <input name="utr" minlength="6" maxlength="100" required>
      <button>Submit Payment Request</button>
    </form>
  </div>`, req.session.user);
});

app.post("/add-funds", auth, async (req, res) => {
  const amount = Number(req.body.amount);
  const utr = String(req.body.utr || "").trim();

  if (!Number.isFinite(amount) || amount < 100 || amount > 2000 ||
      !/^[a-zA-Z0-9-]{6,100}$/.test(utr)) {
    return res.status(400).send("Invalid amount or UTR.");
  }

  try {
    await db.query(
      "INSERT INTO payments(user_id,amount,utr) VALUES($1,$2,$3)",
      [req.session.user.id, amount, utr]
    );

    res.send("Payment request submitted. Await admin approval. <a href='/dashboard'>Dashboard</a>");
  } catch (e) {
    console.error("Payment request error:", e);
    res.status(400).send("Payment request failed.");
  }
});

// SUPPORT
app.get("/support", auth, (req, res) => {
  sendPage(res, "Support", `
  <div class="card">
    <h2>Customer Support</h2>
    ${process.env.WHATSAPP_NUMBER ?
      `<p>WhatsApp: <a href="https://wa.me/${encodeURIComponent(process.env.WHATSAPP_NUMBER)}">Contact Support</a></p>` : ""}
    <form method="POST" action="/support">
      <textarea name="message" placeholder="Write your message..." required maxlength="2000"></textarea>
      <button>Send Message</button>
    </form>
  </div>`, req.session.user);
});

app.post("/support", auth, async (req, res) => {
  const message = String(req.body.message || "").trim();

  if (!message || message.length > 2000) {
    return res.status(400).send("Invalid message");
  }

  try {
    await db.query(
      "INSERT INTO tickets(user_id,message) VALUES($1,$2)",
      [req.session.user.id, message]
    );

    res.redirect("/support");
  } catch (e) {
    console.error("Support error:", e);
    res.status(500).send("Support message failed");
  }
});

// ADMIN PANEL
app.get("/admin", auth, admin, async (req, res) => {
  try {
    const [users, services, orders, payments, tickets] = await Promise.all([
      db.query("SELECT COUNT(*) FROM users"),
      db.query("SELECT * FROM services ORDER BY category,id DESC"),
      db.query(`
        SELECT o.*, COALESCE(s.name,'Service #' || o.service_id::text) AS service_name
        FROM orders o LEFT JOIN services s ON s.id=o.service_id
        ORDER BY o.id DESC LIMIT 100
      `),
      db.query(`
        SELECT p.*,u.email FROM payments p
        JOIN users u ON u.id=p.user_id
        ORDER BY p.id DESC LIMIT 100
      `),
      db.query(`
        SELECT t.*,u.email FROM tickets t
        JOIN users u ON u.id=t.user_id
        ORDER BY t.id DESC LIMIT 100
      `)
    ]);

    let html = `
    <div class="card">
      <h2>Admin Panel</h2>
      <div class="grid">
        <div>Total Users: ${users.rows[0].count}</div>
        <div>Total Services: ${services.rows.length}</div>
        <div>Total Orders: ${orders.rows.length}</div>
      </div>
    </div>

    <div class="card">
      <h2>Add New Service</h2>
      <form method="POST" action="/admin/services">
        <select name="category" required>
          ${categories.map(c => `<option value="${c.name}">${c.icon} ${c.name}</option>`).join("")}
        </select>
        <input name="name" placeholder="Service Name" required maxlength="150">
        <input name="description" placeholder="Description">
        <input name="rate" type="number" min="0" step="0.01" placeholder="Price per 1000" required>
        <input name="min" type="number" min="1" value="100" required>
        <input name="max" type="number" min="1" value="100000" required>
        <button>Add Service</button>
      </form>
    </div>

    <div class="card"><h2>Manage Services</h2>
    <table><tr><th>ID</th><th>Category</th><th>Name</th><th>Rate</th><th>Min</th><th>Max</th><th>Action</th></tr>`;

    for (const s of services.rows) {
      html += `<tr>
        <td>${s.id}</td>
        <td>${esc(s.category)}</td>
        <td>${esc(s.name)}</td>
        <td>${money(s.rate)}</td>
        <td>${s.min}</td>
        <td>${s.max}</td>
        <td>
          <form method="POST" action="/admin/services/${s.id}/toggle">
            <button>${s.active ? "Disable" : "Enable"}</button>
          </form>
        </td>
      </tr>`;
    }

    html += `</table></div><div class="card"><h2>Payment Requests</h2>
    <table><tr><th>ID</th><th>User</th><th>Amount</th><th>UTR</th><th>Status</th><th>Action</th></tr>`;

    for (const p of payments.rows) {
      html += `<tr>
        <td>${p.id}</td>
        <td>${esc(p.email)}</td>
        <td>${money(p.amount)}</td>
        <td>${esc(p.utr)}</td>
        <td>${esc(p.status)}</td>
        <td>${p.status === "Pending" ? `<form method="POST" action="/admin/payments/${p.id}/approve"><button>Approve</button></form>` : ""}</td>
      </tr>`;
    }

    html += `</table></div><div class="card"><h2>Recent Orders</h2>
    <table><tr><th>ID</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th><th>Update</th></tr>`;

    for (const o of orders.rows) {
      html += `<tr>
        <td>${o.id}</td>
        <td>${esc(o.service_name)}</td>
        <td>${o.quantity}</td>
        <td>${money(o.charge)}</td>
        <td>${esc(o.status)}</td>
        <td>
          <form method="POST" action="/admin/orders/${o.id}/status">
            <select name="status">
              ${["Pending","Processing","Completed","Partial","Cancelled"].map(v =>
                `<option ${v === o.status ? "selected" : ""}>${v}</option>`).join("")}
            </select>
            <button>Save</button>
          </form>
        </td>
      </tr>`;
    }

    html += `</table></div><div class="card"><h2>Support Tickets</h2>`;

    for (const t of tickets.rows) {
      html += `<div class="service">
        <b>${esc(t.email)}</b>
        <p>${esc(t.message)}</p>
        <p>${esc(t.status)}</p>
      </div>`;
    }

    html += `</div>`;
    sendPage(res, "Admin", html, req.session.user);
  } catch (e) {
    console.error("Admin page error:", e);
    res.status(500).send("Admin panel loading error");
  }
});

// ADMIN ADD SERVICE
app.post("/admin/services", auth, admin, async (req, res) => {
  const category = String(req.body.category || "");
  const name = String(req.body.name || "").trim();
  const description = String(req.body.description || "");
  const rate = Number(req.body.rate);
  const min = Number(req.body.min);
  const max = Number(req.body.max);

  if (!categories.some(c => c.name === category) ||
      !name || name.length > 150 ||
      !Number.isFinite(rate) || rate < 0 ||
      !Number.isInteger(min) || !Number.isInteger(max) ||
      min < 1 || max < min) {
    return res.status(400).send("Invalid service information");
  }

  try {
    await db.query(`
      INSERT INTO services(category,name,description,rate,min,max,active,updated_at)
      VALUES($1,$2,$3,$4,$5,$6,TRUE,NOW())
    `, [category, name, description, rate, min, max]);

    res.redirect("/admin");
  } catch (e) {
    console.error("Add service error:", e);
    res.status(500).send("Could not add service");
  }
});

// ADMIN ENABLE / DISABLE SERVICE
app.post("/admin/services/:id/toggle", auth, admin, async (req, res) => {
  try {
    await db.query(
      "UPDATE services SET active=NOT active, updated_at=NOW() WHERE id=$1",
      [req.params.id]
    );

    res.redirect("/admin");
  } catch (e) {
    console.error(e);
    res.status(500).send("Service update failed");
  }
});

// ADMIN APPROVE PAYMENT
app.post("/admin/payments/:id/approve", auth, admin, async (req, res) => {
  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const p = await client.query(
      "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    if (!p.rows.length || p.rows[0].status !== "Pending") {
      throw new Error("Payment already processed or not found");
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
    res.redirect("/admin");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Payment approval error:", e);
    res.status(400).send("Payment approval failed");
  } finally {
    client.release();
  }
});

// ADMIN UPDATE ORDER STATUS
app.post("/admin/orders/:id/status", auth, admin, async (req, res) => {
  const allowed = ["Pending", "Processing", "Completed", "Partial", "Cancelled"];
  const status = String(req.body.status || "");

  if (!allowed.includes(status)) {
    return res.status(400).send("Invalid status");
  }

  try {
    await db.query(
      "UPDATE orders SET status=$1 WHERE id=$2",
      [status, req.params.id]
    );

    res.redirect("/admin");
  } catch (e) {
    console.error(e);
    res.status(500).send("Order status update failed");
  }
});

// HEALTH CHECK
app.get("/health", async (req, res) => {
  try {
    await db.query("SELECT 1");
    res.json({ status: "OK", database: "Connected" });
  } catch (e) {
    res.status(503).json({ status: "ERROR", database: "Disconnected" });
  }
});

// 404
app.use((req, res) => {
  res.status(404).send("Page not found. <a href='/dashboard'>Dashboard</a>");
});

// START SERVER
async function start() {
  await initDB();

  app.listen(PORT, "0.0.0.0", () => {
    console.log("ROYAL PANEL server running on port " + PORT);
  });
}

start().catch(err => {
  console.error("Server startup failed:", err);
  process.exit(1);
});
