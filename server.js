
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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("neon.tech")
    ? { rejectUnauthorized: false }
    : undefined
});

async function db(sql, params = []) {
  return pool.query(sql, params);
}

app.use(session({
  secret: process.env.SESSION_SECRET || "royal-panel-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300
}));

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user?.is_admin) {
    return res.status(403).send("Admin access required");
  }
  next();
}

function page(title, content, user = null) {
  return `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} - ROYAL PANEL</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#10131d;color:#fff;font-family:Arial,sans-serif}
header{background:#191e2d;padding:18px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px}
header b{color:#ff4545;font-size:22px}
nav{display:flex;gap:14px;flex-wrap:wrap}
a{color:#ff6262;text-decoration:none}
main{max-width:900px;margin:25px auto;padding:15px}
.card{background:#1b2233;border:1px solid #30394d;border-radius:13px;padding:20px;margin-bottom:18px}
input,select,textarea{width:100%;padding:13px;margin:9px 0 16px;border-radius:8px;border:1px solid #46516b;background:#101725;color:white}
button{padding:12px 18px;background:#e83242;color:white;border:0;border-radius:8px;cursor:pointer;font-weight:bold}
button:hover{background:#c92232}
label{display:block;color:#ddd}
.small{color:#aab3c5;font-size:13px}
table{width:100%;border-collapse:collapse}
td,th{padding:10px;border-bottom:1px solid #39445a;text-align:left}
</style>
</head>
<body>
<header>
<b>ROYAL PANEL</b>
<nav>
${user ? `
<a href="/dashboard">Dashboard</a>
<a href="/services">Services</a>
<a href="/new-order">New Order</a>
<a href="/orders">My Orders</a>
<a href="/add-funds">Add Funds</a>
<a href="/support">Support</a>
${user.is_admin ? '<a href="/admin">Admin</a>' : ""}
<a href="/logout">Logout</a>
` : '<a href="/login">Login</a><a href="/register">Register</a>'}
</nav>
</header>
<main>${content}</main>
</body>
</html>`;
}

async function setupDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      balance NUMERIC DEFAULT 0,
      is_admin BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS services(
      id SERIAL PRIMARY KEY,
      provider_id TEXT,
      name TEXT NOT NULL,
      category TEXT DEFAULT 'Other',
      rate NUMERIC DEFAULT 0,
      min INTEGER DEFAULT 1,
      max INTEGER DEFAULT 100000,
      description TEXT,
      active BOOLEAN DEFAULT TRUE
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS orders(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      service_id INTEGER,
      provider_order_id TEXT,
      link TEXT,
      quantity INTEGER,
      charge NUMERIC,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS payments(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC,
      utr TEXT,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS tickets(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      message TEXT,
      status TEXT DEFAULT 'Open',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/dashboard" : "/login");
});

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h2>Create Account</h2>
      <form method="POST">
        <label>Username</label>
        <input name="username" required>
        <label>Password</label>
        <input name="password" type="password" required>
        <button>Create Account</button>
      </form>
      <a href="/login">Already have an account? Login</a>
    </div>
  `));
});

app.post("/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (username.length < 3 || password.length < 6) {
      return res.send("Username must be 3+ characters and password 6+ characters.");
    }

    const hash = await bcrypt.hash(password, 12);

    await db(
      "INSERT INTO users(username,password) VALUES($1,$2)",
      [username, hash]
    );

    res.redirect("/login");
  } catch (error) {
    res.status(400).send("Username already exists or registration failed.");
  }
});

app.get("/login", (req, res) => {
  res.send(page("Login", `
    <div class="card">
      <h2>ROYAL PANEL Login</h2>
      <form method="POST">
        <label>Username</label>
        <input name="username" required>
        <label>Password</label>
        <input name="password" type="password" required>
        <button>Login</button>
      </form>
      <a href="/register">Create Account</a>
    </div>
  `));
});

app.post("/login", async (req, res) => {
  const result = await db(
    "SELECT * FROM users WHERE username=$1",
    [String(req.body.username || "").trim()]
  );

  const user = result.rows[0];

  if (!user || !(await bcrypt.compare(String(req.body.password || ""), user.password))) {
    return res.status(401).send("Invalid username or password.");
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    is_admin: user.is_admin
  };

  res.redirect("/dashboard");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireLogin, async (req, res) => {
  const result = await db(
    "SELECT balance FROM users WHERE id=$1",
    [req.session.user.id]
  );

  res.send(page("Dashboard", `
    <div class="card">
      <h2>Welcome ${escapeHtml(req.session.user.username)}</h2>
      <h3>Wallet Balance: ₹${Number(result.rows[0].balance).toFixed(2)}</h3>
      <a href="/new-order">Place New Order</a>
    </div>
  `, req.session.user));
});

app.get("/services", requireLogin, async (req, res) => {
  const search = String(req.query.search || "").trim();

  const result = search
    ? await db(`
        SELECT * FROM services
        WHERE active=TRUE AND
        (name ILIKE $1 OR category ILIKE $1)
        ORDER BY category,name
        LIMIT 1000
      `, [`%${search}%`])
    : await db(`
        SELECT * FROM services
        WHERE active=TRUE
        ORDER BY category,name
        LIMIT 1000
      `);

  res.send(page("Services", `
    <div class="card">
      <h2>All Services</h2>
      <form method="GET">
        <input name="search" value="${escapeHtml(search)}" placeholder="Search services">
        <button>Search</button>
      </form>
      ${result.rows.map(s => `
        <p><b>${escapeHtml(s.category)}</b> — ${escapeHtml(s.name)}
        <br><span class="small">₹${Number(s.rate).toFixed(2)}</span></p>
      `).join("")}
    </div>
  `, req.session.user));
});

/* NEW ORDER WITH SEARCH */
app.get("/new-order", requireLogin, async (req, res) => {
  try {
    const search = String(req.query.search || "").trim().slice(0, 100);

    let result;

    if (search) {
      result = await db(`
        SELECT * FROM services
        WHERE active=TRUE
        AND (
          name ILIKE $1
          OR category ILIKE $1
          OR description ILIKE $1
          OR provider_id ILIKE $1
        )
        ORDER BY category,name
        LIMIT 2000
      `, [`%${search}%`]);
    } else {
      result = await db(`
        SELECT * FROM services
        WHERE active=TRUE
        ORDER BY category,name
        LIMIT 2000
      `);
    }

    res.send(page("New Order", `
      <div class="card">
        <h2>Place New Order</h2>

        <form method="GET" action="/new-order">
          <label>Search Service</label>
          <input
            name="search"
            value="${escapeHtml(search)}"
            placeholder="Search Instagram, Facebook, YouTube..."
          >
          <button type="submit">Search</button>
          <a href="/new-order">Clear Search</a>
        </form>

        <p class="small">${result.rows.length} services found</p>

        <form method="POST" action="/new-order">
          <label>Select Service</label>
          <select name="service_id" required>
            <option value="">Choose a service</option>
            ${result.rows.map(s => `
              <option value="${s.id}">
                ${escapeHtml(s.category)} - ${escapeHtml(s.name)}
                - ₹${Number(s.rate).toFixed(2)}
              </option>
            `).join("")}
          </select>

          <label>Post / Profile Link</label>
          <input name="link" type="url" placeholder="Post Profile Link" required>

          <label>Quantity</label>
          <input name="quantity" type="number" min="1" placeholder="Quantity" required>

          <button type="submit">Place Order</button>
        </form>
      </div>
    `, req.session.user));

  } catch (error) {
    console.error(error);
    res.status(500).send("Unable to load services.");
  }
});

app.post("/new-order", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    const serviceId = Number(req.body.service_id);
    const quantity = Number(req.body.quantity);
    const link = String(req.body.link || "").trim();

    if (!Number.isInteger(serviceId) || !Number.isInteger(quantity) || quantity < 1 || !link) {
      return res.status(400).send("Invalid order details.");
    }

    await client.query("BEGIN");

    const serviceResult = await client.query(
      "SELECT * FROM services WHERE id=$1 AND active=TRUE",
      [serviceId]
    );

    const service = serviceResult.rows[0];

    if (!service) throw new Error("Service not found.");

    if (quantity < Number(service.min) || quantity > Number(service.max)) {
      throw new Error(`Quantity must be between ${service.min} and ${service.max}.`);
    }

    const charge = Number(service.rate) * quantity / 1000;

    const userResult = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.session.user.id]
    );

    if (!userResult.rows[0] || Number(userResult.rows[0].balance) < charge) {
      throw new Error("Insufficient wallet balance. Please add funds.");
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [charge, req.session.user.id]
    );

    await client.query(`
      INSERT INTO orders(user_id,service_id,link,quantity,charge,status)
      VALUES($1,$2,$3,$4,$5,'Pending')
    `, [req.session.user.id, serviceId, link, quantity, charge]);

    await client.query("COMMIT");

    res.redirect("/orders");

  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).send(escapeHtml(error.message));
  } finally {
    client.release();
  }
});

app.get("/orders", requireLogin, async (req, res) => {
  const result = await db(`
    SELECT o.*,s.name AS service_name
    FROM orders o
    LEFT JOIN services s ON s.id=o.service_id
    WHERE o.user_id=$1
    ORDER BY o.id DESC
  `, [req.session.user.id]);

  res.send(page("My Orders", `
    <div class="card">
      <h2>My Orders</h2>
      <table>
        <tr><th>ID</th><th>Service</th><th>Quantity</th><th>Charge</th><th>Status</th></tr>
        ${result.rows.map(o => `
          <tr>
            <td>${o.id}</td>
            <td>${escapeHtml(o.service_name)}</td>
            <td>${o.quantity}</td>
            <td>₹${Number(o.charge).toFixed(2)}</td>
            <td>${escapeHtml(o.status)}</td>
          </tr>
        `).join("")}
      </table>
    </div>
  `, req.session.user));
});

app.get("/add-funds", requireLogin, (req, res) => {
  res.send(page("Add Funds", `
    <div class="card">
      <h2>Add Funds</h2>
      <p>Payment approval must be configured by the administrator.</p>
      <form method="POST">
        <label>Amount (₹)</label>
        <input name="amount" type="number" min="100" max="2000" required>
        <label>UTR / Transaction ID</label>
        <input name="utr" required>
        <button>Submit Payment Request</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/add-funds", requireLogin, async (req, res) => {
  const amount = Number(req.body.amount);
  const utr = String(req.body.utr || "").trim();

  if (!Number.isFinite(amount) || amount < 100 || amount > 2000 || !utr) {
    return res.status(400).send("Amount must be ₹100 to ₹2000 and UTR is required.");
  }

  await db(
    "INSERT INTO payments(user_id,amount,utr) VALUES($1,$2,$3)",
    [req.session.user.id, amount, utr]
  );

  res.send("Payment request submitted. Awaiting admin approval.");
});

app.get("/support", requireLogin, (req, res) => {
  res.send(page("Support", `
    <div class="card">
      <h2>Support</h2>
      <form method="POST">
        <textarea name="message" placeholder="Write your message" required></textarea>
        <button>Send Message</button>
      </form>
    </div>
  `, req.session.user));
});

app.post("/support", requireLogin, async (req, res) => {
  await db(
    "INSERT INTO tickets(user_id,message) VALUES($1,$2)",
    [req.session.user.id, String(req.body.message || "").slice(0, 3000)]
  );

  res.redirect("/support");
});

app.get("/admin", requireLogin, requireAdmin, async (req, res) => {
  const users = await db("SELECT id,username,balance,is_admin FROM users ORDER BY id DESC");
  const services = await db("SELECT * FROM services ORDER BY category,name");

  res.send(page("Admin Panel", `
    <div class="card">
      <h2>Admin Panel</h2>
      <h3>Users</h3>
      ${users.rows.map(u => `
        <p>${escapeHtml(u.username)} — ₹${Number(u.balance).toFixed(2)}</p>
      `).join("")}
    </div>

    <div class="card">
      <h3>Add Service</h3>
      <form method="POST" action="/admin/services">
        <input name="name" placeholder="Service Name" required>
        <input name="category" placeholder="Platform / Category" required>
        <input name="rate" type="number" step="0.01" placeholder="Rate per 1000" required>
        <input name="min" type="number" placeholder="Minimum" value="1" required>
        <input name="max" type="number" placeholder="Maximum" value="100000" required>
        <button>Add Service</button>
      </form>
      <h3>Existing Services</h3>
      ${services.rows.map(s => `
        <p>${escapeHtml(s.category)} — ${escapeHtml(s.name)} — ₹${s.rate}
        (${s.active ? "Active" : "Inactive"})</p>
      `).join("")}
    </div>

    <div class="card">
      <h3>Pending Payments</h3>
      <a href="/admin/payments">Manage Payments</a>
      <br><br>
      <a href="/admin/orders">Manage Orders</a>
    </div>
  `, req.session.user));
});

app.post("/admin/services", requireLogin, requireAdmin, async (req, res) => {
  const { name, category, rate, min, max } = req.body;

  await db(`
    INSERT INTO services(name,category,rate,min,max,active)
    VALUES($1,$2,$3,$4,$5,TRUE)
  `, [
    String(name).trim(),
    String(category).trim(),
    Number(rate),
    Number(min),
    Number(max)
  ]);

  res.redirect("/admin");
});

app.get("/admin/payments", requireLogin, requireAdmin, async (req, res) => {
  const result = await db(`
    SELECT p.*,u.username
    FROM payments p JOIN users u ON u.id=p.user_id
    ORDER BY p.id DESC
  `);

  res.send(page("Payments", `
    <div class="card">
      <h2>Payment Requests</h2>
      ${result.rows.map(p => `
        <p>
          ${escapeHtml(p.username)} — ₹${p.amount} — UTR: ${escapeHtml(p.utr)}
          — ${escapeHtml(p.status)}
          ${p.status === "Pending" ? `
            <form method="POST" action="/admin/payments/${p.id}/approve">
              <button>Approve</button>
            </form>
          ` : ""}
        </p>
      `).join("")}
    </div>
  `, req.session.user));
});

app.post("/admin/payments/:id/approve", requireLogin, requireAdmin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    const payment = result.rows[0];

    if (!payment) throw new Error("Payment not found.");

    if (payment.status === "Pending") {
      await client.query(
        "UPDATE payments SET status='Approved' WHERE id=$1",
        [payment.id]
      );

      await client.query(
        "UPDATE users SET balance=balance+$1 WHERE id=$2",
        [payment.amount, payment.user_id]
      );
    }

    await client.query("COMMIT");
    res.redirect("/admin/payments");

  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).send(escapeHtml(error.message));
  } finally {
    client.release();
  }
});

app.get("/admin/orders", requireLogin, requireAdmin, async (req, res) => {
  const result = await db(`
    SELECT o.*,u.username,s.name AS service_name
    FROM orders o
    LEFT JOIN users u ON u.id=o.user_id
    LEFT JOIN services s ON s.id=o.service_id
    ORDER BY o.id DESC
  `);

  res.send(page("Admin Orders", `
    <div class="card">
      <h2>All Orders</h2>
      ${result.rows.map(o => `
        <p>
          #${o.id} — ${escapeHtml(o.username)} —
          ${escapeHtml(o.service_name)} — ${o.quantity} —
          ${escapeHtml(o.status)}
          <form method="POST" action="/admin/orders/${o.id}/status">
            <select name="status">
              <option>Pending</option>
              <option>Processing</option>
              <option>Completed</option>
              <option>Partial</option>
              <option>Canceled</option>
              <option>Failed</option>
            </select>
            <button>Update Status</button>
          </form>
        </p>
      `).join("")}
    </div>
  `, req.session.user));
});

app.post("/admin/orders/:id/status", requireLogin, requireAdmin, async (req, res) => {
  const allowed = ["Pending", "Processing", "Completed", "Partial", "Canceled", "Failed"];
  const status = String(req.body.status);

  if (!allowed.includes(status)) {
    return res.status(400).send("Invalid status.");
  }

  await db(
    "UPDATE orders SET status=$1 WHERE id=$2",
    [status, req.params.id]
  );

  res.redirect("/admin/orders");
});

const PORT = process.env.PORT || 3000;

setupDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`ROYAL PANEL running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database setup failed:", error);
    process.exit(1);
  });
