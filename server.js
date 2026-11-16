require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing in Render Environment Variables");
}

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(helmet({ contentSecurityPolicy: false }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(80) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password TEXT NOT NULL,
      balance NUMERIC(12,2) NOT NULL DEFAULT 0,
      role VARCHAR(20) NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

function page(title, content, user = null) {
  const nav = user
    ? `<nav>
        <a href="/dashboard">Dashboard</a>
        <a href="/logout">Logout</a>
       </nav>`
    : `<nav>
        <a href="/login">Login</a>
        <a href="/register">Register</a>
       </nav>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} - PanelAdminSMM.shop</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f3f4f6;color:#222;font-family:Arial,sans-serif}
header{background:#111827;color:white;padding:20px;text-align:center}
header h2{margin:0;color:#ff3030}
nav{background:#202938;padding:14px;display:flex;gap:20px;justify-content:center}
nav a{color:white;text-decoration:none}
main{max-width:650px;margin:25px auto;padding:15px}
.card{background:white;padding:22px;border-radius:12px;box-shadow:0 2px 10px #00000010}
input{width:100%;padding:13px;margin:8px 0 16px;border:1px solid #ddd;border-radius:7px;font-size:16px}
button,.btn{display:inline-block;background:#e32636;color:white;padding:12px 18px;border:0;border-radius:7px;text-decoration:none;cursor:pointer}
.error{color:#c00}.success{color:green}
footer{text-align:center;padding:25px;color:#777}
</style>
</head>
<body>
<header><h2>ROYAL PANEL</h2><div>PanelAdminSMM.shop</div></header>
${nav}
<main>${content}</main>
<footer>PanelAdminSMM.shop</footer>
</body>
</html>`;
}

async function getUser(id) {
  const result = await pool.query(
    "SELECT id,name,email,balance,role FROM users WHERE id=$1",
    [id]
  );
  return result.rows[0] || null;
}

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}

app.get("/", (req, res) => {
  res.send(page("Home", `
    <div class="card">
      <h2>Welcome to PanelAdminSMM.shop</h2>
      <p>Your social media services panel.</p>
      <a class="btn" href="/register">Create Account</a>
      <a class="btn" href="/login">Login</a>
    </div>
  `));
});

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <div class="card">
      <h2>Create Account</h2>
      <form method="POST" action="/register">
        <label>Full Name</label>
        <input name="name" maxlength="80" required>
        <label>Email</label>
        <input type="email" name="email" required>
        <label>Password</label>
        <input type="password" name="password" minlength="8" required>
        <button>Create Account</button>
      </form>
      <p>Already registered? <a href="/login">Login</a></p>
    </div>
  `));
});

app.post("/register", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || name.length > 80 || !email || password.length < 8) {
      return res.send(page("Register",
        '<div class="card"><p class="error">Please enter valid details. Password must be at least 8 characters.</p><a href="/register">Try again</a></div>'
      ));
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name,email,password)
       VALUES ($1,$2,$3)
       RETURNING id`,
      [name, email, hash]
    );

    req.session.userId = result.rows[0].id;
    req.session.save(err => {
      if (err) return next(err);
      res.redirect("/dashboard");
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.send(page("Register",
        '<div class="card"><p class="error">This email is already registered.</p><a href="/login">Login here</a></div>'
      ));
    }
    next(error);
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
      <p>New user? <a href="/register">Create account</a></p>
    </div>
  `));
});

app.post("/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT id,password FROM users WHERE email=$1",
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.send(page("Login",
        '<div class="card"><p class="error">Incorrect email or password.</p><a href="/login">Try again</a></div>'
      ));
    }

    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.session.save(saveError => {
        if (saveError) return next(saveError);
        res.redirect("/dashboard");
      });
    });
  } catch (error) {
    next(error);
  }
});

app.get("/dashboard", requireLogin, async (req, res, next) => {
  try {
    const user = await getUser(req.session.userId);

    if (!user) {
      req.session.destroy(() => res.redirect("/login"));
      return;
    }

    res.send(page("Dashboard", `
      <div class="card">
        <h2>Hello, ${escapeHtml(user.name)}</h2>
        <p>Your account is saved in the database.</p>
        <p><b>Email:</b> ${escapeHtml(user.email)}</p>
        <p><b>Balance:</b> ₹${Number(user.balance).toFixed(2)}</p>
        <p><b>Account:</b> ${escapeHtml(user.role)}</p>
        <a class="btn" href="/logout">Logout</a>
      </div>
    `, user));
  } catch (error) {
    next(error);
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.redirect("/login");
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch (error) {
    res.status(500).json({ status: "error", database: "disconnected" });
  }
});

app.use((req, res) => {
  res.status(404).send(page("Not Found",
    '<div class="card"><h2>Page not found</h2><a href="/">Home</a></div>'
  ));
});

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);
  res.status(500).send(page("Server Error",
    '<div class="card"><h2>Something went wrong</h2><p>Please try again later.</p></div>'
  ));
});

async function startServer() {
  await initializeDatabase();
  app.listen(PORT, "0.0.0.0", () => {
    console.log("PanelAdminSMM.shop running on port " + PORT);
  });
}

startServer().catch(error => {
  console.error("Server startup failed:", error);
  process.exit(1);
});

