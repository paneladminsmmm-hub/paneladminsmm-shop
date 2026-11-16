require('dotenv').config();

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const {
  providerServices,
  providerAddOrder,
  providerOrderStatus
} = require('./src/provider');

const app = express();

app.set('trust proxy', 1);

if (
  process.env.NODE_ENV === 'production' &&
  (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)
) {
  throw new Error('Set SESSION_SECRET to at least 32 characters.');
}

const db = new Database('panel.sqlite');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  password TEXT,
  balance REAL DEFAULT 0,
  is_admin INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY,
  provider_id TEXT,
  name TEXT,
  category TEXT,
  rate REAL,
  min_qty INTEGER,
  max_qty INTEGER,
  description TEXT DEFAULT '',
  active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY,
  user_id INTEGER,
  service_id INTEGER,
  provider_order_id TEXT,
  link TEXT,
  quantity INTEGER,
  charge REAL,
  status TEXT DEFAULT 'Pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY,
  user_id INTEGER,
  amount REAL,
  reference TEXT,
  status TEXT DEFAULT 'Pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY,
  user_id INTEGER,
  subject TEXT,
  message TEXT,
  status TEXT DEFAULT 'Open',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const adminEmail = (process.env.ADMIN_EMAIL || 'admin@example.com').toLowerCase();
const adminPass = process.env.ADMIN_PASSWORD || 'ChangeMe123!';

if (!db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail)) {
  db.prepare(
    'INSERT INTO users(username,email,password,is_admin) VALUES(?,?,?,1)'
  ).run('admin', adminEmail, bcrypt.hashSync(adminPass, 12));
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
  name: 'panel.sid',
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: '.'
  }),
  secret: process.env.SESSION_SECRET || 'development-only-secret-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

const money = n => '₹' + Number(n || 0).toFixed(2);

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
}[c]));

const currentUser = req => req.session.userId
  ? db.prepare(
      'SELECT id,username,email,balance,is_admin FROM users WHERE id=?'
    ).get(req.session.userId)
  : null;

const auth = (req, res, next) =>
  currentUser(req) ? next() : res.redirect('/login');

const admin = (req, res, next) => {
  const u = currentUser(req);
  if (u?.is_admin) return next();
  return res.status(403).send(page(
    'Forbidden',
    '<section class="panel"><h2>Admin access required</h2></section>',
    u
  ));
};

const page = (title, body, user = null) => `
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} | PanelAdminSMM</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header class="top">
<a class="brand" href="/">PANEL<span>ADMIN</span>SMM</a>
<nav>
<a href="/">Home</a>
<a href="/services">Services</a>
${user ? '<a href="/dashboard">Dashboard</a><a href="/orders">Orders</a><a href="/add-funds">Add Funds</a>' : ''}
${user?.is_admin ? '<a href="/admin">Admin</a>' : ''}
</nav>
<div>
${user
  ? `<span class="muted">${esc(user.username)} · ${money(user.balance)}</span>
     <form class="inline" method="post" action="/logout">
     <button class="outline">Logout</button></form>`
  : '<a class="outline btn" href="/login">Login</a> <a class="primary btn" href="/signup">Sign up</a>'}
</div>
</header>
<main>${body}</main>
<footer>
© ${new Date().getFullYear()} PanelAdminSMM.shop · Social Media Services ·
<a href="/support">Support</a> · <a href="/terms">Terms</a>
</footer>
<script src="/app.js" defer></script>
</body>
</html>`;

app.get('/', (req, res) => {
  const u = currentUser(req);
  res.send(page('Home', `
  <section class="hero">
  <div>
  <div class="eyebrow">SOCIAL MEDIA MARKETING PANEL</div>
  <h1>Grow your social presence.<br><span>Simply. Quickly.</span></h1>
  <p>One dashboard for Instagram, YouTube, Facebook, TikTok, Telegram and more.</p>
  <a class="primary btn big" href="${u ? '/new-order' : '/signup'}">Get Started</a>
  <a class="outline btn big" href="/services">Explore Services</a>
  </div>
  <div class="hero-card">
  <div class="live">● PANEL ONLINE</div>
  <h3>PanelAdminSMM</h3>
  <div class="metric"><b>24/7</b><small>Order access</small></div>
  <div class="metric"><b>API</b><small>Reseller integration</small></div>
  <div class="metric"><b>UPI</b><small>Payment-ready setup</small></div>
  </div>
  </section>
  <section class="features">
  <article><b>01</b><h3>Choose a service</h3><p>Browse services by platform and category.</p></article>
  <article><b>02</b><h3>Add funds</h3><p>Top up your account balance securely.</p></article>
  <article><b>03</b><h3>Place an order</h3><p>Submit a public profile or post link.</p></article>
  </section>
  <section class="panel">
  <h2>Everything in one panel</h2>
  <p>Service catalogue · New orders · Order history · Balance management · Support tickets · Provider API connection.</p>
  </section>`, u));
});

app.get('/signup', (req, res) => {
  res.send(page('Sign up', `
  <section class="auth panel">
  <h1>Create account</h1>
  <form method="post" action="/signup">
  <label>Username</label>
  <input name="username" required minlength="3" maxlength="24">
  <label>Email</label>
  <input type="email" name="email" required>
  <label>Password</label>
  <input type="password" name="password" required minlength="8">
  <button class="primary">Create account</button>
  </form>
  <p>Already registered? <a href="/login">Login</a></p>
  </section>`));
});

app.post('/signup', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username) ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        password.length < 8) {
      throw new Error('Check username, email and password requirements.');
    }

    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(
      'INSERT INTO users(username,email,password) VALUES(?,?,?)'
    ).run(username, email, hash);

    req.session.regenerate(err => {
      if (err) return res.status(500).send('Session error. Please try again.');

      req.session.userId = Number(result.lastInsertRowid);

      req.session.save(saveErr => {
        if (saveErr) return res.status(500).send('Could not save signup session.');
        res.redirect('/dashboard');
      });
    });
  } catch (e) {
    const message = String(e.message).includes('UNIQUE')
      ? 'Username or email already exists.'
      : e.message;

    res.status(400).send(page(
      'Sign up',
      `<section class="panel"><p class="error">${esc(message)}</p><a href="/signup">Try again</a></section>`
    ));
  }
});

app.get('/login', (req, res) => {
  res.send(page('Login', `
  <section class="auth panel">
  <h1>Welcome back</h1>
  <form method="post" action="/login">
  <label>Username or email</label>
  <input name="identity" required>
  <label>Password</label>
  <input type="password" name="password" required>
  <button class="primary">Sign in</button>
  </form>
  <p>New here? <a href="/signup">Create account</a></p>
  </section>`));
});

app.post('/login', async (req, res) => {
  try {
    const identity = String(req.body.identity || '').trim();
    const password = String(req.body.password || '');

    const row = db.prepare(`
      SELECT * FROM users
      WHERE LOWER(username)=LOWER(?) OR LOWER(email)=LOWER(?)
    `).get(identity, identity);

    if (!row || !(await bcrypt.compare(password, row.password))) {
      return res.status(401).send(page(
        'Login',
        '<section class="panel"><p class="error">Invalid login details.</p><a href="/login">Try again</a></section>'
      ));
    }

    req.session.regenerate(err => {
      if (err) return res.status(500).send('Session error. Please try again.');

      req.session.userId = row.id;

      req.session.save(saveErr => {
        if (saveErr) return res.status(500).send('Could not save login session.');
        res.redirect('/dashboard');
      });
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).send('Login error. Please try again.');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('panel.sid');
    res.redirect('/');
  });
});

app.get('/dashboard', auth, (req, res) => {
  const u = currentUser(req);
  const orders = db.prepare(
    'SELECT COUNT(*) n FROM orders WHERE user_id=?'
  ).get(u.id).n;

  res.send(page('Dashboard', `
  <h1>Dashboard</h1>
  <div class="stats">
  <div class="panel"><small>Available balance</small><h2>${money(u.balance)}</h2><a href="/add-funds">Add funds →</a></div>
  <div class="panel"><small>Total orders</small><h2>${orders}</h2><a href="/orders">View orders →</a></div>
  <div class="panel"><small>Quick action</small><h2>New order</h2><a href="/new-order">Place an order →</a></div>
  </div>
  <section class="panel">
  <h2>Welcome, ${esc(u.username)}</h2>
  <p>Choose a service, enter the public URL and submit your order.</p>
  <a class="primary btn" href="/new-order">Create new order</a>
  </section>`, u));
});

app.get('/services', (req, res) => {
  const u = currentUser(req);
  const services = db.prepare(
    'SELECT * FROM services WHERE active=1 ORDER BY category,name'
  ).all();

  res.send(page('Services', `
  <h1>Services</h1>
  <section class="panel">
  <p>Rates are shown per 1,000 units unless stated otherwise.</p>
  <div class="table-wrap"><table>
  <tr><th>ID</th><th>Platform / Service</th><th>Category</th><th>Rate / 1K</th><th>Min</th><th>Max</th></tr>
  ${services.map(s => `
  <tr><td>${s.id}</td><td>${esc(s.name)}</td><td>${esc(s.category)}</td>
  <td>${money(s.rate)}</td><td>${s.min_qty}</td><td>${s.max_qty}</td></tr>
  `).join('')}
  </table></div>
  ${services.length ? '' : '<p>No services imported yet. Admin can sync provider services.</p>'}
  </section>`, u));
});

app.get('/new-order', auth, (req, res) => {
  const u = currentUser(req);
  const services = db.prepare(
    'SELECT * FROM services WHERE active=1 ORDER BY category,name'
  ).all();

  res.send(page('New order', `
  <section class="panel">
  <h1>New order</h1>
  <p>Balance: <b>${money(u.balance)}</b></p>
  <form method="post" action="/new-order">
  <label>Service</label>
  <select name="service_id" required>
  <option value="">Select a service</option>
  ${services.map(s => `
  <option value="${s.id}">${s.id} - ${esc(s.name)} (${money(s.rate)}/1K)</option>
  `).join('')}
  </select>
  <label>Link / URL</label>
  <input name="link" type="url" placeholder="https://www.instagram.com/..." required>
  <label>Quantity</label>
  <input name="quantity" type="number" min="1" required>
  <button class="primary">Submit order</button>
  </form>
  </section>`, u));
});

app.post('/new-order', auth, async (req, res) => {
  try {
    const u = currentUser(req);
    const s = db.prepare(
      'SELECT * FROM services WHERE id=? AND active=1'
    ).get(Number(req.body.service_id));

    const qty = Number(req.body.quantity);
    const link = String(req.body.link || '').trim();

    if (!s || !Number.isInteger(qty) || qty < s.min_qty ||
        qty > s.max_qty || !/^https:\/\//i.test(link)) {
      throw new Error('Please check service, quantity and HTTPS link.');
    }

    const charge = Number((s.rate * qty / 1000).toFixed(2));

    if (!Number.isFinite(charge) || charge <= 0) {
      throw new Error('Invalid service price.');
    }

    const info = await providerAddOrder(s.provider_id, link, qty);

    const tx = db.transaction(() => {
      const freshUser = db.prepare(
        'SELECT balance FROM users WHERE id=?'
      ).get(u.id);

      if (!freshUser || freshUser.balance < charge) {
        throw new Error('Insufficient balance. Please add funds.');
      }

      db.prepare('UPDATE users SET balance=balance-? WHERE id=?')
        .run(charge, u.id);

      db.prepare(`
        INSERT INTO orders(user_id,service_id,provider_order_id,link,quantity,charge,status)
        VALUES(?,?,?,?,?,?,?)
      `).run(
        u.id,
        s.id,
        String(info.order || ''),
        link,
        qty,
        charge,
        info.order ? 'Pending' : 'Manual review'
      );
    });

    tx();
    res.redirect('/orders');
  } catch (e) {
    res.status(400).send(page(
      'Order error',
      `<section class="panel"><p class="error">${esc(e.message)}</p><a href="/new-order">Back</a></section>`,
      currentUser(req)
    ));
  }
});

app.get('/orders', auth, (req, res) => {
  const u = currentUser(req);
  const rows = db.prepare(`
    SELECT o.*,s.name FROM orders o
    LEFT JOIN services s ON s.id=o.service_id
    WHERE o.user_id=? ORDER BY o.id DESC
  `).all(u.id);

  res.send(page('Orders', `
  <h1>Order history</h1>
  <section class="panel table-wrap">
  <table>
  <tr><th>Order</th><th>Service</th><th>Link</th><th>Qty</th><th>Charge</th><th>Status</th><th>Date</th></tr>
  ${rows.map(o => `
  <tr><td>${o.id}</td><td>${esc(o.name || 'Service')}</td>
  <td><a target="_blank" rel="noopener" href="${esc(o.link)}">Open</a></td>
  <td>${o.quantity}</td><td>${money(o.charge)}</td>
  <td>${esc(o.status)}</td><td>${esc(o.created_at)}</td></tr>
  `).join('')}
  </table>
  ${rows.length ? '' : '<p>No orders yet.</p>'}
  </section>`, u));
});

app.get('/add-funds', auth, (req, res) => {
  const u = currentUser(req);

  res.send(page('Add funds', `
  <section class="panel">
  <h1>Add funds</h1>
  <p>Current balance: <b>${money(u.balance)}</b></p>
  <p>Payment gateway credentials are required for automatic UPI/card payments.</p>
  <form method="post" action="/add-funds">
  <label>Amount (₹)</label>
  <input name="amount" type="number" min="100" max="20000" step="1" required>
  <label>UPI transaction reference</label>
  <input name="reference" required minlength="6">
  <button class="primary">Submit payment for verification</button>
  </form>
  <p class="muted">Balance updates only after admin verification.</p>
  </section>`, u));
});

app.post('/add-funds', auth, (req, res) => {
  const amount = Number(req.body.amount);
  const ref = String(req.body.reference || '').trim();

  if (!Number.isFinite(amount) || amount < 100 || amount > 20000 ||
      ref.length < 6) {
    return res.status(400).send(page(
      'Add funds',
      '<section class="panel">Invalid amount or reference. <a href="/add-funds">Try again</a></section>',
      currentUser(req)
    ));
  }

  db.prepare(
    'INSERT INTO payments(user_id,amount,reference) VALUES(?,?,?)'
  ).run(currentUser(req).id, amount, ref);

  res.send(page(
    'Payment submitted',
    '<section class="panel"><h2>Submitted for verification</h2><p>Your balance will update only after payment is verified.</p><a href="/dashboard">Dashboard</a></section>',
    currentUser(req)
  ));
});

app.get('/support', auth, (req, res) => {
  res.send(page('Support', `
  <section class="panel">
  <h1>Support</h1>
  <form method="post" action="/support">
  <label>Subject</label><input name="subject" required>
  <label>Message</label><textarea name="message" rows="5" required></textarea>
  <button class="primary">Create ticket</button>
  </form>
  </section>`, currentUser(req)));
});

app.post('/support', auth, (req, res) => {
  db.prepare(
    'INSERT INTO tickets(user_id,subject,message) VALUES(?,?,?)'
  ).run(
    currentUser(req).id,
    String(req.body.subject || '').slice(0, 200),
    String(req.body.message || '').slice(0, 5000)
  );

  res.redirect('/dashboard');
});

app.get('/terms', (req, res) => {
  res.send(page('Terms', `
  <section class="panel">
  <h1>Terms & conditions</h1>
  <p>Use the panel lawfully and provide only public URLs you are authorized to promote. Service availability and delivery depend on the provider. Refunds and cancellations are subject to published service rules.</p>
  </section>`, currentUser(req)));
});

app.get('/admin', auth, admin, (req, res) => {
  const u = currentUser(req);

  const payments = db.prepare(`
    SELECT p.*,u.username FROM payments p
    JOIN users u ON u.id=p.user_id
    WHERE p.status='Pending' ORDER BY p.id
  `).all();

  const users = db.prepare(
    'SELECT id,username,email,balance FROM users ORDER BY id DESC LIMIT 100'
  ).all();

  res.send(page('Admin', `
  <h1>Admin panel</h1>
  <section class="panel">
  <h2>Provider services</h2>
  <form method="post" action="/admin/sync">
  <button class="primary">Sync services from API</button>
  </form>
  <p class="muted">Set SMM_API_URL and SMM_API_KEY in environment variables first.</p>
  </section>
  <section class="panel">
  <h2>Pending payments</h2>
  ${payments.map(p => `
  <p>#${p.id} ${esc(p.username)} · ${money(p.amount)} · Ref ${esc(p.reference)}
  <form class="inline" method="post" action="/admin/payment/${p.id}/approve">
  <button class="primary">Approve & credit</button>
  </form></p>
  `).join('') || '<p>No pending payments.</p>'}
  </section>
  <section class="panel">
  <h2>Users</h2>
  <div class="table-wrap"><table>
  <tr><th>ID</th><th>Username</th><th>Email</th><th>Balance</th></tr>
  ${users.map(x => `
  <tr><td>${x.id}</td><td>${esc(x.username)}</td>
  <td>${esc(x.email)}</td><td>${money(x.balance)}</td></tr>
  `).join('')}
  </table></div>
  </section>`, u));
});

app.post('/admin/sync', auth, admin, async (req, res) => {
  try {
    const list = await providerServices();

    const insert = db.prepare(`
      INSERT INTO services(provider_id,name,category,rate,min_qty,max_qty,description)
      VALUES(?,?,?,?,?,?,?)
    `);

    const tx = db.transaction(items => {
      for (const x of items) {
        if (!x.service || !x.name) continue;

        const providerId = String(x.service);
        const old = db.prepare(
          'SELECT id FROM services WHERE provider_id=?'
        ).get(providerId);

        const values = [
          x.name,
          x.category || 'Other',
          Number(x.rate) || 0,
          Number(x.min) || 1,
          Number(x.max) || 100000,
          x.desc || ''
        ];

        if (old) {
          db.prepare(`
            UPDATE services
            SET name=?,category=?,rate=?,min_qty=?,max_qty=?,description=?,active=1
            WHERE provider_id=?
          `).run(...values, providerId);
        } else {
          insert.run(providerId, ...values);
        }
      }
    });

    tx(list);
    res.redirect('/admin');
  } catch (e) {
    res.status(400).send(page(
      'Sync failed',
      `<section class="panel"><p class="error">${esc(e.message)}</p><a href="/admin">Back</a></section>`,
      currentUser(req)
    ));
  }
});

app.post('/admin/payment/:id/approve', auth, admin, (req, res) => {
  const p = db.prepare(
    "SELECT * FROM payments WHERE id=? AND status='Pending'"
  ).get(Number(req.params.id));

  if (p) {
    db.transaction(() => {
      db.prepare(
        "UPDATE payments SET status='Approved' WHERE id=? AND status='Pending'"
      ).run(p.id);

      db.prepare(
        'UPDATE users SET balance=balance+? WHERE id=?'
      ).run(p.amount, p.user_id);
    })();
  }

  res.redirect('/admin');
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, site: 'PanelAdminSMM.shop' });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).send('Internal server error. Please try again.');
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`PanelAdminSMM running on port ${PORT}`);
});
