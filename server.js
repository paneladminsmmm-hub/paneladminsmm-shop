require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const dataDir = path.resolve("./data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(process.env.DB_FILE || "./data/panel.sqlite");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', balance_paise INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS services (
 id INTEGER PRIMARY KEY AUTOINCREMENT, platform TEXT NOT NULL, category TEXT NOT NULL,
 name TEXT NOT NULL, description TEXT DEFAULT '', price_per_1000_paise INTEGER NOT NULL,
 min_qty INTEGER NOT NULL DEFAULT 100, max_qty INTEGER NOT NULL DEFAULT 10000,
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, service_id INTEGER NOT NULL,
 service_name TEXT NOT NULL, target_url TEXT NOT NULL, quantity INTEGER NOT NULL,
 total_paise INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'Pending',
 provider_order_id TEXT, refunded_paise INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(service_id) REFERENCES services(id)
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, gateway_order_id TEXT UNIQUE,
 gateway_payment_id TEXT UNIQUE, amount_paise INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'created',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS wallet_transactions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
 amount_paise INTEGER NOT NULL, reference TEXT NOT NULL UNIQUE, note TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS tickets (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, subject TEXT NOT NULL,
 message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Open', admin_reply TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);

const count = db.prepare("SELECT COUNT(*) n FROM services").get().n;
if (!count) {
 const seed = db.prepare(`INSERT INTO services(platform,category,name,description,price_per_1000_paise,min_qty,max_qty) VALUES(?,?,?,?,?,?,?)`);
 [
  ["Instagram","Content promotion","Reel promotion campaign","Legitimate campaign setup and audience targeting; no guaranteed engagement.",12000,1,100],
  ["Instagram","Advertising","Instagram ad campaign setup","Campaign setup assistance; ad spend billed separately.",25000,1,20],
  ["Facebook","Advertising","Facebook ad campaign setup","Authorized page and content promotion campaign.",25000,1,20],
  ["YouTube","Advertising","YouTube video promotion campaign","Promote public videos through compliant advertising.",30000,1,20],
  ["TikTok","Advertising","TikTok ad campaign setup","Availability depends on country and platform policies.",30000,1,20],
  ["WhatsApp","Business","WhatsApp Business profile setup","Business profile and catalog setup assistance.",15000,1,10],
  ["X (Twitter)","Advertising","X campaign setup","Authorized campaign setup; ad spend billed separately.",25000,1,20]
 ].forEach(x=>seed.run(...x));
}

if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
 const exists=db.prepare("SELECT id FROM users WHERE email=?").get(process.env.ADMIN_EMAIL.toLowerCase());
 if (!exists) db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
  .run(process.env.ADMIN_NAME||"Admin",process.env.ADMIN_EMAIL.toLowerCase(),bcrypt.hashSync(process.env.ADMIN_PASSWORD,12));
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({limit:"100kb",verify:(req,res,buf)=>{if(req.originalUrl==="/api/payments/webhook") req.rawBody=Buffer.from(buf);}}));
app.use(express.urlencoded({extended:false}));
app.use(session({
 secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
 resave:false, saveUninitialized:false,
 store:new SQLiteStore({db:"sessions.sqlite",dir:dataDir}),
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*24*60*60*1000}
}));
app.use("/api/auth",rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false}));

const userSafe = u => ({id:u.id,name:u.name,email:u.email,role:u.role,balancePaise:u.balance_paise});
function requireAuth(req,res,next){ if(!req.session.userId) return res.status(401).json({error:"Please log in."}); next(); }
function requireAdmin(req,res,next){
 if(!req.session.userId) return res.status(401).json({error:"Please log in."});
 const u=db.prepare("SELECT role FROM users WHERE id=?").get(req.session.userId);
 if(!u || u.role!=="admin") return res.status(403).json({error:"Admin access only."}); next();
}
function money(n){return Math.round(n);}
function validUrl(s){try{const u=new URL(s);return ["http:","https:"].includes(u.protocol);}catch{return false;}}

app.post("/api/auth/register",async(req,res)=>{
 const {name,email,password}=req.body||{};
 if(!name||String(name).trim().length<2||!email||!String(email).includes("@")||!password||String(password).length<10)
  return res.status(400).json({error:"Enter a name, valid email and password of at least 10 characters."});
 try{
  const info=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)")
   .run(String(name).trim().slice(0,80),String(email).trim().toLowerCase(),await bcrypt.hash(String(password),12));
  req.session.userId=info.lastInsertRowid;
  res.json({user:userSafe(db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid))});
 }catch(e){res.status(409).json({error:"That email may already be registered."});}
});
app.post("/api/auth/login",async(req,res)=>{
 const email=String(req.body?.email||"").toLowerCase().trim(), password=String(req.body?.password||"");
 const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if(!u||!(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:"Email or password is incorrect."});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Could not start session."});req.session.userId=u.id;res.json({user:userSafe(u)});});
});
app.post("/api/auth/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",requireAuth,(req,res)=>res.json({user:userSafe(db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId))}));

app.get("/api/services",(req,res)=>res.json({services:db.prepare("SELECT id,platform,category,name,description,price_per_1000_paise,min_qty,max_qty FROM services WHERE active=1 ORDER BY platform,name").all()}));
app.get("/api/orders",requireAuth,(req,res)=>res.json({orders:db.prepare("SELECT id,service_name,target_url,quantity,total_paise,status,refunded_paise,created_at FROM orders WHERE user_id=? ORDER BY id DESC").all(req.session.userId)}));
app.post("/api/orders",requireAuth,(req,res)=>{
 const service=db.prepare("SELECT * FROM services WHERE id=? AND active=1").get(Number(req.body?.serviceId));
 const qty=Number(req.body?.quantity), target=String(req.body?.targetUrl||"").trim();
 if(!service||!Number.isInteger(qty)||qty<service.min_qty||qty>service.max_qty||!validUrl(target))
  return res.status(400).json({error:"Choose an active service, valid public URL and quantity within the listed limits."});
 const total=Math.ceil(service.price_per_1000_paise*qty/1000);
 const create=db.transaction(()=>{
  const u=db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId);
  if(u.balance_paise<total) throw new Error("INSUFFICIENT");
  db.prepare("UPDATE users SET balance_paise=balance_paise-? WHERE id=?").run(total,u.id);
  const info=db.prepare("INSERT INTO orders(user_id,service_id,service_name,target_url,quantity,total_paise) VALUES(?,?,?,?,?,?)")
   .run(u.id,service.id,service.name,target,qty,total);
  db.prepare("INSERT INTO wallet_transactions(user_id,type,amount_paise,reference,note) VALUES(?,?,?,?,?)")
   .run(u.id,"debit",total,"order-"+info.lastInsertRowid,"Order payment");
  return info.lastInsertRowid;
 });
 try{const id=create();res.json({ok:true,orderId:id,message:"Order accepted as Pending. Provider processing requires admin configuration."});}
 catch(e){res.status(400).json({error:e.message==="INSUFFICIENT"?"Insufficient wallet balance. Add funds first.":"Could not create order."});}
});

app.get("/api/wallet",requireAuth,(req,res)=>{
 const u=db.prepare("SELECT balance_paise FROM users WHERE id=?").get(req.session.userId);
 const transactions=db.prepare("SELECT type,amount_paise,reference,note,created_at FROM wallet_transactions WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.session.userId);
 const payments=db.prepare("SELECT amount_paise,status,gateway_order_id,created_at FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 50").all(req.session.userId);
 res.json({balancePaise:u.balance_paise,transactions,payments,paymentConfigured:!!(process.env.RAZORPAY_KEY_ID&&process.env.RAZORPAY_KEY_SECRET)});
});
app.post("/api/payments/create",requireAuth,async(req,res)=>{
 const amount=Number(req.body?.amount);
 if(!Number.isInteger(amount)||amount<100||amount>2000) return res.status(400).json({error:"Add Funds must be between ₹100 and ₹2,000."});
 if(!process.env.RAZORPAY_KEY_ID||!process.env.RAZORPAY_KEY_SECRET) return res.status(503).json({error:"Payment gateway is not configured. Add Razorpay keys on the server first."});
 try{
  const rz=new Razorpay({key_id:process.env.RAZORPAY_KEY_ID,key_secret:process.env.RAZORPAY_KEY_SECRET});
  const order=await rz.orders.create({amount:amount*100,currency:"INR",receipt:"u"+req.session.userId+"-"+Date.now()});
  db.prepare("INSERT INTO payments(user_id,gateway_order_id,amount_paise,status) VALUES(?,?,?,'created')").run(req.session.userId,order.id,amount*100);
  res.json({keyId:process.env.RAZORPAY_KEY_ID,orderId:order.id,amount:order.amount,currency:order.currency});
 }catch(e){res.status(502).json({error:"Could not create payment order with gateway."});}
});
// Webhook is intentionally separate from normal JSON middleware in production deployments.
// Razorpay signs the exact raw request body; route receives raw bytes.
app.post("/api/payments/webhook",(req,res)=>{
 const secret=process.env.RAZORPAY_WEBHOOK_SECRET;
 if(!secret) return res.status(503).send("Webhook not configured");
 const signature=req.headers["x-razorpay-signature"];
 const expected=crypto.createHmac("sha256",secret).update(req.rawBody || Buffer.from("")).digest("hex");
 if(!signature||!crypto.timingSafeEqual(Buffer.from(signature),Buffer.from(expected))) return res.status(400).send("Invalid signature");
 let event;try{event=JSON.parse((req.rawBody || Buffer.from("")).toString("utf8"));}catch{return res.status(400).send("Bad JSON");}
 if(event.event==="payment.captured"){
  const p=event.payload?.payment?.entity;
  if(p?.order_id&&p?.id){
   const credit=db.transaction(()=>{
    const row=db.prepare("SELECT * FROM payments WHERE gateway_order_id=?").get(p.order_id);
    if(!row||row.status==="paid"||row.amount_paise!==p.amount) return;
    db.prepare("UPDATE payments SET status='paid',gateway_payment_id=? WHERE id=?").run(p.id,row.id);
    db.prepare("UPDATE users SET balance_paise=balance_paise+? WHERE id=?").run(row.amount_paise,row.user_id);
    db.prepare("INSERT OR IGNORE INTO wallet_transactions(user_id,type,amount_paise,reference,note) VALUES(?,?,?,?,?)")
     .run(row.user_id,"credit",row.amount_paise,"payment-"+p.id,"Razorpay payment");
   });credit();
  }
 } else if(event.event==="payment.failed"){
  const p=event.payload?.payment?.entity;
  if(p?.order_id) db.prepare("UPDATE payments SET status='failed' WHERE gateway_order_id=? AND status='created'").run(p.order_id);
 }
 res.json({received:true});
});

app.get("/api/tickets",requireAuth,(req,res)=>res.json({tickets:db.prepare("SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC").all(req.session.userId)}));
app.post("/api/tickets",requireAuth,(req,res)=>{
 const subject=String(req.body?.subject||"").trim(),message=String(req.body?.message||"").trim();
 if(subject.length<3||message.length<5)return res.status(400).json({error:"Enter a subject and message."});
 const r=db.prepare("INSERT INTO tickets(user_id,subject,message) VALUES(?,?,?)").run(req.session.userId,subject.slice(0,120),message.slice(0,3000));
 res.json({ok:true,ticketId:r.lastInsertRowid});
});

app.get("/api/admin/summary",requireAdmin,(req,res)=>{
 res.json({
  users:db.prepare("SELECT COUNT(*) n FROM users WHERE role='user'").get().n,
  orders:db.prepare("SELECT COUNT(*) n FROM orders").get().n,
  pending:db.prepare("SELECT COUNT(*) n FROM orders WHERE status='Pending'").get().n,
  revenuePaise:db.prepare("SELECT COALESCE(SUM(amount_paise),0) n FROM payments WHERE status='paid'").get().n,
  ordersList:db.prepare("SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 100").all(),
  services:db.prepare("SELECT * FROM services ORDER BY id").all(),
  tickets:db.prepare("SELECT t.*,u.email FROM tickets t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 100").all()
 });
});
app.post("/api/admin/services",requireAdmin,(req,res)=>{
 const {platform,category,name,description,priceRupees,minQty,maxQty}=req.body||{};
 if(!platform||!category||!name||!Number.isFinite(Number(priceRupees))||Number(priceRupees)<0||!Number.isInteger(Number(minQty))||!Number.isInteger(Number(maxQty))||Number(minQty)<1||Number(maxQty)<Number(minQty))
  return res.status(400).json({error:"Check service fields."});
 const r=db.prepare("INSERT INTO services(platform,category,name,description,price_per_1000_paise,min_qty,max_qty) VALUES(?,?,?,?,?,?,?)")
 .run(String(platform),String(category),String(name),String(description||""),Math.round(Number(priceRupees)*100),Number(minQty),Number(maxQty));
 res.json({ok:true,id:r.lastInsertRowid});
});
app.patch("/api/admin/services/:id",requireAdmin,(req,res)=>{
 const {priceRupees,active}=req.body||{};
 if(priceRupees!==undefined&&(!Number.isFinite(Number(priceRupees))||Number(priceRupees)<0))return res.status(400).json({error:"Invalid price."});
 db.prepare("UPDATE services SET price_per_1000_paise=COALESCE(?,price_per_1000_paise),active=COALESCE(?,active) WHERE id=?")
 .run(priceRupees===undefined?null:Math.round(Number(priceRupees)*100),active===undefined?null:(active?1:0),Number(req.params.id));
 res.json({ok:true});
});
app.patch("/api/admin/orders/:id",requireAdmin,(req,res)=>{
 const allowed=["Pending","Processing","Completed","Partial","Cancelled","Failed"];
 if(!allowed.includes(req.body?.status))return res.status(400).json({error:"Invalid status."});
 db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,Number(req.params.id));
 res.json({ok:true});
});
app.post("/api/admin/tickets/:id/reply",requireAdmin,(req,res)=>{
 db.prepare("UPDATE tickets SET admin_reply=?,status='Answered' WHERE id=?").run(String(req.body?.reply||"").slice(0,3000),Number(req.params.id));
 res.json({ok:true});
});

app.get("/api/config",(req,res)=>res.json({brand:"SMM.com",domain:"paneladminsmm.shop",whatsappConfigured:!!process.env.WHATSAPP_NUMBER,paymentConfigured:!!(process.env.RAZORPAY_KEY_ID&&process.env.RAZORPAY_KEY_SECRET)}));
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`SMM.com running on port ${PORT}`));
