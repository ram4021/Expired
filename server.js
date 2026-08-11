const express=require("express");
const session=require("express-session");
const path=require("path");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const multer=require("multer");
const nodemailer=require("nodemailer");
require("dotenv").config?.();

const app=express();
const db=new Database("education.db");
const PORT=process.env.PORT||3000;
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||"dev-secret",resave:false,saveUninitialized:false,cookie:{httpOnly:true}}));
app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, mobile TEXT UNIQUE NOT NULL,
 email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, class_name TEXT, role TEXT DEFAULT 'student',
 verified INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS plans(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price INTEGER, features TEXT
);
CREATE TABLE IF NOT EXISTS enrollments(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plan_id INTEGER, status TEXT DEFAULT 'pending',
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plan_id INTEGER, amount INTEGER,
 transaction_id TEXT, screenshot TEXT, status TEXT DEFAULT 'pending',
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS courses(
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, class_name TEXT, subject TEXT,
 description TEXT, video_url TEXT, published INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS live_classes(
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, class_name TEXT, subject TEXT,
 date TEXT, start_time TEXT, end_time TEXT, meeting_link TEXT
);
`);
const count=db.prepare("SELECT COUNT(*) c FROM plans").get().c;
if(!count) db.prepare("INSERT INTO plans(name,price,features) VALUES (?,?,?),(?,?,?),(?,?,?)").run(
 "Basic",3000,"Recorded videos, Study materials, Basic support",
 "Advance",5000,"Full course, Recorded videos, Study materials, Live classes, Tests",
 "Premium",6500,"Complete course, Live classes, Tests, Assignments, Progress, Certificate, Priority support"
);

const upload=multer({dest:path.join(__dirname,"public","uploads")});
function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:"Login required"});next();}
function admin(req,res,next){if(!req.session.user||req.session.user.role!=="admin")return res.status(403).json({error:"Admin only"});next();}

app.post("/api/register",async(req,res)=>{
 const {name,mobile,email,password,class_name}=req.body;
 if(!name||!mobile||!email||!password)return res.status(400).json({error:"Required fields missing"});
 try{
  const hash=await bcrypt.hash(password,10);
  const otp=String(Math.floor(100000+Math.random()*900000));
  db.prepare("INSERT INTO users(name,mobile,email,password,class_name,verified) VALUES(?,?,?,?,?,0)").run(name,mobile,email,hash,class_name||"");
  // Demo OTP is returned only when SMTP is not configured. Production: send via SMTP and never return it.
  let sent=false;
  if(process.env.SMTP_USER&&process.env.SMTP_PASS){
    const transporter=nodemailer.createTransport({host:process.env.SMTP_HOST||"smtp.gmail.com",port:Number(process.env.SMTP_PORT||587),secure:false,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
    await transporter.sendMail({from:process.env.SMTP_USER,to:email,subject:"Manoj Sah Education Center OTP",text:`Your verification OTP is ${otp}. It expires in 10 minutes.`});
    sent=true;
  }
  db.prepare("CREATE TABLE IF NOT EXISTS otps(user_id INTEGER,otp TEXT,expires INTEGER)").run();
  const user=db.prepare("SELECT id FROM users WHERE email=?").get(email);
  db.prepare("DELETE FROM otps WHERE user_id=?").run(user.id);
  db.prepare("INSERT INTO otps VALUES(?,?,?)").run(user.id,otp,Date.now()+600000);
  res.json({message:"Registration successful. Verify OTP.",user_id:user.id,demo_otp:sent?undefined:otp});
 }catch(e){res.status(400).json({error:e.message.includes("UNIQUE")?"Email or mobile already registered":e.message});}
});
app.post("/api/verify-otp",(req,res)=>{
 const {user_id,otp}=req.body;
 const row=db.prepare("SELECT * FROM otps WHERE user_id=? AND otp=? AND expires>?").get(user_id,otp,Date.now());
 if(!row)return res.status(400).json({error:"Invalid or expired OTP"});
 db.prepare("UPDATE users SET verified=1 WHERE id=?").run(user_id);
 db.prepare("DELETE FROM otps WHERE user_id=?").run(user_id);
 res.json({message:"Email verified. You can login."});
});
app.post("/api/login",async(req,res)=>{
 const {login,password}=req.body;
 const u=db.prepare("SELECT * FROM users WHERE email=? OR mobile=?").get(login,login);
 if(!u||!(await bcrypt.compare(password,u.password)))return res.status(401).json({error:"Invalid login details"});
 if(!u.verified&&u.role!=="admin")return res.status(403).json({error:"Please verify your email with OTP first"});
 req.session.user={id:u.id,name:u.name,email:u.email,mobile:u.mobile,class_name:u.class_name,role:u.role};
 res.json({user:req.session.user});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));
app.get("/api/plans",(req,res)=>res.json(db.prepare("SELECT * FROM plans").all()));
app.get("/api/courses",(req,res)=>res.json(db.prepare("SELECT * FROM courses WHERE published=1 ORDER BY id DESC").all()));
app.get("/api/live",(req,res)=>res.json(db.prepare("SELECT * FROM live_classes ORDER BY date,start_time").all()));

app.post("/api/payments",auth,upload.single("screenshot"),(req,res)=>{
 const plan=db.prepare("SELECT * FROM plans WHERE id=?").get(req.body.plan_id);
 if(!plan)return res.status(400).json({error:"Plan not found"});
 const result=db.prepare("INSERT INTO payments(user_id,plan_id,amount,transaction_id,screenshot) VALUES(?,?,?,?,?)")
 .run(req.session.user.id,plan.id,plan.price,req.body.transaction_id||"",req.file?"/uploads/"+req.file.filename:"");
 db.prepare("INSERT INTO enrollments(user_id,plan_id,status) VALUES(?,?,?)").run(req.session.user.id,plan.id,"pending");
 res.json({message:"Payment submitted. Waiting for admin verification.",payment_id:result.lastInsertRowid,esewa_number:process.env.ESEWA_NUMBER||"9802059652"});
});

app.get("/api/my-payments",auth,(req,res)=>res.json(db.prepare(`
SELECT p.*,pl.name plan_name FROM payments p JOIN plans pl ON pl.id=p.plan_id WHERE p.user_id=? ORDER BY p.id DESC`).all(req.session.user.id)));

app.get("/api/admin/payments",admin,(req,res)=>res.json(db.prepare(`
SELECT p.*,u.name,u.email,u.mobile,pl.name plan_name FROM payments p
JOIN users u ON u.id=p.user_id JOIN plans pl ON pl.id=p.plan_id ORDER BY p.id DESC`).all()));
app.post("/api/admin/payment/:id/approve",admin,(req,res)=>{
 const p=db.prepare("SELECT * FROM payments WHERE id=?").get(req.params.id);
 if(!p)return res.status(404).json({error:"Not found"});
 db.prepare("UPDATE payments SET status='approved' WHERE id=?").run(p.id);
 db.prepare("UPDATE enrollments SET status='active' WHERE user_id=? AND plan_id=?").run(p.user_id,p.plan_id);
 res.json({message:"Payment approved"});
});
app.post("/api/admin/course",admin,(req,res)=>{
 const {title,class_name,subject,description,video_url}=req.body;
 const r=db.prepare("INSERT INTO courses(title,class_name,subject,description,video_url) VALUES(?,?,?,?,?)").run(title,class_name,subject,description,video_url);
 res.json({id:r.lastInsertRowid});
});
app.post("/api/admin/live",admin,(req,res)=>{
 const {title,class_name,subject,date,start_time,end_time,meeting_link}=req.body;
 const r=db.prepare("INSERT INTO live_classes(title,class_name,subject,date,start_time,end_time,meeting_link) VALUES(?,?,?,?,?,?,?)")
 .run(title,class_name,subject,date,start_time,end_time,meeting_link);
 res.json({id:r.lastInsertRowid});
});

async function ensureAdmin(){
 const email=process.env.ADMIN_EMAIL||"admin@example.com";
 const exists=db.prepare("SELECT id FROM users WHERE email=?").get(email);
 if(!exists){
  const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD||"ChangeMe123!",10);
  db.prepare("INSERT INTO users(name,mobile,email,password,role,verified) VALUES(?,?,?,?,?,1)")
   .run("Super Admin","9802059652",email,hash,"admin");
 }
}
ensureAdmin().then(()=>app.listen(PORT,()=>console.log(`Manoj Sah Education Center: http://localhost:${PORT}`)));
