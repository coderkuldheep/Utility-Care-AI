require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const Razorpay = require('razorpay');
const { google } = require('googleapis');
const crypto = require('node:crypto');
const path = require('node:path');
const { db, log } = require('./src/db');
const { requireAuth, requireRole, safeEqual, monthValid } = require('./src/security');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PROD = process.env.NODE_ENV === 'production';
const googleClient = process.env.GOOGLE_CLIENT_ID ? new OAuth2Client(process.env.GOOGLE_CLIENT_ID) : null;
const razorpayConfigured = Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET);
const razorpay = razorpayConfigured ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET }) : null;
const gmailConfigured = Boolean(process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_SECRET && process.env.GMAIL_REFRESH_TOKEN && process.env.GMAIL_SENDER_EMAIL);
function gmailClient(){ if(!gmailConfigured) return null; const auth=new google.auth.OAuth2(process.env.GMAIL_CLIENT_ID,process.env.GMAIL_CLIENT_SECRET); auth.setCredentials({refresh_token:process.env.GMAIL_REFRESH_TOKEN}); return google.gmail({version:'v1',auth}); }
function base64url(s){return Buffer.from(s).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function sendGmail(to,subject,body){ const gmail=gmailClient(); if(!gmail) throw new Error('Gmail API is not configured. Add Gmail OAuth client ID, client secret, refresh token and sender email to .env.'); const raw=base64url(`From: UtilityCare <${process.env.GMAIL_SENDER_EMAIL}>\r\nTo: ${to}\r\nSubject: ${subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${body}`); return gmail.users.messages.send({userId:'me',requestBody:{raw}}); }
function createPaymentHoldComplaint(payment,bill,userId){ const marker=`[PAYMENT-HOLD bill #${bill.id} payment #${payment.id}]`; const existing=db.prepare(`SELECT id FROM complaints WHERE category='Payment reconciliation' AND description LIKE ? AND status NOT IN ('resolved','closed')`).get(`%${marker}%`); if(existing) return existing.id; const r=db.prepare('INSERT INTO complaints(user_id,meter_id,category,description,status) VALUES(?,?,?,?,?)').run(userId,bill.meter_id,'Payment reconciliation',`${marker} Payment status is unresolved. User reports a possible bank debit without confirmed utility credit. Staff must review provider evidence before permitting another attempt.`,'new'); db.prepare("UPDATE payments SET status='pending_review',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status!='credit_reconciled'").run(payment.id); db.prepare("UPDATE bills SET status='pending' WHERE id=? AND status!='paid'").run(bill.id); return r.lastInsertRowid; }
const staffEmails = new Set((process.env.STAFF_EMAILS || '').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean));
if (IS_PROD && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) throw new Error('Set SESSION_SECRET to a random value of at least 32 characters in production.');

// Razorpay webhook requires the raw request body for signature validation.
app.post('/api/payments/webhook', express.raw({type:'application/json'}), (req,res)=>{
  if (!process.env.RAZORPAY_WEBHOOK_SECRET) return res.status(503).send('Webhook not configured');
  const signature=req.get('x-razorpay-signature')||'';
  const expected=crypto.createHmac('sha256',process.env.RAZORPAY_WEBHOOK_SECRET).update(req.body).digest('hex');
  if (!safeEqual(signature,expected)) return res.status(400).send('Invalid signature');
  let event; try { event=JSON.parse(req.body.toString('utf8')); } catch { return res.status(400).send('Invalid payload'); }
  const entity=event?.payload?.payment?.entity;
  if (entity?.order_id && entity?.id) {
    const p=db.prepare('SELECT * FROM payments WHERE provider_order_id=?').get(entity.order_id);
    if (p) {
      if (event.event==='payment.captured' || event.event==='order.paid') {
        db.prepare("UPDATE payments SET status='credit_reconciled',provider_payment_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(entity.id,p.id);
        db.prepare("UPDATE bills SET status='paid' WHERE id=?").run(p.bill_id); db.prepare("UPDATE complaints SET status='resolved' WHERE category='Payment reconciliation' AND description LIKE ? AND status NOT IN ('resolved','closed')").run(`%payment #${p.id}]%`);
      } else if (event.event==='payment.failed') {db.prepare("UPDATE payments SET status='failed',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(p.id);db.prepare("UPDATE bills SET status='unpaid' WHERE id=? AND status!='paid'").run(p.bill_id);}
    }
  }
  res.json({received:true});
});
app.use(helmet({contentSecurityPolicy:false, crossOriginOpenerPolicy:{policy:'same-origin-allow-popups'}}));
app.use(express.json({limit:'1mb'}));
app.use(rateLimit({windowMs:15*60*1000,limit:300,standardHeaders:true,legacyHeaders:false}));
app.use(session({
  store:new SQLiteStore({db:'sessions.sqlite',dir:path.join(__dirname,'data')}),
  name:'utilitycare.sid', secret:process.env.SESSION_SECRET || 'dev-only-change-this-session-secret',
  resave:false, saveUninitialized:false, rolling:true,
  cookie:{httpOnly:true,sameSite:'lax',secure:IS_PROD,maxAge:8*60*60*1000}
}));
app.use(express.static(path.join(__dirname,'public')));

const publicUser = u => u && ({id:u.id,email:u.email,name:u.name,phone:u.phone||'',role:u.role,landlordId:u.landlord_id||null});
const audit = (req,action,type,id,details)=>log(req.session.user?.id||null,action,type,id,details);
function ownedMeter(user,meterId) {
  if (user.role==='staff') return db.prepare('SELECT * FROM meters WHERE id=?').get(meterId);
  if (user.role==='landlord') return db.prepare('SELECT * FROM meters WHERE id=? AND landlord_id=?').get(meterId,user.id);
  return db.prepare('SELECT m.* FROM meters m JOIN tenant_links tl ON tl.meter_id=m.id WHERE m.id=? AND tl.tenant_id=?').get(meterId,user.id);
}
function visibleBills(user) {
  if(user.role==='staff') return db.prepare(`SELECT b.*,m.meter_number,m.property_name FROM bills b JOIN meters m ON m.id=b.meter_id ORDER BY b.billing_month DESC`).all();
  if(user.role==='landlord') return db.prepare(`SELECT b.*,m.meter_number,m.property_name FROM bills b JOIN meters m ON m.id=b.meter_id WHERE m.landlord_id=? ORDER BY b.billing_month DESC`).all(user.id);
  return db.prepare(`SELECT b.*,m.meter_number,m.property_name FROM bills b JOIN meters m ON m.id=b.meter_id JOIN tenant_links tl ON tl.meter_id=m.id WHERE tl.tenant_id=? AND b.billing_month>=tl.start_month ORDER BY b.billing_month DESC`).all(user.id);
}

app.get('/api/config',(req,res)=>res.json({googleClientId:process.env.GOOGLE_CLIENT_ID||'',razorpayKeyId:process.env.RAZORPAY_KEY_ID||'',razorpayEnabled:razorpayConfigured,demoMode:process.env.DEMO_MODE==='true',openAiEnabled:Boolean(process.env.OPENAI_API_KEY),gmailEnabled:gmailConfigured}));
app.get('/api/me',(req,res)=>res.json({user:publicUser(req.session.user),demoMode:process.env.DEMO_MODE==='true'}));
app.post('/api/auth/google', async(req,res)=>{
  try {
    const credential=req.body?.credential;
    if(!credential || !googleClient) return res.status(400).json({error:'Google Sign-In is not configured. Add GOOGLE_CLIENT_ID to .env.'});
    const ticket=await googleClient.verifyIdToken({idToken:credential,audience:process.env.GOOGLE_CLIENT_ID});
    const p=ticket.getPayload();
    if(!p?.sub || !p.email || !p.email_verified) return res.status(401).json({error:'Google account email must be verified.'});
    const email=p.email.toLowerCase();
    let u=db.prepare('SELECT * FROM users WHERE google_sub=? OR lower(email)=?').get(p.sub,email);
    const isStaff=staffEmails.has(email);
    if(u) {
      if(!u.active) return res.status(403).json({error:'This account has been disabled. Contact support.'});
      if(u.google_sub && u.google_sub!==p.sub) return res.status(403).json({error:'This email is already linked to a different Google identity.'});
      if(u.role==='staff' && !isStaff) return res.status(403).json({error:'Staff access is no longer authorized for this email.'});
      db.prepare('UPDATE users SET google_sub=?,name=? WHERE id=?').run(p.sub,p.name||u.name,u.id);
      u=db.prepare('SELECT * FROM users WHERE id=?').get(u.id);
    } else if(isStaff) {
      const r=db.prepare('INSERT INTO users(google_sub,email,name,role) VALUES(?,?,?,?)').run(p.sub,email,p.name||'Staff','staff');
      u=db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
    } else if(req.body?.requestedRole==='landlord') {
      const r=db.prepare('INSERT INTO users(google_sub,email,name,role) VALUES(?,?,?,?)').run(p.sub,email,p.name||'Landlord','landlord');
      u=db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
    } else {
      return res.status(403).json({error:'No tenant invitation was found for this Google email. Ask your landlord to add you first, or sign in as a landlord.'});
    }
    if(!u.active) return res.status(403).json({error:'This account has been disabled. Contact support.'});
    req.session.regenerate(err=>{
      if(err) return res.status(500).json({error:'Could not create session.'});
      req.session.user=publicUser(u);
      req.session.save(e=>{if(e)return res.status(500).json({error:'Could not save session.'}); audit(req,'login','user',u.id,{provider:'google'});res.json({user:publicUser(u)});});
    });
  } catch(e) { console.error('Google auth error:',e.message); res.status(401).json({error:'Google sign-in could not be verified. Check your OAuth client configuration.'}); }
});
app.post('/api/auth/demo', (req,res)=>{
  if(process.env.DEMO_MODE!=='true') return res.status(404).json({error:'Demo login is disabled.'});
  const role=req.body?.role; if(!['staff','landlord','tenant'].includes(role)) return res.status(400).json({error:'Choose a valid demo role.'});
  const email=role==='staff'?'staff@demo.local':role==='landlord'?'landlord@demo.local':'tenant@demo.local';
  const u=db.prepare('SELECT * FROM users WHERE email=?').get(email); if(!u)return res.status(404).json({error:'Demo account missing. Restart after enabling DEMO_MODE=true.'});
  req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Session error.'});req.session.user=publicUser(u);req.session.save(()=>res.json({user:publicUser(u)}));});
});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('utilitycare.sid');res.json({ok:true});}));

app.get('/api/dashboard',requireAuth,(req,res)=>{
 const u=req.session.user; const bills=visibleBills(u);
 let meters=[],tenants=[],complaints=[],outages=[];
 if(u.role==='landlord') {
  meters=db.prepare('SELECT m.*, (SELECT COUNT(*) FROM tenant_links tl WHERE tl.meter_id=m.id) tenant_count FROM meters m WHERE landlord_id=? ORDER BY m.id DESC').all(u.id);
  tenants=db.prepare(`SELECT u.id,u.name,u.email,u.phone,tl.start_month,tl.move_in_date,m.meter_number,m.property_name,m.id meter_id FROM tenant_links tl JOIN users u ON u.id=tl.tenant_id JOIN meters m ON m.id=tl.meter_id WHERE m.landlord_id=? ORDER BY u.name`).all(u.id);
  complaints=db.prepare(`SELECT c.*,u.name user_name,m.meter_number FROM complaints c JOIN users u ON u.id=c.user_id LEFT JOIN meters m ON m.id=c.meter_id WHERE m.landlord_id=? OR c.user_id=? ORDER BY c.created_at DESC`).all(u.id,u.id);
 } else if(u.role==='tenant') {
  meters=db.prepare(`SELECT m.*,tl.start_month,tl.move_in_date FROM meters m JOIN tenant_links tl ON tl.meter_id=m.id WHERE tl.tenant_id=?`).all(u.id);
  complaints=db.prepare('SELECT * FROM complaints WHERE user_id=? ORDER BY created_at DESC').all(u.id);
 }
 if(u.role==='staff') {
  tenants=db.prepare(`SELECT u.id,u.name,u.email,u.phone,m.meter_number,m.property_name,tl.start_month FROM users u JOIN tenant_links tl ON tl.tenant_id=u.id JOIN meters m ON m.id=tl.meter_id ORDER BY u.created_at DESC`).all();
  complaints=db.prepare(`SELECT c.*,u.name user_name,m.meter_number FROM complaints c JOIN users u ON u.id=c.user_id LEFT JOIN meters m ON m.id=c.meter_id ORDER BY c.created_at DESC`).all();
 }
 outages=db.prepare('SELECT * FROM outages ORDER BY created_at DESC LIMIT 30').all();
 const stats={bills:bills.length,unpaid:bills.filter(b=>b.status!=='paid').length,unpaidAmount:bills.filter(b=>b.status!=='paid').reduce((a,b)=>a+b.total,0),complaints:complaints.length,newComplaints:complaints.filter(c=>c.status==='new').length,meters:meters.length,tenants:tenants.length};
 res.json({user:u,stats,bills,meters,tenants,complaints,outages,provider:razorpayConfigured?'razorpay-test-or-live':'demo'});
});

app.post('/api/meters',requireAuth,requireRole('landlord'),(req,res)=>{
 const {meterNumber,propertyName,address=''}=req.body||{};
 if(!String(meterNumber||'').trim()||!String(propertyName||'').trim())return res.status(400).json({error:'Meter number and property name are required.'});
 try {const r=db.prepare('INSERT INTO meters(meter_number,property_name,address,landlord_id) VALUES(?,?,?,?)').run(meterNumber.trim(),propertyName.trim(),String(address).trim(),req.session.user.id);audit(req,'meter_created','meter',r.lastInsertRowid);res.json({id:r.lastInsertRowid});}catch(e){res.status(409).json({error:'Meter number already exists. Use a unique meter number.'});}
});
app.post('/api/tenants',requireAuth,requireRole('landlord'),(req,res)=>{
 const {name,email,phone,meterId,startMonth,moveInDate,propertyName,address,meterNumber}=req.body||{};
 if(!name?.trim()||!email?.trim()||!phone?.trim()||!startMonth||!monthValid(startMonth))return res.status(400).json({error:'Name, email, phone and a valid start month (YYYY-MM) are required.'});
 const owner=req.session.user.id;
 const create=db.transaction(()=>{
  let meter=db.prepare('SELECT * FROM meters WHERE id=? AND landlord_id=?').get(Number(meterId),owner);
  if(!meter) {
   if(!meterNumber?.trim() || !propertyName?.trim()) throw new Error('Choose an existing meter or enter both a meter number and property name for a new meter.');
   const r=db.prepare('INSERT INTO meters(meter_number,property_name,address,landlord_id) VALUES(?,?,?,?)').run(meterNumber.trim(),propertyName.trim(),String(address||'').trim(),owner);
   meter=db.prepare('SELECT * FROM meters WHERE id=?').get(r.lastInsertRowid);
  }
  let tenant=db.prepare('SELECT * FROM users WHERE lower(email)=lower(?)').get(email.trim());
  if(tenant && (tenant.role!=='tenant' || (tenant.landlord_id && tenant.landlord_id!==owner))) throw new Error('That email is already assigned to another account.');
  if(tenant && db.prepare('SELECT 1 FROM tenant_links WHERE tenant_id=?').get(tenant.id)) throw new Error('This tenant already has a meter assigned. Each tenant account can access one meter.');
  if(!tenant){const r=db.prepare('INSERT INTO users(email,name,phone,role,landlord_id) VALUES(?,?,?,?,?)').run(email.trim().toLowerCase(),name.trim(),phone.trim(),'tenant',owner);tenant=db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);}
  else db.prepare('UPDATE users SET name=?,phone=?,landlord_id=?,active=1 WHERE id=?').run(name.trim(),phone.trim(),owner,tenant.id);
  db.prepare('INSERT INTO tenant_links(tenant_id,meter_id,start_month,move_in_date) VALUES(?,?,?,?)').run(tenant.id,meter.id,startMonth,moveInDate||`${startMonth}-01`);
  // Seed a few synthetic months beginning at the allowed start month; no earlier bills are created for this meter link.
  const start=new Date(`${startMonth}-01T00:00:00Z`); const now=new Date(); const monthsToNow=(now.getUTCFullYear()-start.getUTCFullYear())*12+(now.getUTCMonth()-start.getUTCMonth())+1; const monthsToCreate=Math.max(0,Math.min(3,monthsToNow)); let previous=500+Math.floor(Math.random()*250);
  for(let i=0;i<monthsToCreate;i++) {const d=new Date(Date.UTC(start.getUTCFullYear(),start.getUTCMonth()+i,1)); const month=`${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`; const units=140+Math.floor(Math.random()*120); const energy=Math.round((Math.min(units,100)*3.2+Math.max(units-100,0)*5.1)*100)/100; const fixed=100; const tax=Math.round((energy+fixed)*.05*100)/100; const total=Math.round((energy+fixed+tax)*100)/100; db.prepare(`INSERT OR IGNORE INTO bills(meter_id,billing_month,previous_reading,current_reading,units,energy_charge,fixed_charge,tax,arrears,adjustment,total,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(meter.id,month,previous,previous+units,units,energy,fixed,tax,0,0,total,'unpaid'); previous+=units; }
  log(owner,'tenant_added','user',tenant.id,{meterId:meter.id,startMonth}); return {tenantId:tenant.id,meterId:meter.id,email:tenant.email};
 });
 try{res.json(create())}catch(e){res.status(400).json({error:e.message||'Could not add tenant.'})}
});
app.get('/api/bills/:id',requireAuth,(req,res)=>{
 const bill=visibleBills(req.session.user).find(b=>b.id===Number(req.params.id)); if(!bill)return res.status(404).json({error:'Bill not found or you do not have access to it.'});
 res.json({bill,explanation:{energy:`₹${bill.energy_charge.toFixed(2)}`,fixed:`₹${bill.fixed_charge.toFixed(2)}`,tax:`₹${bill.tax.toFixed(2)}`,arrears:`₹${bill.arrears.toFixed(2)}`,adjustment:`₹${bill.adjustment.toFixed(2)}`,total:`₹${bill.total.toFixed(2)}`}});
});
app.post('/api/complaints',requireAuth,(req,res)=>{
 const {category,description,meterId}=req.body||{}; if(!category?.trim()||!description?.trim())return res.status(400).json({error:'Category and description are required.'});
 let meter=null;if(meterId){meter=ownedMeter(req.session.user,Number(meterId));if(!meter)return res.status(403).json({error:'You cannot report against this meter.'});}
 const r=db.prepare('INSERT INTO complaints(user_id,meter_id,category,description) VALUES(?,?,?,?)').run(req.session.user.id,meter?.id||null,category.trim(),description.trim());audit(req,'complaint_created','complaint',r.lastInsertRowid);res.json({id:r.lastInsertRowid});
});
app.patch('/api/complaints/:id',requireAuth,requireRole('staff'),(req,res)=>{
 const status=String(req.body?.status||'');if(!['new','investigating','verified','resolved','closed'].includes(status))return res.status(400).json({error:'Invalid complaint status.'});
 const complaint=db.prepare(`SELECT c.*,m.property_name,m.address,m.meter_number FROM complaints c LEFT JOIN meters m ON m.id=c.meter_id WHERE c.id=?`).get(Number(req.params.id));
 if(!complaint)return res.status(404).json({error:'Complaint not found.'});
 db.prepare('UPDATE complaints SET status=? WHERE id=?').run(status,complaint.id);
 // A payment hold is released only after staff explicitly resolves/closes its complaint.
 const hold=String(complaint.description||'').match(/\[PAYMENT-HOLD bill #(\d+) payment #(\d+)\]/);
 if(hold && (status==='resolved'||status==='closed')) { const billId=Number(hold[1]), paymentId=Number(hold[2]); const pay=db.prepare('SELECT * FROM payments WHERE id=? AND bill_id=?').get(paymentId,billId); if(pay && pay.status!=='credit_reconciled'){ db.prepare("UPDATE payments SET status='abandoned',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(pay.id); db.prepare("UPDATE bills SET status='unpaid' WHERE id=? AND status!='paid'").run(billId); } }
 // Verified power-outage complaints create/update a map item from the same persistent record.
 if(status==='verified' && /power\s*outage|outage|power cut|electricity cut/i.test(`${complaint.category} ${complaint.description}`)) {
   const area=complaint.property_name || complaint.address || complaint.meter_number || 'Area reported by resident';
   const existing=db.prepare(`SELECT id FROM outages WHERE details LIKE ? ORDER BY id DESC LIMIT 1`).get(`%complaint #${complaint.id}%`);
   if(!existing) db.prepare(`INSERT INTO outages(title,area,status,planned,details) VALUES(?,?, 'verified',0,?)`).run(`Verified power outage — complaint #${complaint.id}`,area,`Verified from complaint #${complaint.id}: ${complaint.description}`);
   else db.prepare(`UPDATE outages SET status='verified' WHERE id=?`).run(existing.id);
 }
 if(status==='resolved'||status==='closed') db.prepare(`UPDATE outages SET status='resolved' WHERE details LIKE ?`).run(`%complaint #${complaint.id}%`);
 audit(req,'complaint_status_updated','complaint',req.params.id,{status});res.json({ok:true,mapUpdated:status==='verified'&&/power\s*outage|outage|power cut|electricity cut/i.test(`${complaint.category} ${complaint.description}`)});
});
app.post('/api/outages',requireAuth,requireRole('staff'),(req,res)=>{
 const {title,area,planned=false,etaStart='',etaEnd='',details=''}=req.body||{};if(!title?.trim()||!area?.trim())return res.status(400).json({error:'Title and area are required.'});
 const r=db.prepare('INSERT INTO outages(title,area,status,planned,eta_start,eta_end,details) VALUES(?,?,?,?,?,?,?)').run(title.trim(),area.trim(),'reported',planned?1:0,etaStart,etaEnd,details.trim());audit(req,'outage_created','outage',r.lastInsertRowid);res.json({id:r.lastInsertRowid});
});
app.patch('/api/outages/:id',requireAuth,requireRole('staff'),(req,res)=>{
 const {status,planned,details,etaStart,etaEnd}=req.body||{};if(!['reported','verified','planned_maintenance','resolved','unknown'].includes(status))return res.status(400).json({error:'Invalid outage status.'});
 const r=db.prepare('UPDATE outages SET status=?,planned=?,details=COALESCE(?,details),eta_start=COALESCE(?,eta_start),eta_end=COALESCE(?,eta_end) WHERE id=?').run(status,planned?1:0,details??null,etaStart??null,etaEnd??null,Number(req.params.id));if(!r.changes)return res.status(404).json({error:'Outage not found.'});audit(req,'outage_reclassified','outage',req.params.id,{status,planned});res.json({ok:true});
});

app.post('/api/payments/create-order',requireAuth,requireRole('tenant','landlord'),async(req,res)=>{
 const billId=Number(req.body?.billId); const bill=visibleBills(req.session.user).find(b=>b.id===billId);
 if(!bill)return res.status(404).json({error:'Bill not found or you do not have access to it.'});
 if(bill.status==='paid')return res.status(409).json({error:'This bill is already paid.'});
 const hold=db.prepare("SELECT id FROM complaints WHERE category='Payment reconciliation' AND description LIKE ? AND status NOT IN ('resolved','closed') LIMIT 1").get(`%[PAYMENT-HOLD bill #${bill.id} payment #%`); if(hold)return res.status(409).json({error:`Duplicate-payment guard: complaint #${hold.id} is still open. Staff must resolve the payment complaint before you can try paying this bill again.`});
 const existing=db.prepare("SELECT * FROM payments WHERE bill_id=? AND status IN ('initiated','pending','debit_confirmed','pending_review') ORDER BY id DESC LIMIT 1").get(bill.id);
 if(existing){ const age=Date.now()-Date.parse(existing.created_at+'Z'); let complaintId=null; if(age>=2*60*1000){ complaintId=createPaymentHoldComplaint(existing,bill,req.session.user.id); } return res.status(409).json({error:age>=2*60*1000?`Duplicate-payment guard: this attempt is unresolved. Complaint${complaintId?` #${complaintId}`:''} is in the Staff Complaints Queue. Do not pay again until staff resolves it.`:'A payment is already being processed. Refresh status; do not start a second payment.',paymentId:existing.id,complaintId}); }
 const receipt=`uc_${bill.id}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
 if(razorpayConfigured){
  try {
   const order=await razorpay.orders.create({amount:Math.round(bill.total*100),currency:'INR',receipt,notes:{bill_id:String(bill.id),user_id:String(req.session.user.id),meter_number:bill.meter_number}});
   const r=db.prepare("INSERT INTO payments(bill_id,user_id,amount_paise,status,provider,provider_order_id,receipt) VALUES(?,?,?,?,?,?,?)").run(bill.id,req.session.user.id,Math.round(bill.total*100),'initiated','razorpay',order.id,receipt);
   db.prepare("UPDATE bills SET status='pending' WHERE id=?").run(bill.id);audit(req,'payment_order_created','payment',r.lastInsertRowid,{provider:'razorpay',orderId:order.id});
   return res.json({mode:'razorpay',paymentId:r.lastInsertRowid,orderId:order.id,amount:order.amount,currency:order.currency,keyId:process.env.RAZORPAY_KEY_ID,name:'UtilityCare',description:`Electricity bill ${bill.billing_month}`,prefill:{name:req.session.user.name,email:req.session.user.email,contact:req.session.user.phone||''}});
  }catch(e){console.error('Razorpay order error:',e.message);return res.status(502).json({error:'Could not create Razorpay order. Check test keys and server logs.'});}
 }
 const r=db.prepare("INSERT INTO payments(bill_id,user_id,amount_paise,status,provider,receipt) VALUES(?,?,?,?,?,?)").run(bill.id,req.session.user.id,Math.round(bill.total*100),'initiated','demo',receipt);
 db.prepare("UPDATE bills SET status='pending' WHERE id=?").run(bill.id);audit(req,'demo_payment_started','payment',r.lastInsertRowid);res.json({mode:'demo',paymentId:r.lastInsertRowid,amount:Math.round(bill.total*100),currency:'INR',description:`Demo checkout for ${bill.billing_month}`});
});
app.post('/api/payments/verify',requireAuth,requireRole('tenant','landlord'),async(req,res)=>{
 const {paymentId,razorpay_order_id,razorpay_payment_id,razorpay_signature,outcome}=req.body||{};
 const p=db.prepare('SELECT * FROM payments WHERE id=? AND user_id=?').get(Number(paymentId),req.session.user.id);if(!p)return res.status(404).json({error:'Payment attempt not found.'});
 if(p.status==='credit_reconciled')return res.json({status:p.status,message:'Payment already reconciled.'});
 if(p.provider==='razorpay'){
  if(!razorpayConfigured||p.provider_order_id!==razorpay_order_id)return res.status(400).json({error:'Payment order does not match our records.'});
  const expected=crypto.createHmac('sha256',process.env.RAZORPAY_KEY_SECRET).update(`${p.provider_order_id}|${razorpay_payment_id||''}`).digest('hex');
  if(!safeEqual(expected,razorpay_signature))return res.status(400).json({error:'Payment signature could not be verified.'});
  db.prepare("UPDATE payments SET status='debit_confirmed',provider_payment_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(razorpay_payment_id,p.id);
  // Checkout signature confirms order/payment association. Reconcile captured status asynchronously via webhook or status refresh.
  try {
   const live=await awaitPaymentFetch(razorpay_payment_id);
   if(live && live.status==='captured'){db.prepare("UPDATE payments SET status='credit_reconciled',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(p.id);db.prepare("UPDATE bills SET status='paid' WHERE id=?").run(p.bill_id); db.prepare("UPDATE complaints SET status='resolved' WHERE category='Payment reconciliation' AND description LIKE ? AND status NOT IN ('resolved','closed')").run(`%payment #${p.id}]%`);return res.json({status:'credit_reconciled',message:'Payment verified and captured.'});}
  } catch {}
  const billRow=db.prepare('SELECT * FROM bills WHERE id=?').get(p.bill_id); const complaintId=createPaymentHoldComplaint({...p,status:'pending_review'},billRow,req.session.user.id); audit(req,'payment_signature_verified','payment',p.id,{complaintId});return res.json({status:'pending_review',complaintId,message:`Payment is not yet confirmed as credited. Complaint #${complaintId} was raised; do not pay again. You can retry only after staff resolves the complaint.`});
 }
 // Explicitly simulated demo payment states, never represented as a provider confirmation.
 if(!['success','failed','reversed'].includes(outcome))return res.status(400).json({error:'Choose a demo outcome.'});
 const status=outcome==='success'?'credit_reconciled':outcome;
 db.prepare('UPDATE payments SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status,p.id);
 db.prepare('UPDATE bills SET status=? WHERE id=?').run(status==='credit_reconciled'?'paid':status==='reversed'?'reversed':'unpaid',p.bill_id);
 audit(req,'demo_payment_outcome','payment',p.id,{status});res.json({status,message:status==='credit_reconciled'?'Demo payment marked reconciled (not a real transaction).':`Demo payment marked ${status}.`});
});
function awaitPaymentFetch(paymentId){ return razorpay.payments.fetch(paymentId); }
app.post('/api/payments/abandon',requireAuth,requireRole('tenant','landlord'),(req,res)=>{
 const paymentId=Number(req.body?.paymentId);const p=db.prepare('SELECT * FROM payments WHERE id=? AND user_id=?').get(paymentId,req.session.user.id);
 if(!p)return res.status(404).json({error:'Payment attempt not found for your account.'});
 if(p.status==='credit_reconciled')return res.json({status:p.status,message:'Payment is already reconciled. The bill is paid.'});
 if(p.provider_payment_id)return res.json({status:p.status,message:'A provider payment reference exists. Refresh provider status before retrying; this attempt was not closed.'});
 if(['initiated','pending','debit_confirmed','pending_review'].includes(p.status)){
  const bill=db.prepare('SELECT * FROM bills WHERE id=?').get(p.bill_id); const complaintId=createPaymentHoldComplaint(p,bill,req.session.user.id);
  audit(req,'payment_checkout_closed_reconciliation_required','payment',p.id,{complaintId});return res.json({status:'pending_review',complaintId,message:`Checkout closed but payment outcome is not proven. Complaint #${complaintId} has been raised; do not pay again until staff resolves it.`});
 }
 res.json({status:p.status,message:`This payment attempt is ${p.status}. Refresh status before retrying.`});
});
app.post('/api/payments/reconcile',requireAuth,requireRole('tenant','landlord'),async(req,res)=>{
 const billId=Number(req.body?.billId);const bill=visibleBills(req.session.user).find(b=>b.id===billId);if(!bill)return res.status(404).json({error:'Bill not found or you do not have access to it.'});
 const requestedPaymentId=Number(req.body?.paymentId||0);const p=requestedPaymentId?db.prepare("SELECT * FROM payments WHERE id=? AND bill_id=? AND user_id=?").get(requestedPaymentId,billId,req.session.user.id):db.prepare("SELECT * FROM payments WHERE bill_id=? AND user_id=? ORDER BY id DESC LIMIT 1").get(billId,req.session.user.id);if(!p)return res.status(404).json({error:'No payment attempt exists for this bill.'});
 if(p.provider==='razorpay' && razorpayConfigured && p.provider_payment_id){try{const live=await razorpay.payments.fetch(p.provider_payment_id);if(live.status==='captured'){db.prepare("UPDATE payments SET status='credit_reconciled',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(p.id);db.prepare("UPDATE bills SET status='paid' WHERE id=?").run(billId);db.prepare("UPDATE complaints SET status='resolved' WHERE category='Payment reconciliation' AND description LIKE ? AND status NOT IN ('resolved','closed')").run(`%payment #${p.id}]%`);return res.json({status:'credit_reconciled',message:'Provider confirms this payment is captured. The payment hold complaint has been resolved.'});}if(live.status==='failed'){db.prepare("UPDATE payments SET status='failed',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(p.id);db.prepare("UPDATE bills SET status='unpaid' WHERE id=? AND status!='paid'").run(billId);return res.json({status:'failed',message:'Provider reports the payment failed. You can review the bill and retry.'});}const billRow=db.prepare('SELECT * FROM bills WHERE id=?').get(billId);const complaintId=createPaymentHoldComplaint(p,billRow,req.session.user.id);return res.json({status:'pending_review',complaintId,message:`Provider status is ${live.status}; utility credit is not confirmed. Complaint #${complaintId} was raised. Do not pay again until staff resolves it.`});}catch(e){console.error('Payment reconciliation error:',e.message);return res.status(502).json({error:'Could not fetch the provider payment status. Please retry later; do not pay again while it is pending.'});}}
 if(p.provider==='razorpay' && !p.provider_payment_id && ['initiated','pending','debit_confirmed','pending_review'].includes(p.status) && Date.now()-Date.parse(p.created_at+'Z')>2*60*1000){const complaintId=createPaymentHoldComplaint(p,db.prepare('SELECT * FROM bills WHERE id=?').get(billId),req.session.user.id);return res.json({status:'pending_review',complaintId,message:`No confirmed provider credit is available after the waiting window. Complaint #${complaintId} was raised; the duplicate-payment guard remains active until staff resolves it.`});}
 if(['initiated','pending','debit_confirmed','pending_review'].includes(p.status)){ const billRow=db.prepare('SELECT * FROM bills WHERE id=?').get(billId); const complaintId=createPaymentHoldComplaint(p,billRow,req.session.user.id); audit(req,'payment_reconciliation_complaint_created','payment',p.id,{complaintId}); return res.json({status:'pending_review',complaintId,message:`Payment is still unresolved. Complaint #${complaintId} has been raised for staff review. Do not pay again; retry is locked until staff resolves it.`}); } res.json({status:p.status,message:p.provider==='demo'?'This is a demo payment state, not a provider confirmation.':'No provider payment reference is available yet.'});
});
app.get('/api/staff/unpaid-bills',requireAuth,requireRole('staff'),(req,res)=>{ const filter=req.query.filter==='overdue'?'overdue':'upcoming'; const rows=db.prepare(`SELECT b.id bill_id,b.billing_month,b.total,b.status,m.id meter_id,m.meter_number,m.property_name,m.landlord_id,lu.email landlord_email,lu.name landlord_name,tu.id tenant_id,tu.email tenant_email,tu.name tenant_name,tl.start_month FROM bills b JOIN meters m ON m.id=b.meter_id JOIN users lu ON lu.id=m.landlord_id LEFT JOIN tenant_links tl ON tl.meter_id=m.id LEFT JOIN users tu ON tu.id=tl.tenant_id WHERE b.status!='paid' ORDER BY b.billing_month ASC,m.meter_number`).all(); const now=new Date(); const monthsOld=r=>{const [y,mo]=r.billing_month.split('-').map(Number);return (now.getFullYear()-y)*12+(now.getMonth()+1-mo)}; const filtered=rows.filter(r=>filter==='upcoming'?monthsOld(r)<=1:monthsOld(r)>=2).map(r=>({...r,months_old:monthsOld(r),reminder_type:filter})); res.json({bills:filtered,gmailEnabled:gmailConfigured,filter}); });
app.post('/api/staff/send-bill-reminders',requireAuth,requireRole('staff'),async(req,res)=>{ const filter=req.body?.filter==='overdue'?'overdue':'upcoming'; if(!gmailConfigured)return res.status(503).json({error:'Gmail API is not configured. Set GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN and GMAIL_SENDER_EMAIL in .env.'}); const rows=db.prepare(`SELECT b.id bill_id,b.billing_month,b.total,m.meter_number,m.property_name,lu.email landlord_email,lu.name landlord_name,tu.email tenant_email,tu.name tenant_name FROM bills b JOIN meters m ON m.id=b.meter_id JOIN users lu ON lu.id=m.landlord_id LEFT JOIN tenant_links tl ON tl.meter_id=m.id LEFT JOIN users tu ON tu.id=tl.tenant_id WHERE b.status!='paid' ORDER BY b.billing_month ASC`).all(); const now=new Date(); const age=r=>{const [y,mo]=r.billing_month.split('-').map(Number);return (now.getFullYear()-y)*12+(now.getMonth()+1-mo)}; const selected=rows.filter(r=>filter==='upcoming'?age(r)<=1:age(r)>=2); const subject=filter==='upcoming'?'Remainder - Upcoming Bill due date is near':'Bill Due date exceeded !! Please Clear your Pending dues immediately'; let sent=0,failed=0,recipients=0; const landlordGroups=new Map(); for(const r of selected){ if(r.tenant_email){try{await sendGmail(r.tenant_email,subject,`Hello ${r.tenant_name||'Tenant'},\n\n${subject}\nMeter: ${r.meter_number}\nProperty: ${r.property_name}\nBilling month: ${r.billing_month}\nAmount due: INR ${Number(r.total).toFixed(2)}\n\nPlease sign in to UtilityCare to review your bill. If you have already paid, do not pay again while a payment is being reconciled.`);sent++;recipients++;}catch(e){failed++;console.error('Tenant reminder email failed:',e.message);} } if(!landlordGroups.has(r.landlord_email))landlordGroups.set(r.landlord_email,[]);landlordGroups.get(r.landlord_email).push(r); } for(const [email,items] of landlordGroups){ if(!email)continue; try{const lines=items.map(r=>`${r.meter_number} | ${r.billing_month} | INR ${Number(r.total).toFixed(2)} | tenant ${r.tenant_email||'not assigned'}`).join('\n'); await sendGmail(email,subject,`Hello ${items[0].landlord_name||'Landlord'},\n\n${subject}\nThis summary includes unpaid bills across your associated meters:\n\n${lines}\n\nPlease sign in to UtilityCare to review. Tenant reminders are restricted to their assigned meter.`);sent++;recipients++;}catch(e){failed++;console.error('Landlord reminder email failed:',e.message);} } audit(req,'bill_reminders_sent','bill',null,{filter,selected:selected.length,sent,failed}); res.json({ok:true,filter,bills:selected.length,emailsSent:sent,failed,subject,message:`Sent ${sent} email(s); ${failed} failed. Landlords receive summaries for their associated meters; each tenant receives only their assigned meter reminder.`}); });

app.get('/api/payments/history',requireAuth,(req,res)=>{
 const rows=req.session.user.role==='staff' ? db.prepare(`SELECT p.*,b.billing_month,m.meter_number,u.email FROM payments p JOIN bills b ON b.id=p.bill_id JOIN meters m ON m.id=b.meter_id JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 100`).all() : db.prepare(`SELECT p.*,b.billing_month,m.meter_number FROM payments p JOIN bills b ON b.id=p.bill_id JOIN meters m ON m.id=b.meter_id WHERE p.user_id=? ORDER BY p.created_at DESC LIMIT 50`).all(req.session.user.id);
 res.json({payments:rows});
});

app.post('/api/payments/staff-resolve-stale',requireAuth,requireRole('staff'),(req,res)=>{
 const stale=db.prepare("SELECT p.*,b.meter_id,b.id bill_id FROM payments p JOIN bills b ON b.id=p.bill_id WHERE p.provider='razorpay' AND p.status IN ('initiated','pending','debit_confirmed') AND p.created_at < datetime('now','-2 minutes')").all(); let created=0; for(const p of stale){ const id=createPaymentHoldComplaint(p,{id:p.bill_id,meter_id:p.meter_id},p.user_id); if(id)created++; } audit(req,'staff_flag_stale_payments','payment',null,{count:stale.length,complaints:created}); res.json({count:stale.length,message:`Flagged ${stale.length} stale payment attempt(s) for reconciliation. Payment complaints are in the Staff Complaints Queue; retry stays locked until each complaint is resolved.`});
});
app.post('/api/payments/staff-refresh',requireAuth,requireRole('staff'),async(req,res)=>{
 if(!razorpayConfigured)return res.status(503).json({error:'Razorpay is not configured. Add test-mode keys to .env first.'});
 const pending=db.prepare(`SELECT * FROM payments WHERE provider='razorpay' AND status IN ('initiated','pending','debit_confirmed','pending_review') AND provider_payment_id IS NOT NULL ORDER BY created_at DESC LIMIT 100`).all();
 let checked=0,updated=0;
 for(const p of pending){try{const live=await razorpay.payments.fetch(p.provider_payment_id);checked++;
  if(live.status==='captured'){db.prepare(`UPDATE payments SET status='credit_reconciled',updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(p.id);db.prepare(`UPDATE bills SET status='paid' WHERE id=?`).run(p.bill_id);db.prepare("UPDATE complaints SET status='resolved' WHERE category='Payment reconciliation' AND description LIKE ? AND status NOT IN ('resolved','closed')").run(`%payment #${p.id}]%`);updated++;}
  else if(live.status==='failed'){db.prepare(`UPDATE payments SET status='failed',updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(p.id);db.prepare(`UPDATE bills SET status='unpaid' WHERE id=? AND status!='paid'`).run(p.bill_id);db.prepare("UPDATE complaints SET status='resolved' WHERE category='Payment reconciliation' AND description LIKE ? AND status NOT IN ('resolved','closed')").run(`%payment #${p.id}]%`);updated++;}
 }catch(e){console.error('Staff payment refresh:',e.message);}}
 audit(req,'staff_payment_refresh','payment',null,{checked,updated});res.json({checked,updated,message:`Checked ${checked} Razorpay payment(s); updated ${updated} record(s).`});
});

app.post('/api/assistant',requireAuth,async(req,res)=>{
 const question=String(req.body?.message||'').trim();if(!question||question.length>1200)return res.status(400).json({error:'Enter a question under 1,200 characters.'});
 const u=req.session.user; let context='';
 if(u.role==='staff'){
  const recentPayments=db.prepare(`SELECT p.status,p.provider,p.amount_paise,p.provider_order_id,p.provider_payment_id,p.created_at,b.billing_month,m.meter_number FROM payments p JOIN bills b ON b.id=p.bill_id JOIN meters m ON m.id=b.meter_id ORDER BY p.created_at DESC LIMIT 20`).all();
  const counts={newComplaints:db.prepare("SELECT COUNT(*) n FROM complaints WHERE status='new'").get().n,openComplaints:db.prepare("SELECT COUNT(*) n FROM complaints WHERE status IN ('new','investigating')").get().n,unverifiedOutages:db.prepare("SELECT COUNT(*) n FROM outages WHERE status IN ('reported','unknown')").get().n,pendingPayments:db.prepare("SELECT COUNT(*) n FROM payments WHERE status IN ('initiated','pending','debit_confirmed')").get().n,activeMeters:db.prepare('SELECT COUNT(*) n FROM meters').get().n};
  const outages=db.prepare('SELECT title,area,status,planned,eta_start,eta_end FROM outages ORDER BY created_at DESC LIMIT 10').all(); context=JSON.stringify({role:'staff',metrics:counts,outages,recentPayments});
 } else if(u.role==='landlord'){
  const meters=db.prepare('SELECT id,meter_number,property_name FROM meters WHERE landlord_id=?').all(u.id);
  const tenants=db.prepare(`SELECT u.name,u.email,tl.start_month,m.meter_number FROM tenant_links tl JOIN users u ON u.id=tl.tenant_id JOIN meters m ON m.id=tl.meter_id WHERE m.landlord_id=?`).all(u.id);
  const complaints=db.prepare(`SELECT c.category,c.description,c.status,m.meter_number FROM complaints c LEFT JOIN meters m ON m.id=c.meter_id WHERE m.landlord_id=? ORDER BY c.created_at DESC LIMIT 10`).all(u.id);
  context=JSON.stringify({role:'landlord',meters,tenants,complaints,bills:visibleBills(u).map(b=>({month:b.billing_month,meter:b.meter_number,total:b.total,status:b.status}))});
 } else {
  const meters=db.prepare(`SELECT m.id,m.meter_number,m.property_name,tl.start_month FROM meters m JOIN tenant_links tl ON tl.meter_id=m.id WHERE tl.tenant_id=?`).all(u.id);
  context=JSON.stringify({role:'tenant',meters,bills:visibleBills(u).map(b=>({month:b.billing_month,meter:b.meter_number,units:b.units,total:b.total,status:b.status,energy_charge:b.energy_charge,fixed_charge:b.fixed_charge,tax:b.tax,arrears:b.arrears,adjustment:b.adjustment})),complaints:db.prepare('SELECT category,status,created_at FROM complaints WHERE user_id=? ORDER BY created_at DESC LIMIT 10').all(u.id)});
 }
 const prompts={staff:'You are UtilityCare Staff Operations Assistant. Answer only staff operational questions: maintenance schedule, complaint/report counts, outage verification, payment reconciliation queue, service metrics. Never disclose tenant private contact details or full personal records. Do not invent facts; state when information is unavailable.',landlord:'You are UtilityCare Landlord Assistant. You may discuss only the signed-in landlord\'s own meters, assigned tenants, their bill statuses and complaints. Never disclose another landlord\'s data, tenant passwords, Google tokens, payment credentials or OTPs. Bills before a tenant link start month must not be exposed to that tenant; do not reveal a tenant\'s earlier history. Avoid unnecessarily repeating tenant contact information.',tenant:'You are UtilityCare Tenant Assistant. You may discuss only the signed-in tenant\'s assigned meter, bills at/after their access start month, own payments and own complaints. Do not reveal other tenants, landlord private data, other meters, bills before the allowed month, or staff-only operations. Never request OTPs or payment credentials.'};
 let answer;
 if(process.env.OPENAI_API_KEY){
  try{
   const response=await fetch('https://api.openai.com/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${process.env.OPENAI_API_KEY}`},body:JSON.stringify({model:process.env.OPENAI_MODEL||'gpt-4.1-mini',temperature:.2,messages:[{role:'system',content:`${prompts[u.role]} Only use this server-provided role-filtered context. If a request is outside role scope, politely refuse. Context: ${context}`},{role:'user',content:question}]})});
   if(!response.ok)throw new Error(`AI provider status ${response.status}`);const data=await response.json();answer=data.choices?.[0]?.message?.content||'I could not generate a response.';
  }catch(e){console.error('Assistant provider error:',e.message);answer=ruleAnswer(u.role,question,context);}
 } else answer=ruleAnswer(u.role,question,context);
 audit(req,'assistant_query','assistant',null,{role:u.role});res.json({answer,mode:process.env.OPENAI_API_KEY?'ai-with-role-filter':'role-aware-demo'});
});
function ruleAnswer(role,q,raw){
 const c=JSON.parse(raw);const s=q.toLowerCase();
 if(role==='staff'){
  if(/complaint|report|ticket/.test(s))return `Operations snapshot: ${c.metrics.newComplaints} new complaints, ${c.metrics.openComplaints} open complaints, and ${c.metrics.unverifiedOutages} outage reports still need verification. Use the Complaints and Outages panels to review them.`;
  if(/maint|outage|schedule|power cut/.test(s))return `Recent outage / maintenance updates: ${c.outages.length?c.outages.map(o=>`${o.title} — ${o.area}: ${o.status}${o.planned?' (planned maintenance)':''}${o.eta_start&&o.eta_end?`, estimated ${o.eta_start}–${o.eta_end}`:''}`).join('; '):'No outage updates are recorded.'} Times are estimates, not commitments.`;
  if(/payment|reconcil|debit|credit/.test(s))return `There are ${c.metrics.pendingPayments} payment attempts awaiting reconciliation. A bank debit alone is not proof that the utility bill has been credited; check the provider status and webhook/audit trail before advising another payment.`;
  if(/meter|connection/.test(s))return `There are ${c.metrics.activeMeters} registered meter connections. Ask for a meter number and check the Meter/Outage records before making a service claim.`;
  return 'I can help with staff operations: “How many new complaints were registered?”, “What maintenance is scheduled?”, “How many payments need reconciliation?”, or “Which outage reports are unverified?”';
 }
 if(role==='landlord'){
  if(/tenant|occupant/.test(s))return `You currently have ${c.tenants.length} tenant assignment(s) across ${c.meters.length} meter(s). Each tenant is scoped to one meter and can see bills only from their assigned start month.`;
  if(/complaint|report/.test(s))return `There are ${c.complaints.length} complaint record(s) related to your properties. ${c.complaints.filter(x=>x.status==='new').length} are new. Open the Complaints section for details.`;
  if(/bill|due|payment|amount|high|meter/.test(s))return `Your account has ${c.bills.filter(b=>b.status!=='paid').length} unpaid bill record(s). ${c.bills.filter(b=>b.status!=='paid').slice(0,4).map(b=>`${b.meter} (${b.month}): ₹${Number(b.total).toFixed(2)}, ${b.status}`).join('; ')||'No unpaid bills found.'} Review slab charges, fixed charges, tax, arrears and adjustments before concluding a bill is incorrect.`;
  return 'I can help with your own properties: “Which tenants are assigned?”, “What complaints are open?”, “Which bills are unpaid?”, or “How do I add a tenant?”';
 }
 if(/complaint|report/.test(s))return `Your account has ${c.complaints.length} complaint record(s). ${c.complaints.map(x=>`${x.category}: ${x.status}`).join('; ')||'You have not submitted any complaints yet.'}`;
 if(/bill|amount|high|payment|due|meter|unit|charge/.test(s))return `For your assigned meter ${c.meters[0]?.meter_number||'(not assigned)'}, your visible bill history starts at ${c.meters[0]?.start_month||'the assigned start month'}. ${c.bills.slice(0,4).map(b=>`${b.month}: ${b.units} units, ₹${Number(b.total).toFixed(2)}, ${b.status}; energy ₹${Number(b.energy_charge).toFixed(2)}, fixed ₹${Number(b.fixed_charge).toFixed(2)}, tax ₹${Number(b.tax).toFixed(2)}, arrears ₹${Number(b.arrears).toFixed(2)}, adjustments ₹${Number(b.adjustment).toFixed(2)}`).join(' | ')||'No visible bills are available yet.'} If you have paid and the portal still shows unpaid, do not pay again until the payment status is reconciled.`;
 return 'I can help with your assigned meter: “Why is my bill high?”, “Show my latest bill”, “Has my payment cleared?”, or “How do I report an outage?”';
}

app.get('/api/health',(req,res)=>res.json({ok:true,db:'sqlite',payments:razorpayConfigured?'razorpay-configured':'demo-mode',time:new Date().toISOString()}));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Unexpected server error.'});});
app.listen(PORT,()=>console.log(`UtilityCare AI listening on http://localhost:${PORT}`));
