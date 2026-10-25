const Database = require('better-sqlite3');
const fs = require('node:fs');
const path = require('node:path');
const dir = path.join(__dirname, '..', 'data');
fs.mkdirSync(dir, { recursive: true });
const db = new Database(path.join(dir, 'utilitycare.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, google_sub TEXT UNIQUE, email TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL, phone TEXT, role TEXT NOT NULL CHECK(role IN ('staff','landlord','tenant')),
 landlord_id INTEGER REFERENCES users(id), active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS meters (
 id INTEGER PRIMARY KEY AUTOINCREMENT, meter_number TEXT NOT NULL UNIQUE, property_name TEXT NOT NULL,
 address TEXT, landlord_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tenant_links (
 id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL REFERENCES users(id), meter_id INTEGER NOT NULL REFERENCES meters(id),
 start_month TEXT NOT NULL, move_in_date TEXT, UNIQUE(tenant_id, meter_id)
);
CREATE TABLE IF NOT EXISTS bills (
 id INTEGER PRIMARY KEY AUTOINCREMENT, meter_id INTEGER NOT NULL REFERENCES meters(id), billing_month TEXT NOT NULL,
 previous_reading REAL NOT NULL, current_reading REAL NOT NULL, units REAL NOT NULL, energy_charge REAL NOT NULL,
 fixed_charge REAL NOT NULL, tax REAL NOT NULL, arrears REAL NOT NULL DEFAULT 0, adjustment REAL NOT NULL DEFAULT 0,
 total REAL NOT NULL, status TEXT NOT NULL DEFAULT 'unpaid' CHECK(status IN ('unpaid','pending','paid','failed','reversed')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(meter_id,billing_month)
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, bill_id INTEGER NOT NULL REFERENCES bills(id), user_id INTEGER NOT NULL REFERENCES users(id),
 amount_paise INTEGER NOT NULL, currency TEXT NOT NULL DEFAULT 'INR', status TEXT NOT NULL,
 provider TEXT NOT NULL DEFAULT 'demo', provider_order_id TEXT, provider_payment_id TEXT UNIQUE,
 receipt TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS complaints (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), meter_id INTEGER REFERENCES meters(id),
 category TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS outages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, area TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'reported',
 planned INTEGER NOT NULL DEFAULT 0, eta_start TEXT, eta_end TEXT, details TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 target_type TEXT, target_id TEXT, details TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
function log(actorId, action, targetType=null, targetId=null, details=null) {
 db.prepare('INSERT INTO audit_log(actor_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)').run(actorId, action, targetType, targetId == null ? null : String(targetId), details ? JSON.stringify(details) : null);
}
function seed() {
 const count = db.prepare('SELECT COUNT(*) n FROM users').get().n;
 if (count) return;
 // Local demo accounts are created only when DEMO_MODE=true; production Google login is the normal flow.
 if (process.env.DEMO_MODE !== 'true') return;
 const add = db.prepare('INSERT INTO users(email,name,role,phone) VALUES(?,?,?,?)');
 const staff = add.run('staff@demo.local','Utility Staff','staff','');
 const landlord = add.run('landlord@demo.local','Demo Landlord','landlord','9876543210');
 const tenant = add.run('tenant@demo.local','Demo Tenant','tenant','9876501234');
 const meter = db.prepare('INSERT INTO meters(meter_number,property_name,address,landlord_id) VALUES(?,?,?,?)').run('MTR-10001','Sunrise Apartments · Flat 101','Hyderabad, India',landlord.lastInsertRowid);
 db.prepare('INSERT INTO tenant_links(tenant_id,meter_id,start_month,move_in_date) VALUES(?,?,?,?)').run(tenant.lastInsertRowid,meter.lastInsertRowid,'2026-01','2026-01-01');
 const bill = db.prepare(`INSERT INTO bills(meter_id,billing_month,previous_reading,current_reading,units,energy_charge,fixed_charge,tax,arrears,adjustment,total,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`);
 let prev=1280;
 for (const [month, units, status] of [['2026-08',182,'paid'],['2026-09',216,'unpaid'],['2026-10',243,'unpaid']]) {
  const energy=units<=100?units*3.2:100*3.2+(units-100)*5.1, fixed=100, tax=Math.round((energy+fixed)*0.05*100)/100, total=Math.round((energy+fixed+tax)*100)/100;
  bill.run(meter.lastInsertRowid,month,prev,prev+units,units,energy,fixed,tax,0,0,total,status); prev+=units;
 }
 db.prepare('INSERT INTO outages(title,area,status,planned,eta_start,eta_end,details) VALUES(?,?,?,?,?,?,?)').run('Transformer inspection','Sunrise Apartments','verified',1,'14:00','16:00','Scheduled maintenance; times are an estimate.');
 db.prepare('INSERT INTO complaints(user_id,meter_id,category,description,status) VALUES(?,?,?,?,?)').run(tenant.lastInsertRowid,meter.lastInsertRowid,'Billing','Please explain the higher-than-usual bill.','new');
}
seed();
module.exports = { db, log };
