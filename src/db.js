const Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), crypto = require('crypto'), path = require('path');
const db = new Database(process.env.DATABASE_URL || path.join(__dirname, '..', 'reliefledger.db'));
db.pragma('journal_mode=WAL'); db.pragma('foreign_keys=ON');
const T = "TEXT NOT NULL DEFAULT (datetime('now'))";
db.exec(`
CREATE TABLE IF NOT EXISTS roles(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS organizations(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, created_at ${T}, updated_at ${T});
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL, full_name TEXT NOT NULL,
  role_id INTEGER NOT NULL REFERENCES roles(id), organization_id INTEGER REFERENCES organizations(id), is_active INTEGER NOT NULL DEFAULT 1,
  failed_logins INTEGER NOT NULL DEFAULT 0, locked_until TEXT, created_at ${T}, updated_at ${T});
CREATE TABLE IF NOT EXISTS organizations_users(organization_id INTEGER NOT NULL REFERENCES organizations(id), user_id INTEGER NOT NULL REFERENCES users(id), PRIMARY KEY(organization_id,user_id));
CREATE TABLE IF NOT EXISTS locations(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, prefix TEXT NOT NULL, lat REAL, lng REAL);
CREATE TABLE IF NOT EXISTS counters(prefix TEXT PRIMARY KEY, n INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS aid_types(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, cooldown_days INTEGER NOT NULL DEFAULT 14);
CREATE TABLE IF NOT EXISTS households(id INTEGER PRIMARY KEY, relief_id TEXT UNIQUE NOT NULL, head_name TEXT NOT NULL, head_name_norm TEXT NOT NULL, head_name_phonetic TEXT NOT NULL,
  alias TEXT, family_size INTEGER NOT NULL CHECK(family_size>0), children INTEGER NOT NULL DEFAULT 0, elderly INTEGER NOT NULL DEFAULT 0, disabled_members INTEGER NOT NULL DEFAULT 0,
  is_women_led INTEGER NOT NULL DEFAULT 0, origin_location_id INTEGER REFERENCES locations(id), current_location_id INTEGER NOT NULL REFERENCES locations(id),
  displacement_status TEXT NOT NULL DEFAULT 'RESIDENT', lost_documents INTEGER NOT NULL DEFAULT 0, phone TEXT, phone_norm TEXT, lat REAL, lng REAL,
  vulnerability_score INTEGER NOT NULL DEFAULT 0, vulnerability_notes TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN('ACTIVE','MERGED','INACTIVE')),
  merged_into_id INTEGER REFERENCES households(id), registered_by INTEGER NOT NULL REFERENCES users(id), organization_id INTEGER NOT NULL REFERENCES organizations(id),
  device_id TEXT, sync_status TEXT NOT NULL DEFAULT 'SYNCED', client_uuid TEXT UNIQUE, last_aid_at TEXT, total_aid_count INTEGER NOT NULL DEFAULT 0, created_at ${T}, updated_at ${T});
CREATE TABLE IF NOT EXISTS beneficiaries(id INTEGER PRIMARY KEY, household_id INTEGER UNIQUE NOT NULL REFERENCES households(id), full_name TEXT NOT NULL, created_at ${T}, updated_at ${T});
CREATE TABLE IF NOT EXISTS household_members(id INTEGER PRIMARY KEY, household_id INTEGER NOT NULL REFERENCES households(id), full_name TEXT NOT NULL, relation TEXT, age INTEGER);
CREATE TABLE IF NOT EXISTS household_location_history(id INTEGER PRIMARY KEY, household_id INTEGER NOT NULL REFERENCES households(id), from_location_id INTEGER REFERENCES locations(id),
  to_location_id INTEGER NOT NULL REFERENCES locations(id), recorded_by INTEGER NOT NULL REFERENCES users(id), moved_at ${T});
CREATE TABLE IF NOT EXISTS aid_requests(id INTEGER PRIMARY KEY, request_code TEXT UNIQUE, household_id INTEGER REFERENCES households(id), requester_name TEXT NOT NULL,
  location_id INTEGER NOT NULL REFERENCES locations(id), family_size INTEGER NOT NULL, displacement_status TEXT, aid_type_id INTEGER NOT NULL REFERENCES aid_types(id), phone TEXT,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','VERIFIED','APPROVED','REJECTED','FULFILLED')), reviewed_by INTEGER REFERENCES users(id), created_at ${T}, updated_at ${T});
CREATE TABLE IF NOT EXISTS aid_distributions(id INTEGER PRIMARY KEY, tx_id TEXT UNIQUE NOT NULL, household_id INTEGER NOT NULL REFERENCES households(id),
  aid_type_id INTEGER NOT NULL REFERENCES aid_types(id), quantity REAL NOT NULL CHECK(quantity>0), organization_id INTEGER NOT NULL REFERENCES organizations(id),
  created_by INTEGER NOT NULL REFERENCES users(id), location_id INTEGER NOT NULL REFERENCES locations(id), distributed_at TEXT NOT NULL, notes TEXT,
  override_used INTEGER NOT NULL DEFAULT 0, override_reason TEXT, device_id TEXT, sync_status TEXT NOT NULL DEFAULT 'SYNCED', created_at ${T}, updated_at ${T});
CREATE TABLE IF NOT EXISTS verification_records(id INTEGER PRIMARY KEY, distribution_id INTEGER NOT NULL REFERENCES aid_distributions(id),
  method TEXT NOT NULL CHECK(method IN('QR','RELIEF_ID','PIN','WORKER_ASSISTED','SIGNATURE','BIOMETRIC_FUTURE')), verified INTEGER NOT NULL, verified_by INTEGER NOT NULL REFERENCES users(id), verified_at ${T});
CREATE TABLE IF NOT EXISTS duplicate_cases(id INTEGER PRIMARY KEY, case_code TEXT UNIQUE NOT NULL, household_a_id INTEGER NOT NULL REFERENCES households(id), household_b_id INTEGER REFERENCES households(id),
  trigger_type TEXT NOT NULL, match_score REAL NOT NULL, match_band TEXT NOT NULL, details TEXT, status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN('OPEN','CONFIRMED_DUPLICATE','NOT_DUPLICATE','MERGED')),
  raised_by INTEGER REFERENCES users(id), resolved_by INTEGER REFERENCES users(id), resolution_note TEXT, created_at ${T}, updated_at ${T});
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, user_id INTEGER REFERENCES users(id), organization_id INTEGER REFERENCES organizations(id),
  household_id INTEGER REFERENCES households(id), location_id INTEGER REFERENCES locations(id), device_id TEXT, payload TEXT, prev_hash TEXT NOT NULL, hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_logs BEGIN SELECT RAISE(ABORT,'audit_logs is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_logs BEGIN SELECT RAISE(ABORT,'audit_logs is append-only'); END;
CREATE TABLE IF NOT EXISTS sync_queue(id INTEGER PRIMARY KEY, client_uuid TEXT UNIQUE NOT NULL, device_id TEXT, user_id INTEGER REFERENCES users(id), op_type TEXT NOT NULL, payload TEXT,
  client_timestamp TEXT, status TEXT NOT NULL CHECK(status IN('APPLIED','DUPLICATE','CONFLICT')), processed_at ${T});
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, type TEXT NOT NULL, filters TEXT, generated_by INTEGER REFERENCES users(id), created_at ${T});
CREATE INDEX IF NOT EXISTS i_hh_norm ON households(head_name_norm); CREATE INDEX IF NOT EXISTS i_hh_ph ON households(head_name_phonetic);
CREATE INDEX IF NOT EXISTS i_hh_phone ON households(phone_norm); CREATE INDEX IF NOT EXISTS i_hh_loc ON households(current_location_id);
CREATE INDEX IF NOT EXISTS i_d_hh ON aid_distributions(household_id, distributed_at); CREATE INDEX IF NOT EXISTS i_d_org ON aid_distributions(organization_id, distributed_at);
CREATE INDEX IF NOT EXISTS i_audit_hh ON audit_logs(household_id); CREATE INDEX IF NOT EXISTS i_dup_status ON duplicate_cases(status); CREATE INDEX IF NOT EXISTS i_req_status ON aid_requests(status);
`);

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const chainInput = (prev, a, u, h, p, at) => [prev, a, u, h, p, at].join('|');
function audit(action, { userId = null, orgId = null, hhId = null, locId = null, device = null, payload = {} } = {}) {
  const prev = db.prepare('SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1').get()?.hash || 'GENESIS';
  const at = new Date().toISOString(), p = JSON.stringify(payload);
  db.prepare('INSERT INTO audit_logs(action,user_id,organization_id,household_id,location_id,device_id,payload,prev_hash,hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
    .run(action, userId, orgId, hhId, locId, device, p, prev, sha(chainInput(prev, action, userId, hhId, p, at)), at);
}
function verifyChain() {
  let prev = 'GENESIS', n = 0;
  for (const r of db.prepare('SELECT * FROM audit_logs ORDER BY id').iterate()) {
    if (r.prev_hash !== prev || r.hash !== sha(chainInput(prev, r.action, r.user_id, r.household_id, r.payload, r.created_at))) return { valid: false, brokenAt: r.id, checked: n };
    prev = r.hash; n++;
  }
  return { valid: true, checked: n };
}

function seed() {
  const { norm, phon } = require('./services');
  let s = 42; const rnd = () => { s |= 0; s = s + 0x6D2B79F5 | 0; let t = Math.imul(s ^ s >>> 15, 1 | s); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  const pick = a => a[Math.floor(rnd() * a.length)];
  const ins = (q, ...a) => db.prepare(q).run(...a).lastInsertRowid;
  db.transaction(() => {
    ['SUPER_ADMIN', 'RELIEF_ADMIN', 'NGO_ADMIN', 'FIELD_WORKER', 'VERIFIER', 'DONOR_AUDITOR', 'PUBLIC'].forEach(r => ins('INSERT INTO roles(code) VALUES(?)', r));
    const org = {}; [['GOV', 'DDMA Relief Authority', 'GOVERNMENT'], ['RED', 'NGO Red', 'NGO'], ['BLUE', 'NGO Blue', 'NGO'], ['GREEN', 'NGO Green', 'NGO']].forEach(([c, n, t]) => org[c] = ins('INSERT INTO organizations(code,name,type) VALUES(?,?,?)', c, n, t));
    const V = [['Village A', 'KHP', 30.46, 69.82, .92], ['Village B', 'KHR', 30.38, 69.95, .18], ['Village C', 'KNG', 30.52, 69.7, .55], ['Village D', 'SHR', 30.3, 69.78, .75], ['Village E', 'TLR', 30.58, 69.92, .35]];
    const loc = V.map(([n, p, la, ln]) => { ins('INSERT INTO counters(prefix,n) VALUES(?,1000)', p); return ins('INSERT INTO locations(name,prefix,lat,lng) VALUES(?,?,?,?)', n, p, la, ln); });
    const aid = [['FOOD', 'Food Package', 14], ['WATER', 'Water', 7], ['MEDICAL', 'Medical', 10], ['SHELTER', 'Shelter', 60], ['CASH', 'Cash', 30], ['CLOTHING', 'Clothing', 30], ['KIT', 'Emergency Kit', 30], ['OTHER', 'Other', 7]].map(([c, n, d]) => ins('INSERT INTO aid_types(code,name,cooldown_days) VALUES(?,?,?)', c, n, d));
    const pw = bcrypt.hashSync('Demo@12345', 10), role = r => db.prepare('SELECT id FROM roles WHERE code=?').get(r).id;
    const U = (e, n, r, o) => { const id = ins('INSERT INTO users(email,password_hash,full_name,role_id,organization_id) VALUES(?,?,?,?,?)', e, pw, n, role(r), org[o]); ins('INSERT INTO organizations_users VALUES(?,?)', org[o], id); return id; };
    const admin = U('admin@reliefledger.demo', 'System Admin', 'SUPER_ADMIN', 'GOV'); U('ddma@reliefledger.demo', 'DDMA Officer', 'RELIEF_ADMIN', 'GOV');
    U('ngo1@reliefledger.demo', 'Red Admin', 'NGO_ADMIN', 'RED'); U('ngo2@reliefledger.demo', 'Blue Admin', 'NGO_ADMIN', 'BLUE');
    const w = { RED: U('worker@reliefledger.demo', 'Red Field Worker', 'FIELD_WORKER', 'RED'), BLUE: U('blueworker@reliefledger.demo', 'Blue Field Worker', 'FIELD_WORKER', 'BLUE'), GREEN: U('greenworker@reliefledger.demo', 'Green Field Worker', 'FIELD_WORKER', 'GREEN') };
    U('verifier@reliefledger.demo', 'Verifier', 'VERIFIER', 'GOV'); U('donor@reliefledger.demo', 'Donor Auditor', 'DONOR_AUDITOR', 'GOV');
    for (let i = 1; i <= 17; i++) U(`field${i}@reliefledger.demo`, `Field Worker ${i}`, 'FIELD_WORKER', ['RED', 'BLUE', 'GREEN'][i % 3]);
    const first = ['Ghulam', 'Gholam', 'Muhammad', 'Ali', 'Abdul', 'Noor', 'Fatima', 'Zainab', 'Karim', 'Saeed', 'Rahim', 'Gul', 'Aslam', 'Bibi'], last = ['Hussain', 'Hussein', 'Khan', 'Baloch', 'Ahmed', 'Shah', 'Mengal', 'Rind', 'Jan'];
    const when = d => new Date(Date.now() - d * 864e5).toISOString();
    const mk = (li, name, rid, orgC, served) => {
      const i = ins('INSERT INTO households(relief_id,head_name,head_name_norm,head_name_phonetic,family_size,children,elderly,disabled_members,is_women_led,origin_location_id,current_location_id,displacement_status,vulnerability_score,registered_by,organization_id,lat,lng) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        rid, name, norm(name), phon(norm(name)), 3 + Math.floor(rnd() * 7), Math.floor(rnd() * 4), Math.floor(rnd() * 2), Math.floor(rnd() * 2), rnd() < .2 ? 1 : 0, loc[li], loc[li], pick(['DISPLACED', 'RESIDENT', 'RETURNEE']), Math.floor(rnd() * 10), w[orgC], org[orgC], V[li][2] + (rnd() - .5) / 50, V[li][3] + (rnd() - .5) / 50);
      ins('INSERT INTO beneficiaries(household_id,full_name) VALUES(?,?)', i, name);
      audit('REGISTERED', { userId: w[orgC], orgId: org[orgC], hhId: i, locId: loc[li], payload: { reliefId: rid } }); return i;
    };
    const dist = (hh, orgC, code, daysAgo) => {
      const a = aid[['FOOD', 'WATER', 'MEDICAL', 'SHELTER', 'CASH', 'CLOTHING', 'KIT', 'OTHER'].indexOf(code)], at = when(daysAgo), d = ins('INSERT INTO aid_distributions(tx_id,household_id,aid_type_id,quantity,organization_id,created_by,location_id,distributed_at) VALUES(?,?,?,?,?,?,?,?)', 'TX-' + crypto.randomBytes(3).toString('hex').toUpperCase(), hh, a, 1, org[orgC], w[orgC], loc[0], at);
      ins("INSERT INTO verification_records(distribution_id,method,verified,verified_by) VALUES(?,'RELIEF_ID',1,?)", d, w[orgC]);
      db.prepare('UPDATE households SET total_aid_count=total_aid_count+1,last_aid_at=? WHERE id=?').run(at, hh);
      audit('DISTRIBUTED', { userId: w[orgC], orgId: org[orgC], hhId: hh, payload: { aid: code } }); audit('VERIFIED', { userId: w[orgC], orgId: org[orgC], hhId: hh });
    };
    const h1 = mk(0, 'Ghulam Hussain', 'KHP-004821', 'RED'), h2 = mk(0, 'Bibi Zainab', 'KHP-004822', 'RED'); dist(h2, 'RED', 'FOOD', 1);
    const all = [];
    V.forEach((v, li) => { for (let k = 0; k < 22; k++) {
      const n = db.prepare('UPDATE counters SET n=n+1 WHERE prefix=? RETURNING n').get(v[1]).n, oc = pick(['RED', 'BLUE', 'GREEN']);
      const id = mk(li, pick(first) + ' ' + pick(last), `${v[1]}-${String(n).padStart(6, '0')}`, oc); all.push(id);
      if (rnd() < v[4]) for (let j = 0; j < 1 + Math.floor(rnd() * 2); j++) dist(id, pick(['RED', 'BLUE', 'GREEN']), pick(['FOOD', 'WATER', 'MEDICAL', 'SHELTER']), 2 + Math.floor(rnd() * 12));
    } });
    db.prepare("UPDATE counters SET n=MAX(n,4999) WHERE prefix='KHP'").run();
    for (let i = 0; i < 6; i++) ins('INSERT INTO duplicate_cases(case_code,household_a_id,household_b_id,trigger_type,match_score,match_band,raised_by) VALUES(?,?,?,?,?,?,?)', 'DC-' + crypto.randomBytes(3).toString('hex').toUpperCase(), all[i], all[i + 30], 'REGISTRATION', .7 + i * .04, i > 3 ? 'HIGH' : 'MEDIUM', admin);
    all.slice(40, 44).forEach((id, i) => { const to = loc[(i + 1) % 5]; ins('INSERT INTO household_location_history(household_id,from_location_id,to_location_id,recorded_by) VALUES(?,?,?,?)', id, loc[0], to, admin); db.prepare('UPDATE households SET current_location_id=? WHERE id=?').run(to, id); });
    for (let i = 0; i < 10; i++) { const id = ins('INSERT INTO aid_requests(requester_name,location_id,family_size,displacement_status,aid_type_id,phone) VALUES(?,?,?,?,?,?)', pick(first) + ' ' + pick(last), loc[1 + i % 4], 4 + i % 5, 'DISPLACED', aid[i % 4], '0300' + (1000000 + i)); db.prepare('UPDATE aid_requests SET request_code=? WHERE id=?').run('REQ-2026-' + String(id).padStart(5, '0'), id); }
  })();
  console.log('Seeded demo data. Password for all demo users: Demo@12345');
}
module.exports = { db, audit, verifyChain, seed };
// Make sure the demo Admin and Worker accounts always exist, are active, unlocked and use the demo password.
function ensureDemo() {
  if (!db.prepare('SELECT COUNT(*) c FROM users').get().c) return; // brand-new database: seed() creates everything
  db.prepare('UPDATE users SET failed_logins=0,locked_until=NULL').run();
  const pw = bcrypt.hashSync('Demo@12345', 10);
  [['admin@reliefledger.demo', 'System Admin', 'SUPER_ADMIN', 'GOV'], ['worker@reliefledger.demo', 'Red Field Worker', 'FIELD_WORKER', 'RED']].forEach(([e, n, r, o]) => {
    const role = db.prepare('SELECT id FROM roles WHERE code=?').get(r), org = db.prepare('SELECT id FROM organizations WHERE code=?').get(o);
    if (!role || !org) return;
    const u = db.prepare('SELECT id FROM users WHERE email=?').get(e);
    if (u) db.prepare('UPDATE users SET password_hash=?,is_active=1 WHERE id=?').run(pw, u.id);
    else { const id = db.prepare('INSERT INTO users(email,password_hash,full_name,role_id,organization_id) VALUES(?,?,?,?,?)').run(e, pw, n, role.id, org.id).lastInsertRowid; db.prepare('INSERT OR IGNORE INTO organizations_users VALUES(?,?)').run(org.id, id); }
  });
}
ensureDemo();
if (!db.prepare('SELECT COUNT(*) c FROM users').get().c) setImmediate(seed);
