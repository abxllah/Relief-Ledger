const crypto = require('crypto');
const { db, audit } = require('./db');

class AppError extends Error { constructor(status, code, message, details) { super(message); Object.assign(this, { status, code, details }); } }
const PERMS = {
  RELIEF_ADMIN: ['search', 'view_full', 'override', 'resolve', 'review', 'audit', 'reports', 'dashboard'],
  NGO_ADMIN: ['manage_workers', 'register', 'search', 'distribute', 'override', 'review', 'audit', 'reports', 'dashboard'],
  FIELD_WORKER: ['register', 'search', 'distribute'],
  VERIFIER: ['search', 'view_full', 'override', 'resolve', 'review', 'audit'],
  DONOR_AUDITOR: ['reports', 'dashboard', 'audit_sanitized'],
};
const can = (role, p) => role === 'SUPER_ADMIN' || !!PERMS[role]?.includes(p);

// ---------- fuzzy matching ----------
const VAR = { gholam: 'ghulam', ghulaam: 'ghulam', hussein: 'hussain', husain: 'hussain', hosain: 'hussain', mohammad: 'muhammad', mohammed: 'muhammad', muhammed: 'muhammad', mohd: 'muhammad' };
const norm = s => String(s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9 ]/g, ' ').split(/\s+/).filter(Boolean).map(t => VAR[t] || t).sort().join(' ');
function soundex(w) {
  const m = { b: 1, f: 1, p: 1, v: 1, c: 2, g: 2, j: 2, k: 2, q: 2, s: 2, x: 2, z: 2, d: 3, t: 3, l: 4, m: 5, n: 5, r: 6 };
  let out = w[0].toUpperCase(), last = m[w[0]];
  for (const ch of w.slice(1)) { const c = m[ch]; if (c && c !== last) out += c; if (ch !== 'h' && ch !== 'w') last = c; }
  return (out + '000').slice(0, 4);
}
const phon = n => n.split(' ').filter(Boolean).map(soundex).join(' ');
function lev(a, b) {
  let p = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) { const c = [i]; for (let j = 1; j <= b.length; j++) c[j] = Math.min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); p = c; }
  return p[b.length];
}
const sim = (a, b) => (a || b) ? 1 - lev(a, b) / Math.max(a.length, b.length) : 0;
const km = (a, b, c, d) => { const r = x => x * Math.PI / 180, h = Math.sin(r(c - a) / 2) ** 2 + Math.cos(r(a)) * Math.cos(r(c)) * Math.sin(r(d - b) / 2) ** 2; return 12742 * Math.asin(Math.sqrt(h)); };
const digits = p => (p || '').replace(/\D/g, '') || null;

function score(c, h) {
  const parts = [], add = (w, v) => v != null && parts.push([w, v]), nn = norm(c.name);
  const nameS = Math.max(sim(nn, h.head_name_norm), c.alias ? sim(norm(c.alias), h.head_name_norm) : 0);
  const pa = phon(nn).split(' '), pb = h.head_name_phonetic.split(' ');
  const phoneEq = c.phoneNorm && h.phone_norm ? c.phoneNorm === h.phone_norm : null, d = Math.abs(c.size - h.family_size);
  add(.35, nameS); add(.2, pa.filter(x => pb.includes(x)).length / Math.max(pa.length, pb.length));
  add(.1, phoneEq == null ? null : +phoneEq); add(.05, d === 0 ? 1 : d === 1 ? .5 : 0);
  add(.05, c.originId && h.origin_location_id ? +(c.originId == h.origin_location_id) : null); add(.1, +(c.locationId == h.current_location_id));
  const dist = c.lat != null && h.lat != null ? km(c.lat, c.lng, h.lat, h.lng) : null;
  add(.1, dist == null ? null : dist <= .5 ? 1 : dist >= 5 ? 0 : 1 - (dist - .5) / 4.5);
  const tot = parts.reduce((s, [w]) => s + w, 0), total = parts.reduce((s, [w, v]) => s + w * v, 0) / tot;
  return { score: +total.toFixed(3), forceHigh: phoneEq === true && nameS >= .7, signals: { name: +nameS.toFixed(2), phonetic: +parts[1][1].toFixed(2), phone: phoneEq, proximityKm: dist == null ? null : +dist.toFixed(2) } };
}
const bandOf = s => s < .6 ? 'LOW' : s < .85 ? 'MEDIUM' : 'HIGH';
function dupCheck(c) {
  const nn = norm(c.name), t = nn.split(' '), pn = c.phoneNorm || null;
  const rows = db.prepare(`SELECT h.*,l.name village FROM households h JOIN locations l ON l.id=h.current_location_id WHERE h.status='ACTIVE'
    AND (h.head_name_phonetic=? OR h.head_name_norm LIKE ? OR h.head_name_norm LIKE ? OR (? IS NOT NULL AND h.phone_norm=?)) LIMIT 100`).all(phon(nn), '%' + t[0] + '%', '%' + t.at(-1) + '%', pn, pn);
  const matches = rows.map(h => { const r = score(c, h); return { reliefId: h.relief_id, id: h.id, name: h.head_name, village: h.village, score: r.score, band: r.forceHigh ? 'HIGH' : bandOf(r.score), signals: r.signals, lastAid: lastAid(h.id) }; })
    .filter(m => m.score >= .45).sort((a, b) => b.score - a.score).slice(0, 5);
  const order = { LOW: 0, MEDIUM: 1, HIGH: 2 };
  return { band: matches.reduce((b, m) => order[m.band] > order[b] ? m.band : b, 'LOW'), matches };
}

// ---------- queries ----------
const lastAid = id => db.prepare('SELECT d.distributed_at at,a.name aid_name,o.code org_code,o.name org FROM aid_distributions d JOIN aid_types a ON a.id=d.aid_type_id JOIN organizations o ON o.id=d.organization_id WHERE d.household_id=? ORDER BY d.distributed_at DESC LIMIT 1').get(id) || null;
function elig(hhId, aidId) {
  const a = db.prepare('SELECT * FROM aid_types WHERE id=?').get(aidId);
  const l = db.prepare('SELECT d.distributed_at at,o.name org FROM aid_distributions d JOIN organizations o ON o.id=d.organization_id WHERE d.household_id=? AND d.aid_type_id=? ORDER BY d.distributed_at DESC LIMIT 1').get(hhId, aidId);
  if (!l) return { eligible: true };
  const days = (Date.now() - Date.parse(l.at)) / 864e5, left = Math.ceil(a.cooldown_days - days);
  return { eligible: left <= 0, last: { ...l, aid: a.name, daysAgo: Math.floor(days) }, nextEligibleInDays: Math.max(left, 0) };
}
const hex = n => crypto.randomBytes(n).toString('hex').toUpperCase();
const openCase = (a, b, trigger, score, band, userId, details) =>
  db.prepare('INSERT INTO duplicate_cases(case_code,household_a_id,household_b_id,trigger_type,match_score,match_band,raised_by,details) VALUES(?,?,?,?,?,?,?,?)').run('DC-' + hex(3), a, b, trigger, score, band, userId, JSON.stringify(details || {}));

// ---------- register ----------
function register(u, b, { sync = false, deviceId = null } = {}) {
  const name = String(b.headName || '').trim(), size = +b.familySize;
  if (name.length < 2 || !(size > 0) || !b.locationId) throw new AppError(400, 'VALIDATION_ERROR', 'Name, family size and location are required');
  if (!u.org_id) throw new AppError(403, 'FORBIDDEN', 'Your account is not linked to an organization');
  const cand = { name, alias: b.alias, size, locationId: +b.locationId, originId: b.originId, phoneNorm: digits(b.phone), lat: b.lat ?? null, lng: b.lng ?? null };
  const chk = dupCheck(cand);
  if (!sync) {
    if (chk.band === 'HIGH' && !(can(u.role, 'resolve') && b.force)) throw new AppError(409, 'DUPLICATE_REVIEW_REQUIRED', 'Duplicate case requires administrator review.', chk);
    if (chk.band === 'MEDIUM' && !b.force) throw new AppError(409, 'DUPLICATE_WARNING', 'Possible duplicate found. Please check before creating.', chk);
  }
  return db.transaction(() => {
    const loc = db.prepare('SELECT * FROM locations WHERE id=?').get(cand.locationId);
    if (!loc) throw new AppError(400, 'VALIDATION_ERROR', 'Unknown location');
    const n = db.prepare('UPDATE counters SET n=n+1 WHERE prefix=? RETURNING n').get(loc.prefix).n, rid = `${loc.prefix}-${String(n).padStart(6, '0')}`;
    const kids = +b.children || 0, old = +b.elderly || 0, dis = +b.disabled || 0, wl = b.womenLed ? 1 : 0;
    const id = db.prepare(`INSERT INTO households(relief_id,head_name,head_name_norm,head_name_phonetic,alias,family_size,children,elderly,disabled_members,is_women_led,origin_location_id,current_location_id,displacement_status,lost_documents,phone,phone_norm,lat,lng,vulnerability_score,vulnerability_notes,registered_by,organization_id,device_id,sync_status,client_uuid)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(rid, name, norm(name), phon(norm(name)), b.alias || null, size, kids, old, dis, wl, b.originId || null, loc.id, b.displacement || 'RESIDENT', b.lostDocuments ? 1 : 0,
      b.phone || null, cand.phoneNorm, cand.lat, cand.lng, Math.min(10, kids + old * 2 + dis * 3 + wl * 2 + (b.displacement === 'DISPLACED' ? 2 : 0)), b.vulnerabilityNotes || null, u.id, u.org_id, deviceId, 'SYNCED', b.clientUuid || null).lastInsertRowid;
    db.prepare('INSERT INTO beneficiaries(household_id,full_name) VALUES(?,?)').run(id, name);
    audit('REGISTERED', { userId: u.id, orgId: u.org_id, hhId: id, locId: loc.id, device: deviceId, payload: { reliefId: rid } });
    if (chk.band !== 'LOW') { const m = chk.matches[0]; openCase(m.id, id, 'REGISTRATION', m.score, chk.band, u.id, m.signals); audit('DUPLICATE_FLAGGED', { userId: u.id, orgId: u.org_id, hhId: id, payload: { against: m.reliefId, score: m.score } }); }
    return { reliefId: rid, duplicateBand: chk.band };
  }).immediate();
}

// ---------- distribute ----------
const distTx = db.transaction((u, b, sync, deviceId) => {
  if (!u.org_id) throw new AppError(403, 'FORBIDDEN', 'Your account is not linked to an organization');
  const h = db.prepare('SELECT * FROM households WHERE relief_id=?').get(String(b.reliefId || '').toUpperCase().trim());
  if (!h || h.status !== 'ACTIVE') throw new AppError(404, 'BENEFICIARY_NOT_FOUND', 'Unable to verify beneficiary.');
  const a = db.prepare('SELECT * FROM aid_types WHERE code=?').get(b.aidType), qty = +b.quantity || 1;
  if (!a || qty <= 0) throw new AppError(400, 'VALIDATION_ERROR', 'Valid aid type and quantity are required');
  const e = elig(h.id, a.id); let override = 0, conflict = 0;
  if (!e.eligible) {
    if (b.override) {
      if (!can(u.role, 'override')) throw new AppError(403, 'OVERRIDE_NOT_ALLOWED', 'Only authorized staff can override a cooldown.');
      if (!String(b.overrideReason || '').trim()) throw new AppError(400, 'VALIDATION_ERROR', 'An override reason is required');
      override = 1;
    } else if (sync) conflict = 1;
    else throw new AppError(409, 'AID_COOLDOWN_ACTIVE', 'This household was recently served.', e);
  }
  const at = sync && b.distributedAt ? b.distributedAt : new Date().toISOString(), tx = 'TX-' + hex(3), method = b.method || 'RELIEF_ID';
  const d = db.prepare('INSERT INTO aid_distributions(tx_id,household_id,aid_type_id,quantity,organization_id,created_by,location_id,distributed_at,notes,override_used,override_reason,device_id,sync_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(tx, h.id, a.id, qty, u.org_id, u.id, h.current_location_id, at, b.notes || null, override, override ? b.overrideReason : null, deviceId, conflict ? 'CONFLICT' : 'SYNCED').lastInsertRowid;
  db.prepare('INSERT INTO verification_records(distribution_id,method,verified,verified_by) VALUES(?,?,1,?)').run(d, method, u.id);
  db.prepare("UPDATE households SET last_aid_at=?,total_aid_count=total_aid_count+1,updated_at=datetime('now') WHERE id=?").run(at, h.id);
  const ctx = { userId: u.id, orgId: u.org_id, hhId: h.id, locId: h.current_location_id, device: deviceId };
  audit('DISTRIBUTED', { ...ctx, payload: { tx, aid: a.code, qty } }); audit('VERIFIED', { ...ctx, payload: { tx, method } });
  if (override) audit('OVERRIDE', { ...ctx, payload: { tx, reason: b.overrideReason } });
  if (conflict) { openCase(h.id, null, 'SYNC', 1, 'HIGH', u.id, e); audit('DUPLICATE_FLAGGED', { ...ctx, payload: { tx, reason: 'offline conflict' } }); }
  return { txId: tx, reliefId: h.relief_id, aid: a.name, organization: u.org_name, verified: true, at, override: !!override, conflict: !!conflict };
});
function distribute(u, b, { sync = false, deviceId = null } = {}) {
  try { return distTx.immediate(u, b, sync, deviceId); }
  catch (e) {
    if (e.code === 'AID_COOLDOWN_ACTIVE') db.transaction(() => { // blocked attempts are recorded, not lost
      const h = db.prepare('SELECT id,current_location_id FROM households WHERE relief_id=?').get(String(b.reliefId).toUpperCase().trim());
      openCase(h.id, null, 'DISTRIBUTION_ATTEMPT', 1, 'HIGH', u.id, e.details);
      audit('DUPLICATE_BLOCKED', { userId: u.id, orgId: u.org_id, hhId: h.id, payload: { aid: b.aidType } });
    })();
    throw e;
  }
}

// ---------- sync ----------
function syncOps(u, deviceId, ops) {
  return ops.map(op => {
    try {
      if (db.prepare('SELECT 1 FROM sync_queue WHERE client_uuid=?').get(op.clientUuid)) return { clientUuid: op.clientUuid, status: 'DUPLICATE' };
      const p = { ...op.payload, clientUuid: op.clientUuid, distributedAt: op.clientTimestamp };
      const result = op.type === 'REGISTER' ? register(u, p, { sync: true, deviceId }) : op.type === 'DISTRIBUTE' ? distribute(u, p, { sync: true, deviceId }) : (() => { throw new AppError(400, 'VALIDATION_ERROR', 'Unknown operation'); })();
      const status = result.conflict ? 'CONFLICT' : 'APPLIED';
      db.transaction(() => {
        db.prepare('INSERT INTO sync_queue(client_uuid,device_id,user_id,op_type,payload,client_timestamp,status) VALUES(?,?,?,?,?,?,?)').run(op.clientUuid, deviceId, u.id, op.type, JSON.stringify(op.payload), op.clientTimestamp, status);
        audit('SYNCED', { userId: u.id, orgId: u.org_id, device: deviceId, payload: { op: op.type, status } });
      })();
      return { clientUuid: op.clientUuid, status, result };
    } catch (e) { return { clientUuid: op.clientUuid, status: 'FAILED', errorCode: e.code || 'INTERNAL_ERROR', message: e.status ? e.message : 'Could not process this record' }; }
  });
}

// ---------- stats ----------
function coverage() {
  const since = new Date(Date.now() - 30 * 864e5).toISOString();
  return db.prepare(`SELECT l.name,l.lat,l.lng,COUNT(DISTINCT h.id) households,COUNT(DISTINCT CASE WHEN d.id IS NOT NULL THEN h.id END) served FROM locations l
    LEFT JOIN households h ON h.current_location_id=l.id AND h.status='ACTIVE' LEFT JOIN aid_distributions d ON d.household_id=h.id AND d.distributed_at>=? GROUP BY l.id`).all(since)
    .map(r => { const pct = r.households ? Math.round(r.served * 1000 / r.households) / 10 : 0; return { ...r, coverage: pct, band: pct >= 70 ? 'GREEN' : pct >= 40 ? 'YELLOW' : 'RED', criticalGap: pct < 40 }; });
}
function stats() {
  const g = q => db.prepare(q).get().c, households = g("SELECT COUNT(*) c FROM households WHERE status='ACTIVE'");
  const served = g("SELECT COUNT(DISTINCT d.household_id) c FROM aid_distributions d JOIN households h ON h.id=d.household_id WHERE h.status='ACTIVE'");
  return { households, served, unreached: households - served, packages: g('SELECT COUNT(*) c FROM aid_distributions'), pendingRequests: g("SELECT COUNT(*) c FROM aid_requests WHERE status='PENDING'"),
    duplicateCases: g("SELECT COUNT(*) c FROM duplicate_cases WHERE status='OPEN'"),
    byAid: db.prepare('SELECT a.name name,COUNT(*) value FROM aid_distributions d JOIN aid_types a ON a.id=d.aid_type_id GROUP BY a.id ORDER BY value DESC').all(),
    byOrg: db.prepare('SELECT o.name name,COUNT(*) value FROM aid_distributions d JOIN organizations o ON o.id=d.organization_id GROUP BY o.id ORDER BY value DESC').all() };
}
module.exports = { AppError, can, norm, phon, dupCheck, elig, lastAid, register, distribute, syncOps, coverage, stats, digits, openCase };
