import express from 'express';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import db from './database.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`;
const ALLOWED_DOMAIN       = 'realworklabs.com';

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn('\n  ⚠️  GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set in your .env file.\n');
}

function generateToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// Short-lived in-memory store for OAuth state (CSRF protection)
const oauthStates = new Map();
function createState() {
  const state = crypto.randomUUID();
  oauthStates.set(state, Date.now());
  for (const [k, t] of oauthStates) if (Date.now() - t > 600_000) oauthStates.delete(k);
  return state;
}
function consumeState(state) {
  const t = oauthStates.get(state);
  if (!t || Date.now() - t > 600_000) return false;
  oauthStates.delete(state);
  return true;
}

function getCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    if (k) cookies[k.trim()] = decodeURIComponent(v.join('='));
  });
  return cookies;
}

function requireAuth(req, res, next) {
  const { auth_token } = getCookies(req);
  const valid = auth_token && db.prepare('SELECT token FROM sessions WHERE token = ?').get(auth_token);
  if (valid) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
}

app.use(express.json());
app.use(express.static(join(__dirname, 'public')));

// ── Auth (public) ──
app.get('/login', (_req, res) => res.sendFile(join(__dirname, 'public', 'login.html')));

app.get('/auth/google', (_req, res) => {
  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope:         'openid email profile',
    access_type:   'online',
    state:         createState(),
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error || !code || !consumeState(state)) {
    return res.redirect('/login?error=cancelled');
  }
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri:  GOOGLE_REDIRECT_URI,
        grant_type:    'authorization_code',
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokens.error || 'token exchange failed');

    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const user = await userRes.json();
    if (!userRes.ok) throw new Error('userinfo fetch failed');

    if (!user.email?.endsWith(`@${ALLOWED_DOMAIN}`)) {
      return res.redirect('/login?error=domain');
    }

    const token = generateToken();
    db.prepare('INSERT INTO sessions (token) VALUES (?)').run(token);
    res.setHeader('Set-Cookie', `auth_token=${token}; Path=/; HttpOnly; SameSite=Lax`);
    res.redirect('/dashboard');
  } catch (err) {
    console.error('OAuth callback error:', err.message);
    res.redirect('/login?error=failed');
  }
});

app.post('/api/auth/login', (req, res) => {
  if (req.body.password !== 'duda') {
    return res.status(401).json({ error: 'Incorrect password.' });
  }
  const token = generateToken();
  db.prepare('INSERT INTO sessions (token) VALUES (?)').run(token);
  res.setHeader('Set-Cookie', `auth_token=${token}; Path=/; HttpOnly; SameSite=Lax`);
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  const { auth_token } = getCookies(req);
  if (auth_token) db.prepare('DELETE FROM sessions WHERE token = ?').run(auth_token);
  res.setHeader('Set-Cookie', 'auth_token=; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// ── Launches API (protected except POST — form submissions are public) ──
const VALID_STATUSES = [
  'new', 'in_progress', 'awaiting_dns',
  'awaiting_approval', 'launched'
];

app.get('/api/launches', requireAuth, (req, res) => {
  const { status, search, department, industry, owner } = req.query;
  let query = 'SELECT * FROM launches';
  const params = [];
  const conditions = [];

  if (status && status !== 'all') { conditions.push('status = ?'); params.push(status); }
  if (department && department !== 'all') { conditions.push('department = ?'); params.push(department); }
  if (industry && industry !== 'all') { conditions.push('industry = ?'); params.push(industry); }
  if (owner && owner !== 'all') { conditions.push('owner = ?'); params.push(owner); }
  if (search) {
    conditions.push('(account_name LIKE ? OR domain_name LIKE ? OR contact_name LIKE ?)');
    const term = `%${search}%`;
    params.push(term, term, term);
  }
  if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
  query += ' ORDER BY created_at DESC';

  res.json(db.prepare(query).all(...params));
});

app.get('/api/launches/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM launches WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

// POST is public — the submission form doesn't require a login
app.post('/api/launches', (req, res) => {
  const { department, account_name, domain_name, contact_name, email, phone, industry, notes } = req.body;
  if (!department || !account_name || !domain_name || !contact_name || !email || !phone || !industry) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  const result = db.prepare(`
    INSERT INTO launches (department, account_name, domain_name, contact_name, email, phone, industry, notes, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new')
  `).run(department, account_name.trim(), domain_name.trim().toLowerCase(), contact_name.trim(), email.trim().toLowerCase(), phone.trim(), industry, (notes || '').trim());
  db.prepare('INSERT INTO status_history (launch_id, status) VALUES (?, ?)').run(result.lastInsertRowid, 'new');
  res.status(201).json(db.prepare('SELECT * FROM launches WHERE id = ?').get(result.lastInsertRowid));
});

app.patch('/api/launches/:id', requireAuth, (req, res) => {
  const { status, notes, department, industry, account_name, domain_name, contact_name, email, phone, owner } = req.body;
  const row = db.prepare('SELECT * FROM launches WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (status && !VALID_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });

  const newStatus   = status       || row.status;
  const newNotes    = notes        !== undefined ? notes               : row.notes;
  const newDept     = department   || row.department;
  const newIndustry = industry     !== undefined ? industry            : row.industry;
  const newAccount  = account_name ? account_name.trim()              : row.account_name;
  const newDomain   = domain_name  ? domain_name.trim().toLowerCase() : row.domain_name;
  const newContact  = contact_name ? contact_name.trim()              : row.contact_name;
  const newEmail    = email        ? email.trim().toLowerCase()        : row.email;
  const newPhone    = phone        ? phone.trim()                      : row.phone;
  const newOwner    = owner        !== undefined ? owner               : row.owner;
  const statusChanged = newStatus !== row.status;

  const changedAt = statusChanged ? `, status_changed_at = datetime('now')` : '';
  db.prepare(`UPDATE launches SET status=?, notes=?, department=?, industry=?, account_name=?, domain_name=?, contact_name=?, email=?, phone=?, owner=?, updated_at=datetime('now')${changedAt} WHERE id=?`)
    .run(newStatus, newNotes, newDept, newIndustry, newAccount, newDomain, newContact, newEmail, newPhone, newOwner, Number(req.params.id));

  if (statusChanged) {
    db.prepare('INSERT INTO status_history (launch_id, status) VALUES (?, ?)').run(Number(req.params.id), newStatus);
  }

  res.json(db.prepare('SELECT * FROM launches WHERE id = ?').get(req.params.id));
});

app.get('/api/launches/:id/history', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM status_history WHERE launch_id = ? ORDER BY entered_at ASC').all(Number(req.params.id));
  res.json(rows);
});

app.delete('/api/launches/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM launches WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM launches WHERE id = ?').run(Number(req.params.id));
  res.json({ success: true });
});

// ── RDAP / Domain Info ──
// Cache the IANA bootstrap (which RDAP server handles each TLD) for 24h
let rdapBootstrap = null;
let rdapBootstrapExpiry = 0;

async function getRdapBaseUrl(tld) {
  if (!rdapBootstrap || Date.now() > rdapBootstrapExpiry) {
    const res = await fetch('https://data.iana.org/rdap/dns.json', {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) throw new Error('Failed to fetch RDAP bootstrap');
    rdapBootstrap = await res.json();
    rdapBootstrapExpiry = Date.now() + 86400000;
  }
  for (const [tlds, urls] of rdapBootstrap.services) {
    if (tlds.map(t => t.toLowerCase()).includes(tld)) {
      return urls.find(u => u.startsWith('https://')) || urls[0];
    }
  }
  return null;
}

// Cache domain results server-side for 1 hour
const domainCache = new Map();

app.get('/api/domain-info/:domain', requireAuth, async (req, res) => {
  const domain = req.params.domain.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];

  const cached = domainCache.get(domain);
  if (cached && Date.now() < cached.expiry) return res.json(cached.data);

  try {
    const tld = domain.split('.').pop();
    const baseUrl = await getRdapBaseUrl(tld);
    if (!baseUrl) return res.status(404).json({ error: `No RDAP server found for .${tld}` });

    const rdapRes = await fetch(`${baseUrl}domain/${domain}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10000),
    });
    if (!rdapRes.ok) return res.status(404).json({ error: 'Domain not found.' });
    const data = await rdapRes.json();

    // Registrar
    let registrar = null;
    const regEntity = data.entities?.find(e => e.roles?.includes('registrar'));
    if (regEntity?.vcardArray?.[1]) {
      const fn = regEntity.vcardArray[1].find(p => p[0] === 'fn');
      if (fn) registrar = fn[3];
    }

    // Key dates
    const dates = {};
    for (const ev of data.events || []) {
      if (ev.eventAction === 'registration') dates.created = ev.eventDate;
      if (ev.eventAction === 'expiration')   dates.expires = ev.eventDate;
      if (ev.eventAction === 'last changed') dates.updated = ev.eventDate;
    }

    // Nameservers
    const nameservers = (data.nameservers || [])
      .map(ns => ns.ldhName?.toLowerCase())
      .filter(Boolean);

    const result = { registrar, nameservers, ...dates };
    domainCache.set(domain, { data: result, expiry: Date.now() + 3600000 });
    res.json(result);
  } catch (err) {
    if (err.name === 'TimeoutError') return res.status(504).json({ error: 'Lookup timed out.' });
    console.error('RDAP error:', err.message);
    res.status(500).json({ error: 'Lookup failed.' });
  }
});

// ── Pages ──
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'dashboard.html')));

app.listen(PORT, () => {
  console.log(`\n  Site Launch Tracker running at http://localhost:${PORT}`);
  console.log(`  Dashboard:              http://localhost:${PORT}/dashboard\n`);
});
