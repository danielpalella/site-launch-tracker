import express from 'express';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import db from './database.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

const PASSWORD = 'duda';

function generateToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) + Date.now().toString(36);
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

app.post('/api/auth/login', (req, res) => {
  if (req.body.password !== PASSWORD) {
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
  const { status, search, department, industry } = req.query;
  let query = 'SELECT * FROM launches';
  const params = [];
  const conditions = [];

  if (status && status !== 'all') { conditions.push('status = ?'); params.push(status); }
  if (department && department !== 'all') { conditions.push('department = ?'); params.push(department); }
  if (industry && industry !== 'all') { conditions.push('industry = ?'); params.push(industry); }
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
  const { department, account_name, domain_name, contact_name, email, phone, industry } = req.body;
  if (!department || !account_name || !domain_name || !contact_name || !email || !phone || !industry) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  const result = db.prepare(`
    INSERT INTO launches (department, account_name, domain_name, contact_name, email, phone, industry, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'new')
  `).run(department, account_name.trim(), domain_name.trim().toLowerCase(), contact_name.trim(), email.trim().toLowerCase(), phone.trim(), industry);
  res.status(201).json(db.prepare('SELECT * FROM launches WHERE id = ?').get(result.lastInsertRowid));
});

app.patch('/api/launches/:id', requireAuth, (req, res) => {
  const { status, notes, department, industry, account_name, domain_name, contact_name, email, phone } = req.body;
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
  const statusChanged = newStatus !== row.status;

  const changedAt = statusChanged ? `, status_changed_at = datetime('now')` : '';
  db.prepare(`UPDATE launches SET status=?, notes=?, department=?, industry=?, account_name=?, domain_name=?, contact_name=?, email=?, phone=?, updated_at=datetime('now')${changedAt} WHERE id=?`)
    .run(newStatus, newNotes, newDept, newIndustry, newAccount, newDomain, newContact, newEmail, newPhone, Number(req.params.id));

  res.json(db.prepare('SELECT * FROM launches WHERE id = ?').get(req.params.id));
});

app.delete('/api/launches/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM launches WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM launches WHERE id = ?').run(Number(req.params.id));
  res.json({ success: true });
});

// ── Pages ──
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'dashboard.html')));

app.listen(PORT, () => {
  console.log(`\n  Site Launch Tracker running at http://localhost:${PORT}`);
  console.log(`  Dashboard:              http://localhost:${PORT}/dashboard\n`);
});
