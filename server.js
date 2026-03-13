import express from 'express';
import nodemailer from 'nodemailer';
import multer from 'multer';
import { getStorage } from 'firebase-admin/storage';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { initializeApp, getApps } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ── Firebase init ──
if (!getApps().length) initializeApp();
const db = getFirestore();

// ── Google OAuth config ──
const GOOGLE_CLIENT_ID     = process.env.OAUTH_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.OAUTH_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`;
const ALLOWED_DOMAIN       = 'realworklabs.com';

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn('\n  ⚠️  OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET must be set.\n');
}

function generateToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// ── OAuth state (CSRF) ──
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

// ── Session cache (in-memory, 5 min TTL) to reduce Firestore reads ──
// Stores { expiry, email } per token
const sessionCache = new Map();

async function requireAuth(req, res, next) {
  const { auth_token } = getCookies(req);
  const fail = () => {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
    res.setHeader('Set-Cookie', `auth_return_to=${encodeURIComponent(req.originalUrl)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`);
    res.redirect('/login');
  };
  if (!auth_token) return fail();
  const cached = sessionCache.get(auth_token);
  if (cached && cached.expiry > Date.now()) {
    req.userEmail = cached.email;
    return next();
  }
  try {
    const session = await db.collection('sessions').doc(auth_token).get();
    if (!session.exists) { sessionCache.delete(auth_token); return fail(); }
    const email = session.data().email || '';
    sessionCache.set(auth_token, { expiry: Date.now() + 300_000, email });
    req.userEmail = email;
    next();
  } catch { fail(); }
}

// Like requireAuth but never blocks — attaches req.userEmail if session is valid
async function optionalAuth(req, res, next) {
  const { auth_token } = getCookies(req);
  if (!auth_token) return next();
  const cached = sessionCache.get(auth_token);
  if (cached && cached.expiry > Date.now()) {
    req.userEmail = cached.email;
    return next();
  }
  try {
    const session = await db.collection('sessions').doc(auth_token).get();
    if (session.exists) {
      const email = session.data().email || '';
      sessionCache.set(auth_token, { expiry: Date.now() + 300_000, email });
      req.userEmail = email;
    }
  } catch { /* silent */ }
  next();
}

// ── Email (Gmail SMTP via nodemailer) ──
function getMailTransport() {
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) return null;
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: { user, pass },
  });
}

async function sendClaimEmail(toEmail, accountName) {
  if (!toEmail) return;
  const transport = getMailTransport();
  if (!transport) {
    console.warn('Email not sent: GMAIL_USER or GMAIL_APP_PASSWORD is not set.');
    return;
  }
  try {
    const info = await transport.sendMail({
      from:    `"Launch Tracker" <${process.env.GMAIL_USER}>`,
      to:      toEmail,
      subject: `${accountName} / RealWork Website`,
      text:    `${accountName} has been assigned to you.\n\nView the dashboard to get started.`,
    });
    console.log('Email sent:', info.messageId, '→', toEmail);
  } catch (err) {
    console.error('Email send error:', err.message);
    throw err;
  }
}

// ── Slack notifications ──
async function sendSlack(blocks) {
  const url = process.env.SLACK_WEBHOOK_URL;
  if (!url) return;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blocks }),
    });
  } catch (err) {
    console.error('Slack notify error:', err.message);
  }
}

// ── Audit log ──
async function logAudit(event) {
  try {
    await db.collection('audit_log').add({
      ...event,
      at: FieldValue.serverTimestamp(),
    });
  } catch (err) {
    console.error('audit log error:', err.message);
  }
}

// ── Firestore helpers ──
function fmtTs(timestamp) {
  if (!timestamp) return null;
  const d = timestamp.toDate ? timestamp.toDate() : new Date(timestamp);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

function formatLaunch(doc) {
  const d = doc.data();
  return {
    id:               doc.id,
    department:       d.department       || '',
    account_name:     d.account_name     || '',
    domain_name:      d.domain_name      || '',
    contact_name:     d.contact_name     || '',
    email:            d.email            || '',
    phone:            d.phone            || '',
    status:           d.status           || 'new',
    notes:            d.notes            || '',
    industry:         d.industry         || '',
    owner:            d.owner            || '',
    is_renewal:       d.is_renewal       || false,
    archived:         d.archived         || false,
    submitted_by:     d.submitted_by     || '',
    created_at:       fmtTs(d.created_at),
    updated_at:       fmtTs(d.updated_at),
    status_changed_at: fmtTs(d.status_changed_at),
  };
}

app.use(express.json());
// ── Auth (public) ──
app.get('/login', (_req, res) => res.sendFile(join(__dirname, 'public', 'login.html')));
app.get('/', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'index.html')));

app.use(express.static(join(__dirname, 'public')));

app.get('/auth/google', (_req, res) => {
  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope:         'openid email profile https://www.googleapis.com/auth/gmail.readonly',
    access_type:   'offline',
    prompt:        'consent',
    state:         createState(),
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error || !code || !consumeState(state)) return res.redirect('/login?error=cancelled');
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
    if (!user.email?.endsWith(`@${ALLOWED_DOMAIN}`)) return res.redirect('/login?error=domain');

    // Persist OAuth tokens for Gmail API use (refresh_token only present on first auth)
    const tokenData = {
      access_token: tokens.access_token,
      expiry:       Date.now() + (tokens.expires_in || 3600) * 1000,
    };
    if (tokens.refresh_token) tokenData.refresh_token = tokens.refresh_token;
    await db.collection('tokens').doc(user.email).set(tokenData, { merge: true });

    const token = generateToken();
    await db.collection('sessions').doc(token).set({
      email: user.email,
      created_at: FieldValue.serverTimestamp(),
    });
    await logAudit({ type: 'login', email: user.email });
    const returnToCookie = decodeURIComponent(getCookies(req).auth_return_to || '') || '/dashboard';
    res.setHeader('Set-Cookie', [
      `auth_token=${token}; Path=/; HttpOnly; SameSite=Lax`,
      `auth_return_to=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
    ]);
    res.redirect(returnToCookie);
  } catch (err) {
    console.error('OAuth callback error:', err.message);
    res.redirect('/login?error=failed');
  }
});


app.post('/api/auth/logout', async (req, res) => {
  const { auth_token } = getCookies(req);
  if (auth_token) {
    sessionCache.delete(auth_token);
    await db.collection('sessions').doc(auth_token).delete().catch(() => {});
  }
  res.setHeader('Set-Cookie', 'auth_token=; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// ── Launches API ──
const VALID_STATUSES = ['new', 'in_progress', 'awaiting_dns', 'awaiting_approval', 'launched', 'decommissioned'];

app.get('/api/launches', requireAuth, async (req, res) => {
  try {
    const { status, search, department, industry, owner } = req.query;
    const snapshot = await db.collection('launches').orderBy('created_at', 'desc').get();
    let launches = snapshot.docs.map(formatLaunch);

    // Archived filter: default shows active only; ?archived=true shows archived only
    if (req.query.archived === 'true') launches = launches.filter(r => r.archived);
    else launches = launches.filter(r => !r.archived);

    if (status     && status     !== 'all') launches = launches.filter(r => r.status     === status);
    if (department && department !== 'all') launches = launches.filter(r => r.department === department);
    if (industry   && industry   !== 'all') launches = launches.filter(r => r.industry   === industry);
    if (owner      && owner      !== 'all') launches = launches.filter(r => r.owner      === owner);
    if (search) {
      const term = search.toLowerCase();
      launches = launches.filter(r =>
        r.account_name.toLowerCase().includes(term) ||
        r.domain_name.toLowerCase().includes(term)  ||
        r.contact_name.toLowerCase().includes(term)
      );
    }
    // Decommissioned always last, launched second-to-last
    const sortWeight = s => s === 'decommissioned' ? 2 : s === 'launched' ? 1 : 0;
    launches.sort((a, b) => sortWeight(a.status) - sortWeight(b.status));
    res.json(launches);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch launches.' });
  }
});

app.get('/api/launches/:id', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    res.json(formatLaunch(doc));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch launch.' });
  }
});

app.post('/api/launches', requireAuth, async (req, res) => {
  const { department, account_name, domain_name, contact_name, email, phone, industry, notes, is_renewal } = req.body;
  if (!department || !account_name || !domain_name || !contact_name || !email || !phone || !industry) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  try {
    const now = FieldValue.serverTimestamp();
    const ref = await db.collection('launches').add({
      department,
      account_name:      account_name.trim(),
      domain_name:       domain_name.trim().toLowerCase(),
      contact_name:      contact_name.trim(),
      email:             email.trim().toLowerCase(),
      phone:             phone.trim(),
      industry,
      notes:             (notes || '').trim(),
      is_renewal:        is_renewal === true || is_renewal === 'true',
      submitted_by:      req.userEmail || '',
      status:            'new',
      owner:             '',
      created_at:        now,
      updated_at:        now,
      status_changed_at: now,
    });
    await ref.collection('history').add({ status: 'new', entered_at: now });
    const doc = await ref.get();
    sendSlack([
      { type: 'header', text: { type: 'plain_text', text: '🌐 New Site Intake Submitted' } },
      { type: 'section', fields: [
        { type: 'mrkdwn', text: `*Account*\n${account_name.trim()}` },
        { type: 'mrkdwn', text: `*Domain*\n${domain_name.trim().toLowerCase()}` },
        { type: 'mrkdwn', text: `*Department*\n${department}` },
        { type: 'mrkdwn', text: `*Industry*\n${industry}` },
        { type: 'mrkdwn', text: `*Contact*\n${contact_name.trim()}` },
        { type: 'mrkdwn', text: `*Submitted by*\n${req.userEmail || '—'}` },
      ]},
    ]); // fire-and-forget
    res.status(201).json(formatLaunch(doc));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create launch.' });
  }
});

app.patch('/api/launches/:id', requireAuth, async (req, res) => {
  try {
    const { status, notes, department, industry, account_name, domain_name, contact_name, email, phone, owner, is_renewal, archived } = req.body;
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const row = doc.data();
    if (status && !VALID_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });

    const newStatus     = status || row.status;
    const statusChanged = newStatus !== row.status;
    const newOwner      = owner !== undefined ? owner : (row.owner || '');
    const ownerChanged  = owner !== undefined && owner !== (row.owner || '') && !!owner;

    const updates = {
      status:       newStatus,
      notes:        notes        !== undefined ? notes               : (row.notes || ''),
      department:   department   || row.department,
      industry:     industry     !== undefined ? industry            : (row.industry || ''),
      account_name: account_name ? account_name.trim()              : row.account_name,
      domain_name:  domain_name  ? domain_name.trim().toLowerCase() : row.domain_name,
      contact_name: contact_name ? contact_name.trim()              : row.contact_name,
      email:        email        ? email.trim().toLowerCase()        : row.email,
      phone:        phone        ? phone.trim()                      : row.phone,
      owner:        owner        !== undefined ? owner               : (row.owner || ''),
      is_renewal:   is_renewal   !== undefined ? Boolean(is_renewal) : (row.is_renewal || false),
      updated_at:   FieldValue.serverTimestamp(),
    };
    if (archived  !== undefined) updates.archived = Boolean(archived);
    if (statusChanged) updates.status_changed_at = FieldValue.serverTimestamp();

    await ref.update(updates);
    if (statusChanged) {
      await ref.collection('history').add({ status: newStatus, entered_at: FieldValue.serverTimestamp() });
    }

    // Build diff of changed fields for audit
    const changedFields = {};
    const watched = ['status','notes','department','industry','account_name','domain_name','contact_name','email','phone','owner'];
    for (const f of watched) {
      const oldVal = row[f] ?? '';
      const newVal = updates[f] ?? '';
      if (String(oldVal) !== String(newVal)) changedFields[f] = { from: oldVal, to: newVal };
    }
    await logAudit({ type: 'edit', email: req.userEmail || '', launch_id: req.params.id, changes: changedFields });

    if (ownerChanged) {
      const configDoc  = await db.collection('config').doc('ownerEmails').get();
      const ownerEmail = configDoc.exists ? configDoc.data()[newOwner] : null;
      const name       = updates.account_name || row.account_name || '';
      sendClaimEmail(ownerEmail, name); // fire-and-forget
    }

    if (statusChanged && newStatus === 'launched') {
      const name   = updates.account_name || row.account_name || '';
      const domain = updates.domain_name  || row.domain_name  || '';
      sendSlack([
        { type: 'header', text: { type: 'plain_text', text: '🚀 Site Launched!' } },
        { type: 'section', fields: [
          { type: 'mrkdwn', text: `*Account*\n${name}` },
          { type: 'mrkdwn', text: `*Domain*\n<https://${domain}|${domain}>` },
          { type: 'mrkdwn', text: `*Owner*\n${newOwner || '—'}` },
          { type: 'mrkdwn', text: `*Marked by*\n${req.userEmail || '—'}` },
        ]},
      ]); // fire-and-forget
    }

    const updated = await ref.get();
    res.json(formatLaunch(updated));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update launch.' });
  }
});

app.get('/api/launches/:id/history', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('launches').doc(req.params.id)
      .collection('history').orderBy('entered_at', 'asc').get();
    res.json(snapshot.docs.map(doc => ({
      id:         doc.id,
      launch_id:  req.params.id,
      status:     doc.data().status,
      entered_at: fmtTs(doc.data().entered_at),
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch history.' });
  }
});

app.delete('/api/launches/:id', requireAuth, async (req, res) => {
  try {
    const ref = db.collection('launches').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const data = doc.data();
    const history = await ref.collection('history').get();
    const batch = db.batch();
    history.docs.forEach(d => batch.delete(d.ref));
    batch.delete(ref);
    await batch.commit();
    await logAudit({ type: 'delete', email: req.userEmail || '', launch_id: req.params.id, account_name: data.account_name || '' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete launch.' });
  }
});

app.delete('/api/edit-requests/:id', requireAuth, async (req, res) => {
  try {
    const ref = db.collection('edit_requests').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.delete();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete edit request.' });
  }
});

// ── Admin audit log ──
app.get('/api/admin/logs', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('audit_log')
      .orderBy('at', 'desc')
      .limit(200)
      .get();
    const logs = snapshot.docs.map(doc => {
      const d = doc.data();
      return { id: doc.id, ...d, at: fmtTs(d.at) };
    });
    res.json(logs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch logs.' });
  }
});

// ── Admin test email ──
app.post('/api/admin/test-email', requireAuth, async (req, res) => {
  const { to } = req.body;
  if (!to) return res.status(400).json({ error: 'Missing to address.' });
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    return res.status(500).json({ error: 'GMAIL_USER or GMAIL_APP_PASSWORD is not set.' });
  }
  try {
    await sendClaimEmail(to, 'Test Account');
    res.json({ ok: true, to, from: process.env.GMAIL_USER });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Admin owner email config ──
app.get('/api/admin/owner-emails', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('config').doc('ownerEmails').get();
    res.json(doc.exists ? doc.data() : {});
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch emails.' });
  }
});

app.post('/api/admin/owner-emails', requireAuth, async (req, res) => {
  try {
    const data = {};
    if (typeof req.body.Daniel  === 'string') data.Daniel  = req.body.Daniel.trim();
    if (typeof req.body.Thierry === 'string') data.Thierry = req.body.Thierry.trim();
    await db.collection('config').doc('ownerEmails').set(data, { merge: true });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save emails.' });
  }
});

// ── RDAP / Domain Info ──
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
    let registrar = null;
    const regEntity = data.entities?.find(e => e.roles?.includes('registrar'));
    if (regEntity?.vcardArray?.[1]) {
      const fn = regEntity.vcardArray[1].find(p => p[0] === 'fn');
      if (fn) registrar = fn[3];
    }
    const dates = {};
    for (const ev of data.events || []) {
      if (ev.eventAction === 'registration') dates.created = ev.eventDate;
      if (ev.eventAction === 'expiration')   dates.expires = ev.eventDate;
      if (ev.eventAction === 'last changed') dates.updated = ev.eventDate;
    }
    const nameservers = (data.nameservers || []).map(ns => ns.ldhName?.toLowerCase()).filter(Boolean);
    const result = { registrar, nameservers, ...dates };
    domainCache.set(domain, { data: result, expiry: Date.now() + 3600000 });
    res.json(result);
  } catch (err) {
    if (err.name === 'TimeoutError') return res.status(504).json({ error: 'Lookup timed out.' });
    console.error('RDAP error:', err.message);
    res.status(500).json({ error: 'Lookup failed.' });
  }
});

// ── Edit Requests ──
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024, files: 3 } });

const EDIT_REQUEST_STATUSES = ['new', 'in_progress', 'completed', 'need_info', 'rejected'];

async function uploadToStorage(buffer, filename, mimetype) {
  // STORAGE_BUCKET can be set explicitly; if not, derive from the project ID
  // that Cloud Run / Firebase App Hosting injects automatically.
  const projectId  = process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
  const bucketName = process.env.STORAGE_BUCKET || (projectId ? `${projectId}.firebasestorage.app` : null);
  if (!bucketName) { console.warn('uploadToStorage: no bucket name available'); return null; }
  try {
    const token       = crypto.randomUUID();
    const safeName    = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
    const path        = `edit-requests/${Date.now()}-${safeName}`;
    const bucket      = getStorage().bucket(bucketName);
    const file        = bucket.file(path);
    await file.save(buffer, {
      metadata: { contentType: mimetype, metadata: { firebaseStorageDownloadTokens: token } },
    });
    return `https://firebasestorage.googleapis.com/v0/b/${bucketName}/o/${encodeURIComponent(path)}?alt=media&token=${token}`;
  } catch (err) {
    console.error('Storage upload error:', err.message);
    return null;
  }
}

function formatEditRequest(doc) {
  const d = doc.data();
  return {
    id:           doc.id,
    company_name: d.company_name || '',
    first_name:   d.first_name   || '',
    last_name:    d.last_name    || '',
    email:        d.email        || '',
    phone:        d.phone        || '',
    requests:     d.requests     || [],
    status:       d.status       || 'new',
    owner:        d.owner        || '',
    archived:     d.archived     || false,
    notes:        d.notes        || '',
    created_at:   fmtTs(d.created_at),
    updated_at:   fmtTs(d.updated_at),
  };
}

app.post('/api/edit-requests', upload.any(), async (req, res) => {
  const { company_name, first_name, last_name, email, phone } = req.body || {};
  if (!company_name || !first_name || !last_name || !email || !phone) {
    return res.status(400).json({ error: 'All contact fields are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  const requests = [];
  for (let i = 0; i < 3; i++) {
    const description = (req.body[`request_${i}_description`] || '').trim();
    if (!description) continue;
    const fileField = `request_${i}_image`;
    const file = (req.files || []).find(f => f.fieldname === fileField);
    let image_url = null, image_name = null;
    if (file) {
      image_url  = await uploadToStorage(file.buffer, file.originalname, file.mimetype);
      image_name = file.originalname;
    }
    requests.push({ description, image_url, image_name });
  }
  if (!requests.length) return res.status(400).json({ error: 'At least one edit request is required.' });
  try {
    const now = FieldValue.serverTimestamp();
    const ref = await db.collection('edit_requests').add({
      company_name: company_name.trim(),
      first_name:   first_name.trim(),
      last_name:    last_name.trim(),
      email:        email.trim().toLowerCase(),
      phone:        phone.trim(),
      requests,
      status:    'new',
      owner:     '',
      notes:     '',
      created_at: now,
      updated_at: now,
    });
    const doc = await ref.get();
    res.status(201).json(formatEditRequest(doc));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to submit request.' });
  }
});

app.get('/api/edit-requests', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('edit_requests').orderBy('created_at', 'desc').get();
    let requests = snapshot.docs.map(formatEditRequest);
    if (req.query.archived === 'true') requests = requests.filter(r => r.archived);
    else requests = requests.filter(r => !r.archived);
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch edit requests.' });
  }
});

app.get('/api/edit-requests/:id', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('edit_requests').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    res.json(formatEditRequest(doc));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch edit request.' });
  }
});

app.patch('/api/edit-requests/:id', requireAuth, async (req, res) => {
  try {
    const { status, notes, owner, archived } = req.body;
    const ref = db.collection('edit_requests').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    if (status && !EDIT_REQUEST_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });
    const updates = { updated_at: FieldValue.serverTimestamp() };
    if (status   !== undefined) updates.status   = status;
    if (notes    !== undefined) updates.notes    = notes;
    if (owner    !== undefined) updates.owner    = owner;
    if (archived !== undefined) updates.archived = Boolean(archived);
    await ref.update(updates);
    const updated = await ref.get();
    res.json(formatEditRequest(updated));
  } catch (err) {
    res.status(500).json({ error: 'Failed to update edit request.' });
  }
});

// ── Gmail API ──
async function getGmailAccessToken(email) {
  const doc = await db.collection('tokens').doc(email).get();
  if (!doc.exists) return null;
  const { access_token, refresh_token, expiry } = doc.data();
  if (!refresh_token) return null;
  if (Date.now() < expiry - 60_000) return access_token;
  // Refresh expired token
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type:    'refresh_token',
      refresh_token,
      client_id:     GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) return null;
  await db.collection('tokens').doc(email).update({
    access_token: data.access_token,
    expiry:       Date.now() + (data.expires_in || 3600) * 1000,
  });
  return data.access_token;
}

function decodeBase64Url(encoded) {
  if (!encoded) return '';
  return Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
}

function extractMessageBody(payload) {
  if (!payload) return { text: '', html: '' };
  if (payload.body?.data) {
    const content = decodeBase64Url(payload.body.data);
    return payload.mimeType === 'text/html' ? { text: '', html: content } : { text: content, html: '' };
  }
  if (payload.parts) {
    let text = '', html = '';
    for (const part of payload.parts) {
      const result = extractMessageBody(part);
      if (result.html) html = result.html;
      if (result.text) text = result.text;
    }
    return { text, html };
  }
  return { text: '', html: '' };
}

// Batch unread-thread check for dashboard badges
app.get('/api/gmail/unread', requireAuth, async (req, res) => {
  const emails = (req.query.emails || '').split(',').map(e => e.trim()).filter(Boolean).slice(0, 50);
  if (!emails.length) return res.json({});
  const accessToken = await getGmailAccessToken(req.userEmail);
  if (!accessToken) return res.json({}); // silently skip if not connected
  try {
    const results = await Promise.all(emails.map(async (email) => {
      const q = `(from:${email} OR to:${email}) is:unread`;
      const r = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/threads?q=${encodeURIComponent(q)}&maxResults=10`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      if (!r.ok) return [email, 0];
      const data = await r.json();
      return [email, data.threads?.length || 0];
    }));
    res.json(Object.fromEntries(results.filter(([, n]) => n > 0)));
  } catch (err) {
    console.error('Gmail unread error:', err);
    res.json({});
  }
});

// List threads for a contact email
app.get('/api/gmail/threads', requireAuth, async (req, res) => {
  const { email: contactEmail } = req.query;
  if (!contactEmail) return res.status(400).json({ error: 'email param required' });
  const accessToken = await getGmailAccessToken(req.userEmail);
  if (!accessToken) return res.status(403).json({ error: 'gmail_not_connected' });
  try {
    const q = `from:${contactEmail} OR to:${contactEmail}`;
    const listRes = await fetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/threads?q=${encodeURIComponent(q)}&maxResults=10`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    if (listRes.status === 401) return res.status(403).json({ error: 'gmail_not_connected' });
    if (!listRes.ok) return res.status(listRes.status).json({ error: 'Gmail API error' });
    const listData = await listRes.json();
    const threads = listData.threads || [];
    const getHeader = (msg, name) => msg?.payload?.headers?.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || '';
    const detailed = await Promise.all(threads.map(async (t) => {
      const tRes = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/threads/${t.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Date`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      if (!tRes.ok) return { id: t.id, snippet: t.snippet, subject: '(error)', from: '', date: '', messageCount: 1 };
      const tData = await tRes.json();
      const msgs = tData.messages || [];
      return {
        id:           t.id,
        snippet:      t.snippet,
        subject:      getHeader(msgs[0], 'Subject') || '(no subject)',
        from:         getHeader(msgs[msgs.length - 1], 'From'),
        date:         getHeader(msgs[msgs.length - 1], 'Date'),
        messageCount: msgs.length,
      };
    }));
    res.json(detailed);
  } catch (err) {
    console.error('Gmail threads error:', err);
    res.status(500).json({ error: 'Failed to fetch Gmail threads.' });
  }
});

// Get full thread messages
app.get('/api/gmail/threads/:threadId', requireAuth, async (req, res) => {
  const accessToken = await getGmailAccessToken(req.userEmail);
  if (!accessToken) return res.status(403).json({ error: 'gmail_not_connected' });
  try {
    const tRes = await fetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/threads/${req.params.threadId}?format=full`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    if (tRes.status === 401) return res.status(403).json({ error: 'gmail_not_connected' });
    if (!tRes.ok) return res.status(tRes.status).json({ error: 'Gmail API error' });
    const thread = await tRes.json();
    const getHeader = (msg, name) => msg?.payload?.headers?.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || '';
    const messages = (thread.messages || []).map(msg => {
      const { text, html } = extractMessageBody(msg.payload);
      return {
        id:      msg.id,
        from:    getHeader(msg, 'From'),
        to:      getHeader(msg, 'To'),
        date:    getHeader(msg, 'Date'),
        subject: getHeader(msg, 'Subject'),
        bodyHtml: html,
        bodyText: text,
      };
    });
    res.json(messages);
  } catch (err) {
    console.error('Gmail thread detail error:', err);
    res.status(500).json({ error: 'Failed to fetch thread.' });
  }
});

// ── Lighthouse / PageSpeed Insights ──
app.post('/api/launches/:id/lighthouse', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const domain = doc.data().domain_name;
    if (!domain) return res.status(400).json({ error: 'No domain on this launch.' });

    const url    = `https://${domain}`;
    const apiKey = process.env.PAGESPEED_API_KEY;
    if (!apiKey) return res.status(400).json({ error: 'PAGESPEED_API_KEY is not configured. Add it in Firebase App Hosting environment settings.' });

    const params = new URLSearchParams({ url, strategy: 'mobile', key: apiKey });
    for (const cat of ['performance', 'accessibility', 'best-practices', 'seo']) params.append('category', cat);

    const psiRes = await fetch(`https://www.googleapis.com/pagespeedonline/v5/runPagespeed?${params}`, {
      signal: AbortSignal.timeout(110_000),
    });
    if (!psiRes.ok) {
      const err = await psiRes.json().catch(() => ({}));
      const msg = err.error?.message || 'PageSpeed API error';
      const isQuota = psiRes.status === 429 || msg.toLowerCase().includes('quota');
      return res.status(psiRes.status).json({ error: isQuota ? 'API quota exceeded. Check your PAGESPEED_API_KEY quota in Google Cloud Console.' : msg });
    }
    const psi = await psiRes.json();
    const cats = psi.lighthouseResult?.categories || {};
    const audit = {
      performance:   Math.round((cats.performance?.score    ?? 0) * 100),
      accessibility: Math.round((cats.accessibility?.score  ?? 0) * 100),
      best_practices:Math.round((cats['best-practices']?.score ?? 0) * 100),
      seo:           Math.round((cats.seo?.score            ?? 0) * 100),
      url,
      created_at: FieldValue.serverTimestamp(),
    };
    const ref = await db.collection('launches').doc(req.params.id).collection('lighthouse_audits').add(audit);
    const saved = await ref.get();
    res.json({ id: saved.id, ...audit, created_at: new Date().toISOString() });
  } catch (err) {
    if (err.name === 'TimeoutError') return res.status(504).json({ error: 'PageSpeed timed out.' });
    console.error('Lighthouse error:', err);
    res.status(500).json({ error: 'Lighthouse audit failed.' });
  }
});

app.get('/api/launches/:id/lighthouse', requireAuth, async (req, res) => {
  try {
    const snapshot = await db.collection('launches').doc(req.params.id)
      .collection('lighthouse_audits').orderBy('created_at', 'desc').limit(10).get();
    res.json(snapshot.docs.map(d => {
      const data = d.data();
      return { id: d.id, ...data, created_at: fmtTs(data.created_at) };
    }));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch Lighthouse history.' });
  }
});

// ── Pages ──
app.get('/edit-request', (_req, res) => res.sendFile(join(__dirname, 'public', 'edit-request.html')));
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'dashboard.html')));

app.listen(PORT, () => {
  console.log(`\n  Site Launch Tracker running at http://localhost:${PORT}`);
  console.log(`  Dashboard:              http://localhost:${PORT}/dashboard\n`);
});
