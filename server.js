import express from 'express';
import multer from 'multer';
import { google } from 'googleapis';
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
    analytics_start_date: d.analytics_start_date || null,
    duda_site_name:       d.duda_site_name       || null,
  };
}

app.use(express.json());
// ── Auth (public) ──
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ email: req.userEmail || '' });
});

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
const VALID_STATUSES = ['new', 'in_progress', 'awaiting_dns', 'awaiting_approval', 'launched', 'in_progress_frozen', 'awaiting_dns_frozen', 'awaiting_approval_frozen', 'decommissioned'];

app.get('/api/launches', requireAuth, async (req, res) => {
  try {
    const { status, search, department, industry, owner } = req.query;
    const snapshot = await db.collection('launches').orderBy('created_at', 'desc').get();
    let launches = snapshot.docs.map(formatLaunch);

    // Archived filter: default shows active (non-archived, non-decommissioned) only
    // archived=true shows explicitly archived records AND decommissioned sites
    if (req.query.archived === 'true') launches = launches.filter(r => r.archived || r.status === 'decommissioned');
    else launches = launches.filter(r => !r.archived && r.status !== 'decommissioned');

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
    const { status, notes, department, industry, account_name, domain_name, contact_name, email, phone, owner, is_renewal, archived, analytics_start_date, launch_date, duda_site_name } = req.body;
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
    if (analytics_start_date !== undefined) updates.analytics_start_date = analytics_start_date || null;
    if (duda_site_name       !== undefined) updates.duda_site_name       = duda_site_name       || null;
    if (statusChanged) {
      updates.status_changed_at = FieldValue.serverTimestamp();
    } else if (launch_date) {
      // Manual override of the launch date (e.g. site was live before it was added here)
      updates.status_changed_at = new Date(launch_date);
    }

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
      performance:    Math.round((cats.performance?.score    ?? 0) * 100),
      accessibility:  Math.round((cats.accessibility?.score  ?? 0) * 100),
      best_practices: Math.round((cats['best-practices']?.score ?? 0) * 100),
      seo:            Math.round((cats.seo?.score            ?? 0) * 100),
      url,
      is_post_launch: doc.data().status === 'launched',
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

// ── Google Analytics & Search Console (OAuth) ──
// User connects by clicking "Connect Analytics Account" in the Analytics tab.
// Refresh token is stored in Firestore at config/analytics_oauth.

const ANALYTICS_REDIRECT_URI = (() => {
  const base = (process.env.OAUTH_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`)
    .replace(/\/auth\/google\/callback$/, '');
  return `${base}/auth/analytics/callback`;
})();

const ANALYTICS_SCOPES = [
  'email',
  'https://www.googleapis.com/auth/webmasters.readonly',
  'https://www.googleapis.com/auth/analytics.readonly',
];

// In-memory token cache (avoids Firestore read on every request)
let _analyticsToken = null; // { access_token, expires_at }

async function getAnalyticsAccessToken() {
  if (_analyticsToken && Date.now() < _analyticsToken.expires_at - 60_000) {
    return _analyticsToken.access_token;
  }
  const snap = await db.collection('config').doc('analytics_oauth').get();
  if (!snap.exists) throw Object.assign(new Error('not_connected'), { code: 'not_connected' });
  const { refresh_token } = snap.data();
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token,
      grant_type: 'refresh_token',
    }),
  });
  const data = await r.json();
  if (!data.access_token) throw new Error('Failed to refresh analytics token');
  _analyticsToken = { access_token: data.access_token, expires_at: Date.now() + (data.expires_in || 3600) * 1000 };
  return _analyticsToken.access_token;
}

// OAuth connect flow
app.get('/auth/analytics', requireAuth, (req, res) => {
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', ANALYTICS_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', ANALYTICS_SCOPES.join(' '));
  url.searchParams.set('access_type', 'offline');
  url.searchParams.set('prompt', 'consent');
  res.redirect(url.toString());
});

app.get('/auth/analytics/callback', requireAuth, async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect('/dashboard?analytics_error=' + encodeURIComponent(error));
  try {
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: ANALYTICS_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    });
    const tokens = await r.json();
    if (!tokens.refresh_token) throw new Error('No refresh token returned — ensure prompt=consent');
    // Get connected email
    const userInfo = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    }).then(r => r.json());
    await db.collection('config').doc('analytics_oauth').set({
      refresh_token: tokens.refresh_token,
      email: userInfo.email || '',
      connected_at: new Date().toISOString(),
    });
    _analyticsToken = null; // bust cache
    ga4Cache = null;
    res.redirect('/dashboard?tab=analytics&analytics_connected=1');
  } catch (err) {
    console.error('Analytics OAuth callback error:', err.message);
    res.redirect('/dashboard?analytics_error=' + encodeURIComponent(err.message));
  }
});

app.get('/api/analytics/debug-domains', requireAuth, async (req, res) => {
  try {
    const token = await getAnalyticsAccessToken();
    ga4Cache = null; // force fresh fetch
    const map = await refreshGa4Cache(token);
    res.json({ domains: Object.keys(map).sort(), map });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analytics/connection', requireAuth, async (req, res) => {
  const snap = await db.collection('config').doc('analytics_oauth').get();
  if (!snap.exists) return res.json({ connected: false });
  const { email, connected_at } = snap.data();
  res.json({ connected: true, email, connected_at });
});

app.delete('/api/analytics/connection', requireAuth, async (req, res) => {
  await db.collection('config').doc('analytics_oauth').delete();
  _analyticsToken = null;
  ga4Cache = null;
  res.json({ ok: true });
});

// GA4 property discovery cache: normalised domain → propertyId
let ga4Cache = null; // { map: {domain: propertyId}, at: timestamp }

async function refreshGa4Cache(token) {
  const map = {};
  const allProps = [];
  let pageToken;
  do {
    const r = await fetch(
      `https://analyticsadmin.googleapis.com/v1alpha/accountSummaries?pageSize=200${pageToken ? '&pageToken=' + pageToken : ''}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = await r.json();
    for (const acc of data.accountSummaries || [])
      for (const p of acc.propertySummaries || []) allProps.push(p.property);
    pageToken = data.nextPageToken;
  } while (pageToken);

  for (let i = 0; i < allProps.length; i += 10) {
    await Promise.all(allProps.slice(i, i + 10).map(async propResource => {
      try {
        const r = await fetch(
          `https://analyticsadmin.googleapis.com/v1alpha/${propResource}/dataStreams?pageSize=50`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        const data = await r.json();
        const propId = propResource.replace('properties/', '');
        for (const s of data.dataStreams || []) {
          if (s.type === 'WEB_DATA_STREAM' && s.webStreamData?.defaultUri) {
            const d = s.webStreamData.defaultUri
              .replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
            map[d] = propId;
          }
        }
      } catch { /* skip inaccessible */ }
    }));
  }
  return map;
}

async function getGa4PropertyId(domain, token) {
  if (!ga4Cache || Date.now() - ga4Cache.at > 600_000) {
    ga4Cache = { map: await refreshGa4Cache(token), at: Date.now() };
  }
  const clean = domain.replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
  return ga4Cache.map[clean] || null;
}

function isoDate(d) { return d.toISOString().slice(0, 10); }

function computePctChange(weeks, key) {
  if (weeks.length < 4) return null;
  const n = Math.min(4, Math.floor(weeks.length / 2));
  const prev = weeks.slice(-n * 2, -n).reduce((s, w) => s + (w[key] || 0), 0);
  const last = weeks.slice(-n).reduce((s, w) => s + (w[key] || 0), 0);
  if (prev === 0) return null;
  return Math.round((last - prev) / prev * 1000) / 10;
}

async function fetchGSC(domain, launchDate, token) {
  const startDate = isoDate(new Date(launchDate));
  const endDate = isoDate(new Date());
  const cleanDomain = domain.replace(/^www\./, '');

  async function querySC(siteUrl, body) {
    const r = await fetch(
      `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/searchAnalytics/query`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }
    );
    if (!r.ok) throw new Error(`GSC ${r.status}`);
    return r.json();
  }

  // Try all common GSC siteUrl formats in order
  const siteUrlCandidates = [
    `sc-domain:${cleanDomain}`,
    `https://www.${cleanDomain}/`,
    `https://${cleanDomain}/`,
    `http://www.${cleanDomain}/`,
    `http://${cleanDomain}/`,
  ];
  let siteUrl = null;
  let rows = [];
  for (const candidate of siteUrlCandidates) {
    try {
      const data = await querySC(candidate, { startDate, endDate, dimensions: ['date'], rowLimit: 500 });
      rows = data.rows || [];
      siteUrl = candidate;
      break;
    } catch { /* try next */ }
  }
  if (!siteUrl) return { available: false };

  const topData = await querySC(siteUrl, { startDate, endDate, dimensions: ['query'], rowLimit: 5 })
    .catch(() => ({ rows: [] }));

  const weekMap = {};
  let clicks = 0, impressions = 0, posSum = 0, posCount = 0;
  for (const row of rows) {
    const d = new Date(row.keys[0]);
    d.setDate(d.getDate() - d.getDay());
    const wk = isoDate(d);
    if (!weekMap[wk]) weekMap[wk] = { clicks: 0, impressions: 0 };
    weekMap[wk].clicks += row.clicks || 0;
    weekMap[wk].impressions += row.impressions || 0;
    clicks += row.clicks || 0;
    impressions += row.impressions || 0;
    if (row.position) { posSum += row.position; posCount++; }
  }
  const weeks = Object.entries(weekMap)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([week, d]) => ({ week, ...d }));

  return {
    available: true,
    total: {
      clicks,
      impressions,
      ctr: impressions > 0 ? Math.round(clicks / impressions * 10000) / 100 : 0,
      position: posCount > 0 ? Math.round(posSum / posCount * 10) / 10 : null,
    },
    comparison: {
      clicksPct: computePctChange(weeks, 'clicks'),
      impressionsPct: computePctChange(weeks, 'impressions'),
    },
    weeks,
    topQueries: (topData.rows || []).map(r => ({
      query: r.keys[0],
      clicks: r.clicks || 0,
      position: r.position ? Math.round(r.position * 10) / 10 : null,
    })),
  };
}

async function fetchGA4(propertyId, launchDate, token) {
  const property = `properties/${propertyId}`;
  const startDate = isoDate(new Date(launchDate));

  async function runReport(body) {
    const r = await fetch(
      `https://analyticsdata.googleapis.com/v1beta/${property}:runReport`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }
    );
    if (!r.ok) throw new Error(`GA4 ${r.status}`);
    return r.json();
  }

  const [dailyData, channelData] = await Promise.all([
    runReport({
      dateRanges: [{ startDate, endDate: 'today' }],
      dimensions: [{ name: 'date' }],
      metrics: [
        { name: 'sessions' },
        { name: 'activeUsers' },
        { name: 'newUsers' },
        { name: 'engagementRate' },
      ],
      orderBys: [{ dimension: { dimensionName: 'date' } }],
      limit: 500,
    }),
    runReport({
      dateRanges: [{ startDate, endDate: 'today' }],
      dimensions: [{ name: 'sessionDefaultChannelGrouping' }],
      metrics: [{ name: 'sessions' }],
      orderBys: [{ metric: { metricName: 'sessions' }, desc: true }],
      limit: 6,
    }),
  ]);

  const weekMap = {};
  let sessions = 0, users = 0, newUsers = 0, engSum = 0, engCount = 0;
  for (const row of dailyData.rows || []) {
    const raw = row.dimensionValues[0].value;
    const d = new Date(`${raw.slice(0,4)}-${raw.slice(4,6)}-${raw.slice(6,8)}`);
    d.setDate(d.getDate() - d.getDay());
    const wk = isoDate(d);
    const [s, u, n, e] = row.metricValues.map(m => parseFloat(m.value) || 0);
    if (!weekMap[wk]) weekMap[wk] = { sessions: 0, users: 0 };
    weekMap[wk].sessions += s;
    weekMap[wk].users += u;
    sessions += s; users += u; newUsers += n;
    if (e > 0) { engSum += e; engCount++; }
  }
  const weeks = Object.entries(weekMap)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([week, d]) => ({ week, sessions: Math.round(d.sessions), users: Math.round(d.users) }));

  return {
    available: true,
    total: {
      sessions: Math.round(sessions),
      users: Math.round(users),
      newUsers: Math.round(newUsers),
      engagementRate: engCount > 0 ? Math.round(engSum / engCount * 1000) / 10 : null,
    },
    comparison: {
      sessionsPct: computePctChange(weeks, 'sessions'),
      usersPct: computePctChange(weeks, 'users'),
    },
    weeks,
    channels: (channelData.rows || []).map(r => ({
      channel: r.dimensionValues[0].value,
      sessions: parseInt(r.metricValues[0].value) || 0,
    })),
  };
}

// ── Duda Analytics ──
let dudaCredsCache = null;
async function getDudaCredentials() {
  if (dudaCredsCache) return dudaCredsCache;
  const snap = await db.collection('config').doc('duda_credentials').get();
  if (!snap.exists) throw new Error('Duda credentials not configured');
  dudaCredsCache = snap.data();
  return dudaCredsCache;
}

const dudaCache = {};
const DUDA_TTL  = 10 * 60 * 1000; // 10 minutes

app.post('/api/analytics/duda/clear-cache', requireAuth, (_req, res) => {
  Object.keys(dudaCache).forEach(k => delete dudaCache[k]);
  res.json({ ok: true });
});

async function fetchDuda(siteName, launchDate) {
  const cacheKey = `${siteName}`;
  const cached   = dudaCache[cacheKey];
  if (cached && Date.now() - cached.ts < DUDA_TTL) return cached.data;

  const creds  = await getDudaCredentials();
  const token  = Buffer.from(`${creds.api_user}:${creds.api_pass}`).toString('base64');
  const base   = 'https://api.duda.co/api';
  const headers = { Authorization: `Basic ${token}`, 'Content-Type': 'application/json' };

  const from = launchDate ? launchDate.slice(0, 10) : undefined;
  const to   = new Date().toISOString().slice(0, 10);
  const dateParams = from ? `?from=${from}&to=${to}&dateGranularity=DAYS` : `?to=${to}&dateGranularity=DAYS`;

  const [trafficRes, activityRes] = await Promise.all([
    fetch(`${base}/analytics/site/${siteName}${dateParams}&result=traffic`,     { headers }),
    fetch(`${base}/analytics/site/${siteName}${dateParams}&result=activities`,  { headers }),
  ]);

  if (!trafficRes.ok) {
    const err = await trafficRes.text();
    throw new Error(`Duda API error ${trafficRes.status}: ${err}`);
  }

  const trafficDaily  = await trafficRes.json();
  const activityDaily = activityRes.ok ? await activityRes.json() : {};

  // Parse {"2026-03-18": [{VISITORS:4,...}]} into sorted day arrays
  function parseDaily(obj, keyMap) {
    return Object.entries(obj).map(([day, rows]) => {
      const row = rows[0] || {};
      const entry = { day };
      for (const [src, dst] of Object.entries(keyMap)) entry[dst] = row[src] ?? 0;
      return entry;
    }).sort((a, b) => a.day.localeCompare(b.day));
  }

  const tDays = parseDaily(trafficDaily,  { VISITORS: 'visitors', VISITS: 'visits', PAGE_VIEWS: 'pageViews' });
  const aDays = parseDaily(activityDaily, { FORM_SUBMITS: 'formSubmits', CLICK_TO_CALLS: 'callClicks', CLICK_TO_EMAILS: 'emailClicks', CLICK_TO_MAPS: 'mapClicks' });

  // Merge traffic + activity by day key
  const dayMap = {};
  const zeroActivity = { formSubmits: 0, callClicks: 0, emailClicks: 0, mapClicks: 0 };
  for (const d of tDays) dayMap[d.day] = { ...zeroActivity, ...d };
  for (const d of aDays) {
    if (dayMap[d.day]) Object.assign(dayMap[d.day], d);
    else dayMap[d.day] = { day: d.day, visitors: 0, visits: 0, pageViews: 0, ...d };
  }
  const days = Object.values(dayMap).sort((a, b) => a.day.localeCompare(b.day));

  // Group daily data into ISO weeks (Mon start) for charting
  function isoWeekStart(dateStr) {
    const d = new Date(dateStr + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() - d.getUTCDay()); // back to Sunday, matching GSC/GA4
    return d.toISOString().slice(0, 10);
  }
  const weekMap = {};
  for (const d of days) {
    const wk = isoWeekStart(d.day);
    if (!weekMap[wk]) weekMap[wk] = { week: wk, visitors: 0, visits: 0, pageViews: 0, formSubmits: 0, callClicks: 0, emailClicks: 0, mapClicks: 0 };
    weekMap[wk].visitors    += d.visitors    || 0;
    weekMap[wk].visits      += d.visits      || 0;
    weekMap[wk].pageViews   += d.pageViews   || 0;
    weekMap[wk].formSubmits += d.formSubmits || 0;
    weekMap[wk].callClicks  += d.callClicks  || 0;
    weekMap[wk].emailClicks += d.emailClicks || 0;
    weekMap[wk].mapClicks   += d.mapClicks   || 0;
  }
  const weeks = Object.values(weekMap).sort((a, b) => a.week.localeCompare(b.week));

  // Full-range totals from daily data
  const total = days.reduce((acc, d) => {
    acc.visitors    += d.visitors    || 0;
    acc.visits      += d.visits      || 0;
    acc.pageViews   += d.pageViews   || 0;
    acc.formSubmits += d.formSubmits || 0;
    acc.callClicks  += d.callClicks  || 0;
    acc.emailClicks += d.emailClicks || 0;
    acc.mapClicks   += d.mapClicks   || 0;
    return acc;
  }, { visitors: 0, visits: 0, pageViews: 0, formSubmits: 0, callClicks: 0, emailClicks: 0, mapClicks: 0 });

  const data = { available: true, days, weeks, total };

  dudaCache[cacheKey] = { ts: Date.now(), data };
  return data;
}

app.get('/api/launches/:id/forms', requireAuth, async (req, res) => {
  try {
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const siteName = doc.data().duda_site_name;
    if (!siteName) return res.json({ available: false, reason: 'No Duda site ID set' });
    const creds = await getDudaCredentials();
    const token = Buffer.from(`${creds.api_user}:${creds.api_pass}`).toString('base64');
    const r = await fetch(`https://api.duda.co/api/sites/multiscreen/get-forms/${siteName}`, {
      headers: { Authorization: `Basic ${token}`, 'Content-Type': 'application/json' },
    });
    const rawText = await r.text();
    console.log('[forms] Duda status:', r.status, 'body:', rawText.slice(0, 1500));
    if (!r.ok) return res.json({ available: false, reason: `Duda error ${r.status}: ${rawText.slice(0, 200)}` });
    const data = JSON.parse(rawText);
    // data may be an array or { results: [...] }
    const submissions = Array.isArray(data) ? data : (data.results || []);
    console.log('[forms] parsed submissions count:', submissions.length, 'first:', JSON.stringify(submissions[0]).slice(0, 300));
    res.json({ available: true, submissions });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/analytics/:id', requireAuth, async (req, res) => {
  try {
    const token = await getAnalyticsAccessToken();
    const doc = await db.collection('launches').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    const launch = formatLaunch(doc);
    if (launch.status !== 'launched') return res.status(400).json({ error: 'Not a launched site' });

    const domain = launch.domain_name.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const rawLaunchDate = launch.status_changed_at || launch.created_at;
    // analytics_start_date overrides the status_changed_at for data range
    const analyticsStartDate = launch.analytics_start_date || null;
    const startDate = analyticsStartDate || rawLaunchDate;
    const daysSince = Math.floor((Date.now() - new Date(startDate.replace(' ', 'T') + 'Z')) / 86_400_000);

    const [gsc, ga4PropertyId, duda] = await Promise.all([
      fetchGSC(domain, startDate, token).catch(() => ({ available: false })),
      getGa4PropertyId(domain, token).catch(() => null),
      launch.duda_site_name
        ? fetchDuda(launch.duda_site_name, startDate).catch(e => ({ available: false, reason: e.message }))
        : Promise.resolve({ available: false, reason: 'No Duda site ID set' }),
    ]);
    const ga4 = ga4PropertyId
      ? await fetchGA4(ga4PropertyId, startDate, token).catch(() => ({ available: false }))
      : { available: false, reason: 'GA4 property not found for this domain' };

    res.json({ id: launch.id, account_name: launch.account_name, domain, launchDate: rawLaunchDate, analyticsStartDate, daysSince, gsc, ga4, duda });
  } catch (err) {
    console.error('Analytics error:', err.message);
    if (err.code === 'not_connected')
      return res.status(503).json({ error: 'not_connected' });
    res.status(500).json({ error: err.message || 'Failed to fetch analytics' });
  }
});


// ── AI SEO Suggestions (Gemini) ──
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
app.post('/api/seo-suggestions', requireAuth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(503).json({ error: 'GEMINI_API_KEY not configured' });
  try {
    const { account_name, domain, daysSince, health } = req.body;
    const trendStr = health.trendPct !== null
      ? (health.trendPct >= 0 ? `up ${health.trendPct}%` : `down ${Math.abs(health.trendPct)}%`)
      : 'unknown (insufficient data)';
    const prompt = `You are an SEO expert advising a local business website owner. The site "${account_name}" (${domain}) has been live for ${daysSince} days with these Google Search Console metrics:
- Health score: ${health.score ?? 'N/A'}/100 (${health.label})
- Daily impressions: ${health.impPerDay}
- CTR: ${health.ctr}%
- Avg ranking position: ${health.position ? Math.round(health.position) : 'N/A'}
- 4-week impression trend: ${trendStr}
- Flagged issues: ${health.issues.length ? health.issues.join(', ') : 'None'}

Provide exactly 4 specific, actionable SEO recommendations to improve this site's performance. Keep each recommendation to 2-3 sentences. Focus on the highest-impact improvements first. Respond ONLY with a valid JSON array of 4 strings, nothing else.`;

    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`;
    const body = JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] });
    let r;
    for (let attempt = 0; attempt < 4; attempt++) {
      if (attempt > 0) await new Promise(resolve => setTimeout(resolve, attempt * 5000));
      r = await fetch(geminiUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      if (r.status !== 429) break;
    }
    if (!r.ok) {
      const status = r.status;
      throw new Error(status === 429 ? 'Rate limit reached — please wait a moment and try again.' : `Gemini API error: ${status}`);
    }
    const data = await r.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
    if (!text) throw new Error('Empty response from Gemini');
    const jsonMatch = text.match(/\[[\s\S]*\]/);
    const suggestions = JSON.parse(jsonMatch ? jsonMatch[0] : text);
    res.json({ suggestions });
  } catch (err) {
    console.error('SEO suggestions error:', err.message);
    res.status(500).json({ error: err.message || 'Failed to generate suggestions' });
  }
});

// ── Pages ──
app.get('/edit-request', (_req, res) => res.sendFile(join(__dirname, 'public', 'edit-request.html')));
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile(join(__dirname, 'public', 'dashboard.html')));

app.listen(PORT, () => {
  console.log(`\n  Site Launch Tracker running at http://localhost:${PORT}`);
  console.log(`  Dashboard:              http://localhost:${PORT}/dashboard\n`);
});
